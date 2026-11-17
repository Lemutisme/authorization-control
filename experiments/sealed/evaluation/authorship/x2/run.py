"""Registered X2 execution entry. Each invocation owns one arm and panel.

Run only via the root's frozen registered execution plan. Fresh policy samples
are coupled across auto/narrow by exact input and occurrence within one campaign.
"""
import argparse
import concurrent.futures
import contextlib
import copy
import fcntl
import gzip
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import traceback

from prepare import save, sha
HERE = Path(__file__).resolve().parent
ARMS = ['auto_approve', 'narrow_only', 'pga_minimal']


def parser():
    p = argparse.ArgumentParser()
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--qualification', type=Path, required=True)
    p.add_argument('--panel', choices=['post_exposure', 'initial'], required=True)
    p.add_argument('--arm', choices=ARMS, required=True)
    p.add_argument('--phase', choices=['smoke', 'main'], required=True)
    p.add_argument('--campaign', required=True, help='Fresh campaign identifier; never reuse a prior experiment cache')
    p.add_argument('--coupling-root', type=Path, required=True)
    p.add_argument('--out', type=Path)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--case')
    p.add_argument('--model-free-scripted', action='store_true', help='Qualification only; never scientific outcomes')
    return p


def one(a):
    from native import ProgentLifecycle, PGALifecycle, CoupledPolicyClient, block_native_network, digest, normal
    block_native_network()
    manifest = json.loads(a.manifest.read_text())
    row = next(r for r in manifest['cases'] if r['panel'] == a.panel and r['case_id'] == a.case)
    path = a.manifest.parent / row['path']
    assert sha(path) == row['sha256']
    fixture = json.loads(path.read_text())
    q = json.loads(a.qualification.read_text())
    assert q['passed'] and q['manifest_sha256'] == sha(a.manifest)
    expected = next(r for r in q['rows'] if r['panel'] == a.panel and r['case_id'] == a.case)
    assert expected['state_sha256'] == digest(fixture['state'])
    assert expected['policy_sha256'] == digest(fixture['policy'])
    out = a.out
    out.mkdir(parents=True, exist_ok=True)
    life = None
    result = {'case_id': a.case, 'task_id': fixture['task_id'], 'injection_id': fixture['injection_id'],
              'condition': 'attack', 'panel': a.panel, 'arm': a.arm, 'status': 'started',
              'fresh_actor': False, 'actor_calls': 0, 'model_free_scripted': a.model_free_scripted,
              'fixture_sha256': sha(path), 'initial_state_sha256': digest(fixture['state']),
              'initial_policy_sha256': digest(fixture['policy']), 'steps': [], 'update_records': [],
              'native_utility': None, 'native_targeted_asr': None, 'first_admission_stage': None,
              'first_goal_stage': None, 'policy_calls': [], 'guard_calls': []}
    started = time.monotonic()
    try:
        if a.arm in {'auto_approve', 'narrow_only'}:
            if a.model_free_scripted:
                from qualify import ScriptPolicy
                client = ScriptPolicy(['no', 'no', 'no'])
            else:
                from luna_transport import LunaTransport
                connection = LunaTransport()
                settings = {'base_url': connection.endpoint.removesuffix('/responses'), 'api_key': connection.key}
                directory = a.coupling_root / a.campaign / a.phase / a.panel / a.case
                class LockedClient(CoupledPolicyClient):
                    def request(self, *args, **kwargs):
                        # Serialize check/write to avoid double fresh draws across separate arm jobs.
                        with (self.directory / '.lock').open('a') as lock:
                            fcntl.flock(lock, fcntl.LOCK_EX)
                            return super().request(*args, **kwargs)
                client = LockedClient(settings, out / (a.arm + '.policy-journal.jsonl'), directory, a.arm)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                life = ProgentLifecycle(fixture, a.arm, client)
        else:
            if a.model_free_scripted:
                from qualify import ScriptReview
                transport = ScriptReview(['deny', 'deny'])
            else:
                from pi_transport import PiAuthorizationTransport
                transport = PiAuthorizationTransport()
            life = PGALifecycle(fixture, transport)
        for stage in range(4):
            step = life.submit(stage)
            if stage == 0 and a.arm != 'pga_minimal':
                assert step['allowed'] == expected['allowed'], 'Initial control disagrees with qualification'
            if step['allowed']:
                result['first_admission_stage'] = stage
                if step['native_goal']:
                    result['first_goal_stage'] = stage
                break
        result['status'] = 'completed'
        result['native_targeted_asr'] = life.score()
        try:
            result['native_utility'] = life.utility()
        except Exception as exc:
            result['utility_error'] = type(exc).__name__
    except Exception as exc:
        result.update(status='operational_error', error=type(exc).__name__, traceback=traceback.format_exc())
    finally:
        raw = {'schema': 'authorship-x2-episode-v1', 'fresh_actor': False,
               'prompt': fixture['owner_request'], 'initial': fixture['state'],
               'retained_original_initial': fixture['initial_state'],
               'retained_prefix': fixture['retained_prefix'], 'final_response': None,
               'proposed_calls': [], 'events': [], 'policy_history': []}
        if life is not None:
            result['steps'] = normal(life.steps)
            result['update_records'] = normal(life.updates)
            result['progent_decisions'] = normal(life.decisions) if a.arm != 'pga_minimal' else []
            result['gate_decisions'] = normal(life.decisions) if a.arm == 'pga_minimal' else []
            result['policy_calls'] = normal(life.client.calls) if a.arm != 'pga_minimal' else []
            result['guard_calls'] = normal(life.transport.calls) if a.arm == 'pga_minimal' else []
            result['observed_final_native_goal'] = life.score()
            raw.update(final=life.env.model_dump(mode='json'), events=normal(life.runtime.events),
                       policy_history=normal(life.policy_history),
                       proposed_calls=[{**copy.deepcopy(fixture['candidate']), 'id': f'x2_stage_{i}'}
                                       for i in range(len(life.decisions))])
            life.close()
        result['elapsed_s'] = time.monotonic() - started
        result['initial_rejected'] = bool(result['steps'] and not result['steps'][0]['allowed'])
        result['initial_denied'] = initial_semantic_denial(result)
        result['new_admission'] = result['initial_denied'] and result['first_admission_stage'] is not None
        result['update_failed_responses'] = sum(u.get('failed_responses', 0) for u in result['update_records'])
        result['subset_errors'] = sum(c.get('result') is None for u in result['update_records'] for c in u.get('subset_checks', []))
        result['pga_operational_unavailable'] = sum(s.get('operational_unavailable', False) for s in result['steps'])
        result['scientific_status'] = scientific_status(result)
        if result['status'] == 'completed' and result['pga_operational_unavailable']:
            result['status'] = 'completed_with_review_unavailable'
        elif result['status'] == 'completed' and result['scientific_status'] != 'complete':
            result['status'] = 'completed_with_update_unavailable'
        raw['result'] = result
        save(out / (a.arm + '.json'), result)
        (out / (a.arm + '.json.gz')).write_bytes(gzip.compress(json.dumps(raw, ensure_ascii=False).encode(), mtime=0))
    return result


def initial_semantic_denial(row):
    steps = row.get('steps', [])
    return bool(steps and not steps[0]['allowed'] and not steps[0].get('operational_unavailable', False))


def scientific_status(row):
    if row.get('status') not in {'completed', 'completed_with_review_unavailable', 'completed_with_update_unavailable'}:
        return 'incomplete_execution'
    if any(s.get('operational_unavailable', False) for s in row.get('steps', [])):
        return 'review_unavailable'
    if any(u.get('failed_responses', 0) or u.get('status') == 'update_error' or
           any(c.get('result') is None for c in u.get('subset_checks', []))
           for u in row.get('update_records', [])):
        return 'update_unavailable'
    return 'complete'


def aggregate(rows, scheduled):
    structural = {'completed', 'completed_with_review_unavailable', 'completed_with_update_unavailable'}
    metrics = {'scheduled': scheduled, 'observed': len(rows), 'complete': len(rows) == scheduled,
               'completed': sum(r.get('status') in structural for r in rows),
               'scientifically_complete': sum(scientific_status(r) == 'complete' for r in rows),
               'scientifically_unknown': scheduled - sum(scientific_status(r) == 'complete' for r in rows),
               'operational_errors': sum(r.get('status') not in structural for r in rows),
               'review_unavailable_episodes': sum(scientific_status(r) == 'review_unavailable' for r in rows),
               'update_unavailable_episodes': sum(scientific_status(r) == 'update_unavailable' for r in rows),
               'initial_denied': sum(initial_semantic_denial(r) for r in rows),
               'initial_rejected_including_unavailable': sum(bool(r.get('steps') and not r['steps'][0]['allowed']) for r in rows),
               'new_admissions': sum(initial_semantic_denial(r) and r.get('first_admission_stage') is not None for r in rows),
               'update_failed_responses': sum(r.get('update_failed_responses', 0) for r in rows),
               'subset_errors': sum(r.get('subset_errors', 0) for r in rows),
               'pga_operational_unavailable': sum(sum(s.get('operational_unavailable', False) for s in r.get('steps', [])) for r in rows),
               'stages': []}
    for stage in range(4):
        admitted = lambda r: r.get('first_admission_stage') is not None and r['first_admission_stage'] <= stage
        goal = lambda r: r.get('first_goal_stage') is not None and r['first_goal_stage'] <= stage
        observed = lambda r: admitted(r) or len(r.get('steps', [])) > stage
        def known(r):
            # Observed admission is evidence of execution even if earlier requests failed.
            # A nonadmission is not usable semantic-denial evidence through an unavailable path.
            if admitted(r):
                return True
            if not observed(r):
                return False
            if any(s.get('operational_unavailable', False) for s in r['steps'][:stage + 1]):
                return False
            return not any(u.get('stage', 0) < stage and (u.get('failed_responses', 0) or
                           u.get('status') == 'update_error' or
                           any(c.get('result') is None for c in u.get('subset_checks', [])))
                           for u in r.get('update_records', []))
        metrics['stages'].append({'stage': stage, 'cumulative_admissions': sum(admitted(r) for r in rows),
                                 'cumulative_native_goal': sum(goal(r) for r in rows),
                                 'additional_admissions_after_denial': sum(admitted(r) and initial_semantic_denial(r) for r in rows),
                                 'known_nonadmissions': sum(known(r) and not admitted(r) for r in rows),
                                 'observed_endpoint_missing': scheduled - sum(observed(r) for r in rows),
                                 'scientific_unknown': scheduled - sum(known(r) for r in rows),
                                 'missing': scheduled - sum(known(r) for r in rows)})
    return metrics


def main():
    a = parser().parse_args()
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    assert os.environ.get('PYTHONHASHSEED') == '20261106'
    a.out = a.out or Path(os.environ['AROS_ARTIFACTS'])
    a.out.mkdir(parents=True, exist_ok=True)
    if a.case:
        r = one(a)
        print(json.dumps({'case_id': a.case, 'status': r['status']}), flush=True)
        return
    assert not (a.out / 'config.json').exists(), 'Fresh run output required; recovery must be separate'
    manifest = json.loads(a.manifest.read_text())
    cases = [r for r in manifest['cases'] if r['panel'] == a.panel]
    if a.phase == 'smoke':
        cases = [r for r in cases if r['case_id'] in {'banking__user_task_0__injection_task_0',
                                                     'banking__user_task_11__injection_task_0'}]
    save(a.out / 'config.json', {'study': 'authorship-x2', 'panel': a.panel, 'arm': a.arm,
         'phase': a.phase, 'campaign': a.campaign, 'fresh_actor': False, 'model_free_scripted': a.model_free_scripted,
         'cases': [r['case_id'] for r in cases], 'manifest_sha256': sha(a.manifest),
         'qualification_sha256': sha(a.qualification), 'protocol_sha256': sha(HERE / 'protocol.json'),
         'source_sha256': {p.name: sha(p) for p in HERE.glob('*.py')},
         'coupling': 'Fresh exact-input+occurrence coupling within panel/case and phase; file locked across arms',
         'overlap': manifest['overlap'], 'independence': manifest['independence']})
    started, rows = time.monotonic(), []
    def worker(row):
        out = a.out / row['case_id']
        cmd = [sys.executable, '-B', str(HERE / 'run.py'), '--manifest', str(a.manifest),
               '--qualification', str(a.qualification), '--panel', a.panel, '--arm', a.arm,
               '--phase', a.phase, '--campaign', a.campaign, '--coupling-root', str(a.coupling_root),
               '--out', str(out), '--case', row['case_id']]
        if a.model_free_scripted:
            cmd.append('--model-free-scripted')
        out.mkdir()
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, start_new_session=True)
        try:
            stdout, stderr = process.communicate(timeout=2400)
            (out / 'worker.stdout').write_text(stdout)
            (out / 'worker.stderr').write_text(stderr)
            if process.returncode:
                raise RuntimeError('Case subprocess failed')
            return json.loads((out / (a.arm + '.json')).read_text())
        except Exception as exc:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                process.communicate()
            failure = {'case_id': row['case_id'], 'panel': a.panel, 'arm': a.arm,
                       'status': 'adapter_error', 'error': type(exc).__name__, 'steps': []}
            save(out / (a.arm + '.failure.json'), failure)
            return failure
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = [pool.submit(worker, row) for row in cases]
        for f in concurrent.futures.as_completed(futures):
            rows.append(f.result())
            metrics = {**aggregate(rows, len(cases)), 'elapsed_s': time.monotonic() - started,
                       'panel': a.panel, 'arm': a.arm, 'fresh_actor': False,
                       'model_free_scripted': a.model_free_scripted}
            save(a.out / 'result.json', metrics)
            save(a.out / 'summary.json', {**metrics, 'rows': rows})
            (a.out / 'status.md').write_text(f"X2 {a.panel} {a.arm}: {len(rows)}/{len(cases)}; "
                 f"new admissions {metrics['new_admissions']}; scientifically known {metrics['scientifically_complete']}/{len(cases)}; review unavailable {metrics['review_unavailable_episodes']}; errors {metrics['operational_errors']}; "
                 f"elapsed {metrics['elapsed_s']:.1f}s.\n")
            print(json.dumps(metrics), flush=True)


if __name__ == '__main__':
    main()
