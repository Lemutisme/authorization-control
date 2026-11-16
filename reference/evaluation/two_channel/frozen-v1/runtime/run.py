"""Fixed two-channel continuation schedule. No model calls on import/dry-run."""
from __future__ import annotations
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ARMS = ['f0_u0', 'f0_u1', 'f1_u0', 'f1_u1', 'f0_off', 'f1_off']
DEFAULT_MANIFEST = '/artifact-source/968854d6265c/manifest-v1.json'


def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n'); tmp.replace(path)


def schedule(protocol):
    arms = protocol.get('arms', ARMS)
    if arms != ARMS:
        raise ValueError('Six declared cells/references required in frozen order')
    repeats = protocol.get('repeats', 1)
    if not isinstance(repeats, int) or repeats < 1:
        raise ValueError('Invalid repetition count')
    units = protocol['units']
    seen = set()
    jobs = []
    for index, unit in enumerate(units):
        if unit['unit_id'] in seen or Path(unit['unit_id']).name != unit['unit_id']:
            raise ValueError('Invalid or duplicate source identity')
        seen.add(unit['unit_id'])
        path = Path(unit['packet'])
        if sha(path) != unit['packet_sha256']:
            raise ValueError('Source packet changed')
        source = json.loads(path.read_text())
        if source['unit_id'] != unit['unit_id']:
            raise ValueError('Source identity mismatch')
        for repetition in range(repeats):
            offset = (index + repetition) % len(arms)
            jobs.append((unit, repetition, arms[offset:] + arms[:offset]))
    if protocol.get('expected_episodes', len(jobs) * len(arms)) != len(jobs) * len(arms):
        raise ValueError('Declared denominator differs from schedule')
    return jobs


def summarize(rows, expected):
    groups = {}
    for panel in sorted({r['panel'] for r in rows}):
        groups[panel] = {}
        for arm in ARMS:
            selected = [r for r in rows if r['panel'] == panel and r['factorial_arm'] == arm]
            groups[panel][arm] = {'n': len(selected),
                'known': sum(r.get('factorial_scientific_status') == 'known' for r in selected),
                'utility': sum(r.get('native_utility') is True for r in selected),
                'native_target': sum(r.get('native_targeted_asr') is True for r in selected),
                'first_update_new_admission': sum((r.get('factorial_first_refusal') or {}).get('new_admission') is True for r in selected),
                'value_exposure_available': sum((r.get('factorial_first_refusal') or {}).get('feedback_detail', {}).get('constraint_available') is True for r in selected),
                'actor_budget_exhaustion': sum(r.get('actor_status') == 'model_round_limit' for r in selected),
                'policy_budget_exhaustion': sum(r.get('factorial_resources', {}).get('total_policy_budget_slots', 0) >= 64 for r in selected)}
    return {'scheduled': expected, 'observed': len(rows), 'complete': len(rows) == expected,
            'unknown': sum(r.get('factorial_scientific_status') != 'known' for r in rows), 'groups': groups}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--protocol', type=Path, required=True)
    p.add_argument('--registration', type=Path)
    p.add_argument('--campaign', required=True)
    p.add_argument('--out', type=Path)
    p.add_argument('--coupling-root', type=Path, required=True)
    p.add_argument('--manifest', type=Path, default=Path(DEFAULT_MANIFEST))
    p.add_argument('--workers', type=int, default=3)
    p.add_argument('--dry-run', action='store_true')
    a = p.parse_args()
    protocol = json.loads(a.protocol.read_text())
    jobs = schedule(protocol)
    expected = len(jobs) * len(ARMS)
    if a.dry_run:
        print(json.dumps({'scheduled': expected, 'source_units': len(protocol['units']),
              'repeats': protocol.get('repeats', 1), 'arms': ARMS, 'model_calls': 0})); return
    if not a.registration or not a.registration.is_file():
        raise ValueError('Frozen root registration required')
    if os.environ.get('CUDA_VISIBLE_DEVICES') != '' or os.environ.get('ENABLE_SECAGENT', '').lower() != 'true':
        raise ValueError('Expected CPU-only native gate environment')
    if any(name.startswith('CHANNELS_QUALIFICATION_') for name in os.environ):
        raise ValueError('Qualification environment cannot launch model cohort')
    if not 1 <= a.workers <= 16 or a.campaign != Path(a.campaign).name:
        raise ValueError('Invalid worker count/campaign')
    out = (a.out or Path(os.environ['AROS_ARTIFACTS'])).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'config.json').exists():
        raise ValueError('No silent restart or output replacement')
    config = {'protocol_sha256': sha(a.protocol), 'registration_sha256': sha(a.registration),
              'campaign': a.campaign, 'scheduled': expected, 'source_units': len(protocol['units']),
              'manifest_sha256': sha(a.manifest), 'arms': ARMS,
              'model': 'gpt-6-luna', 'actor_profile': {'reasoning': 'none', 'output_tokens': 1400, 'cumulative_calls': 16},
              'policy_profile': {'reasoning': 'none', 'output_tokens': 8192, 'cumulative_calls': 64},
              'coupling': 'Exact finalized request/within-arm occurrence shared only within source unit and repetition. Fresh campaign namespace.',
              'schedule': [{'unit': unit['unit_id'], 'repetition': rep, 'arm_order': order} for unit, rep, order in jobs],
              'source_sha256': {p.name: sha(p) for p in sorted(HERE.iterdir()) if p.is_file() and p.suffix in {'.py', '.mjs'}},
              'started_unix': time.time()}
    save(out / 'config.json', config)
    started = time.monotonic(); rows = []

    def one(item):
        unit, repetition, arms = item
        folder = out / unit['unit_id'] / f'repetition-{repetition}'
        folder.mkdir(parents=True, exist_ok=True)
        cache = a.coupling_root.resolve() / a.campaign / unit['unit_id'] / f'repetition-{repetition}'
        cache.mkdir(parents=True, exist_ok=True)
        result = []
        for arm in arms:
            with (cache / (arm + '.started')).open('x') as stream:
                stream.write(str(folder))
            target = folder / arm
            command = ['node', str(HERE / 'agent.mjs'), '--python', sys.executable,
                '--manifest', str(a.manifest.resolve()), '--packet', str(Path(unit['packet']).resolve()),
                '--packet-sha256', unit['packet_sha256'], '--arm', arm, '--out', str(target),
                '--judge-cache', str(cache / 'judge'), '--policy-cache', str(cache / 'policy'),
                '--actor-cache', str(cache / 'actor')]
            with target.with_suffix('.stdout.log').open('w') as stdout, target.with_suffix('.stderr.log').open('w') as stderr:
                process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                failure = None
                try:
                    code = process.wait(timeout=1800)
                except subprocess.TimeoutExpired:
                    failure = 'watchdog_timeout'; code = 'timeout'
                    os.killpg(process.pid, signal.SIGTERM)
                    try: process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL); process.wait(timeout=10)
            try:
                row = json.loads(target.with_suffix('.json').read_text())
            except (OSError, json.JSONDecodeError):
                row = {'factorial_arm': arm, 'factorial_unit_id': unit['unit_id'],
                    'factorial_scientific_status': 'operationally_unknown',
                    'factorial_unknown_reasons': [failure or 'missing_result'],
                    'native_utility': None, 'native_targeted_asr': None}
            row.update(panel=unit['panel'], task_id=unit['task_id'], repetition=repetition, launcher_exit_code=code)
            if failure or code != 0:
                row['factorial_scientific_status'] = 'operationally_unknown'
                row.setdefault('factorial_unknown_reasons', []).append(failure or 'process_error')
            result.append(row)
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = [pool.submit(one, item) for item in jobs]
        for future in concurrent.futures.as_completed(futures):
            rows.extend(future.result())
            report = summarize(rows, expected)
            report['elapsed_s'] = time.monotonic() - started
            save(out / 'progress.json', report)
            (out / 'status.md').write_text(f"Two-channel main: {len(rows)}/{expected}; unknown {report['unknown']}; elapsed {report['elapsed_s']:.1f}s.\n")
            print(json.dumps(report), flush=True)
    rows.sort(key=lambda row: (row['factorial_unit_id'], row['repetition'], ARMS.index(row['factorial_arm'])))
    report = summarize(rows, expected); report['elapsed_s'] = time.monotonic() - started
    save(out / 'result.json', {**report, 'rows': rows})
    (out / 'status.md').write_text(f"Two-channel completed: {len(rows)}/{expected}; unknown {report['unknown']}; elapsed {report['elapsed_s']:.1f}s.\n")


if __name__ == '__main__':
    main()
