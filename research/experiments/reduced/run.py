"""Fixed matched constructor schedule. Launch only with root registration."""
from __future__ import annotations
from pipeline.paths import resolve as research_path
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
HERE = Path(__file__).resolve().parent
ARMS = ['all_tools_complete', 'known_function_complete', 'known_function_protected']
PYTHON = research_path('python')

def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def schedule(protocol):
    if protocol['arms'] != ARMS:
        raise ValueError('Arm ordering differs from declared interface')
    if type(protocol['repeats']) is not int or protocol['repeats'] < 1:
        raise ValueError('Invalid repetition count')
    if protocol.get('model') and any((protocol['model'].get(k) != v for k, v in {'harness': 'Pi 1.5.0', 'name': 'gpt-6-luna', 'reasoning': 'low', 'max_output_tokens': 1536, 'actor_calls': 0, 'owner_audits': 0}.items())):
        raise ValueError('Declared model/profile differs from fixed implementation')
    groups = {}
    for unit in protocol['units']:
        path = Path(unit['runtime_packet']).resolve()
        if sha(path) != unit['runtime_packet_sha256']:
            raise ValueError('Packet hash changed')
        packet = json.loads(path.read_text())
        if packet['unit_id'] != unit['unit_id']:
            raise ValueError('Unit identity mismatch')
        if unit['context_group'] not in {'tax', 'refund'}:
            raise ValueError('Context group required')
        groups.setdefault(unit['context_group'], []).append(unit)
    items = []
    for i, (group, units) in enumerate(sorted(groups.items())):
        for rep in range(protocol['repeats']):
            offset = (i + rep) % len(ARMS)
            items.append((group, units, rep, ARMS[offset:] + ARMS[:offset]))
    if sum((len(x[1]) * len(x[3]) for x in items)) != protocol['expected_draws']:
        raise ValueError('Schedule denominator mismatch')
    if 'expected_fresh_draws' in protocol and len(items) * 3 != protocol['expected_fresh_draws']:
        raise ValueError('Fresh semantic draw denominator mismatch')
    return items

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--protocol', type=Path, required=True)
    p.add_argument('--registration', type=Path)
    p.add_argument('--out', type=Path)
    p.add_argument('--campaign', required=True)
    p.add_argument('--workers', type=int, default=3)
    p.add_argument('--python', default=PYTHON)
    p.add_argument('--dry-run', action='store_true')
    p.add_argument('--fake-replies', type=Path)
    a = p.parse_args()
    protocol = json.loads(a.protocol.read_text())
    items = schedule(protocol)
    if a.dry_run:
        print(json.dumps({'scheduled': protocol['expected_draws'], 'fresh_draws': len(items) * 3, 'units': len(protocol['units']), 'repeats': protocol['repeats'], 'arms': ARMS, 'semantic_contexts': sorted({u['context_group'] for u in protocol['units']}), 'network_calls': 0}))
        return
    if not a.fake_replies:
        if not a.registration or not a.registration.is_file():
            raise ValueError('Root registration required')
        if os.environ.get('CUDA_VISIBLE_DEVICES') != '':
            raise ValueError('CPU-only experiment')
        if os.environ.get('ENABLE_SECAGENT', '').lower() != 'true':
            raise ValueError('Native gate must be enabled')
    if not 1 <= a.workers <= 7 or a.campaign != Path(a.campaign).name:
        raise ValueError('Invalid workers/campaign')
    out = (a.out or Path(os.environ['AROS_ARTIFACTS'])).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'config.json').exists():
        raise ValueError('No overwrite or silent run resumption')
    config = {'protocol_sha256': sha(a.protocol), 'registration_sha256': sha(a.registration) if a.registration else None, 'campaign': a.campaign, 'scheduled': protocol['expected_draws'], 'model': 'gpt-6-luna', 'reasoning': 'low', 'max_output_tokens': 1536, 'model_retries': 0, 'actor_draws': 0, 'schedule': [{'context_group': group, 'unit_ids': [u['unit_id'] for u in units], 'replicate': rep, 'arm_order': arms, 'representative': units[0]['unit_id']} for group, units, rep, arms in items], 'fake_output_qualification': bool(a.fake_replies), 'started_unix': time.time()}
    save(out / 'config.json', config)
    rows = []

    def work(item):
        group, units, rep, arms = item
        answer = []
        for arm in arms:
            representative = None
            for unit in units:
                stem = out / unit['unit_id'] / f'replicate-{rep}' / arm
                stem.parent.mkdir(parents=True, exist_ok=True)
                command = ['node', str(HERE / 'draw.mjs'), '--python', a.python, '--packet', unit['runtime_packet'], '--packet-sha256', unit['runtime_packet_sha256'], '--arm', arm, '--replicate', str(rep), '--out', str(stem)]
                if representative:
                    command += ['--reuse-draw', str(representative)]
                elif a.fake_replies:
                    command += ['--fake-reply', str(a.fake_replies.resolve() / f'{arm}.json')]
                start = time.time()
                failed = None
                with stem.with_suffix('.stdout.log').open('w') as stdout, stem.with_suffix('.stderr.log').open('w') as stderr:
                    try:
                        child = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                        try:
                            code = child.wait(timeout=300)
                        except subprocess.TimeoutExpired:
                            failed = 'draw_watchdog_timeout'
                            code = 'timeout'
                            try:
                                os.killpg(child.pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                            try:
                                child.wait(timeout=10)
                            except subprocess.TimeoutExpired:
                                try:
                                    os.killpg(child.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                                child.wait(timeout=10)
                    except OSError as exc:
                        failed = type(exc).__name__
                        code = 'launch_error'
                try:
                    row = json.loads(stem.with_suffix('.json').read_text())
                except (OSError, json.JSONDecodeError):
                    row = {'source': {'unit_id': unit['unit_id']}, 'arm': arm, 'replicate': rep, 'scientific_status': 'operationally_unknown'}
                    failed = failed or 'missing_or_invalid_record'
                row.update(context_group=group, launcher_elapsed_s=time.time() - start, launcher_exit_code=code)
                if failed:
                    row.update(launcher_error=failed, scientific_status='operationally_unknown')
                answer.append(row)
                if representative is None:
                    representative = stem.with_suffix('.json')
        return answer
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = [pool.submit(work, item) for item in items]
        for future in concurrent.futures.as_completed(futures):
            rows.extend(future.result())
            save(out / 'progress.json', {'completed': len(rows), 'scheduled': protocol['expected_draws']})
            (out / 'status.md').write_text(f'Phase: matched constructor diagnostic\nCompleted: {len(rows)}/{protocol['expected_draws']}\nUnknown: {sum((r['scientific_status'] != 'known' for r in rows))}\n')
    rows.sort(key=lambda r: (r['source']['unit_id'], r['replicate'], ARMS.index(r['arm'])))
    result = {'scheduled': protocol['expected_draws'], 'completed_records': len(rows), 'unknown': sum((r['scientific_status'] != 'known' for r in rows)), 'rows': rows, 'new_actor_calls': 0, 'logical_constructor_evaluations': sum((r.get('constructor_draws', 0) for r in rows)), 'new_constructor_calls': sum((r.get('fresh_constructor_draws', 0) for r in rows)), 'actual_network_calls': sum((r.get('constructor_meta', {}).get('actual_network_call') is True for r in rows))}
    save(out / 'result.json', result)
    (out / 'status.md').write_text(f'Phase: completed matched constructor diagnostic\nCompleted: {len(rows)}/{protocol['expected_draws']}\nUnknown: {result['unknown']}\n')
    print(json.dumps({k: v for k, v in result.items() if k != 'rows'}))
if __name__ == '__main__':
    main()
