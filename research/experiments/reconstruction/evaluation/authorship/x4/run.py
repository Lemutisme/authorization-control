"""Registered X4 full native episode runner on fixed X1 diagnostic units."""
import argparse
import collections
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import signal
import subprocess
import sys
import time

from arms import MAIN_ARMS, SMOKE_ARMS, DIAGNOSTIC_ARMS, ALL_ARMS
from release import verify_release

HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--phase', choices=['smoke', 'main', 'audit_diagnostic'], required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--arms', help='Explicitly registered comma-separated subset; no implicit outcome-based pruning')
    parser.add_argument('--smoke-unit', default='banking__user_task_11__send_money__amount')
    args = parser.parse_args()
    args.out = args.out or Path(os.environ['AROS_ARTIFACTS'])
    args.out.mkdir(parents=True, exist_ok=True)
    assert not (args.out / 'config.json').exists()
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    assert os.environ.get('PYTHONHASHSEED') == '20261106'
    release = verify_release()
    manifest = json.loads(args.manifest.read_text())
    assert sha(args.prefix / 'summary.json') == manifest['prefix_summary_sha256']
    rows = manifest['rows']
    if args.phase == 'smoke':
        rows = [row for row in rows if row['unit_id'] == args.smoke_unit and row['fault_class'] == 'M1']
        assert len(rows) == 1, 'Registered smoke unit/M1 unavailable in frozen pretreatment; do not replace silently'
    defaults = SMOKE_ARMS if args.phase == 'smoke' else DIAGNOSTIC_ARMS if args.phase == 'audit_diagnostic' else MAIN_ARMS
    arms = args.arms.split(',') if args.arms else defaults
    assert arms and len(arms) == len(set(arms)) and set(arms).issubset(ALL_ARMS)
    assert set(arms).issubset(DIAGNOSTIC_ARMS if args.phase == 'audit_diagnostic' else MAIN_ARMS)
    rows = list(rows)
    random.Random(20261111).shuffle(rows)
    config = {
        'phase': args.phase, 'arms': arms, 'conditions': [row['condition_id'] for row in rows],
        'release': release,
        'scheduled': len(rows), 'scheduled_episodes': len(rows) * len(arms),
        'manifest_sha256': sha(args.manifest), 'prefix_summary_sha256': manifest['prefix_summary_sha256'],
        'coupling': 'Frozen ordinary X1 prefix cache copied into each condition; actual context captured live. NEW empty occurrence-indexed repair bank shares only identical repair requests across arms. No within-arm repair-sample reuse.',
        'actor': 'Pi1.5/gpt-6-luna none/1400,16ordinaryrounds plus1extra repair draw,900swholeepisode',
        'constructor': 'Pi1.5/gpt-6-luna low/1536, one draw, no automatic retry',
        'scope': 'X1 static-controller fault lifecycle; malicious X2b and full generated-controller/PGA integrations remain separate studies',
        'source_sha256': {path.name: sha(path) for path in HERE.iterdir() if path.suffix in {'.py', '.mjs', '.json'}},
    }
    save(args.out / 'config.json', config)
    completed = []
    started = time.monotonic()

    def one(index, condition):
        folder = args.out / condition['condition_id']
        folder.mkdir()
        source_cache = args.prefix / condition['case_id'] / 'actor-cache'
        shutil.copytree(source_cache, folder / 'actor-cache')
        (folder / 'repair-bank').mkdir()  # Must start empty, separate from prefix cache.
        order = arms[index % len(arms):] + arms[:index % len(arms)]
        outcomes = {}
        panel = condition['fault_class'] + '/' + condition['stratum']
        for arm in order:
            audit = 'H10' if arm == 'x4_projection_H10_diagnostic' else 'H0'
            plan = args.manifest.parent / manifest['audit_plans'][panel + '/' + audit]
            target = folder / arm
            command = [
                'node', str(HERE / 'agent.mjs'), '--python', sys.executable,
                '--manifest', str(args.manifest.parent / manifest['cohort']),
                '--condition', str(args.manifest.parent / condition['condition_file']),
                '--arm', arm, '--out', str(target), '--actor-cache', str(folder / 'actor-cache'),
                '--repair-bank', str(folder / 'repair-bank'), '--audit-plan', str(plan),
                '--audit-ledger', str(args.out / 'audit-ledgers' / arm / (panel.replace('/', '-') + '.json')),
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=1050)
                (folder / (arm + '.process.txt')).write_text(stdout + stderr)
                if process.returncode:
                    raise RuntimeError('episode_process_error')
                outcomes[arm] = json.loads(target.with_suffix('.json').read_text())
            except Exception as error:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.communicate()
                outcomes[arm] = {'status': 'adapter_error', 'error': type(error).__name__, 'native_utility': None}
                save(folder / (arm + '.failure.json'), outcomes[arm])
        row = {key: condition[key] for key in ['condition_id', 'case_id', 'unit_id', 'cluster_id', 'fault_class', 'stratum']}
        row.update(order=order, arms=outcomes)
        save(folder / 'case.json', row)
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=1 if args.phase == 'smoke' else 4) as pool:
        futures = [pool.submit(one, index, condition) for index, condition in enumerate(rows)]
        for future in concurrent.futures.as_completed(futures):
            completed.append(future.result())
            groups = {}
            for arm in arms:
                values = [row['arms'][arm] for row in completed]
                groups[arm] = {
                    'n': len(values), 'native_utility': sum(value.get('native_utility') is True for value in values),
                    'unknown': sum(value.get('native_utility') is None or value.get('status') in {'adapter_error', 'inference_error', 'episode_timeout', 'no_response', 'operationally_unknown'} for value in values),
                    'repair_attempts': sum(len(value.get('x4_records', [])) for value in values),
                    'native_repair_events': sum(value.get('x4_repaired_effects', 0) for value in values),
                    'expert_audits': sum(record['resources']['expert_audits'] for value in values for record in value.get('x4_records', [])),
                }
            summary = {'scheduled': len(rows), 'observed': len(completed), 'complete': len(completed) == len(rows),
                       'groups': groups, 'elapsed_s': time.monotonic() - started}
            save(args.out / 'summary.json', {**summary, 'rows': completed})
            save(args.out / 'result.json', summary)
            (args.out / 'status.md').write_text(f"X4 {args.phase}: {len(completed)}/{len(rows)} conditions, {len(arms)} arms; elapsed {summary['elapsed_s']:.1f}s.\n")
            print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
