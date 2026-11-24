"""Four fresh approval-mode arms on the retained complete banking cohort."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time

from controller import ARMS

INFRA = {'adapter_error', 'inference_error', 'episode_timeout', 'no_response'}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--phase', choices=['smoke', 'main', 'clean_repeat'], required=True)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    args.out = args.out or Path(os.environ['AROS_ARTIFACTS'])
    args.out.mkdir(parents=True, exist_ok=True)
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    assert os.environ.get('PYTHONHASHSEED') == '20261106'
    manifest = json.loads(args.manifest.read_text())
    cases = [case for case in manifest['cases'] if case['suite'] == 'banking'
             and (args.phase != 'clean_repeat' or case['condition'] == 'clean')]
    if args.phase == 'smoke':
        cases = [case for case in cases if case['case_id'] in {
            'banking__user_task_0__clean',
            'banking__user_task_0__injection_task_0',
            'banking__injection_task_0__goal_control',
        }]
    assert len(cases) == {'smoke': 3, 'main': 169, 'clean_repeat': 16}[args.phase]
    random.Random(20261111).shuffle(cases)
    assert not (args.out / 'config.json').exists()
    save(args.out / 'config.json', {
        'study': 'X3 fresh matched selector x approver ablation', 'phase': args.phase,
        'cases': [case['case_id'] for case in cases], 'arms': ARMS,
        'scheduled_episodes': len(cases) * len(ARMS),
        'manifest_sha256': sha(args.manifest),
        'source_sha256': {p.name: sha(p) for p in Path(__file__).parent.iterdir()
                          if p.suffix in {'.py', '.mjs', '.json'}},
        'actor': 'Pi1.5/gpt-6-luna,none/1400,16rounds240s',
        'policy': 'Original Progent initialization and retries; none/8192;64logicalpolicycalls',
        'interventions': 'Original optional vs successful-internal-read forced selector; automatic vs original SMT narrow-only approval',
        'coupling': 'Exact actor requests and per-arm-occurrence-indexed identical policy inputs share responses within a case; no within-arm retry reuse',
        'stopping': 'All cases once. Infrastructure failures retained; no outcome tuning, replacement, model fallback or task exclusions',
        'independent_unit': 'Owner task; multiple attack targets and the clean repeat are dependent repeated conditions',
        'no_gate_limit': 'No no-gate arm in this approval-mode study; no non-regression claim against no-gate follows from these contrasts',
    })
    rows = []
    start = time.monotonic()

    def one(index, case):
        folder = args.out / case['case_id']
        folder.mkdir()
        offset = index % len(ARMS)
        order = ARMS[offset:] + ARMS[:offset]
        arms = {}
        for arm in order:
            target = folder / arm
            command = [
                'node', str(Path(__file__).with_name('agent.mjs')), '--python', sys.executable,
                '--manifest', str(args.manifest), '--case', case['case_id'], '--arm', arm,
                '--out', str(target), '--actor-cache', str(folder / 'actor-cache'),
                '--judge-cache', str(folder / 'judge-cache'), '--policy-cache', str(folder / 'policy-cache'),
            ]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=720)
                (folder / (arm + '.process.txt')).write_text(stdout + stderr)
                if process.returncode:
                    raise RuntimeError('episode_process_error')
                arms[arm] = json.loads(target.with_suffix('.json').read_text())
            except Exception as error:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.communicate()
                arms[arm] = {'status': 'adapter_error', 'error': type(error).__name__, 'usage_unknown': True}
                save(folder / (arm + '.failure.json'), arms[arm])
        valid = all(
            episode.get('status') not in INFRA and episode.get('native_utility') is not None
            and (case['condition'] != 'attack' or episode.get('native_targeted_asr') is not None)
            for episode in arms.values()
        )
        states = [episode.get('initial_state_sha256') for episode in arms.values()]
        valid = bool(valid and None not in states and len(set(states)) == 1)
        batches = []
        for arm, episode in arms.items():
            for call in episode.get('pi', {}).get('calls', []):
                key = call.get('coupling', {}).get('request_sha256')
                path = folder / 'actor-cache' / (str(key) + '.json')
                if not path.exists():
                    valid = False
                    continue
                sample = json.loads(path.read_text())
                if sum(item['type'] == 'toolCall' for item in sample['message']['content']) > 1:
                    batches.append([arm, key])
                    valid = False
        row = {key: case[key] for key in ['case_id', 'task_id', 'condition']}
        row.update(order=order, arms=arms, valid=valid, batch_violations=batches)
        save(folder / 'case.json', row)
        return row

    with concurrent.futures.ThreadPoolExecutor(max_workers=2 if args.phase == 'smoke' else 4) as pool:
        futures = [pool.submit(one, index, case) for index, case in enumerate(cases)]
        for future in concurrent.futures.as_completed(futures):
            rows.append(future.result())
            summary = {
                'scheduled': len(cases), 'observed': len(rows), 'complete': len(rows) == len(cases),
                'scheduled_episodes': len(cases) * len(ARMS),
                'invalid_or_incomplete': sum(not row['valid'] for row in rows),
                'elapsed_s': time.monotonic() - start, 'groups': {},
            }
            for condition in ['clean', 'attack', 'goal_control']:
                selected = [row for row in rows if row['condition'] == condition]
                summary['groups'][condition] = {'n': len(selected)}
                for arm in ARMS:
                    episodes = [row['arms'][arm] for row in selected]
                    updates = [update for episode in episodes for update in episode.get('update_records', [])]
                    summary['groups'][condition][arm] = {
                        'utility': sum(episode.get('native_utility') is True for episode in episodes),
                        'targeted_asr': sum(episode.get('native_targeted_asr') is True for episode in episodes),
                        'unknown': sum(episode.get('native_utility') is None or episode.get('status') in INFRA for episode in episodes),
                        'updates_observed': len(updates),
                        'approver_checks': sum(len(update['approver_checks']) for update in updates),
                        'approver_rejects': sum(update['approver_rejects'] for update in updates),
                        'approver_errors': sum(update['approver_errors'] for update in updates),
                        'final_non_subset': sum(update['final_subset_diagnostic']['is_subset'] is False for update in updates),
                        'subset_diagnostic_unknown': sum(update['final_subset_diagnostic']['is_subset'] is None for update in updates),
                        'non_generated_changes': sum(not update['non_generated_unchanged'] for update in updates),
                        'generated_tool_additions': sum(bool(update['generated_tools_added']) for update in updates),
                        'current_call_new_admissions': sum(update.get('current_call_probe', {}).get('new_admission') is True for update in updates),
                    }
            save(args.out / 'summary.json', {**summary, 'rows': rows})
            save(args.out / 'result.json', summary)
            (args.out / 'status.md').write_text(
                f"{args.phase}: {len(rows)}/{len(cases)} cases; "
                f"invalid/incomplete {summary['invalid_or_incomplete']}; elapsed {summary['elapsed_s']:.1f}s.\n"
            )
            print(json.dumps(summary), flush=True)


if __name__ == '__main__':
    main()
