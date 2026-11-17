"""Fresh X6 cohort jobs; imports never call a model or initialize an endpoint."""
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
ARMS = ('no_gate', 'originalauto', 'sealed_exact', 'no_agreement',
        'unsealed_ctor_exact', 'opaque_no_update', 'trusted_edit', 'sealed_compatible')
STRATEGIES = ('direct', 'feedback_adaptive', 'insist')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def schedule(manifest, phase, role, strategy):
    roles = ('attack', 'honest') if role == 'both' else (role,)
    strategies = STRATEGIES if strategy == 'all' else (strategy,)
    jobs = []
    for case in manifest['cases']:
        if case['x2b_role'] not in roles:
            continue
        if phase == 'smoke':
            if case['task_id'] != 'user_task_0' or (case['x2b_role'] == 'attack' and case['injection_id'] != 'injection_task_0'):
                continue
        elif case['x2b_panel'] != 'holdout':
            continue
        for current in strategies if case['x2b_role'] == 'attack' else ('direct',):
            jobs.append((case, current))
    if not jobs:
        raise ValueError('Registered source cohort is empty; do not substitute cases')
    return jobs


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--phase', choices=['smoke', 'main'], required=True)
    p.add_argument('--contract-profile', choices=['banking_financial', 'all_writes'], default='banking_financial')
    arm_group = p.add_mutually_exclusive_group()
    arm_group.add_argument('--arm', choices=ARMS)
    arm_group.add_argument('--arms', help='Comma-separated registered arms; default is all eight')
    p.add_argument('--role', choices=['honest', 'attack', 'both'], default='both')
    p.add_argument('--strategy', choices=[*STRATEGIES, 'all'], default=None)
    p.add_argument('--coupling-root', type=Path, required=True)
    p.add_argument('--campaign', required=True)
    p.add_argument('--registration', type=Path, help='Root-registered protocol artifact, recorded by exact hash')
    p.add_argument('--out', type=Path)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--dry-run', action='store_true', help='Print fixed schedule without starting brokers or models')
    a = p.parse_args()
    if not a.campaign or Path(a.campaign).name != a.campaign:
        p.error('--campaign must be one fresh namespace component')
    if not 1 <= a.workers <= 32:
        p.error('--workers must be in 1..32')
    arms = [a.arm] if a.arm else a.arms.split(',') if a.arms else list(ARMS)
    if not arms or len(set(arms)) != len(arms) or not set(arms) <= set(ARMS):
        p.error('Unregistered or repeated arm')
    strategy = a.strategy or ('direct' if a.phase == 'smoke' else 'all')
    if a.phase == 'smoke' and strategy != 'direct':
        p.error('Fixed smoke uses direct strategy only')
    manifest = json.loads(a.manifest.read_text())
    jobs = schedule(manifest, a.phase, a.role, strategy)
    summary = {'phase': a.phase, 'arms': arms, 'scheduled_conditions': len(jobs),
               'scheduled_episodes': len(jobs) * len(arms),
               'attack_episodes': sum(case['x2b_role'] == 'attack' for case, _ in jobs) * len(arms),
               'honest_episodes': sum(case['x2b_role'] == 'honest' for case, _ in jobs) * len(arms)}
    if a.dry_run:
        print(json.dumps(summary, indent=2))
        return
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == '', 'CPU-only registered environment required'
    assert os.environ.get('PYTHONHASHSEED') == '20261106', 'Registered hash seed required'
    a.out = (a.out or Path(os.environ['AROS_ARTIFACTS'])).resolve()
    a.out.mkdir(parents=True, exist_ok=True)
    assert not (a.out / 'config.json').exists(), 'Do not rerun into existing episode output'
    source = sorted(path for path in HERE.rglob('*') if path.suffix in {'.py', '.mjs'} and 'node_modules' not in path.parts and 'qualification' not in path.parts)
    config = {key: str(value) if isinstance(value, Path) else value for key, value in vars(a).items()}
    config.update(summary, strategy=strategy, manifest_sha256=sha(a.manifest),
        registration_sha256=sha(a.registration) if a.registration else None,
        cases=[{'case_id': case['case_id'], 'role': case['x2b_role'], 'strategy': current} for case, current in jobs],
        source_sha256={str(path.relative_to(HERE)): sha(path) for path in source},
        source_cohort_status='Known reused X2b cohort; holdout denotes source partition, not pristine unseen data.',
        coupling='Fresh campaign/phase/task/strategy namespace; exact request bytes plus within-arm occurrence across arms. No repeated-arm retry reuse.',
        actor_budget={'model': 'gpt-6-luna', 'reasoning': 'none', 'max_output_tokens': 1400, 'total_ordinary_plus_repair_draws': 16},
        constructor_budget={'model': 'gpt-6-luna', 'base_reasoning': 'none', 'base_max_output_tokens': 8192, 'repair_reasoning': 'low', 'repair_max_output_tokens': 1536, 'total_base_plus_reserved_repair_calls': 64},
        strict_primary='sealed_exact', compatibility_adaptation='sealed_compatible', expert_audits=0)
    save(a.out / 'config.json', config)
    started, rows = time.monotonic(), []

    def one(index, item):
        case, current = item
        key = case['case_id'] + '__' + current
        folder = a.out / key
        folder.mkdir()
        cache = a.coupling_root.resolve() / a.campaign / a.phase / a.contract_profile / case['x2b_role'] / current / case['case_id']
        cache.mkdir(parents=True, exist_ok=True)
        order = arms[index % len(arms):] + arms[:index % len(arms)]
        outcomes = []
        for arm in order:
            # This protects against a restarted arm silently retrieving its own
            # earlier samples. Different arms retain fresh occurrence counters.
            claim = cache / (arm + '.started.json')
            try:
                with claim.open('x') as handle:
                    json.dump({'output': str(folder), 'arm': arm, 'manifest_sha256': config['manifest_sha256']}, handle)
            except FileExistsError as error:
                raise RuntimeError(f'Arm already started in coupling namespace: {arm}/{key}') from error
            target = folder / arm
            command = ['node', str(HERE / 'agent.mjs'), '--python', sys.executable,
                '--manifest', str(a.manifest.resolve()), '--case', case['case_id'], '--arm', arm,
                '--role', case['x2b_role'], '--strategy', current, '--contract-profile', a.contract_profile, '--out', str(target),
                '--judge-cache', str(cache / 'judge'), '--policy-cache', str(cache / 'policy'),
                '--actor-cache', str(cache / 'actor'), '--constructor-cache', str(cache / 'constructor')]
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=1800)
                (folder / (arm + '.stdout')).write_text(stdout)
                (folder / (arm + '.stderr')).write_text(stderr)
                if process.returncode:
                    raise RuntimeError('episode_process_error')
                row = json.loads(target.with_suffix('.json').read_text())
            except Exception as error:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    process.communicate()
                row = {'case_id': case['case_id'], 'task_id': case['task_id'], 'x6_arm': arm,
                    'x2b_role': case['x2b_role'], 'strategy': current, 'status': 'adapter_error',
                    'x6_scientific_status': 'operationally_unknown', 'error': type(error).__name__,
                    'native_utility': None, 'native_targeted_asr': None}
                save(folder / (arm + '.failure.json'), row)
            outcomes.append(row)
        save(folder / 'case.json', {'case_id': case['case_id'], 'strategy': current, 'order': order, 'arms': {row['x6_arm']: row for row in outcomes}})
        return outcomes

    with concurrent.futures.ThreadPoolExecutor(max_workers=1 if a.phase == 'smoke' else a.workers) as pool:
        futures = [pool.submit(one, index, item) for index, item in enumerate(jobs)]
        for future in concurrent.futures.as_completed(futures):
            rows.extend(future.result())
            groups = {}
            for arm in arms:
                values = [row for row in rows if row['x6_arm'] == arm]
                groups[arm] = {'n': len(values),
                    'utility': sum(row.get('native_utility') is True for row in values),
                    'native_target': sum(row.get('native_targeted_asr') is True for row in values),
                    'partial_harm': sum(row.get('partial_harm', {}).get('any_declared_partial_harm', False) for row in values),
                    'operationally_unknown': sum(row.get('x6_scientific_status') == 'operationally_unknown' for row in values),
                    'repairs': sum(len(row.get('x6_repairs', [])) for row in values),
                    'repair_effects': sum(record.get('status') == 'executed' for row in values for record in row.get('x6_repairs', [])),
                    'actor_draws': sum(row.get('pi', {}).get('actor_draw_budget', {}).get('used', 0) for row in values),
                    'combined_constructor_calls': sum(row.get('combined_constructor_calls', 0) for row in values)}
            result = {**summary, 'observed': len(rows), 'complete': len(rows) == summary['scheduled_episodes'], 'groups': groups, 'elapsed_s': time.monotonic() - started}
            save(a.out / 'result.json', result)
            save(a.out / 'summary.json', {**result, 'rows': rows})
            (a.out / 'status.md').write_text(f"X6 {a.phase}: {len(rows)}/{summary['scheduled_episodes']} episodes; elapsed {result['elapsed_s']:.1f}s.\n")
            print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
