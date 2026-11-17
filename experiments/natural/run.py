"""Launch registered56 retained-prefix continuations; imports are model-free."""
from pipeline.paths import resolve as research_path
import argparse, concurrent.futures, hashlib, json, os, signal, subprocess, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
ARMS = ['no_gate', 'originalauto', 'sealed_exact', 'no_agreement', 'unsealed_ctor_exact', 'opaque_no_update', 'trusted_edit', 'sealed_compatible']

def save(p, x):
    p.parent.mkdir(parents=True, exist_ok=True)
    q = p.with_suffix(p.suffix + '.tmp')
    q.write_text(json.dumps(x, indent=2) + '\n')
    q.replace(p)

def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path)
    p.add_argument('--protocol', type=Path, default=HERE / 'protocol.json')
    p.add_argument('--registration', type=Path)
    p.add_argument('--coupling-root', type=Path, required=True)
    p.add_argument('--campaign', required=True)
    p.add_argument('--workers', type=int, default=3)
    p.add_argument('--python', default=research_path('python'))
    p.add_argument('--dry-run', action='store_true')
    a = p.parse_args()
    protocol = json.loads(a.protocol.read_text())
    units = protocol['units']
    assert len(units) == 7 and protocol['proposed_episodes'] == 56
    if a.dry_run:
        print(json.dumps({'episodes': 56, 'source_prefixes': 7, 'state_policy_wire_groups': 3, 'arms': ARMS}))
        return
    assert a.registration and a.registration.is_file(), 'Root registration required before inference'
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == '', 'CPU only'
    assert os.environ.get('ENABLE_SECAGENT', '').lower() == 'true', 'Native Progent wrappers must be enabled'
    assert 1 <= a.workers <= 7 and a.campaign == Path(a.campaign).name
    out = (a.out or Path(os.environ['AROS_ARTIFACTS'])).resolve()
    out.mkdir(parents=True, exist_ok=True)
    assert not (out / 'config.json').exists(), 'No overwrite'
    cache = a.coupling_root.resolve() / a.campaign
    assert not cache.exists(), 'Fresh campaign cache required'
    cache.mkdir(parents=True)
    save(out / 'config.json', {'protocol_sha256': sha(a.protocol), 'registration_sha256': sha(a.registration), 'episodes': 56, 'units': [u['unit_id'] for u in units], 'arms': ARMS, 'campaign': a.campaign, 'models': 'Pi1.5/gpt-6-luna', 'budgets': 'historical+new U<=16,T<=64; H0', 'started_unix': time.time()})
    (out / 'status.md').write_text('Phase: natural retained-prefix continuations\nStatus: running\nCompleted source units: 0/7\nCompleted episodes: 0/56\n')

    def work(pair):
        index, unit = pair
        uid = unit['unit_id']
        packet = HERE / 'runtime' / Path(unit['runtime_packet']).name
        assert sha(packet) == unit['runtime_packet_sha256']
        rows = []
        for arm in ARMS[index % 8:] + ARMS[:index % 8]:
            stem = out / uid / arm
            stem.parent.mkdir(parents=True, exist_ok=True)
            bank = cache / uid
            (stem.parent / 'status.md').write_text(f'Phase: natural retained-prefix continuation\nSource unit: {uid}\nStatus: running {arm}\nCompleted arms: {len(rows)}/8\n')
            command = ['node', str(HERE / 'agent.mjs'), '--python', a.python, '--natural-packet', str(packet), '--manifest', str(Path(research_path('experiments/sealed/evaluation/authorship/x2b/manifest-v1.json'))), '--arm', arm, '--out', str(stem), '--actor-cache', str(bank / 'actor'), '--constructor-cache', str(bank / 'repair-constructor'), '--policy-cache', str(bank / 'base-policy'), '--judge-cache', str(bank / 'unused-judge')]
            start = time.time()
            launcher_error = None
            with stem.with_suffix('.stdout.log').open('w') as stdout, stem.with_suffix('.stderr.log').open('w') as stderr:
                try:
                    process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True)
                    try:
                        code = process.wait(timeout=1200)
                    except subprocess.TimeoutExpired:
                        code = 'timeout'
                        launcher_error = 'episode_watchdog_timeout'
                        stderr.write('Natural continuation watchdog expired; terminating entire episode process group.\n')
                        stderr.flush()
                        try:
                            os.killpg(process.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=10)
                        except subprocess.TimeoutExpired:
                            try:
                                os.killpg(process.pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            process.wait(timeout=10)
                except OSError as error:
                    code = 'launch_error'
                    launcher_error = type(error).__name__
                    stderr.write(repr(error) + '\n')
            path = stem.with_suffix('.json')
            try:
                row = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as error:
                row = {'natural_unit_id': uid, 'x6_arm': arm, 'status': 'operationally_unknown', 'x6_scientific_status': 'operationally_unknown', 'exit_code': code, 'record_read_error': type(error).__name__}
                launcher_error = launcher_error or 'episode_record_missing_or_invalid'
            row['launcher_elapsed_s'] = time.time() - start
            row['launcher_exit_code'] = code
            if launcher_error:
                row['launcher_error'] = launcher_error
                row['status'] = 'operationally_unknown'
            rows.append(row)
        (out / uid / 'status.md').write_text(f'Phase: natural retained-prefix continuation\nSource unit: {uid}\nStatus: completed\nCompleted arms: {len(rows)}/8\n')
        return rows
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = [pool.submit(work, pair) for pair in enumerate(units)]
        for completed_units, future in enumerate(concurrent.futures.as_completed(futures), 1):
            rows.extend(future.result())
            save(out / 'progress.json', {'finished': len(rows), 'scheduled': 56, 'completed_units': completed_units, 'scheduled_units': 7})
            (out / 'status.md').write_text(f'Phase: natural retained-prefix continuations\nStatus: running\nCompleted source units: {completed_units}/7\nCompleted episodes: {len(rows)}/56\n')
    save(out / 'result.json', {'scheduled': 56, 'completed_records': len(rows), 'rows': rows, 'historical_vs_new_costs': 'See natural_history_budget and x6_resources; historical calls are not re-billed as current network calls.'})
    (out / 'status.md').write_text(f'Phase: natural retained-prefix continuations\nStatus: completed\nCompleted source units: 7/7\nCompleted episodes: {len(rows)}/56\nLauncher failures: {sum((bool(row.get('launcher_error')) for row in rows))}\n')
    print(json.dumps({'scheduled': 56, 'completed_records': len(rows)}))
if __name__ == '__main__':
    main()
