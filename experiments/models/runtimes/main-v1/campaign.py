"""Bounded-concurrency supervisor for the fixed model-role schedules.

Each provider/role is launched as its own AROS run; each scheduled row retains
stdout/stderr, a raw compressed result or a failure record. No automatic retry.
"""
from pipeline.paths import resolve as research_path
import argparse, concurrent.futures, gzip, hashlib, json, os, subprocess, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
PYTHON = research_path('python')

def save(p, value):
    p.parent.mkdir(parents=True, exist_ok=True)
    temp = p.with_suffix(p.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(p)

def task(row, out):
    began = time.monotonic()
    raw = out / 'raw' / (row['id'] + '.json.gz')
    log = out / 'logs' / (row['id'] + '.log')
    log.parent.mkdir(parents=True, exist_ok=True)
    if hashlib.sha256(Path(row['packet']).read_bytes()).hexdigest() != row['packet_sha256']:
        return {'id': row['id'], 'ok': False, 'error': 'input_hash_mismatch', 'elapsed_s': 0}
    if raw.exists():
        raise RuntimeError('Output namespace already contains this row')
    command = [PYTHON, '-B', str(HERE / ('update_trial.py' if row['kind'] == 'update' else 'actor_trial.py')), '--packet', row['packet'], '--model', row['model'], '--repetition', str(row['repetition']), '--out', str(raw)]
    if row['kind'] == 'update':
        command += ['--visible', str(int(row['visible']))]
    else:
        command += ['--direction', row['direction'], '--feedback', row['feedback']]
        if row['kind'] == 'unforced':
            command += ['--unforced']
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'CUDA_VISIBLE_DEVICES': ''}
    with log.open('w') as stream:
        process = subprocess.run(command, cwd=HERE, env=env, stdout=stream, stderr=subprocess.STDOUT)
    record = {'id': row['id'], 'ok': process.returncode == 0 and raw.exists(), 'returncode': process.returncode, 'elapsed_s': time.monotonic() - began, 'raw': str(raw) if raw.exists() else None, 'log': str(log)}
    if raw.exists():
        try:
            d = json.loads(gzip.decompress(raw.read_bytes()))
            record['status'] = d.get('status', 'update_returned')
            record['transport_failed'] = d.get('transport_failed')
            record['network_requests'] = sum((r.get('network_requests', 1) for r in d.get('requests', [])))
            record['model_identity_mismatches'] = sum((r.get('ok') and (not r.get('model_label_matches')) for r in d.get('requests', [])))
        except Exception as exc:
            record.update(ok=False, error=type(exc).__name__)
    return record

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--protocol', required=True)
    p.add_argument('--model', required=True)
    p.add_argument('--kind', choices=['actor', 'update', 'unforced', 'all'], required=True)
    p.add_argument('--workers', type=int, default=4)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    protocol = json.loads(Path(a.protocol).read_text())
    rows = [r for r in protocol['rows'] if r['model'] == a.model and (a.kind == 'all' or r['kind'] == a.kind)]
    if not rows:
        raise ValueError('Empty fixed schedule')
    out = Path(a.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'schedule.json').exists():
        raise ValueError('Use a fresh run namespace')
    save(out / 'schedule.json', {'protocol': str(Path(a.protocol).resolve()), 'protocol_sha256': hashlib.sha256(Path(a.protocol).read_bytes()).hexdigest(), 'rows': rows})
    began = time.monotonic()
    results = []
    artifacts = Path(os.environ.get('AROS_ARTIFACTS', str(out)))

    def status():
        text = f'{len(results)}/{len(rows)} completed; model={a.model}; role={a.kind}; process failures={sum((not r['ok'] for r in results))}; elapsed={time.monotonic() - began:.1f}s\n'
        (out / 'status.md').write_text(text)
        if artifacts != out:
            (artifacts / 'status.md').write_text(text)
        save(out / 'progress.json', {'scheduled': len(rows), 'completed': len(results), 'elapsed_s': time.monotonic() - began, 'rows': results})
    status()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        futures = {pool.submit(task, row, out): row for row in rows}
        for future in concurrent.futures.as_completed(futures):
            row = futures[future]
            try:
                r = future.result()
            except Exception as exc:
                r = {'id': row['id'], 'ok': False, 'error': type(exc).__name__}
            results.append(r)
            status()
    summary = {'scheduled': len(rows), 'completed': len(results), 'process_successes': sum((r['ok'] for r in results)), 'elapsed_s': time.monotonic() - began, 'network_requests': sum((r.get('network_requests', 0) for r in results)), 'rows': results, 'efficacy_scored_separately': True}
    save(out / 'result.json', summary)
    save(artifacts / 'campaign-result.json', summary)
    print(json.dumps({k: v for k, v in summary.items() if k != 'rows'}))
if __name__ == '__main__':
    main()
