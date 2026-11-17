"""Fixed full envelope for the independent recovery-acknowledgement experiment."""
from pipeline.paths import resolve as research_path
import argparse, concurrent.futures, json, os, subprocess, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
PYTHON = research_path('python')

def save(p, d):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(d, indent=2) + '\n')

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--protocol', required=True)
    p.add_argument('--phase', choices=['pilot', 'main'], required=True)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    proto = json.loads(Path(a.protocol).read_text())
    rows = [r for r in proto['rows'] if a.phase == 'main' or r['unit_id'] in proto['pilot_units']]
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if (out / 'schedule.json').exists():
        raise ValueError('Fresh namespace required')
    save(out / 'schedule.json', {'phase': a.phase, 'rows': rows})
    results = []
    began = time.monotonic()

    def one(r):
        raw = out / 'raw' / (r['id'] + '.json.gz')
        log = out / 'logs' / (r['id'] + '.log')
        log.parent.mkdir(parents=True, exist_ok=True)
        cmd = [PYTHON, '-B', str(HERE / 'ack_trial.py'), '--packet', r['packet'], '--sha', r['packet_sha256'], '--model', r['model'], '--arm', r['arm'], '--out', str(raw)]
        with log.open('w') as stream:
            proc = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT)
        return {'id': r['id'], 'returncode': proc.returncode, 'raw': str(raw), 'log': str(log)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for r in pool.map(one, rows):
            results.append(r)
            save(out / 'progress.json', {'scheduled': len(rows), 'completed': len(results), 'rows': results, 'elapsed_s': time.monotonic() - began})
            status = f'Recovery-ack {a.phase}: {len(results)}/{len(rows)}; elapsed{time.monotonic() - began:.1f}s\n'
            (out / 'status.md').write_text(status)
            if os.environ.get('AROS_ARTIFACTS'):
                (Path(os.environ['AROS_ARTIFACTS']) / 'status.md').write_text(status)
    save(out / 'result.json', {'scheduled': len(rows), 'completed': len(results), 'rows': results, 'elapsed_s': time.monotonic() - began})
    print(json.dumps({'scheduled': len(rows), 'completed': len(results), 'elapsed_s': time.monotonic() - began}))
if __name__ == '__main__':
    main()
