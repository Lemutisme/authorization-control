"""Run the actual model-free JS/Python wire qualification in the native venv."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=HERE / '../authorship/x2b/manifest-v1.json')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert not (args.out / 'result.json').exists(), 'Use a new qualification directory'
    env = dict(os.environ)
    env.setdefault('BASELINE_VENDOR', '/artifact-source/3d9fa19e91e5/vendor')
    env.setdefault('PROGENT_SOURCE', '/artifact-source/c4751a2fc0fe/progent')
    env['CUDA_VISIBLE_DEVICES'] = ''
    env['PYTHONHASHSEED'] = '20261106'
    results = {}
    for label, script in [('wire', 'qualify_wire.mjs'), ('rpc', 'qualify_rpc.mjs')]:
        command = ['node', str(HERE / script), '--python', sys.executable, '--out', str(args.out / label)]
        if label == 'rpc':
            command += ['--manifest', str(args.manifest.resolve())]
        process = subprocess.run(command, capture_output=True, text=True, env=env)
        (args.out / (label + '.stdout')).write_text(process.stdout)
        (args.out / (label + '.stderr')).write_text(process.stderr)
        if process.returncode:
            raise RuntimeError(f'{label} qualification failed; see {args.out / (label + ".stderr")}')
        results[label] = json.loads((args.out / label / 'result.json').read_text())
    summary = {'passed': True, 'checks': sum(result['passed'] for result in results.values()),
               'model_requests': 0, 'external_network_requests': 0,
               'results': {label: str((args.out / label / 'result.json').resolve()) for label in results}}
    (args.out / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary))


if __name__ == '__main__':
    main()
