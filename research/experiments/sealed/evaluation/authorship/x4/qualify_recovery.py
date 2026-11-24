"""All v2 recovery checks on one source snapshot, with zero model requests."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from release import source_hashes, x1_hashes, sha

HERE = Path(__file__).resolve().parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--v1-job', type=Path, required=True)
    parser.add_argument('--x1-job', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=False)
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    assert os.environ.get('PYTHONHASHSEED') == '20261106'
    sources, x1 = source_hashes(), x1_hashes()
    manifest = HERE / 'dataset-v1/manifest.json'
    py = [sys.executable, '-B']
    steps = [
        ('kernel', py + [str(HERE / 'qualify.py'), '--out', str(args.out / 'kernel')]),
        ('lifecycle', py + [str(HERE / 'qualify_lifecycle.py'), '--out', str(args.out / 'lifecycle')]),
        ('cohort', py + [str(HERE / 'qualify_cohort.py'), '--manifest', str(manifest), '--prefix', str(args.prefix), '--out', str(args.out / 'cohort')]),
        ('rpc', ['node', str(HERE / 'diagnostics/qualify_rpc.mjs'), '--python', sys.executable, '--v1-job', str(args.v1_job), '--prefix', str(args.prefix), '--out', str(args.out / 'rpc')]),
        ('continuations', py + [str(HERE / 'diagnostics/check_continuations.py'), '--manifest', str(manifest), '--prefix', str(args.prefix), '--x1-job', str(args.x1_job), '--out', str(args.out / 'continuations.json')]),
        ('v1-reanalysis', py + [str(HERE / 'analyze.py'), '--manifest', str(manifest), '--job', str(args.v1_job), '--out', str(args.out / 'v1-reanalysis')]),
    ]
    receipts = []
    for name, command in steps:
        result = subprocess.run(command, capture_output=True, text=True)
        log = args.out / (name + '.log')
        log.write_text(result.stdout + result.stderr)
        receipts.append({'step': name, 'command': command, 'returncode': result.returncode, 'log_sha256': sha(log)})
        print(json.dumps({'step': name, 'returncode': result.returncode}), flush=True)
        if result.returncode:
            (args.out / 'suite.json').write_text(json.dumps({'passed': False, 'steps': receipts, 'source_sha256': sources, 'x1_core_sha256': x1}, indent=2) + '\n')
            raise SystemExit(result.returncode)
    assert source_hashes() == sources and x1_hashes() == x1, 'Source changed during qualification'
    cohort = json.loads((args.out / 'cohort/result.json').read_text())
    rpc = json.loads((args.out / 'rpc/result.json').read_text())
    analysis = json.loads((args.out / 'v1-reanalysis/analysis.json').read_text())
    assert cohort['n'] == cohort['passed'] == 84 and rpc['passed'] == 8
    assert analysis['audit_findings'] == []
    assert analysis['groups']['base_F0/M1']['wrong_effect'] == 1
    for arm in ['x4_projection_H0', 'fresh_rebinding_H0', 'extra_review_H0']:
        assert analysis['groups'][arm + '/M1']['episodes_known'] == 0
        assert analysis['groups'][arm + '/M1']['effects_unknown'] == 1
    result = {'passed': True, 'steps': receipts, 'source_sha256': sources, 'x1_core_sha256': x1,
              'python': sys.version, 'executable': sys.executable, 'model_requests': 0, 'network_requests': 0,
              'cohort': {'n': cohort['n'], 'passed': cohort['passed']}, 'rpc_checks': rpc['passed'],
              'qualification_inputs': {str(path): sha(path) for path in [manifest, args.prefix / 'summary.json', args.v1_job / 'config.json']},
              'scope': 'Model-free recovery qualification, including the complete production RPC and one retained source-context replay. No model-effectiveness or malicious-actor result.'}
    (args.out / 'suite.json').write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    main()
