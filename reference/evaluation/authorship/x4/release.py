"""Portable source identity for the X4 v2 recovery; creates no model jobs."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RELEASE = HERE / 'recovery-v2/release.json'
X1_FROZEN = Path('/artifact-source/9efadf13d615/x1')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_hashes():
    paths = [path for path in HERE.iterdir() if path.suffix in {'.py', '.mjs', '.json', '.md'}]
    paths += list((HERE / 'diagnostics').glob('*.py')) + list((HERE / 'diagnostics').glob('*.mjs'))
    paths += list((HERE / 'dataset-v1').rglob('*.json'))
    return {str(path.relative_to(HERE)): sha(path) for path in sorted(paths)}


def x1_hashes():
    expected = {path.name: sha(path) for path in X1_FROZEN.iterdir() if path.suffix in {'.py', '.mjs', '.json'}}
    actual = {name: sha(HERE.parent / 'x1' / name) for name in expected}
    if actual != expected:
        raise ValueError('X1 component differs from frozen-x1-branch-v1')
    return actual


def verify_release(path=RELEASE):
    release = json.loads(path.read_text())
    if source_hashes() != release['source_sha256']:
        raise ValueError('X4 source or frozen dataset changed since recovery qualification')
    if x1_hashes() != release['x1_core_sha256']:
        raise ValueError('X1 identity differs from the X4 release')
    return {'version': release['version'], 'release_sha256': sha(path),
            'source_files': len(release['source_sha256']), 'x1_core_files': len(release['x1_core_sha256'])}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--freeze-from', type=Path, help='Completed model-free qualification suite JSON')
    args = parser.parse_args()
    if args.freeze_from:
        if RELEASE.exists():
            raise ValueError('Recovery release already exists; never overwrite a frozen release')
        qualification = json.loads(args.freeze_from.read_text())
        if qualification['passed'] is not True or qualification['source_sha256'] != source_hashes():
            raise ValueError('Qualification does not certify the current source')
        if qualification['x1_core_sha256'] != x1_hashes():
            raise ValueError('Qualification does not certify the current X1 dependencies')
        result = {'version': 'x4-recovery-v2', 'source_sha256': source_hashes(), 'x1_core_sha256': x1_hashes(),
                  'qualification_file': str(args.freeze_from.relative_to(HERE)),
                  'qualification_sha256': sha(args.freeze_from),
                  'model_requests': 0, 'network_requests': 0,
                  'scope': 'Finite X1 static fault/repair panel. Mechanism and RPC qualification only; registered v2 model recovery has not run.'}
        RELEASE.parent.mkdir(exist_ok=True, parents=True)
        RELEASE.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(verify_release(), indent=2))


if __name__ == '__main__':
    main()
