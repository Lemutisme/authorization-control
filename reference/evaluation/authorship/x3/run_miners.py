"""Run unchanged post-hoc miners with an explicit X3 arm-list adaptation."""
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys

from controller import ARMS


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--scripts', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('jobs', type=Path, nargs='+')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    records = []
    for name in ['adoption.py', 'policy_mine.py']:
        source = args.scripts / name
        spec = importlib.util.spec_from_file_location('x3_' + source.stem, source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original_arms = list(module.ARMS)
        module.ARMS = list(ARMS)
        output = args.out / (source.stem + '.json')
        previous_args = sys.argv
        sys.argv = [str(source), str(output), *map(str, args.jobs)]
        text = io.StringIO()
        try:
            with contextlib.redirect_stdout(text):
                module.main()
        finally:
            sys.argv = previous_args
        (args.out / (source.stem + '.txt')).write_text(text.getvalue())
        records.append({'script': name, 'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                        'original_arms': original_arms, 'adapted_arms': ARMS,
                        'output_sha256': hashlib.sha256(output.read_bytes()).hexdigest()})
    (args.out / 'miner-adaptation.json').write_text(json.dumps({
        'records': records, 'scope': 'Only module.ARMS changes in memory. Source files remain unchanged. The original policy miner optional-arm-only print subsection is inapplicable to renamed X3 arms; all per-arm JSON records remain available. Existing task-truth and disclosure-parser limitations carry over; this is not independent semantic adjudication.'
    }, indent=2) + '\n')


if __name__ == '__main__':
    main()
