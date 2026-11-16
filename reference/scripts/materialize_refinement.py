#!/usr/bin/env python3
"""Check and optionally restore the original compressed refinement traces."""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def decode(record):
    payload = base64.b64decode(record['payload_base64'], validate=True)
    assert digest(payload) == record['payload_sha256']
    decoded = gzip.decompress(payload)
    assert len(decoded) == record['decoded_bytes']
    assert digest(decoded) == record['decoded_sha256']
    assert record['source_format'] in {'gzip', 'text'}
    original = payload if record['source_format'] == 'gzip' else decoded
    assert digest(original) == record['source_sha256']
    return original, decoded.decode('utf-8')


def indexed_files():
    index = json.loads((ROOT / 'evidence/refinement/artifact-index.json').read_text())
    rows = []
    for part in index['parts']:
        raw = (ROOT / part['path']).read_bytes()
        assert digest(raw) == part['sha256']
        rows.extend(json.loads(raw))
    assert len(rows) == index['count']
    assert len({(x['run'], x['restore_path']) for x in rows}) == len(rows)
    return rows


def validate(scanner=None, output=None):
    """Scan decoded text as well as envelopes; never exempt encoded data."""
    count = 0
    for row in indexed_files():
        record = json.loads((ROOT / row['path']).read_text())
        assert all(record[k] == row[k] for k in ['restore_path', 'source_sha256', 'decoded_sha256'])
        original, text = decode(record)
        if scanner:
            scanner(row['path'] + ' decoded', text)
        relative = Path(row['run']) / row['restore_path']
        assert not relative.is_absolute() and '..' not in relative.parts
        if output:
            dest = output / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(original)
        count += 1
    encoded = ROOT / 'evidence/refinement/refinement-initial-authority-v1/summary.encoded.json'
    record = json.loads(encoded.read_text())
    original, text = decode(record)
    if scanner:
        scanner(str(encoded.relative_to(ROOT)) + ' decoded', text)
    if output:
        dest = output / 'refinement-initial-authority-v1/summary.json'
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(original)
        for run in ['refinement-episode-main-v2', 'refinement-clean-repeat-v2', 'refinement-conditional-main-v3']:
            source = ROOT / 'evidence/refinement' / run
            summary = json.loads((source / 'result.json').read_text())
            order = json.loads((source / 'completion-order.json').read_text())
            summary['rows'] = [json.loads((output / run / case / 'case.json').read_text()) for case in order]
            (output / run / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
            (output / run / 'config.json').write_bytes((source / 'config.json').read_bytes())
    return count + 1


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New empty directory outside this repository')
    args = parser.parse_args()
    if args.output:
        args.output = args.output.resolve()
        if args.output.is_relative_to(ROOT):
            parser.error('Use a directory outside the publication bundle.')
        args.output.mkdir(parents=True, exist_ok=False)
    print(json.dumps({'verified_trace_envelopes': validate(output=args.output)}))
