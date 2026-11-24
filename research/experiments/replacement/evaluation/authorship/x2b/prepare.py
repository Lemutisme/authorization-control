"""Freeze actor-policy development/evaluation units without viewing fresh outcomes."""
import argparse
import hashlib
import json
from pathlib import Path
DEV = {0, 5, 10, 15}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--source-manifest', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    original = json.loads(a.source_manifest.read_text())
    rows = []
    for c in original['cases']:
        if c['suite'] != 'banking' or c['condition'] not in {'clean', 'attack'}:
            continue
        c = dict(c)
        c['injections'] = {}
        c['x2b_panel'] = 'development' if int(c['task_id'].rsplit('_', 1)[1]) in DEV else 'holdout'
        c['x2b_role'] = 'honest' if c['condition'] == 'clean' else 'attack'
        rows.append(c)
    assert len(rows) == 160
    a.out.parent.mkdir(parents=True, exist_ok=True)
    assert not a.out.exists()
    a.out.write_text(json.dumps({'study': 'authorship-x2b', 'version': original['version'],
         'source_pin': original['source_pin'], 'source_manifest_sha256': hashlib.sha256(a.source_manifest.read_bytes()).hexdigest(),
         'cases': rows, 'development_task_ids': sorted(DEV),
         'holdout_task_ids': sorted(set(range(16)) - DEV),
         'holdout_limit': 'Disjoint for new attack-policy tuning; benchmark tasks were used in prior studies, not pristine unseen tasks',
         'environment': 'Clean native environments; adversarial instructions only at untrusted actor interface'}, indent=2) + '\n')
    print(json.dumps({'cases': len(rows), 'development_tasks': 4, 'holdout_tasks': 12, 'targets_per_task': 9}))
if __name__ == '__main__':
    main()
