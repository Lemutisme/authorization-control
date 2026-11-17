"""Normalize retained qualified panels; no model calls or input mutation."""
import argparse
import hashlib
import json
from pathlib import Path


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--prefix', type=Path, required=True)
    p.add_argument('--initial', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    assert not (a.out / 'manifest.json').exists(), 'Use a fresh preparation directory'
    manifest = json.loads((a.prefix / 'manifest.json').read_text())
    assert manifest['passed'] == 98
    rows, panels = [], {'post_exposure': {}, 'initial': {}}
    for row in manifest['cases']:
        assert row['passed']
        source = a.prefix / row['path']
        assert sha(source) == row['sha256']
        d = json.loads(source.read_text())
        fixture = {k: d[k] for k in ['case_id', 'task_id', 'injection_id', 'owner_request',
                                    'state', 'initial_state', 'pga_receipts', 'tool_definitions']}
        fixture.update(panel='post_exposure', candidate=d['evaluator']['candidate'],
                       policy=d['update']['post_policy'], prefix_calls=len(d['prefix']),
                       retained_anchor_update=d['update'], source_path=str(source), source_sha256=sha(source),
                       policy_origin='retained completed anchor update.post_policy',
                       retained_prefix=d['prefix'], retained_observations=d['observations'])
        panels['post_exposure'][d['case_id']] = fixture
    exclusions = []
    for source in sorted(a.initial.glob('banking__*.json')):
        r = json.loads(source.read_text())
        if r.get('coverage') != 'qualified_single_candidate':
            exclusions.append({'case_id': r['case_id'], 'coverage': r.get('coverage')})
            continue
        assert r['replay_passed'] and r['original_replay_verified']
        packet = a.initial / r['packet_file']
        assert sha(packet) == r['packet_sha256']
        d = json.loads(packet.read_text())
        fixture = {k: r[k] for k in ['case_id', 'task_id', 'injection_id', 'owner_request']}
        fixture.update(panel='initial', state=d['native_initial_state'], initial_state=d['native_initial_state'],
                       policy=d['initial_policy'], candidate=d['candidate'], pga_receipts=[], prefix_calls=0,
                       policy_origin='retained original completed initial policy', source_path=str(packet),
                       source_sha256=sha(packet), qualification_path=str(source), qualification_sha256=sha(source),
                       retained_initial_allowed=r['initial_progent']['allowed'], retained_prefix=[], retained_observations=[])
        panels['initial'][r['case_id']] = fixture
    assert len(panels['post_exposure']) == 98 and len(panels['initial']) == 112
    overlap = sorted(set(panels['post_exposure']) & set(panels['initial']))
    overlap_rows = []
    for cid in overlap:
        post, initial = panels['post_exposure'][cid], panels['initial'][cid]
        effect = lambda d: {k: d['candidate'][k] for k in ['function', 'args']}
        overlap_rows.append({'case_id': cid, 'same_state': post['state'] == initial['state'],
                             'same_candidate': effect(post) == effect(initial),
                             'same_policy': post['policy'] == initial['policy']})
    for panel, fixtures in panels.items():
        for cid, d in sorted(fixtures.items()):
            path = a.out / panel / (cid + '.json')
            save(path, d)
            rows.append({'case_id': cid, 'panel': panel, 'task_id': d['task_id'],
                         'path': str(path.relative_to(a.out)), 'sha256': sha(path)})
    save(a.out / 'manifest.json', {'study': 'authorship-x2', 'cases': rows,
         'panels': {k: {'n': len(v), 'owner_tasks': len({d['task_id'] for d in v.values()})} for k, v in panels.items()},
         'overlap': overlap_rows, 'overlap_count': len(overlap), 'initial_exclusions': exclusions,
         'source_manifest_sha256': sha(a.prefix / 'manifest.json'),
         'initial_summary_sha256': sha(a.initial / 'summary.json'),
         'independence': 'Panels overlap and targets share owner tasks; no pooled independent-task estimate',
         'fresh_actor': False, 'model_calls': 0})
    print(json.dumps({'panels': {k: len(v) for k, v in panels.items()}, 'overlap': len(overlap),
                      'same_state_same_candidate': sum(r['same_state'] and r['same_candidate'] for r in overlap_rows)}))


if __name__ == '__main__':
    main()
