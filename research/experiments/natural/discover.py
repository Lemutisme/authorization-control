"""Retained natural-binding discovery; no model/runtime constructor input."""
from pipeline.paths import resolve as research_path
import base64, gzip, hashlib, json
from pathlib import Path
HERE = Path(__file__).resolve().parent
PUB = Path(research_path('experiments/shared'))
X3 = Path(research_path('runs'))

def sha(b):
    return hashlib.sha256(b).hexdigest()

def objsha(x):
    return sha(json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())

def main():
    sources = []
    for panel in ['main', 'clean-repeat']:
        run = 'authorship-x3-' + panel + '-v1'
        for task in [11, 15]:
            for arm in ['optional_auto', 'optional_narrow', 'forced_auto', 'forced_narrow']:
                path = X3 / run / 'artifacts' / f'banking__user_task_{task}__clean' / (arm + '.json.gz')
                sources.append((run, task, arm, path, path.read_bytes(), None))
    index = json.loads((PUB / 'evidence/refinement/artifact-index.json').read_text())
    for part in index['parts']:
        blob = (PUB / part['path']).read_bytes()
        assert sha(blob) == part['sha256']
        for row in json.loads(blob):
            if row['run'] not in ['refinement-episode-main-v2', 'refinement-clean-repeat-v2']:
                continue
            rp = Path(row['restore_path'])
            if rp.name not in ['optional.json.gz', 'forced.json.gz', 'result_aware.json.gz']:
                continue
            for task in [11, 15]:
                if rp.parts[0] != f'banking__user_task_{task}__clean':
                    continue
                path = PUB / row['path']
                env = json.loads(path.read_text())
                blob = base64.b64decode(env['payload_base64'])
                assert sha(blob) == env['payload_sha256']
                decoded = gzip.decompress(blob)
                assert sha(decoded) == env['decoded_sha256']
                assert sha(blob) == env['source_sha256']
                dest = HERE / 'source_materialized' / row['run'] / rp
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(blob)
                sources.append((row['run'], task, rp.name.removesuffix('.json.gz'), path, blob, str(dest)))
    rows = []
    for run, task, arm, path, blob, materialized in sources:
        x = json.loads(gzip.decompress(blob))
        field = 'amount' if task == 11 else 'recipient'
        item = {'run': run, 'task': task, 'arm': arm, 'source_path': str(path), 'source_original_sha256': sha(blob), 'materialized_path': materialized, 'source_decoded_sha256': sha(gzip.decompress(blob)), 'case_id': x['result']['case_id'], 'refusals': []}
        history = x['policy_history']
        events = [e for e in x['events'] if e.get('depth', 0) == 0]
        for i, e in enumerate(events):
            op = e['operation']
            err = e.get('error')
            if not err or op['function'] != 'send_money':
                continue
            policy = history[i]['policy'] if i < len(history) else None
            rules = (policy or {}).get('send_money', [])
            restrictions = [r[2][field] for r in rules if field in r[2]]
            prior_errors = [z.get('error', '') or '' for z in events[:i]]
            values = []
            for restriction in restrictions:
                if isinstance(restriction, dict):
                    values.extend(restriction.get('enum', []))
                    values.extend([restriction['const']] if 'const' in restriction else [])
            boundary = {'event_index': i, 'operation': op, 'error': err, 'target_field_restrictions': restrictions, 'target_field_values': values, 'wrongness_status': 'requires_offline_source_check', 'policy': policy, 'policy_sha256': objsha(policy), 'state': e['before'], 'state_sha256': objsha(e['before']), 'prior_wrong_value_disclosure': any((str(v) in prior for v in values for prior in prior_errors)), 'prior_refusal_count': len([z for z in events[:i] if z.get('error')]), 'context_recovery': 'not_yet_qualified', 'native_replay': 'not_yet_qualified'}
            item['refusals'].append(boundary)
        item['status'] = 'candidate_refusals' if item['refusals'] else 'no_named_function_refusal'
        item['actor_calls'] = x['result']['pi']['calls']
        rows.append(item)
    out = {'version': 'natural-discovery-v1', 'scope': 'all clean target-task Progent episodes in fixed two studies/two samples', 'episodes': rows, 'counts': {'episodes': len(rows), 'candidate_episodes': sum((bool(r['refusals']) for r in rows)), 'candidate_refusals': sum((len(r['refusals']) for r in rows))}}
    (HERE / 'discovery.json').write_text(json.dumps(out, indent=2) + '\n')
    print(json.dumps(out['counts']))
    for r in rows:
        for e in r['refusals']:
            print(r['run'], r['task'], r['arm'], e['event_index'], e['target_field_restrictions'], e['operation']['args']['amount' if r['task'] == 11 else 'recipient'])
if __name__ == '__main__':
    main()
