"""Read-only coverage audit after the X4 dataset freeze; never selects rows."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path


def load(path):
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--x1-job', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    manifest = load(args.manifest)
    cohort = load(args.manifest.parent / manifest['cohort'])
    units = {row['unit_id']: row for row in cohort['units']}
    pairs = sorted({(row['case_id'], units[row['unit_id']]['function']) for row in manifest['rows']})
    rows = []
    for case_id, function in pairs:
        path = args.prefix / case_id / 'prefix.json.gz'
        raw = load(path)
        calls = [row for row in raw['proposed_calls'] if row['function'] == function]
        effects = [row for row in raw['events'] if row['operation']['function'] == function
                   and row.get('entry_state_changed') and row.get('error') is None]
        if len(calls) > 1:
            rows.append({'case_id': case_id, 'function': function, 'proposal_count': len(calls),
                         'state_changing_effects': len(effects), 'calls': calls,
                         'native_utility': raw['result']['native_utility'], 'source_sha256': sha(path)})
    unit_id = 'banking__user_task_2__update_scheduled_transaction__amount'
    selected = [row for row in manifest['rows'] if row['unit_id'] == unit_id]
    assert len(selected) == 1 and selected[0]['fault_class'] == 'none'
    old_outcomes = []
    for filename in ['none.json.gz', unit_id + '__oracle_correct__F0.json.gz', unit_id + '__oracle_correct__F3.json.gz']:
        path = args.x1_job / unit_id / filename
        raw = load(path)
        old_outcomes.append({'file': str(path), 'sha256': sha(path), 'status': raw['result']['status'],
                             'native_utility': raw['result']['native_utility'],
                             'calls': [row for row in raw['proposed_calls'] if row['function'] == 'update_scheduled_transaction'],
                             'events': [{'operation': row['operation'], 'state_changed': row.get('entry_state_changed'), 'error': row.get('error')}
                                        for row in raw['events'] if row['operation']['function'] == 'update_scheduled_transaction']})
    result = {'dataset_sha256': sha(args.manifest), 'conditions': len(manifest['rows']),
              'case_function_pairs': len(pairs), 'multiple_proposal_pairs': len(rows), 'rows': rows,
              'bank2_retained_condition': selected[0], 'old_x1_no_gate_and_controls': old_outcomes,
              'selection_changed': False, 'model_requests': 0, 'network_requests': 0,
              'scope': 'Read-only outcome/continuation audit after dataset-v1 freeze. Old outcomes are diagnostic references, not new paired model samples. Distinct later calls retain the original static gate; no authority is inherited from a repair.'}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'case_function_pairs': len(pairs), 'multiple_proposal_pairs': len(rows),
                      'bank2_retained': True, 'old_native_utility': [row['native_utility'] for row in old_outcomes]}))


if __name__ == '__main__':
    main()
