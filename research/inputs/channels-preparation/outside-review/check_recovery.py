"""Check v2 policy receipts independently; rerun all v1 mismatching traces."""
from pipeline.paths import resolve as research_path
from pathlib import Path
import copy, gzip, hashlib, json, sys
HERE = Path(__file__).resolve().parent
WORK = HERE.parent / 'native_audit'
BASE = Path(research_path('external/812f263b19c4/sp27-two-channel-20261113'))

def load(p):
    p = Path(p)
    return json.loads(gzip.decompress(p.read_bytes()) if p.suffix == '.gz' else p.read_bytes())

def digest(x):
    return hashlib.sha256(json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
protocol = load(BASE / 'frozen-v1/protocol-main.json')
units = {u['unit_id']: u for u in protocol['units']}
v1 = load(WORK / 'main-v1/result.json')
v2 = load(WORK / 'main-v2/result.json')
assert v2['counts'] == {'pass': 816} and v2['passed']
checked = changed = 0
methods = {}
for row in v2['rows']:
    raw = load(row['raw_path'])
    n = len(raw['factorial_source_packet']['prior_native_events'])
    event_report = load(WORK / 'main-v2/episodes' / row['unit_id'] / ('repetition-' + str(row['repetition'])) / (row['arm'] + '.json'))
    for event in event_report['event_reports']:
        record = raw['result']['factorial_records'][event['event'] - n]
        recovery = event['policy_representation']
        restored = copy.deepcopy(record['decision_policy'])
        if not record['decisions']:
            assert recovery['method'] == 'no_native_policy_decision'
            continue
        assert recovery['status'] == 'verified' and recovery['hash_matches'] == 1
        assert recovery['expected_sha256'] == record['decisions'][0]['policy_before_sha256']
        for change in recovery['changed']:
            cursor = restored
            for part in change['path'][:-1]:
                cursor = cursor[part]
            leaf = change['path'][-1]
            assert type(cursor[leaf]) is int
            assert repr(cursor[leaf]) == change['serialized']
            cursor[leaf] = float(cursor[leaf])
            assert repr(cursor[leaf]) == change['restored']
        assert digest(restored) == recovery['expected_sha256']
        if recovery['method'] == 'bounded_schema_numeric_search':
            assert recovery['candidates_tested'] == recovery['candidate_count'] <= recovery['max_candidates']
        checked += 1
        changed += bool(recovery['changed'])
        methods[recovery['method']] = methods.get(recovery['method'], 0) + 1
sys.path.insert(0, str(WORK))
import audit
manifest = load(research_path('experiments/sealed/evaluation/authorship/x2b/manifest-v1.json'))
cases = {c['case_id']: c for c in manifest['cases']}
reruns = []
for old in v1['rows']:
    if old['status'] == 'pass':
        continue
    raw = load(old['raw_path'])
    packet = load(units[old['unit_id']]['packet'])
    new = audit.audit_raw(raw, cases[old['case_id']], manifest['version'], packet)
    assert new['status'] == 'pass', new['issues']
    reruns.append({'unit': old['unit_id'], 'arm': old['arm'], 'status': new['status'], 'events': new['continuation_events']})
result = {'decision_policy_receipts_checked': checked, 'representations_restored': changed, 'methods': methods, 'previous_mismatch_traces_rerun': len(reruns), 'all_reruns_pass': all((r['status'] == 'pass' for r in reruns)), 'reruns': reruns, 'model_calls': 0, 'network_calls': 0}
(HERE / 'recovery-check.json').write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({k: v for k, v in result.items() if k != 'reruns'}, indent=2))
