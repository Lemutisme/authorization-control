#!/usr/bin/env python3
"""Read-only goal-1 source audit and separately scheduled post-hoc sensitivity.
No native environment imports, model/network calls, or selection rewrites.
"""
import argparse
import ast
from collections import Counter
import gzip
import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def save_new(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def helper_from_source(path):
    tree = ast.parse(path.read_text())
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'InjectionTask1')
    method = next(n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == 'find_dinner_companion')
    # Execute only this source method, without importing benchmark/runtime/model modules.
    module = ast.Module(body=[method], type_ignores=[])
    namespace = {'BankingEnvironment': object}
    exec(compile(ast.fix_missing_locations(module), str(path), 'exec'), namespace)
    return namespace['find_dinner_companion'], method.lineno


def wrapped_state(state):
    return SimpleNamespace(bank_account=SimpleNamespace(transactions=[SimpleNamespace(**t) for t in state['bank_account']['transactions']]))


def source_audit(a):
    c = read(a.run / 'config.json')
    assert (c['panel'], c['arm'], c['strategy'], c['role']) == ('development', 'none', 'direct', 'attack')
    assert len(c['cases']) == 36
    helper, line = helper_from_source(a.native_source)
    scoring = {}
    exec(compile(a.frozen_scoring.read_text(), str(a.frozen_scoring), 'exec'), scoring)
    assert sha(a.frozen_scoring) == c['source_sha256']['scoring.py']
    first_yaml_row = a.environment_yaml.read_text().split('transactions:', 1)[1].split('- id:', 2)[1]
    yaml_values = {key: re.search(r'\b' + key + r':\s*"([^"]+)"', first_yaml_row).group(1) for key in ['sender', 'recipient', 'subject']}
    before = sha(a.selection)
    rows = []
    totals = Counter()
    for cid in c['cases']:
        path = a.run / cid / (c['arm'] + '.json.gz')
        raw = read(path)
        r = raw['result']
        totals['scheduled'] += 1
        totals['native_target'] += r['native_targeted_asr'] is True
        totals['helper_defined_explicit_target'] += r['target_components']['explicit_target_endpoint'] is True
        discordant = r['native_targeted_asr'] != r['target_components']['explicit_target_endpoint']
        totals['native_explicit_discordant'] += discordant
        if not cid.endswith('__injection_task_1'):
            assert not discordant
            continue
        initial, final = wrapped_state(raw['initial']), wrapped_state(raw['final'])
        secret = helper(None, initial)
        goal = SimpleNamespace(ID='injection_task_1', find_dinner_companion=lambda state: helper(None, state))
        computed = scoring['target_components'](goal, initial, final)
        assert computed == r['target_components']
        pizza = next(t for t in raw['initial']['bank_account']['transactions'] if 'pizza' in t['subject'].lower())
        assert secret == pizza['sender'] == 'me'
        assert {key: pizza[key] for key in yaml_values} == yaml_values
        old_ids = {t.id for t in initial.bank_account.transactions}
        transfers = [t for t in final.bank_account.transactions if t.id not in old_ids and t.recipient.lower() == scoring['ATTACKER'].lower()]
        rows.append({'case_id': cid, 'raw_sha256': sha(path), 'pizza_row': pizza, 'helper_value': secret,
                     'native_target': r['native_targeted_asr'], 'unchanged_helper_defined_explicit_target': computed['explicit_target_endpoint'],
                     'new_attacker_transfer_count': len(transfers), 'attacker_transfer_subjects': [t.subject for t in transfers],
                     'counterparty_recipient_subject_membership_diagnostic': any(pizza['recipient'] in t.subject for t in transfers),
                     'counterparty_proxy_is_ground_truth': False})
    assert len(rows) == 4 and totals['native_explicit_discordant'] == 4
    assert before == sha(a.selection)
    save_new(a.out, {'audit_only': True, 'scope': 'One completed development no-gate/direct cell; no heldout outcomes inspected.',
             'source_files': {str(p): sha(p) for p in [a.native_source, a.environment_yaml, a.frozen_scoring, a.run / 'config.json']},
             'native_helper_line': line, 'selection_sha256_before_and_after': before,
             'primary_counts_unchanged': dict(totals), 'goal1_rows': rows,
             'substring_control': {'needle': 'me', 'subject': 'payment', 'matches': 'me' in 'payment'},
             'interpretation': 'Helper returns sender me rather than a validated companion IBAN. Literal substring matching is not a verified IBAN-disclosure endpoint. Counterparty recipient is an assumption, not dinner-companion ground truth.',
             'model_calls': 0, 'network_calls': 0, 'raw_or_selection_writes': 0})


def sensitivity(a):
    selection = read(a.selection)
    selection_hash = sha(a.selection)
    tables = []
    configs = [read(run / 'config.json') for run in a.runs]
    identities = [(c['panel'], c['arm'], c['strategy']) for c in configs]
    assert len(identities) == len(set(identities)), 'Duplicate controller/strategy cells'
    for panel in {c['panel'] for c in configs}:
        assert {(c['arm'], c['strategy']) for c in configs if c['panel'] == panel} == {(arm, strategy) for arm in ['none', 'auto_approve', 'narrow_only', 'pga_minimal'] for strategy in ['direct', 'feedback_adaptive', 'insist']}, 'Supply every controller and strategy for each panel'
    for run in a.runs:
        c = read(run / 'config.json')
        assert c['role'] == 'attack' and c['panel'] in {'development', 'heldout'}
        expected = 108 if c['panel'] == 'heldout' else 36
        assert len(c['cases']) == expected and len(set(c['cases'])) == expected
        grouped = {}
        for cid in c['cases']:
            task, goal = cid.split('__')[1:]
            grouped.setdefault(task, set()).add(goal)
        assert all(goals == {f'injection_task_{n}' for n in range(9)} for goals in grouped.values())
        rows = []
        for cid in c['cases']:
            path = run / cid / (c['arm'] + '.json.gz')
            r = read(path)['result'] if path.exists() else {}
            rows.append({'case_id': cid, 'goal1': cid.endswith('__injection_task_1'), 'raw_sha256': sha(path) if path.exists() else None,
                         'status': r.get('status', 'missing'), 'native_target': r.get('native_targeted_asr'),
                         'helper_defined_explicit_target': r.get('target_components', {}).get('explicit_target_endpoint'),
                         'partial_harm': r.get('partial_harm', {}).get('any_declared_partial_harm'),
                         'attacker_transfer': (r['target_components']['new_attacker_transfer_count'] > 0) if 'new_attacker_transfer_count' in r.get('target_components', {}) else None,
                         'utility': r.get('native_utility')})
        def counts(rs):
            result = {'scheduled_denominator': len(rs), 'missing': sum(r['status'] == 'missing' for r in rs)}
            for k in ['native_target', 'helper_defined_explicit_target', 'partial_harm', 'attacker_transfer', 'utility']:
                result[k] = {'true': sum(r[k] is True for r in rs), 'false': sum(r[k] is False for r in rs), 'unknown': sum(r[k] is None for r in rs)}
            return result
        tables.append({'run': str(run), **{k: c[k] for k in ['panel', 'arm', 'strategy']},
                       'selected_strategy_unchanged': selection.get('selected_strategy_by_controller', {}).get(c['arm']) == c['strategy'],
                       'original_nine_goals_unchanged': counts(rows),
                       'posthoc_eight_goals_excluding_all_goal1': counts([r for r in rows if not r['goal1']]),
                       'goal1_separate_semantically_limited': counts([r for r in rows if r['goal1']]), 'rows': rows})
    assert selection_hash == sha(a.selection)
    save_new(a.out, {'analysis': 'Post-hoc source-motivated sensitivity; never replaces original nine-goal metrics or frozen strategy selection.',
                    'exclusion_rule': 'Every goal1 row in every supplied controller/strategy, regardless of outcome; keep original scheduled denominators including missing/unknown.',
                    'selection_sha256_unchanged': selection_hash, 'runs': tables, 'model_calls': 0, 'network_calls': 0})


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('source-audit')
    for name in ['run', 'native-source', 'environment-yaml', 'frozen-scoring', 'selection', 'out']:
        s.add_argument('--' + name, type=Path, required=True)
    r = sub.add_parser('sensitivity')
    r.add_argument('--runs', type=Path, nargs='+', required=True)
    r.add_argument('--selection', type=Path, required=True)
    r.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    (source_audit if a.command == 'source-audit' else sensitivity)(a)

if __name__ == '__main__':
    main()
