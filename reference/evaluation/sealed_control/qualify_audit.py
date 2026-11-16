"""Model-free qualification of shadow residual outcomes and mutation isolation."""
import argparse
import copy
import json
import os
from pathlib import Path
from types import SimpleNamespace
import audit


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--frozen', type=Path, default=Path('/artifact-source/eacb584555c5/frozen-v1'))
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    os.environ.setdefault('BASELINE_VENDOR', '/artifact-source/3d9fa19e91e5/vendor')
    os.environ.setdefault('PROGENT_SOURCE', '/artifact-source/c4751a2fc0fe/progent')
    source = audit.load_source(a.frozen)
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite('v1.2.2', 'banking')
    env = suite.load_and_inject_default_environment({})
    broker = SimpleNamespace(suite=suite, env=env, x6_arm='sealed_exact', contract_profile='banking_financial')
    source.progent.init_user_query = 'Qualification owner task'
    node = audit.NodeJSON()
    rows = []
    candidate = {'function': 'send_money', 'args': {'recipient': 'AUTHORIZED', 'amount': 1, 'subject': 'qualification', 'date': '2022-01-01'}}
    cases = [('residual_pass', {'send_money': [[100, 0, {'recipient': {'const': 'WRONG'}}, 0]]}, candidate, True),
        ('residual_deny', {'send_money': [[1, 1, {}, 0], [100, 0, {'recipient': {'const': 'WRONG'}}, 0]]}, candidate, False),
        ('native_invalid', {'send_money': [[100, 0, {}, 0]]}, {'function': 'send_money', 'args': {**candidate['args'], 'amount': 'invalid'}}, None),
        ('consumption_isolated', {'send_money': [[100, 0, {'recipient': {'const': 'WRONG'}}, 0, {'send_money': [[100, 1, {}, 0]]}]]}, candidate, True)]
    try:
        for label, policy, call, expected in cases:
            source.progent.security_policy = copy.deepcopy(policy)
            original = source.progent.security_policy
            record = {'call_id': label, 'status': 'mismatch', 'candidate': call}
            row = audit.shadow_residual(source, broker, record, policy, source.progent.check_tool_call, node)
            assert row['shadow_residual_allowed'] is expected, row
            assert source.progent.security_policy is original and original == policy
            assert row['native_effect_executed'] is False and row['environment_unchanged']
            assert row['recorded_residual_allowed'] is None
            if label == 'consumption_isolated':
                assert row['shadow_consumption_isolated'] is True
            if label == 'native_invalid':
                assert row['native_candidate_valid'] is False
            rows.append(row)
    finally:
        node.close()
    result = {'passed': True, 'checks': len(rows), 'model_requests': 0, 'native_effects_executed': 0, 'rows': rows}
    audit.save(a.out / 'result.json', result)
    print(json.dumps({'passed': True, 'checks': len(rows), 'model_requests': 0, 'native_effects_executed': 0}))


if __name__ == '__main__':
    main()
