"""Model-free qualification: all source states plus native update/cache edge paths."""
import argparse
import copy
import json
import os
from pathlib import Path
from native import (ProgentLifecycle, PGALifecycle, NativeState, FunctionsRuntime,
                    block_native_network, digest, progent, normal)
from prepare import sha, save


class ScriptPolicy:
    def __init__(self, values):
        self.values = list(values)
        self.calls = []
        self.stage = 'initial'
    def request(self, system, user, temperature=0):
        assert self.values, 'Unexpected policy call'
        self.calls.append({'system': system, 'user': user, 'temperature': temperature,
                           'ok': True, 'coupling': {'stage': self.stage}})
        return self.values.pop(0)
    def close(self):
        pass


class ScriptReview:
    def __init__(self, decisions):
        self.values = list(decisions)
        self.calls = []
    def request(self, history, tools, instructions):
        assert self.values, 'Unexpected reviewer call'
        value = self.values.pop(0)
        self.calls.append({'instructions': instructions, 'history': history})
        if value == 'unavailable':
            raise RuntimeError('Qualification transport failure')
        binding = json.loads(history[-1]['content'])['review_binding']
        return {'status': 'completed', 'output': [{'type': 'function_call', 'name': 'authorize_effect',
                 'arguments': json.dumps({'reviewed_binding': json.dumps(binding),
                                          'basis': 'Qualification scripted verdict', 'decision': value})}]}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    block_native_network()
    m = json.loads(a.manifest.read_text())
    rows, witness = [], None
    for r in m['cases']:
        path = a.manifest.parent / r['path']
        assert sha(path) == r['sha256']
        f = json.loads(path.read_text())
        state = NativeState(f)
        assert not state.score()
        bare = state.env.model_copy(deep=True)
        value, error = FunctionsRuntime(state.suite.tools).run_function(bare, state.target.function,
                                                                       copy.deepcopy(state.target.args))
        assert error is None and state.score(bare)
        outcomes = []
        for arm in ['auto_approve', 'narrow_only']:
            life = ProgentLifecycle(f, arm)
            try:
                step = life.submit(0, update_on_refusal=False)
                outcomes.append(step)
                assert normal(step['policy_before']) == normal(f['policy'])
                assert normal(step['policy_after']) == normal(f['policy'])
                assert step['native_goal'] == step['allowed']
            finally:
                life.close()
        assert outcomes[0] == outcomes[1], 'Initial denial controls differ'
        if f['panel'] == 'initial':
            assert outcomes[0]['allowed'] == f['retained_initial_allowed']
        if not outcomes[0]['allowed'] and witness is None:
            witness = f
        rows.append({'case_id': f['case_id'], 'panel': f['panel'], 'allowed': outcomes[0]['allowed'],
                     'state_sha256': digest(f['state']), 'policy_sha256': digest(f['policy']),
                     'updater_result': outcomes[0]['native_updater_input']['tool_call_result']})
    assert witness is not None
    # Deterministic, held-out synthetic policy response: broadens only generated rules.
    candidate_policy = json.dumps([{'name': witness['candidate']['function'], 'args': {}}])
    mechanisms = {}
    for arm in ['auto_approve', 'narrow_only']:
        client = ScriptPolicy(['yes', candidate_policy])
        life = ProgentLifecycle(witness, arm, client)
        try:
            first = life.submit(0)
            second = life.submit(1, update_on_refusal=False)
            assert not first['allowed']
            assert second['allowed'] == (arm == 'auto_approve')
            assert len(client.calls) == 2 and not client.values
            assert '\nTOOL_CALL_RESULT: [\'\']\n' in client.calls[1]['user']
            assert first['native_error'] not in client.calls[1]['user']
            if arm == 'narrow_only':
                assert first['subset_checks'] and first['subset_checks'][0]['result'] is False
            mechanisms[arm] = {'first_allowed': first['allowed'], 'second_allowed': second['allowed'],
                               'subset_checks': first['subset_checks'], 'native_updater_input': first['native_updater_input']}
        finally:
            life.close()
    # Semantic negatives are memoized after adjudication; allows are not imposed.
    for label, values, expected_calls, expected_allowed in [
        ('negative_cache', ['deny', 'deny'], [2, 2, 2, 2], [False] * 4),
        ('adjudication_can_allow', ['deny', 'allow'], [2], [True]),
        ('unavailable_can_recover', ['unavailable', 'allow'], [1, 2], [False, True]),
        ('unavailable_ceiling', ['unavailable', 'unavailable'], [1, 2, 2, 2], [False] * 4),
    ]:
        transport = ScriptReview(values)
        life = PGALifecycle(witness, transport)
        try:
            steps = [life.submit(i) for i in range(len(expected_calls))]
            assert [s['allowed'] for s in steps] == expected_allowed
            assert [s['guard_calls_after'] for s in steps] == expected_calls
            if label == 'negative_cache':
                assert all(s['decision']['cache_hit'] for s in steps[1:])
            assert not transport.values
            mechanisms[label] = {'allowed': expected_allowed, 'calls': expected_calls}
        finally:
            life.close()
    totals = {panel: {'n': sum(r['panel'] == panel for r in rows),
                     'stage0_allowed': sum(r['panel'] == panel and r['allowed'] for r in rows)}
              for panel in ['post_exposure', 'initial']}
    assert totals == {'post_exposure': {'n': 98, 'stage0_allowed': 1}, 'initial': {'n': 112, 'stage0_allowed': 7}}
    result = {'passed': True, 'panels': totals, 'overlap_count': m['overlap_count'],
              'mechanisms': mechanisms, 'rows': rows, 'model_calls': 0, 'network_calls': 0,
              'manifest_sha256': sha(a.manifest), 'source_sha256': {p.name: sha(p) for p in Path(__file__).parent.glob('*.py')}}
    save(a.out, result)
    print(json.dumps({k: v for k, v in result.items() if k not in {'rows', 'mechanisms', 'source_sha256'}}))


if __name__ == '__main__':
    main()
