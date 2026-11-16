"""Matched constructor diagnostic: frozen state restoration and native effect forks.

No model code or task-correctness oracle lives here. The frozen natural broker
loads a source prefix without fresh generation. Every candidate is evaluated on
its own boundary-state copy, with the exact frozen residual-policy function.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import sys
from pathlib import Path

sys.dont_write_bytecode = True
NATURAL = Path('/artifact-source/b24eb20cebce/natural-frozen-v1')
FROZEN = Path('/artifact-source/eacb584555c5/frozen-v1')
MANIFEST = FROZEN / 'evaluation/authorship/x2b/manifest-v1.json'
spec = importlib.util.spec_from_file_location('matched_frozen_natural', NATURAL / 'broker.py')
frozen_natural = importlib.util.module_from_spec(spec)
spec.loader.exec_module(frozen_natural)
x6 = frozen_natural.m
contracts = sys.modules['contracts']
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.types import text_content_block_from_string

ARMS = ('all_tools_complete', 'known_function_complete', 'known_function_protected')
PROFILE = 'banking_financial'


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class MatchedNative:
    def __init__(self):
        self.broker = None
        self.prepared = False

    def prepare(self, params):
        if self.prepared:
            raise ValueError('One source prefix per native process')
        path = Path(params['packet']).resolve()
        self.packet = json.loads(path.read_text())
        if params.get('packet_sha256') and file_sha(path) != params['packet_sha256']:
            raise ValueError('Frozen source packet hash mismatch')
        self.arm = params['arm']
        if self.arm not in ARMS:
            raise ValueError('Unknown arm')
        self.function = self.packet['original_proposal']['function']
        # The prespecified retained panel contains only send_money proposals.
        # Fail explicitly instead of silently extending protected-only scaffolds.
        if self.function != 'send_money':
            raise ValueError('This matched panel is qualified for send_money only')
        if self.packet['historical_constructor_calls'] >= 64:
            raise ValueError('No remaining source constructor slot')
        scratch = Path(params['scratch']).resolve()
        scratch.mkdir(parents=True, exist_ok=True)
        self.broker = frozen_natural.Broker()
        init = self.broker.init({
            'natural_packet': str(path), 'manifest': str(MANIFEST),
            'x6_arm': 'no_gate', 'contract_profile': PROFILE,
            'model': 'gpt-6-luna', 'delegate_reference': True,
            'clock_anchor': '2026-11-05T00:00:00',
            'judge_cache': str(scratch / 'unused-judge'),
            'policy_cache': str(scratch / 'unused-policy'),
            'policy_journal': str(scratch / 'unused-policy.jsonl'),
        })
        if self.broker.env.model_dump(mode='json') != self.packet['native_boundary_state']:
            raise ValueError('Native prefix restoration failed')
        self.boundary = self.broker.env.model_copy(deep=True)
        self.policy = copy.deepcopy(self.packet['policy_at_boundary'])
        self.contracts = contracts.registry_packet(profile=PROFILE)
        if self.contracts != self.packet['registered_contracts']:
            raise ValueError('Source contract registry changed')
        self.tools = {tool.name: tool for tool in self.broker.suite.tools}
        self.original_check = x6.progent.check_tool_call
        self.decisions = []

        def traced_check(name, kwargs):
            before = copy.deepcopy(x6.progent.security_policy)
            fields = set(self.tools[name].parameters.model_fields)
            operation = {'function': name, 'args': {k: copy.deepcopy(v) for k, v in kwargs.items() if k in fields}}
            try:
                result = self.original_check(name, kwargs)
            except Exception as exc:
                self.decisions.append({'operation': operation, 'allowed': False, 'reason': str(exc),
                    'policy_before': before, 'policy_after': copy.deepcopy(x6.progent.security_policy)})
                raise
            self.decisions.append({'operation': operation, 'allowed': True, 'policy_before': before,
                'policy_after': copy.deepcopy(x6.progent.security_policy)})
            return result

        x6.progent.check_tool_call = traced_check
        x6.progent.available_tools = []
        self.wrapped = [tool.model_copy(update={'run': x6.progent.apply_secure_tool_wrapper(tool.run)})
                        for tool in self.broker.suite.tools]
        self.prepared = True
        constructor_packet = {'owner_request': self.packet['authentic_owner_request'],
            'observations': copy.deepcopy(self.packet['successful_observations']),
            'contracts': copy.deepcopy(self.contracts), 'mode': 'constructor'}
        return {
            'connection': init['connection'],  # Private RPC only; never persisted.
            'constructor_packet': constructor_packet, 'known_function': self.function,
            'source': {'unit_id': self.packet['unit_id'], 'packet_sha256': file_sha(path),
                'context_equivalence_group': self.packet.get('context_equivalence_group'),
                'constructor_input_sha256': digest(constructor_packet),
                'native_boundary_sha256': digest(self.packet['native_boundary_state']),
                'policy_sha256': digest(self.policy),
                'historical_constructor_calls': self.packet['historical_constructor_calls'],
                'historical_actor_calls': self.packet['historical_actor_calls']},
        }

    def parse(self, reply):
        """Retain raw coordinate content even when full construction is invalid."""
        candidates = []
        if not isinstance(reply, dict) or set(reply) != {'status', 'authorizations'}:
            return 'invalid_envelope', candidates, 'Expected exactly status and authorizations'
        auths = reply['authorizations']
        if reply['status'] == 'abstain':
            return ('abstain', [], None) if auths == [] else ('invalid_envelope', [], 'Nonempty abstention')
        if reply['status'] != 'bind' or not isinstance(auths, list) or not 1 <= len(auths) <= 32:
            return 'invalid_envelope', [], 'Bind requires one to 32 tuples'
        for index, auth in enumerate(auths):
            entry = {'index': index, 'authorization': copy.deepcopy(auth), 'raw_call': None,
                'normalized_call': None, 'projection': None, 'shape_error': None}
            candidates.append(entry)
            if isinstance(auth, dict) and isinstance(auth.get('selector'), dict) and isinstance(auth.get('assignments'), dict):
                entry['raw_call'] = {'function': auth.get('function'),
                    'args': {**copy.deepcopy(auth['selector']), **copy.deepcopy(auth['assignments'])}}
            try:
                if not isinstance(auth, dict) or set(auth) != {'function', 'selector', 'assignments'}:
                    raise ValueError('Tuple must contain function, selector, assignments only')
                if self.arm != 'all_tools_complete' and auth['function'] != self.function:
                    raise ValueError('Known-function arm returned a different function')
                complete = copy.deepcopy(auth)
                if self.arm == 'known_function_protected':
                    keys = set(contracts.protected_fields(self.function, PROFILE))
                    selectors = set(self.contracts['functions'][self.function]['selector_fields'])
                    writes = keys - selectors
                    if set(auth['selector']) != selectors or set(auth['assignments']) != writes:
                        raise ValueError('Protected-only reply must supply exactly the protected coordinates')
                    # Only residual arguments are carried over. Protected actor
                    # values are removed before constructor assignments are merged.
                    scaffold = {k: copy.deepcopy(v) for k, v in self.packet['original_proposal']['args'].items() if k not in keys}
                    complete['assignments'] = {**scaffold, **copy.deepcopy(auth['assignments'])}
                normalized = contracts.validate_binding({'status': 'bind', 'authorizations': [complete]}, PROFILE)
                call = contracts.materialize(normalized, profile=PROFILE)
                native = self.tools[call['function']]
                call['args'] = native.parameters.model_validate(call['args']).model_dump()
                entry['normalized_call'] = call
                entry['projection'] = contracts.project(call['function'], call['args'], PROFILE)
            except Exception as exc:
                entry['shape_error'] = type(exc).__name__ + ': ' + str(exc)
        # Preserve original X6 whole-packet validation: do not skip an invalid
        # first tuple or execute later tuples from an otherwise malformed reply.
        status = 'valid_bind' if all(e['shape_error'] is None for e in candidates) else 'invalid_binding'
        return status, candidates, None

    def _fork(self, call, policy):
        env = self.boundary.model_copy(deep=True)
        before = env.model_dump(mode='json')
        x6.progent.security_policy = copy.deepcopy(policy)
        x6.progent.init_user_query = self.packet['authentic_owner_request']
        self.decisions = []
        runtime = FunctionsRuntime(self.wrapped)
        value, error = runtime.run_function(env, call['function'], call['args'])
        after = env.model_dump(mode='json')
        decisions = copy.deepcopy(self.decisions)
        if len(decisions) != 1:
            raise ValueError('Expected exactly one original native gate check')
        allowed = decisions[0]['allowed']
        utility = utility_error = None
        proposals = [FunctionCall.model_validate(c) for c in self.packet['prior_native_proposals']]
        proposals.append(FunctionCall(function=call['function'], args=call['args'], id='matched-constructor'))
        try:
            utility = self.broker.suite._check_user_task_utility(self.broker.task,
                [text_content_block_from_string('')], self.broker.initial.model_copy(deep=True),
                env.model_copy(deep=True), proposals)
        except Exception as exc:
            utility_error = type(exc).__name__ + ': ' + str(exc)
        return {'allowed': allowed, 'native_error': error if allowed else None,
            'denial': error if not allowed else None, 'native_result': x6.base.tool_result_to_str(value),
            'before': before, 'after': after, 'native_utility': utility,
            'utility_error': utility_error, 'decisions': decisions,
            'policy_before': copy.deepcopy(policy), 'policy_after': copy.deepcopy(x6.progent.security_policy)}

    def evaluate(self, params):
        if not self.prepared:
            raise ValueError('Not prepared')
        if params.get('generation_unavailable'):
            status, candidates, parse_error = 'model_error', [], 'Generation unavailable or incomplete'
        elif params.get('generation_budget_exhausted'):
            status, candidates, parse_error = 'output_limit', [], 'Fixed generation output cap exhausted'
        else:
            status, candidates, parse_error = self.parse(params.get('reply'))
        results = []
        for entry in candidates:
            result = {'index': entry['index'], 'normalized_call': entry['normalized_call'],
                'raw_call': entry['raw_call'], 'projection': entry['projection'],
                'shape_error': entry['shape_error'], 'executed': False,
                'residual_allowed': None, 'native_error': None,
                'before': copy.deepcopy(self.packet['native_boundary_state']),
                'after': copy.deepcopy(self.packet['native_boundary_state']), 'native_utility': None,
                'counterfactual_candidate_fork': entry['index'] != 0,
                'original_policy_allowed': None}
            if status == 'valid_bind':
                call = entry['normalized_call']
                original = self._fork(call, self.policy)
                residual = x6.residual_policy(self.policy, call['function'], contracts.protected_fields(call['function'], PROFILE))
                repair = self._fork(call, residual)
                result.update(original_policy_allowed=original['allowed'], original_policy_check=original,
                    residual_policy=residual, residual_allowed=repair['allowed'], native_error=repair['native_error'],
                    before=repair['before'], after=repair['after'], native_utility=repair['native_utility'],
                    utility_error=repair['utility_error'], decisions=repair['decisions'],
                    policy_before=repair['policy_before'], policy_after=repair['policy_after'],
                    executed=repair['allowed'] and repair['native_error'] is None,
                    native_result=repair['native_result'], denial=repair['denial'])
            results.append(result)
        x6.progent.security_policy = copy.deepcopy(self.policy)
        out = {'parse_status': status, 'parse_error': parse_error,
            'candidate_calls': candidates, 'candidate_results': results,
            'selected_index': 0 if status == 'valid_bind' else None,
            'selection_rule': 'First tuple of a wholly valid packet; never skip malformed tuples',
            'source_packet': copy.deepcopy(self.packet), 'native_network_disabled': True}
        try:
            from evaluator import evaluate
        except ImportError:
            out['endpoint_evaluation'] = {'status': 'evaluator_not_installed'}
        else:
            out['endpoint_evaluation'] = evaluate(self.packet, candidates, results, status)
        return out

    def close(self):
        if self.prepared:
            x6.progent.check_tool_call = self.original_check
        if self.broker:
            self.broker.close()


def main():
    broker = MatchedNative()
    try:
        for line in sys.stdin:
            ident = None
            try:
                q = json.loads(line); ident = q['id']
                if set(q) != {'id', 'method', 'params'} or q['method'] not in {'prepare', 'evaluate'}:
                    raise ValueError('Invalid RPC')
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    result = getattr(broker, q['method'])(q['params'])
                print(json.dumps({'id': ident, 'ok': True, 'result': result}, default=str), flush=True)
            except Exception as exc:
                print(json.dumps({'id': ident, 'ok': False, 'error': type(exc).__name__, 'reason': str(exc)}), flush=True)
    finally:
        broker.close()


if __name__ == '__main__':
    main()
