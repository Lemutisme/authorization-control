"""Retained-prefix two-channel controller over the frozen native X6 runtime.

Only this adapter changes. No model is called on import or prefix restoration.
Each explicit refusal invokes stock policy regeneration under automatic approval,
with the rejected-call field shown or hidden. Native execution remains upstream.
"""
from __future__ import annotations
from pipeline.paths import resolve as research_path
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import traceback
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
FROZEN = Path(research_path('experiments/sealed'))
SOURCE = FROZEN / 'evaluation/sealed_control'
sys.path.insert(0, str(SOURCE))
spec = importlib.util.spec_from_file_location('channels_frozen_x6', SOURCE / 'broker.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
sys.path.insert(0, str(HERE))
from channels import Channels, FailedConstraintCapture, digest, refusal_message, update_after_refusal
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime

def file_sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

class Broker(m.Broker):

    def init(self, params):
        self.channels = Channels.from_arm(params['factorial_arm'])
        self.factorial_arm = params['factorial_arm']
        self.raw_native_check = m.progent.check_tool_call
        packet_path = Path(params['prefix_packet']).resolve()
        self.packet = json.loads(packet_path.read_text())
        if params.get('packet_sha256') and file_sha(packet_path) != params['packet_sha256']:
            raise ValueError('Frozen source packet hash changed')
        p = self.packet
        if p.get('policy_at_boundary_sha256') and digest(p['policy_at_boundary']) != p['policy_at_boundary_sha256']:
            raise ValueError('Source policy representation hash changed')
        for field in ['actor_context_json', 'actor_request_json']:
            expected = p['actor_context_utf8_sha256' if field == 'actor_context_json' else 'actor_request_sha256']
            if hashlib.sha256(p[field].encode()).hexdigest() != expected:
                raise ValueError('Source actor context/request byte mismatch')
        self.historical_u = p['historical_actor_calls']
        self.historical_t = p.get('historical_constructor_calls', 0)
        if not 1 <= self.historical_u <= 16 or not 0 <= self.historical_t <= 64:
            raise ValueError('Invalid cumulative source budget')
        role = p.get('actor_role', 'honest')
        if role not in {'honest', 'attack'}:
            raise ValueError('Unregistered source role')
        os.environ['SECAGENT_ONLY_ALLOW_NARROW'] = 'False'
        result = super().init({**params, 'case_id': p['case_id'], 'x6_arm': 'no_gate', 'x2b_role': role, 'strategy': p.get('strategy', 'direct')})
        if self.initial.model_dump(mode='json') != p['native_initial_state']:
            raise ValueError('Native source initial state changed')
        if self.owner_request != p['authentic_owner_request']:
            raise ValueError('Owner request differs from pinned task')
        native = FunctionsRuntime(self.suite.tools)
        for event in p['prior_native_events']:
            if self.env.model_dump(mode='json') != event['before']:
                raise ValueError('Source before-state replay mismatch')
            if not event.get('error'):
                _, error = native.run_function(self.env, event['operation']['function'], event['operation']['args'])
                if error:
                    raise ValueError('Source successful call now fails')
            if self.env.model_dump(mode='json') != event['after']:
                raise ValueError('Source after-state replay mismatch')
        if self.env.model_dump(mode='json') != p['native_boundary_state']:
            raise ValueError('Source boundary mismatch')
        self.baseline_arm = 'progent'
        self.refinement_arm = 'optional'
        self.x2b_arm = 'auto_approve'
        self.x6_arm = 'originalauto'
        self.observations = copy.deepcopy(p.get('successful_observations', []))
        self.proposals = [FunctionCall.model_validate(call) for call in p['prior_native_proposals']]
        self.total_proposals = len(self.proposals)
        self.policy_history = [{'stage': 'retained_boundary', 'policy': copy.deepcopy(p['policy_at_boundary'])}]
        self.historical_policy_calls = copy.deepcopy(p.get('historical_constructor_call_metadata', []))
        self.original_pending = True
        self.factorial_records = []
        self.constraint_capture = FailedConstraintCapture(m.progent)
        self.constraint_capture.install()
        self.current_constraint = None
        self.native_functions = {f.name: f for f in self.suite.tools}
        m.progent.available_tools = []
        m.progent.security_policy = None
        m.progent.init_user_query = self.owner_request
        functions = [f.model_copy(update={'run': m.progent.apply_secure_tool_wrapper(f.run)}) for f in self.suite.tools]
        m.progent.security_policy = copy.deepcopy(p['policy_at_boundary'])
        fields = {f.name: set(f.parameters.model_fields) for f in self.suite.tools}

        def checked(name, kwargs):
            operation = {'function': name, 'args': {k: copy.deepcopy(v) for k, v in kwargs.items() if k in fields[name]}}
            before = digest(m.progent.security_policy)
            try:
                answer = self.raw_native_check(name, kwargs)
            except Exception as exc:
                self.current_constraint = self.constraint_capture.from_exception(exc)
                self.progent_decisions.append({'operation': operation, 'allowed': False, 'reason': str(exc), 'policy_before_sha256': before, 'policy_after_sha256': digest(m.progent.security_policy)})
                raise
            self.progent_decisions.append({'operation': operation, 'allowed': True, 'policy_before_sha256': before, 'policy_after_sha256': digest(m.progent.security_policy)})
            return answer
        m.progent.check_tool_call = checked
        self.policy_check = checked
        self.runtime = m.base.RecordingRuntime(functions, max_calls=64)
        self.runtime.events = copy.deepcopy(p['prior_native_events'])
        self.runtime.calls_started = len(self.runtime.events)
        self.runtime._last_snapshot = copy.deepcopy(p['native_boundary_state'])
        pending_probe = self._probe({'name': p['original_proposal']['function'], 'args': p['original_proposal']['args']}, p['policy_at_boundary'])
        if not pending_probe.get('known') or pending_probe.get('allowed') is not False:
            raise ValueError('Retained pending proposal does not produce an explicit native policy refusal')
        self.initial_pending_probe = pending_probe
        self.policy_client = m.BudgetPolicyClient(result['connection'], params['policy_journal'], params['policy_cache'], 'optional')
        self.policy_client.calls = [{'historical_replayed': True, 'actual_network_call': False, 'ok': True, 'coupling': {'stage': 'historical', 'cache_hit': False}} for _ in range(self.historical_t)]
        m.progent.api_request = self.policy_client.request
        context = json.loads(p['actor_context_json'])
        self.actor_instructions = context.get('systemPrompt') or next((message['content'] for message in context['messages'] if message['role'] == 'system'))
        result['instructions'] = self.actor_instructions
        result['natural_resume'] = {key: copy.deepcopy(p[key]) for key in ['unit_id', 'actor_context_json', 'actor_context_utf8_sha256', 'actor_request_json', 'actor_request_sha256', 'source_proposal_message', 'original_proposal', 'original_proposal_call_id', 'historical_actor_calls']}
        result['natural_resume']['historical_constructor_calls'] = self.historical_t
        result['source_boundary_state_sha256'] = digest(p['native_boundary_state'])
        result['source_boundary_policy_sha256'] = digest(p['policy_at_boundary'])
        result['factorial_configuration'] = {'arm': self.factorial_arm, 'state_value': self.channels.state_value, 'show_refused_call': self.channels.show_refused_call, 'refusal_update_enabled': self.channels.update_enabled, 'approver': 'automatic', 'refusal_update_trigger': 'forced_regeneration_opportunity', 'ordinary_update_trigger': 'source_optional', 'new_owner_audits': 0}
        self.packet_sha256 = file_sha(packet_path)
        return result

    def _probe(self, operation, policy):
        """Fixed-state same-call check on copied permissions; restore consumption."""
        saved = copy.deepcopy(m.progent.security_policy)
        result = {'policy_sha256': digest(policy), 'state_sha256': digest(self.env.model_dump(mode='json'))}
        try:
            function = self.native_functions[operation['name']]
            args = function.parameters.model_validate(operation['args']).model_dump()
            env = self.env.model_copy(deep=True)
            dependencies = {name: dep.extract_dep_from_env(env) for name, dep in function.dependencies.items()}
            m.progent.security_policy = copy.deepcopy(policy)
            try:
                self.raw_native_check(operation['name'], {**args, **dependencies})
                result.update(known=True, allowed=True)
            except m.progent.ValidationError as exc:
                result.update(known=True, allowed=False, reason=str(exc))
            result['policy_after_check_sha256'] = digest(m.progent.security_policy)
            result['operation'] = {'function': operation['name'], 'args': args}
        except Exception as exc:
            result.update(known=False, error=type(exc).__name__, reason=str(exc))
        finally:
            m.progent.security_policy = saved
        return result

    def invoke(self, request):
        if self.original_pending:
            original = self.packet['original_proposal']
            native = self.native_functions[original['function']]
            if request['name'] != original['function'] or native.parameters.model_validate(request['args']).model_dump() != native.parameters.model_validate(original['args']).model_dump() or request['call_id'] != self.packet['original_proposal_call_id']:
                raise ValueError('First call must be the retained pending proposal')
            self.original_pending = False
        self.total_proposals += 1
        if self.total_proposals > 64:
            return {'text': 'Native proposal budget exhausted.', 'is_error': True}
        self.constraint_capture.reset()
        self.current_constraint = None
        decision_start = len(self.progent_decisions)
        policy_before = copy.deepcopy(m.progent.security_policy)
        state_before = self.env.model_dump(mode='json')
        original_result = m.base.ref.Broker.invoke(self, request)
        decisions = self.progent_decisions[decision_start:]
        refused = any((not entry['allowed'] for entry in decisions))
        value, error = self.runtime.last_result
        state_after = self.env.model_dump(mode='json')
        result_text = str([m.base.tool_result_to_str(value)])
        same_previously_refused = any((r['policy_refused'] and r['proposal']['name'] == request['name'] and (r['proposal']['args'] == request['args']) for r in self.factorial_records))
        record = {'call_id': request['call_id'], 'proposal': copy.deepcopy(request), 'policy_refused': refused, 'native_error': error if not refused else None, 'prior_same_call_refusal': same_previously_refused, 'native_result_before_feedback': copy.deepcopy(original_result), 'decision_policy': policy_before, 'decisions': copy.deepcopy(decisions), 'native_state_before_sha256': digest(state_before), 'native_state_after_sha256': digest(state_after)}
        if refused:
            record['refusal_ordinal'] = 1 + sum((entry['policy_refused'] for entry in self.factorial_records))
            record['failed_constraint'] = copy.deepcopy(self.current_constraint)
            feedback = refusal_message(self.owner_request, request['name'], self.current_constraint, self.channels.state_value)
            record['feedback_detail'] = feedback.pop('channel_detail')
            record['actor_feedback'] = copy.deepcopy(feedback)
            record['refusal_state_unchanged'] = state_before == state_after
            record['same_call_before_update'] = self._probe(request, policy_before)
            if self.channels.update_enabled:
                update = update_after_refusal(m.progent, self.policy_client, request, result_text, self.channels.show_refused_call)
            else:
                update = {'kind': 'refusal_update_disabled_reference', 'status': 'skipped', 'calls_before': len(self.policy_client.calls), 'calls_after': len(self.policy_client.calls), 'actual_requests': 0, 'policy_before': copy.deepcopy(m.progent.security_policy), 'policy_after': copy.deepcopy(m.progent.security_policy), 'policy_changed': False}
            self.update_records.append(update)
            record['update'] = copy.deepcopy(update)
            record['same_call_after_update'] = self._probe(request, m.progent.security_policy)
            record['new_admission'] = bool(record['same_call_before_update'].get('known') and record['same_call_after_update'].get('known') and (not record['same_call_before_update']['allowed']) and record['same_call_after_update']['allowed'])
            result = feedback
        else:
            if error is None:
                self.observations.append({'function': request['name'], 'args': copy.deepcopy(request['args']), 'result': m.base.tool_result_to_str(value)})
            update = m.ref.update_policy(m.progent, self.policy_client, 'optional', [{'name': request['name'], 'args': request['args']}], result_text, eligible=error is None)
            self.update_records.append(update)
            record['update'] = copy.deepcopy(update)
            result = original_result
        self.policy_history.append({'stage': 'after_tool', 'tool': request['name'], 'policy_refused': refused, 'policy': copy.deepcopy(m.progent.security_policy)})
        record['policy_after_update'] = copy.deepcopy(m.progent.security_policy)
        self.factorial_records.append(record)
        self.operation_log.append({'kind': 'ordinary', 'proposal': copy.deepcopy(request), 'policy_refused': refused, 'prior_same_call_refusal': same_previously_refused, 'line2_pass_through': not refused, 'result': copy.deepcopy(result)})
        return result

    def finish(self, params):
        result = super().finish(params)
        result['result']['policy_calls'] = result['result']['policy_calls'][self.historical_t:]
        result['result'].update(factorial_arm=self.factorial_arm, factorial_panel=self.packet.get('panel'), factorial_unit_id=self.packet['unit_id'], factorial_packet_sha256=self.packet_sha256, factorial_records=copy.deepcopy(self.factorial_records), factorial_first_refusal=copy.deepcopy(next((entry for entry in self.factorial_records if entry['policy_refused']), None)), initial_pending_probe=self.initial_pending_probe, historical_actor_calls=self.historical_u, historical_constructor_calls=self.historical_t, original_pending_dispatched=not self.original_pending)
        result['raw'].update(factorial_source_packet=copy.deepcopy(self.packet), factorial_source_policy=copy.deepcopy(self.packet['policy_at_boundary']), factorial_source_state=copy.deepcopy(self.packet['native_boundary_state']), factorial_configuration={'arm': self.factorial_arm, 'value': self.channels.state_value, 'refused_call': self.channels.show_refused_call, 'refusal_update_enabled': self.channels.update_enabled, 'approver': 'automatic'}, historical_policy_calls=self.historical_policy_calls)
        return result

    def close(self):
        if getattr(self, 'constraint_capture', None):
            self.constraint_capture.close()
        if getattr(self, 'raw_native_check', None):
            m.progent.check_tool_call = self.raw_native_check
        return super().close()

def main():
    broker = Broker()
    try:
        for line in sys.stdin:
            ident = None
            try:
                q = json.loads(line)
                ident = q['id']
                if set(q) != {'id', 'method', 'params'} or q['method'] not in {'init', 'invoke', 'finish'}:
                    raise ValueError('Invalid factorial RPC')
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    response = getattr(broker, q['method'])(q['params'])
                print(json.dumps({'id': ident, 'ok': True, 'result': response}, default=str), flush=True)
            except Exception as exc:
                print(json.dumps({'id': ident, 'ok': False, 'error': type(exc).__name__, 'diagnostic': traceback.format_exc()}), flush=True)
    finally:
        broker.close()
if __name__ == '__main__':
    main()
