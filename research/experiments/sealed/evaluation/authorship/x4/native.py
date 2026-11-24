"""Local native Progent grant adapter for X4 qualification and future integration.

Only declared protected fields of one existing generated allow rule may be
rebound. Registry, non-generated rules, and all other restrictions remain.
No model or task-scoring oracle is supplied by this module.
"""
import contextlib
import copy
import io
from pathlib import Path
import sys

EVAL = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(EVAL), str(EVAL / 'intent_guard'), str(EVAL / 'pi')]
from pga_runtime import AuditedRuntime
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from kernel import Contract, digest, equivalent


class NativeGrantAdapter:
    def __init__(self, *, suite, environment, owner_request, progent, policy, protected_fields,
                 effective_arguments=None, normalize_field=None):
        self.suite, self.environment = suite, environment
        self.owner_request, self.progent = owner_request, progent
        self.policy = copy.deepcopy(policy)
        self.effective_arguments = effective_arguments
        self.normalize_field = normalize_field or (lambda field, value: value)
        self.functions = {function.name: function for function in suite.tools}
        self.contracts = {}
        for name, fields in protected_fields.items():
            schema = self.functions[name].parameters.model_json_schema()
            contract = Contract(name, tuple(fields), tuple(field for field in schema['properties'] if field not in fields), schema)
            contract.validate()
            self.contracts[name] = contract
        self.runtime = AuditedRuntime(suite.tools, max_calls=64)
        self.sealed = {}
        self.consumed = set()
        self.authorization_records = []

    def normalize(self, call):
        if not isinstance(call, dict) or set(call) != {'function', 'args'}:
            raise ValueError('Expected one tool call')
        function = self.functions[call['function']]
        args = function.parameters.model_validate(call['args']).model_dump(mode='json')
        return {'function': call['function'], 'args': args}

    def revision(self):
        return digest(self.environment.model_dump(mode='json'))

    def effective(self, call):
        args = copy.deepcopy(call['args'])
        if self.effective_arguments:
            args = self.effective_arguments(call['function'], args, self.environment.model_dump(mode='json'))
        return args

    def projection(self, call, fields):
        args = self.effective(call)
        return {'function': call['function'],
                'args': {field: self.normalize_field(field, args.get(field)) for field in fields}}

    def normalize_binding(self, binding):
        return {'function': binding['function'],
                'args': {field: self.normalize_field(field, value) for field, value in binding['args'].items()}}

    def _replacement(self, call, grant):
        contract = self.contracts.get(call['function'])
        if contract is None:
            raise ValueError('No registered protected projection')
        if grant['owner_request_sha256'] != digest(self.owner_request):
            raise ValueError('Owner mismatch')
        if grant['native_state_revision'] != self.revision():
            raise ValueError('State changed')
        if grant['complete_call_sha256'] != digest(call):
            raise ValueError('Call changed')
        tuple_grant = grant['tuple']
        if tuple_grant['function'] != call['function']:
            raise ValueError('Grant function mismatch')
        if not set(contract.protected_fields).issubset(tuple_grant['args']):
            raise ValueError('Grant omits protected fields')
        projected = self.projection(call, tuple_grant['args'])
        if any(not equivalent(projected['args'][field], value) for field, value in tuple_grant['args'].items()):
            raise ValueError('Grant tuple mismatch')
        policy = copy.deepcopy(self.policy)
        rules = [rule for rule in (policy or {}).get(call['function'], []) if rule[0] == 100 and rule[1] == 0]
        if len(rules) != 1:
            raise ValueError('Repair needs one existing generated allow rule for this tool')
        if not isinstance(rules[0][2], dict):
            raise ValueError('Unsupported generated restriction')
        for field in contract.protected_fields:
            rules[0][2][field] = {'enum': [copy.deepcopy(projected['args'][field])]}
        return policy

    def residual_authorize(self, call, grant):
        try:
            replacement = self._replacement(call, grant)
            prior_policy, prior_request = self.progent.security_policy, self.progent.init_user_query
            self.progent.security_policy, self.progent.init_user_query = replacement, self.owner_request
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    kwargs = {field: self.normalize_field(field, value) for field, value in self.effective(call).items()}
                    self.progent.check_tool_call(call['function'], kwargs)
            finally:
                self.progent.security_policy, self.progent.init_user_query = prior_policy, prior_request
            self.sealed[grant['repair_id']] = {'grant': copy.deepcopy(grant), 'call': copy.deepcopy(call), 'policy': replacement}
            result = {'allow': True, 'trusted_model_calls': 0, 'scope': 'Original checker with only protected fields rebound; all residual and non-generated restrictions retained'}
        except Exception as error:
            result = {'allow': False, 'trusted_model_calls': 0, 'error': type(error).__name__, 'reason': str(error)}
        self.authorization_records.append({'call': copy.deepcopy(call), 'grant': copy.deepcopy(grant), **result})
        return result

    def execute(self, call, grant):
        key = grant['repair_id']
        if key in self.consumed or key not in self.sealed:
            raise ValueError('Missing or consumed grant')
        sealed = self.sealed[key]
        if digest(sealed['grant']) != digest(grant) or digest(sealed['call']) != digest(call):
            raise ValueError('Sealed grant changed')
        if self.revision() != grant['native_state_revision']:
            raise ValueError('State changed at commit')
        self.consumed.add(key)
        before = self.environment.model_dump(mode='json')
        value, error = self.runtime.run_function(self.environment, call['function'], copy.deepcopy(call['args']))
        after = self.environment.model_dump(mode='json')
        # The attempt consumes the local grant even when the native function
        # reports an error; no exactly-once or remote-commit guarantee is claimed.
        def portable(value):
            if hasattr(value, 'model_dump'):
                return value.model_dump(mode='json')
            if isinstance(value, dict):
                return {str(key): portable(item) for key, item in value.items()}
            if isinstance(value, list):
                return [portable(item) for item in value]
            if value is None or isinstance(value, (str, int, float, bool)):
                return value
            return str(value)
        return {'native_error': error, 'value': tool_result_to_str(value), 'native_value': portable(value), 'state_changed': before != after,
                'before_sha256': digest(before), 'after_sha256': digest(after),
                'operation': copy.deepcopy(call)}


class ReviewedNativeAdapter(NativeGrantAdapter):
    """PGA-facing hook: retain a separately supplied ordinary full-call check.

    The caller must use the measured PGA implementation and retain its calls,
    cache behavior, argument binding and errors. This class does not substitute
    tuple agreement for that decision, and does not invalidate cached denials.
    """
    def __init__(self, *, ordinary_authorizer, residual_model_call_cap=2, **kwargs):
        super().__init__(policy={}, **kwargs)
        self.ordinary_authorizer = ordinary_authorizer
        self.residual_model_call_cap = residual_model_call_cap

    def residual_authorize(self, call, grant):
        try:
            contract = self.contracts[call['function']]
            assert grant['owner_request_sha256'] == digest(self.owner_request)
            assert grant['native_state_revision'] == self.revision()
            assert grant['complete_call_sha256'] == digest(call)
            assert grant['tuple']['function'] == call['function']
            assert set(contract.protected_fields).issubset(grant['tuple']['args'])
            projected = self.projection(call, grant['tuple']['args'])
            assert all(equivalent(projected['args'][field], value) for field, value in grant['tuple']['args'].items())
            verdict = self.ordinary_authorizer(copy.deepcopy(call), copy.deepcopy(grant))
            count = verdict.get('trusted_model_calls')
            if not isinstance(count, int) or count < 0 or count > self.residual_model_call_cap:
                raise ValueError('Unknown or exceeded residual review cost')
            allow = verdict.get('allow') is True
            result = {'allow': allow, 'trusted_model_calls': count, 'ordinary_review': verdict,
                      'scope': 'Fresh tuple agreement plus separately retained ordinary full-call authorization; no cache bypass'}
            if allow:
                self.sealed[grant['repair_id']] = {'grant': copy.deepcopy(grant), 'call': copy.deepcopy(call), 'policy': None}
        except Exception as error:
            result = {'allow': False, 'trusted_model_calls': None, 'error': type(error).__name__, 'reason': str(error)}
        self.authorization_records.append({'call': copy.deepcopy(call), 'grant': copy.deepcopy(grant), **result})
        return result
