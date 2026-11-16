"""Fresh 2x2 selector/approver study using the original banking broker path."""
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(Path(__file__).parent), str(ROOT / 'intent_guard'), str(ROOT / 'pi'), str(ROOT)]


def no_native_network(*args, **kwargs):
    raise RuntimeError('Native evaluator network disabled')


socket.create_connection = no_native_network
socket.socket.connect = no_native_network
spec = importlib.util.spec_from_file_location('x3_original_baseline', ROOT / 'baseline_audit/broker.py')
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
from controller import CoupledPolicyClient, split_arm, update_with_approval
from catalog import PURE_READS


class Broker(base.Broker):
    def init(self, params):
        self.x3_arm = params['x3_arm']
        self.selector, self.approver = split_arm(self.x3_arm)
        self.update_records = []
        # Capture the uninstrumented checker before baseline wraps it for decision logs.
        self.probe_checker = base.progent.check_tool_call
        original_client = base.PolicyClient
        base.PolicyClient = lambda connection, journal: CoupledPolicyClient(
            connection, journal, params['policy_cache'], self.x3_arm
        )
        try:
            answer = super().init({**params, 'baseline_arm': 'progent'})
        finally:
            base.PolicyClient = original_client
        # Initial generation is identical in every arm: no previous permission to narrow.
        answer['x3_arm'] = self.x3_arm
        return answer

    def invoke(self, params):
        # Bypass only baseline.Broker.invoke's automatic update call, then call
        # the same updater with the original parameters/results serialization.
        result = base.ref.Broker.invoke(self, params)
        value, error = self.runtime.last_result
        call = [{'name': params['name'], 'args': params['args']}]
        formatted_result = str([base.tool_result_to_str(value)])
        # Defaults are supplied by the native parameter model, just as at invocation.
        function = next(tool for tool in self.suite.tools if tool.name == params['name'])
        candidate, probe_error = None, None
        try:
            candidate = {
                'function': params['name'],
                'args': function.parameters.model_validate(params['args']).model_dump(),
            }
        except Exception as exception:
            # A malformed actor call still takes the original post-call update
            # path; absence of a schema-valid diagnostic must not change it.
            probe_error = type(exception).__name__
        update = update_with_approval(
            base.progent, self.policy_client, self.x3_arm, call, formatted_result,
            eligible=error is None and params['name'] in PURE_READS,
            candidate=candidate, admission_checker=self.probe_checker,
        )
        update['native_error'] = error
        update['tool_result_for_update'] = formatted_result
        update['current_call_probe_unavailable'] = probe_error
        self.update_records.append(update)
        self.policy_history.append({
            'stage': 'after_tool', 'tool': params['name'],
            'had_native_error': error is not None,
            'policy': copy.deepcopy(base.progent.security_policy),
        })
        return result

    def finish(self, params):
        answer = super().finish(params)
        answer['result'].update(
            refinement_arm=self.x3_arm, x3_arm=self.x3_arm,
            x3_selector=self.selector, x3_approver=self.approver,
            update_records=self.update_records,
        )
        return answer


def main():
    broker = Broker()
    try:
        for line in sys.stdin:
            ident = None
            try:
                query = json.loads(line)
                ident = query['id']
                assert set(query) == {'id', 'method', 'params'}
                assert query['method'] in {'init', 'invoke', 'finish'}
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    result = getattr(broker, query['method'])(query['params'])
                print(json.dumps({'id': ident, 'ok': True, 'result': result}, default=str), flush=True)
            except Exception as error:
                if getattr(broker, 'policy_client', None):
                    with broker.policy_client.journal.open('a') as handle:
                        handle.write(json.dumps({
                            'stage': 'broker_error', 'error': type(error).__name__,
                            'traceback': traceback.format_exc(),
                        }) + '\n')
                print(json.dumps({'id': ident, 'ok': False, 'error': type(error).__name__}), flush=True)
    finally:
        broker.close()


if __name__ == '__main__':
    main()
