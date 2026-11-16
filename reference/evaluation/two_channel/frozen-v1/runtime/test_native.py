"""No-model tests of the consequential pinned-native adapter branches."""
from __future__ import annotations

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest

from broker import Broker, m
from channels import FailedConstraintCapture, digest, refusal_message, update_after_refusal
from fixture_broker import FixtureBroker

P = m.progent
ROOT = Path(__file__).resolve().parent
PACKET = ROOT.parent / 'cohort/runtime/natural-source-cfaa02c1cd4cde69.json'


class NativeHooks(unittest.TestCase):
    def setUp(self):
        self.saved = {name: getattr(P, name) for name in [
            'security_policy', 'check_arg', 'check_tool_call', 'init_user_query',
            'api_request', 'available_tools', 'generate_policy', 'ignore_update_error',
            'decide_whether_to_update', 'extract_json', 'delete_generated_policy']}
        P.init_user_query = 'Pay the task merchant.'
        self.capture = FailedConstraintCapture(P)
        self.capture.install()

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(P, name, value)

    def refused(self, policy, tool='send_money', args=None):
        P.security_policy = copy.deepcopy(policy)
        self.capture.reset()
        try:
            P.check_tool_call(tool, args or {'recipient': 'merchant', 'amount': 200.29})
        except P.ValidationError as exc:
            return self.capture.from_exception(exc)
        self.fail('Expected native refusal')

    def test_positive_failed_constraint_and_only_value_clause_differs(self):
        constraint = self.refused({'send_money': [(100, 0, {'amount': {'const': 195.29}}, 0)]})
        self.assertEqual(constraint, {'argument': 'amount', 'restriction': {'const': 195.29}})
        low = refusal_message(P.init_user_query, 'send_money', constraint, False)
        high = refusal_message(P.init_user_query, 'send_money', constraint, True)
        self.assertEqual(high['text'].replace(' Policy constraint: {"const":195.29}.', ''), low['text'])

    def test_missing_function_has_identical_feedback(self):
        constraint = self.refused({})
        self.assertIsNone(constraint)
        self.assertEqual(refusal_message('task', 'send_money', constraint, False),
                         refusal_message('task', 'send_money', constraint, True))

    def test_explicit_deny_does_not_disclose_earlier_nonmatching_deny(self):
        constraint = self.refused({'send_money': [
            (10, 1, {'recipient': {'const': 'different-account'}}, 0),
            (100, 1, {}, 0)]})
        self.assertIsNone(constraint)
        self.assertEqual(refusal_message('task', 'send_money', constraint, False),
                         refusal_message('task', 'send_money', constraint, True))

    def generation(self, responses, visible):
        class Client:
            stage = 'ordinary'
            calls = []
        client = Client()
        client.calls = []
        iterator = iter(responses)
        def request(system, user, temperature):
            client.calls.append({'system': system, 'user': user, 'temperature': temperature})
            response = next(iterator)
            if isinstance(response, Exception):
                raise response
            return response
        P.api_request = request
        P.generate_policy = True
        P.ignore_update_error = False
        P.available_tools = [{'name': 'send_money', 'args': {'amount': {'type': 'number'}}}]
        P.security_policy = {'base_read': [(1, 0, {}, 0)],
                             'send_money': [(100, 0, {'amount': {'const': 195.29}}, 0)]}
        selector_calls = []
        def selector(params):
            selector_calls.append(params)
            raise AssertionError('Selector must be bypassed at an explicit refusal')
        P.decide_whether_to_update = selector
        with contextlib.redirect_stderr(io.StringIO()):
            record = update_after_refusal(P, client,
                {'name': 'send_money', 'args': {'amount': 200.29}}, "['']", visible)
        self.assertEqual(selector_calls, [])
        self.assertIs(P.decide_whether_to_update, selector)
        self.assertEqual(client.stage, 'ordinary')
        return record, client.calls

    def test_native_parser_retry_and_successful_install_are_recorded(self):
        result, calls = self.generation([
            '[{"name":"send_money","args":{"amount":{"const":200.29}}},{"name":"incomplete"}]',
            '[{"name":"send_money","args":{"amount":{"const":200.29}}}]'], True)
        self.assertEqual(result['status'], 'returned')
        self.assertEqual(result['actual_requests'], 2)
        self.assertEqual(len(result['delete_events']), 2)
        self.assertEqual(len(result['candidate_parse_events']), 2)
        self.assertEqual(P.security_policy['send_money'], [(100, 0, {'amount': {'const': 200.29}}, 0)])
        self.assertIn('base_read', P.security_policy)
        self.assertEqual(calls[0]['user'], calls[1]['user'])
        self.assertEqual([c['temperature'] for c in calls], [0.0, 0.2])
        self.assertIn('TOOL_CALL_PARAM: [{"name": "send_money", "args": {"amount": 200.29}}]', calls[0]['user'])
        self.assertIn("TOOL_CALL_RESULT: ['']", calls[0]['user'])

    def test_six_failed_installations_retain_partial_native_mutation(self):
        malformed = '[{"name":"send_money","args":{"amount":{"const":200.29}}},{"name":"incomplete"}]'
        result, calls = self.generation([malformed] * 6, False)
        self.assertEqual(result['status'], 'raised')
        self.assertEqual(result['error'], 'KeyError')
        self.assertEqual(result['actual_requests'], 6)
        self.assertEqual(len(result['delete_events']), 6)
        self.assertTrue(result['policy_changed'])
        self.assertEqual(result['policy_after'], P.security_policy)
        self.assertEqual(P.security_policy['send_money'], [(100, 0, {'amount': {'const': 200.29}}, 0)])
        self.assertIn('TOOL_CALL_PARAM: []', calls[0]['user'])

    def test_transport_retries_leave_policy_intact_and_are_counted(self):
        result, calls = self.generation([ConnectionError('fixture transport')] * 6, False)
        self.assertEqual(result['status'], 'raised')
        self.assertEqual(result['actual_requests'], 6)
        self.assertEqual(result['candidate_parse_events'], [])
        self.assertEqual(result['delete_events'], [])
        self.assertFalse(result['policy_changed'])

    def test_probe_restores_consumed_policy_and_native_state(self):
        # Initializing the official policy worker only starts its RPC process.
        # No request is made; the qualification connection never reaches a socket.
        self.capture.close()
        with tempfile.TemporaryDirectory() as directory:
            broker = FixtureBroker()
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    broker.init({'factorial_arm': 'f0_off', 'prefix_packet': str(PACKET),
                        'manifest': '/artifact-source/968854d6265c/manifest-v1.json',
                        'model': 'gpt-6-luna', 'delegate_reference': True,
                        'clock_anchor': '2026-11-05T00:00:00',
                        'judge_cache': directory + '/judge', 'policy_cache': directory + '/policy',
                        'policy_journal': directory + '/journal.jsonl'})
                before_policy = copy.deepcopy(P.security_policy)
                before_state = broker.env.model_dump(mode='json')
                consumable = {'send_money': [(100, 0, {}, 0, {'send_money': []})]}
                source = broker.packet['original_proposal']
                probe = broker._probe({'name': source['function'], 'args': source['args']}, consumable)
                self.assertTrue(probe['known'])
                self.assertTrue(probe['allowed'])
                self.assertNotEqual(probe['policy_after_check_sha256'], digest(consumable))
                self.assertEqual(P.security_policy, before_policy)
                self.assertEqual(broker.env.model_dump(mode='json'), before_state)
                self.assertEqual(len(broker.policy_client.calls), broker.historical_t)
            finally:
                broker.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
