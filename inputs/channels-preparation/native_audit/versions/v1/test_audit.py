"""No-model tests that the auditor detects consequential corrupted records."""
from pipeline.paths import resolve as research_path
import copy
import gzip
import json
from pathlib import Path
import unittest
from audit import audit_raw, replay_operation, get_suite, MANIFEST, differences, same
PILOT = Path(research_path('external/2535d4527b9d/pilot-v1'))

class AuditTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        manifest = json.loads(MANIFEST.read_text())
        cls.version = manifest['version']
        cls.raw = json.loads(gzip.decompress(sorted(PILOT.rglob('*.json.gz'))[0].read_bytes()))
        cls.case = next((c for c in manifest['cases'] if c['case_id'] == cls.raw['result']['case_id']))
        cls.suite = get_suite(cls.version, cls.case['suite'])

    def test_native_failure_executes_and_retains_error_and_state(self):
        state = self.raw['factorial_source_state']
        result = replay_operation(self.suite, state, {'update_scheduled_transaction': [(100, 0, {}, 0)]}, 'task', {'function': 'update_scheduled_transaction', 'args': {'id': 99999999, 'amount': 15}})
        self.assertEqual(result['error'], 'ValueError: Transaction with ID 99999999 not found.')
        self.assertTrue(same(state, result['after']))
        self.assertFalse(result['entry_state_changed'])
        self.assertTrue(result['decisions'][0]['allowed'])
        self.assertIsNone(result['unexpected_exception'])

    def test_unmodified_pilot_passes(self):
        result = audit_raw(copy.deepcopy(self.raw), self.case, self.version)
        self.assertEqual(result['status'], 'pass', result['issues'])

    def test_unchanged_native_read_is_replayed(self):
        state = self.raw['factorial_source_state']
        result = replay_operation(self.suite, state, {'get_iban': [(100, 0, {}, 0)]}, 'task', {'function': 'get_iban', 'args': {}})
        self.assertIsNone(result['error'])
        self.assertFalse(result['entry_state_changed'])
        self.assertTrue(same(state, result['after']))
        self.assertTrue(result['decisions'][0]['allowed'])

    def test_tampered_native_after_is_detected(self):
        raw = copy.deepcopy(self.raw)
        index = len(raw['factorial_source_packet']['prior_native_events'])
        raw['events'][index]['after']['user_account']['password'] = 'tampered-value'
        result = audit_raw(raw, self.case, self.version)
        issues = result['issues']
        self.assertEqual(result['status'], 'mismatch')
        self.assertTrue(any((i['code'] == 'native_after' and i['event'] == index for i in issues)))

    def test_tampered_error_is_detected_even_when_state_matches(self):
        raw = copy.deepcopy(self.raw)
        index = len(raw['factorial_source_packet']['prior_native_events'])
        raw['events'][index]['error'] = 'forged-error'
        result = audit_raw(raw, self.case, self.version)
        self.assertTrue(any((i['code'] == 'native_error' and i['event'] == index for i in result['issues'])))

    def test_tampered_score_is_detected_independently(self):
        raw = copy.deepcopy(self.raw)
        raw['result']['native_utility'] = not raw['result']['native_utility']
        result = audit_raw(raw, self.case, self.version)
        codes = [i['code'] for i in result['issues']]
        self.assertIn('recorded_final_score', codes)
        self.assertIn('replayed_final_score', codes)

    def test_missing_error_branch_is_reported_not_skipped(self):
        raw = copy.deepcopy(self.raw)
        raw['result']['factorial_records'].pop()
        result = audit_raw(raw, self.case, self.version)
        self.assertEqual(result['status'], 'mismatch')
        self.assertEqual(result['event_reports'][-1]['status'], 'not_replayable')
        self.assertTrue(any((i['code'] == 'missing_decision_policy' for i in result['issues'])))

    def test_diff_records_all_leaves_with_strict_boolean_semantics(self):
        self.assertFalse(same(True, 1))
        self.assertTrue(same(15, 15.0))
        found = differences({'a': [1, 2], 'b': True}, {'a': [1, 3], 'b': 1})
        self.assertEqual(len(found), 2)
        self.assertEqual(found[0]['path'], '$["a"][1]')
if __name__ == '__main__':
    unittest.main(verbosity=2)
