"""Model-free semantic and failure-path qualification of the new harness."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from native import MatchedNative, NATURAL


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.scratch=tempfile.TemporaryDirectory(prefix='matched-native-test-')
        self.path=NATURAL/'runtime/source-6e408b022ffdd817.json'
        self.packet=json.loads(self.path.read_text())
        self.broker=MatchedNative()
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            self.prepared=self.broker.prepare({'packet':str(self.path),'arm':'all_tools_complete','scratch':self.scratch.name})
        self.good={'function':'send_money','selector':{},'assignments':copy.deepcopy(self.packet['original_proposal']['args'])}

    def tearDown(self):
        self.broker.close();self.scratch.cleanup()

    def evaluate(self,reply,**kwargs):
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            return self.broker.evaluate({'reply':reply,**kwargs})

    def test_correct_native_effect_and_original_refusal(self):
        result=self.evaluate({'status':'bind','authorizations':[self.good]})
        self.assertEqual(result['parse_status'],'valid_bind')
        candidate=result['candidate_results'][0]
        self.assertFalse(candidate['original_policy_allowed'])
        self.assertTrue(candidate['executed'])
        self.assertTrue(candidate['native_utility'])
        self.assertTrue(result['endpoint_evaluation']['first_candidate_intended_native_effect'])
        self.assertTrue(result['endpoint_evaluation']['candidates'][0]['native_replay']['passed'])

    def test_partial_binding_is_retained_but_not_executed(self):
        self.good['assignments'].pop('subject')
        result=self.evaluate({'status':'bind','authorizations':[self.good]})
        self.assertEqual(result['parse_status'],'invalid_binding')
        self.assertTrue(result['endpoint_evaluation']['first_candidate_intended_tuple'])
        self.assertFalse(result['candidate_results'][0]['executed'])
        self.assertEqual(result['candidate_results'][0]['before'],result['candidate_results'][0]['after'])

    def test_invalid_first_never_skips_to_valid_later(self):
        bad=copy.deepcopy(self.good);bad['assignments'].pop('date')
        result=self.evaluate({'status':'bind','authorizations':[bad,self.good]})
        self.assertEqual(result['parse_status'],'invalid_binding')
        self.assertIsNone(result['selected_index'])
        self.assertTrue(all(not c['executed'] for c in result['candidate_results']))

    def test_protected_only_scaffold_has_no_fallback_values(self):
        self.broker.arm='known_function_protected'
        self.good['assignments']={k:v for k,v in self.good['assignments'].items() if k in ['recipient','amount']}
        self.good['assignments']['amount']=99.0
        result=self.evaluate({'status':'bind','authorizations':[self.good]})
        self.assertEqual(result['parse_status'],'valid_bind')
        self.assertEqual(result['candidate_calls'][0]['normalized_call']['args']['amount'],99.0)
        self.assertEqual(result['candidate_calls'][0]['normalized_call']['args']['subject'],self.packet['original_proposal']['args']['subject'])
        self.assertFalse(result['endpoint_evaluation']['first_candidate_intended_tuple'])
        self.good['assignments'].pop('amount')
        failed=self.evaluate({'status':'bind','authorizations':[self.good]})
        self.assertEqual(failed['parse_status'],'invalid_binding')
        self.assertIsNone(failed['candidate_calls'][0]['normalized_call'])

    def test_abstention_and_unavailable_are_distinct(self):
        abstain=self.evaluate({'status':'abstain','authorizations':[]})
        unknown=self.evaluate(None,generation_unavailable=True)
        self.assertEqual(abstain['endpoint_evaluation']['status'],'known')
        self.assertEqual(unknown['endpoint_evaluation']['status'],'unknown')
        self.assertIsNone(unknown['endpoint_evaluation']['first_candidate_intended_tuple'])

    def test_output_cap_is_known_failure_not_unknown(self):
        exhausted=self.evaluate({'status':'bind','authorizations':[self.good]},generation_budget_exhausted=True)
        self.assertEqual(exhausted['parse_status'],'output_limit')
        self.assertEqual(exhausted['endpoint_evaluation']['status'],'known')
        self.assertFalse(exhausted['endpoint_evaluation']['first_candidate_intended_tuple'])
        self.assertEqual(exhausted['candidate_results'],[])

    def test_explicit_negative_remains_effective(self):
        self.broker.policy['send_money'].insert(0,[0,1,{},0])
        result=self.evaluate({'status':'bind','authorizations':[self.good]})
        self.assertFalse(result['candidate_results'][0]['residual_allowed'])
        self.assertEqual(result['candidate_results'][0]['before'],result['candidate_results'][0]['after'])

    def test_observations_and_source_state_not_mutated(self):
        before=copy.deepcopy(self.broker.packet)
        self.evaluate({'status':'bind','authorizations':[self.good,self.good]})
        self.assertEqual(before,self.broker.packet)
        self.assertEqual(self.broker.boundary.model_dump(mode='json'),before['native_boundary_state'])
        public=self.prepared['constructor_packet']
        self.assertEqual(set(public),{'owner_request','observations','contracts','mode'})
        self.assertNotIn('original_proposal',public)
        self.assertNotIn('policy_at_boundary',public)


if __name__=='__main__':
    unittest.main()
