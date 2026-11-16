#!/usr/bin/env python3
"""Negative controls for measurement validity, with synthetic local records."""
import argparse,copy,gzip,json,tempfile,sys
from pathlib import Path
from summarize_intent_guard import audit_pair
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'evaluation/intent_guard'))
from campaign import contrast

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    checks=[]
    with tempfile.TemporaryDirectory() as temp:
        directory=Path(temp)
        def fixture():
            b={'pi':{'registered_tools':['read'],'calls':[{'coupling':{'request_sha256':'request','response_sha256':'response','cache_hit':False,'network_requested':True}}]}}
            g=copy.deepcopy(b);g['pi']['calls'][0]['coupling'].update(cache_hit=True,network_requested=False)
            row={'same_initial_state':True,'arms':{'none':b,'intent_guard':g},'common_actor_request_prefix':1}
            raw={k:{'result':v,'initial':{'object':1},'prompt':'Read the object.'} for k,v in row['arms'].items()}
            return row,raw
        def check(name,change,expected_valid,expected_error=None):
            row,raw=fixture();change(row,raw)
            for arm,value in raw.items():(directory/(arm+'.json.gz')).write_bytes(gzip.compress(json.dumps(value).encode()))
            result=audit_pair(row,directory,'coupled_actor_and_native_writer_clock')
            passed=result['valid']==expected_valid and (expected_error is None or expected_error in result['errors'])
            checks.append({'name':name,'passed':passed,'audit':result})
        check('same_inputs_and_sample_are_valid',lambda r,d:None,True)
        check('same_request_different_sample_is_invalid',lambda r,d:r['arms']['intent_guard']['pi']['calls'][0]['coupling'].update(response_sha256='other'),False,'intent_guard:same_request_different_response')
        check('raw_state_mismatch_overrides_equal_claimed_hashes',lambda r,d:d['intent_guard'].update(initial={'object':2}),False,'raw_initial_states_differ')
        check('raw_summary_mismatch_is_invalid',lambda r,d:d['intent_guard'].update(result={}),False,'intent_guard:raw_summary_mismatch')
        check('claimed_prefix_is_independently_recomputed',lambda r,d:r['arms']['intent_guard']['pi']['calls'][0]['coupling'].update(request_sha256='different'),False,'campaign_prefix_mismatch')
        check('cached_sample_cannot_also_be_billed',lambda r,d:r['arms']['intent_guard']['pi']['calls'][0].update(provider_usage={'input_tokens':1}),False,'intent_guard:cached_response_charged')
        row,raw=fixture();b=row['arms']['none'];g=row['arms']['intent_guard']
        for x in [b,g]:x.update(initial_state_sha256='same',native_utility=True,native_targeted_asr=False)
        other=copy.deepcopy(g);other.update(native_utility=False,native_targeted_asr=True)
        first=contrast(b,g,'attack',False);second=contrast(b,other,'attack',False)
        checks.append({'name':'three_arm_contrasts_do_not_contaminate_each_other','passed':not first['utility_regression'] and not first['new_attack_success'] and second['utility_regression'] and second['new_attack_success']})
        missing={'native_utility':None,'native_targeted_asr':True}
        unknown=contrast(b,missing,'attack',False)
        checks.append({'name':'invalid_shared_baseline_comparison_is_not_new_asr','passed':unknown['regression_unknown'] and not unknown['new_attack_success']})
    report={'kind':'synthetic paired-measurement negative controls, no model or benchmark outcome','checks':checks,'passed':sum(x['passed'] for x in checks),'n':len(checks)}
    (a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
    if report['passed']!=report['n']:raise SystemExit(1)
if __name__=='__main__':main()
