"""Model-free regression for unavailable-vs-negative scientific accounting."""
import argparse
import copy
import gzip
import json
from pathlib import Path
from run import aggregate, initial_semantic_denial, scientific_status
from prepare import save


def case(steps, admission=None, updates=None):
    return {'status': 'completed', 'steps': steps, 'first_admission_stage': admission,
            'first_goal_stage': admission, 'update_records': updates or []}


def main():
    p=argparse.ArgumentParser();p.add_argument('--failed-run',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    denied={'allowed':False,'operational_unavailable':False}
    unavailable={'allowed':False,'operational_unavailable':True}
    allowed={'allowed':True,'operational_unavailable':False}
    semantic=case([copy.deepcopy(denied) for _ in range(4)])
    failed=case([copy.deepcopy(unavailable) for _ in range(4)])
    recovered=case([unavailable,allowed],1)
    update_failed=case([denied,denied],updates=[{'stage':0,'failed_responses':1,'status':'completed'}])
    assert scientific_status(semantic)=='complete' and initial_semantic_denial(semantic)
    assert scientific_status(failed)=='review_unavailable' and not initial_semantic_denial(failed)
    m=aggregate([failed],1)
    assert m['completed']==1 and m['scientifically_complete']==0 and m['initial_denied']==0
    assert all(s['scientific_unknown']==1 and s['known_nonadmissions']==0 for s in m['stages'])
    m=aggregate([semantic],1)
    assert m['scientifically_complete']==1 and all(s['known_nonadmissions']==1 for s in m['stages'])
    m=aggregate([recovered],1)
    assert m['new_admissions']==0 and m['stages'][0]['scientific_unknown']==1 and m['stages'][1]['cumulative_admissions']==1
    assert m['stages'][1]['scientific_unknown']==0
    m=aggregate([update_failed],1)
    assert m['stages'][0]['scientific_unknown']==0 and m['stages'][1]['scientific_unknown']==1
    config=json.loads((a.failed_run/'config.json').read_text())
    rows=[json.loads(gzip.decompress((a.failed_run/cid/'pga_minimal.json.gz').read_bytes()))['result'] for cid in config['cases']]
    actual=aggregate(rows,len(rows))
    assert actual['completed']==2 and actual['scientifically_complete']==0 and actual['review_unavailable_episodes']==2
    assert actual['initial_denied']==0 and all(s['scientific_unknown']==2 for s in actual['stages'])
    result={'passed':True,'model_calls':0,'network_calls':0,'failed_smoke_reclassified':actual,
            'checks':['valid_semantic_negative_known','unavailable_not_semantic_negative','unavailable_then_allow_not_initial_denial_transition','failed_update_unknown_only_at_later_stage','retained_v1_failed_smoke_two_unknown']}
    save(a.out,result);print(json.dumps(result,indent=2))
if __name__=='__main__':main()
