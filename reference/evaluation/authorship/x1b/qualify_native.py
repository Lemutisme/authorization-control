"""Model-free lifecycle of both X1b broker paths with supplied policy replies."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import broker

class FixturePolicy:
    def __init__(self,*args):
        self.calls=[];self.stage='initial';self.journal=Path(args[1])
    def request(self,system,user,temperature=0):
        self.calls.append({'ok':True,'coupling':{'stage':self.stage},'actual_network_call':False})
        return 'Yes' if self.stage=='selector' else '[]'
    def close(self):pass

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    broker.PolicyClient=FixturePolicy
    records=[]
    with tempfile.TemporaryDirectory() as temp:
        for arm in ['nogate_unone','forced_unone_cnone']:
            b=broker.Broker()
            try:
                with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    init=b.init(dict(manifest=a.manifest,case_id='banking__user_task_0__clean',x1b_arm=arm,constructor_reasoning='none',model='gpt-6-luna',delegate_reference=True,clock_anchor='2026-11-05T00:00:00',judge_cache=temp,policy_cache=temp,policy_journal=str(Path(temp)/'policy.jsonl')))
                    name='get_balance';available={x['name'] for x in init['tools']}
                    if name not in available:name='get_iban'
                    assert name in available
                    result=b.invoke(dict(name=name,args={},call_id='fixture-read'))
                    finished=b.finish(dict(final_text='Fixture only.'))
                assert 'initial' in finished['raw'] and 'final' in finished['raw']
                assert finished['result']['x1b_arm']==arm
                assert 'native_utility' in finished['result']
                if arm.startswith('nogate'):assert not finished['result']['policy_calls']
                else:assert finished['result']['policy_calls'] and len(finished['result']['update_records'])==1
                records.append(dict(arm=arm,tool=name,native_error=result.get('is_error'),native_utility=finished['result']['native_utility'],policy_calls=len(finished['result']['policy_calls']),initial_state_sha256=init['initial_state_sha256']))
            finally:b.close()
    assert len({r['initial_state_sha256'] for r in records})==1
    a.out.write_text(json.dumps(dict(passed=True,model_calls=0,checks=['no-gate init/read/finish','forced-auto init/read/update/finish','native state and score retention','equal initial states'],records=records),indent=2)+'\n')
if __name__=='__main__':main()
