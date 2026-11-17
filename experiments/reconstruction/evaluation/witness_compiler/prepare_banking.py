"""Collect fixed native read observations; reference projections are evaluator-only."""
import argparse,json,hashlib,inspect
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();suite=get_suite('v1.2.2','banking');rows=[]
    for i in [4,6,11]:
        task=suite.get_user_task_by_id(f'user_task_{i}');env=task.init_environment(suite.load_and_inject_default_environment({}));before=env.model_dump(mode='json');runtime=FunctionsRuntime(suite.tools)
        observations={}
        for name,args in [('get_most_recent_transactions',{'n':100}),('get_scheduled_transactions',{})]:
            value,error=runtime.run_function(env,name,args);assert error is None
            observations[name]=json.loads(json.dumps(value,default=lambda x:x.model_dump(mode='json')))
        assert before==env.model_dump(mode='json'),'Read preparation changed native state'
        expected=[]
        # This is a separate oracle output. The constructor receives none of
        # these reference actions, selected IDs or labels.
        for call in task.ground_truth(env):
            if call.function=='send_money':fields=['recipient','amount']
            elif call.function=='schedule_transaction':fields=['recipient','amount','recurring']
            else:continue
            expected.append({'function':call.function,'arguments':{k:call.args[k] for k in fields}})
        assert expected
        reference_projection=expected
        oracle_note='Reference projection agrees with the scoped owner/source endpoint.'
        if i==11:
            # The native reference says recipient="Apple", although the tool
            # expects an IBAN, and native utility checks amount only. Derive the
            # scoped recipient/amount endpoint from the visible owner request
            # and its unique iPhone payment observation, before model outcomes.
            from decimal import Decimal
            import re
            candidates=[t for t in observations['get_most_recent_transactions'] if t['sender']=='me' and 'iphone' in t['subject'].lower()]
            assert len(candidates)==1
            percent,fee=re.search(r'additional (\d+(?:\.\d+)?)%.*fee of (\d+(?:\.\d+)?)',task.PROMPT).groups()
            amount=(Decimal(str(candidates[0]['amount']))*Decimal(percent)/100+Decimal(fee)).quantize(Decimal('.01'))
            expected=[{'function':'send_money','arguments':{'recipient':candidates[0]['recipient'],'amount':float(amount)}}]
            oracle_note='Owner/source endpoint resolves Apple via the unique iPhone payment. Native reference uses the merchant name, and native utility omits recipient checking; those native artifacts remain unchanged.'
        rows.append({'case_id':f'dojo_banking_{i}','owner':task.PROMPT,'tables':{'transactions':observations['get_most_recent_transactions'],'scheduled':observations['get_scheduled_transactions']},'expected_effects':expected,'reference_projection':reference_projection,'source':{'native_pin':'089ed468cf3ed0322acc66b0211f26d9d90dbf60','task_source_sha256':sha(Path(inspect.getfile(type(task)))),'shared_read_calls':['get_most_recent_transactions(n=100)','get_scheduled_transactions()'],'native_read_state_unchanged':True,'oracle_note':oracle_note}})
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps({'cases':rows},indent=2)+'\n');print('Prepared',len(rows),'banking source views; oracle action projections remain separate.')
if __name__=='__main__':main()
