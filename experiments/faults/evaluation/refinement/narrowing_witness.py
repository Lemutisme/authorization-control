"""Post-hoc native causal localization of a correct actor action rejected by a wrong bound."""
import argparse,contextlib,copy,gzip,hashlib,io,json,os,re,socket,sys
from decimal import Decimal
from pathlib import Path
sys.path[:0]=[os.environ['BASELINE_VENDOR'],os.environ['PROGENT_SOURCE']]
def blocked(*a,**k):raise RuntimeError('Network disabled in narrowing localization')
socket.create_connection=blocked;socket.socket.connect=blocked
from secagent import tool as progent
from secagent.policy_analysis import security_policy_subset_check
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime,FunctionCall
from agentdojo.types import text_content_block_from_string

def main():
 p=argparse.ArgumentParser();p.add_argument('--case-dir',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS']);a.out.mkdir(parents=True,exist_ok=True)
 paths={arm:a.case_dir/(arm+'.json.gz') for arm in ['none','pga_minimal','optional','forced','result_aware']};raw={arm:json.loads(gzip.decompress(p.read_bytes())) for arm,p in paths.items()};bad=raw['forced'];owner=bad['prompt'];request=next(p for p in bad['proposed_calls'] if p['function']=='send_money');event=next(e for e in bad['events'] if e['operation']['function']=='send_money');initial=bad['policy_history'][0]['policy'];wrong=bad['policy_history'][1]['policy'];suite=get_suite('v1.2.2','banking');Env=type(suite.load_and_inject_default_environment({}));before=Env.model_validate(event['before']);initial_env=Env.model_validate(bad['initial'])
 rate,fee=re.search(r'additional (\d+(?:\.\d+)?)%.*fee of (\d+(?:\.\d+)?)',owner).groups();tx=[t for t in before.bank_account.transactions if t.sender=='me' and 'iphone' in t.subject.lower()];assert len(tx)==1;amount=float((Decimal(str(tx[0].amount))*Decimal(rate)/100+Decimal(fee)).quantize(Decimal('.01')));assert request['args']['amount']==amount and request['args']['recipient']==tx[0].recipient
 pairs=[[(c['coupling']['request_sha256'],c['coupling']['response_sha256']) for c in x['result']['pi']['calls'][:2]] for x in raw.values()];assert len({json.dumps(x) for x in pairs})==1
 corrected=copy.deepcopy(wrong);assert len(corrected['send_money'])==1;old_bound=corrected['send_money'][0][2]['amount'];assert old_bound['minimum']==old_bound['maximum'];old_amount=old_bound['minimum'];corrected['send_money'][0][2]['amount']={'type':'number','minimum':amount,'maximum':amount}
 with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
  # The original API asks whether the second policy is a subset of the first.
  narrowing=security_policy_subset_check(initial,wrong)
 results={}
 for name,policy in [('wrong_recorded_bound',wrong),('oracle_arithmetic_correction',corrected)]:
  progent.available_tools=[];progent.security_policy=None;progent.init_user_query=owner
  with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
   wrapped=[f.model_copy(update={'run':progent.apply_secure_tool_wrapper(f.run)}) for f in suite.tools];progent.update_always_allowed_tools(['get_most_recent_transactions'],allow_all_no_arg_tools=True);progent.security_policy=copy.deepcopy(policy);env=before.model_copy(deep=True);_,err=FunctionsRuntime(wrapped).run_function(env,request['function'],copy.deepcopy(request['args']))
  utility=suite._check_task_result(suite.get_user_task_by_id('user_task_11'),[text_content_block_from_string('')],initial_env.model_copy(deep=True),env.model_copy(deep=True),[FunctionCall.model_validate(request)])
  results[name]={'error':err,'native_utility':bool(utility),'state_changed':env.model_dump(mode='json')!=before.model_dump(mode='json'),'after':env.model_dump(mode='json')}
 assert results['wrong_recorded_bound']['error'] and not results['wrong_recorded_bound']['state_changed'];assert results['oracle_arithmetic_correction']['error'] is None and results['oracle_arithmetic_correction']['native_utility']
 result={'case_id':'banking__user_task_11__clean','kind':'Post-hoc diagnostic repair, not an automatic defense or new actor rollout','owner_request':owner,'source_payment_amount':tx[0].amount,'owner_rate':float(rate),'owner_fee':float(fee),'correct_amount':amount,'recorded_wrong_bound':old_amount,'same_first_two_actor_requests_and_responses':True,'smt_reports_wrong_policy_is_narrowing':bool(narrowing),'original_utilities':{a:x['result']['native_utility'] for a,x in raw.items()},'recorded_actor_calls':{a:x['proposed_calls'] for a,x in raw.items()},'initial_policy':initial,'wrong_policy':wrong,'corrected_policy':corrected,'native_checks':results,'raw_sha256':{a:hashlib.sha256(p.read_bytes()).hexdigest() for a,p in paths.items()},'model_requests':0,'network_requests':0,'limit':'The arithmetic correction uses a manually selected correct relation as an evaluator-side diagnostic. No oracle is provided to the measured controllers. No general statement that monotonic confinement is violated: this particular narrowing is relative to the initial policy, not proof of task fidelity.'};(a.out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['recorded_actor_calls','initial_policy','wrong_policy','corrected_policy','native_checks','raw_sha256']},indent=2))
if __name__=='__main__':main()
