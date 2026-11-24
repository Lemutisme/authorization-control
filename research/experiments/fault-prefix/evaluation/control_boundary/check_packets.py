"""Re-execute qualified native boundary probes from publication packets only."""
import argparse,contextlib,copy,hashlib,io,json,os,socket,sys
from pathlib import Path
def deny_network(*a,**k):raise RuntimeError('Network disabled in packet verification')
socket.create_connection=deny_network;socket.socket.connect=deny_network
sys.path[:0]=[os.environ['BASELINE_VENDOR'],os.environ['PROGENT_SOURCE']]
from secagent import tool as progent
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime,FunctionCall
from agentdojo.types import text_content_block_from_string

def main():
 p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS'])/'packet-check.json';s=json.loads((a.bundle/'summary.json').read_text());suite=get_suite('v1.2.2','banking');Env=type(suite.load_and_inject_default_environment({}));rows=[]
 original=progent.check_tool_call
 for r in s['rows']:
  if r['coverage']!='qualified_single_candidate':continue
  p=a.bundle/r['packet_file'];assert hashlib.sha256(p.read_bytes()).hexdigest()==r['packet_sha256'];q=json.loads(p.read_text());initial=Env.model_validate(q['native_initial']);anchor=Env.model_validate(q['anchor_state']);candidate=FunctionCall.model_validate(q['candidate']);goal=suite.get_injection_task_by_id(r['injection_id']);decisions=[]
  def checked(name,kwargs):
   try:answer=original(name,kwargs)
   except Exception:decisions.append(False);raise
   decisions.append(True);return answer
  progent.available_tools=[];progent.security_policy=None;progent.init_user_query=q['owner_request'];progent.check_tool_call=checked
  with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
   wrapped=[f.model_copy(update={'run':progent.apply_secure_tool_wrapper(f.run)}) for f in suite.tools];progent.update_always_allowed_tools(['get_most_recent_transactions'],allow_all_no_arg_tools=True);progent.security_policy=copy.deepcopy(q['anchor_policy'])
   bare=anchor.model_copy(deep=True);guarded=anchor.model_copy(deep=True);_,be=FunctionsRuntime(suite.tools).run_function(bare,candidate.function,copy.deepcopy(candidate.args));_,ge=FunctionsRuntime(wrapped).run_function(guarded,candidate.function,copy.deepcopy(candidate.args))
  score=lambda env:bool(suite._check_injection_task_security(goal,[text_content_block_from_string('')],initial.model_copy(deep=True),env.model_copy(deep=True),[candidate]))
  findings=[]
  if bare.model_dump(mode='json')!=q['bare_after']:findings.append('bare_state')
  if guarded.model_dump(mode='json')!=q['guarded_after']:findings.append('guarded_state')
  if decisions!=[r['progent']['allowed']]:findings.append('admission')
  if be!=r['bare']['error'] or ge!=r['progent']['error']:findings.append('native_error')
  if score(bare)!=r['bare']['native_goal'] or score(guarded)!=r['progent']['native_goal']:findings.append('native_goal')
  rows.append({'case_id':r['case_id'],'findings':findings,'allowed':decisions[0],'native_goal':score(guarded)})
 out={'qualified':len(rows),'matching':sum(not r['findings'] for r in rows),'admitted':sum(r['allowed'] for r in rows),'native_goal':sum(r['native_goal'] for r in rows),'model_requests':0,'network_requests':0,'rows':rows,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'scope':'Re-execution by a separate routine from published state/policy/candidate packets using original native functions and checker; does not independently reconstruct original model request histories.'};a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items() if k!='rows'},indent=2));assert out['matching']==out['qualified']==s['qualified']
if __name__=='__main__':main()
