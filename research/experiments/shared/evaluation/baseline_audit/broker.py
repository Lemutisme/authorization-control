"""Banking-only feasibility adapter for the original Progent function path."""
import contextlib,copy,hashlib,importlib.util,io,json,os,subprocess,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[os.environ['BASELINE_VENDOR'],os.environ['PROGENT_SOURCE'],str(ROOT/'intent_guard'),str(ROOT/'contract_study'),str(ROOT/'pi'),str(ROOT)]
os.environ.update(SECAGENT_POLICY_MODEL='gpt-6-luna',SECAGENT_GENERATE='True',SECAGENT_UPDATE='True',SECAGENT_IGNORE_UPDATE_ERROR='True',SECAGENT_ONLY_ALLOW_NARROW='False')
from secagent import tool as progent
spec=importlib.util.spec_from_file_location('study_reference',ROOT/'contract_study/broker.py');ref=importlib.util.module_from_spec(spec);spec.loader.exec_module(ref)
from pga_runtime import AuditedRuntime
from guard import digest
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

class PolicyClient:
 def __init__(self,connection,journal):
  self.journal=Path(journal);self.journal.parent.mkdir(parents=True,exist_ok=True)
  self.child=subprocess.Popen(['node',str(Path(__file__).with_name('policy_client.mjs'))],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True);self.calls=[];self.send({'method':'init','connection':connection})
 def send(self,x):
  self.child.stdin.write(json.dumps(x)+'\n');self.child.stdin.flush();line=self.child.stdout.readline()
  if not line:raise RuntimeError('Policy worker exited')
  try:r=json.loads(line)
  except Exception:
   with self.journal.open('a') as f:f.write(json.dumps({'stage':'worker_protocol_error','response_line':line})+'\n')
   raise
  if x.get('method')!='init':
   with self.journal.open('a') as f:f.write(json.dumps({'stage':'policy_response','request_sha256':hashlib.sha256(json.dumps({k:x[k] for k in ['system','user','temperature']},sort_keys=True).encode()).hexdigest(),'response':r})+'\n')
  return r
 def request(self,system,user,temperature=0):
  if len(self.calls)>=64:raise RuntimeError('Policy request cap reached')
  r=self.send({'method':'complete','system':system,'user':user,'temperature':temperature});self.calls.append(r['meta'])
  if not r['ok']:raise RuntimeError(r['error'])
  return r['text']
 def close(self):
  self.child.stdin.close()
  try:self.child.wait(timeout=5)
  except subprocess.TimeoutExpired:self.child.terminate();self.child.wait(timeout=5)

class RecordingRuntime(AuditedRuntime):
 def run_function(self,env,function,args,raise_on_error=False):
  value,error=super().run_function(env,function,args,raise_on_error=raise_on_error);self.last_result=(value,error);return value,error

class Broker(ref.Broker):
 def init(self,p):
  self.baseline_arm=p['baseline_arm'];assert self.baseline_arm in {'none','pga_minimal','progent'};self.policy_client=None;self.policy_history=[];self.progent_decisions=[]
  init=super().init({**p,'study_arm':'no_facts_no_feedback' if self.baseline_arm=='pga_minimal' else 'none'})
  assert self.case['suite']=='banking','Only the audited banking wrapper/allowlist is adapted'
  if self.baseline_arm!='progent':return init
  progent.available_tools=[];progent.security_policy=None;progent.init_user_query=None
  functions=[]
  for f in self.suite.tools:functions.append(f.model_copy(update={'run':progent.apply_secure_tool_wrapper(f.run)}))
  # Exact registration rule from upstream banking/task_suite.py:45.
  progent.update_always_allowed_tools(['get_most_recent_transactions'],allow_all_no_arg_tools=True)
  original_check=progent.check_tool_call;fields={f.name:set(f.parameters.model_fields) for f in self.suite.tools}
  def checked(name,kwargs):
   operation={'function':name,'args':{k:copy.deepcopy(v) for k,v in kwargs.items() if k in fields[name]}};before=digest(progent.security_policy)
   try:answer=original_check(name,kwargs)
   except Exception as e:self.progent_decisions.append({'operation':operation,'allowed':False,'reason':str(e),'policy_before_sha256':before,'policy_after_sha256':digest(progent.security_policy)});raise
   self.progent_decisions.append({'operation':operation,'allowed':True,'policy_before_sha256':before,'policy_after_sha256':digest(progent.security_policy)});return answer
  progent.check_tool_call=checked
  self.runtime=RecordingRuntime(functions,max_calls=64);self.policy_client=PolicyClient(init['connection'],p['policy_journal']);progent.api_request=self.policy_client.request
  progent.generate_security_policy(self.prompt);self.policy_history.append({'stage':'initial','policy':copy.deepcopy(progent.security_policy)})
  return init
 def invoke(self,p):
  result=super().invoke(p)
  if self.baseline_arm=='progent':
   value,error=self.runtime.last_result
   # Original ToolsExecutor passes formatted value, not its error string.
   progent.generate_update_security_policy([{'name':p['name'],'args':p['args']}],str([tool_result_to_str(value)]),manual_check=False)
   self.policy_history.append({'stage':'after_tool','tool':p['name'],'had_native_error':error is not None,'policy':copy.deepcopy(progent.security_policy)})
  return result
 def finish(self,p):
  r=super().finish(p);r['result'].update(baseline_arm=self.baseline_arm,policy_calls=self.policy_client.calls if self.policy_client else [],progent_decisions=self.progent_decisions)
  r['raw']['policy_history']=self.policy_history;return r
 def close(self):
  if self.policy_client:self.policy_client.close()

def main():
 b=Broker()
 try:
  for line in sys.stdin:
   ident=None
   try:
    q=json.loads(line);ident=q['id'];assert set(q)=={'id','method','params'} and q['method'] in {'init','invoke','finish'}
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):r=getattr(b,q['method'])(q['params'])
    print(json.dumps({'id':ident,'ok':True,'result':r},default=str),flush=True)
   except Exception as e:
    if getattr(b,'policy_client',None):
     with b.policy_client.journal.open('a') as f:f.write(json.dumps({'stage':'broker_error','error':type(e).__name__,'traceback':traceback.format_exc(),'recorded_policy_calls':len(b.policy_client.calls)})+'\n')
    print(json.dumps({'id':ident,'ok':False,'error':type(e).__name__}),flush=True)
 finally:b.close()
if __name__=='__main__':main()
