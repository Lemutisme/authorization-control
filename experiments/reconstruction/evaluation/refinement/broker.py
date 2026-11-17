"""Five controlled closed-loop arms; Progent interventions share its native path."""
import contextlib,copy,importlib.util,io,json,os,socket,sys,traceback
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(Path(__file__).parent),str(ROOT/'intent_guard'),str(ROOT/'pi'),str(ROOT)]
# All production model I/O occurs in dedicated Pi children. Native Python
# functions and schema references cannot contact external services.
def no_native_network(*x,**k):raise RuntimeError('Native evaluator network disabled')
socket.create_connection=no_native_network;socket.socket.connect=no_native_network
spec=importlib.util.spec_from_file_location('original_baseline',ROOT/'baseline_audit/broker.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from controllers import CoupledPolicyClient,update_policy,digest
from pi_transport import PiAuthorizationTransport
from coupled_authorizer import provider_scope
from catalog import PURE_READS
class PiTransport(PiAuthorizationTransport):
 def __init__(self,directory=None):
  super().__init__();self.scope=provider_scope(self.endpoint,self.key)
base.ref.CoupledAuthorizationTransport=PiTransport
class Broker(base.Broker):
 def init(self,p):
  self.refinement_arm=p['refinement_arm'];assert self.refinement_arm in {'none','pga_minimal','optional','forced','result_aware'};self.update_records=[]
  original_client=base.PolicyClient
  base.PolicyClient=lambda connection,journal:CoupledPolicyClient(connection,journal,p['policy_cache'],self.refinement_arm)
  try:
   init=super().init({**p,'baseline_arm':self.refinement_arm if self.refinement_arm in {'none','pga_minimal'} else 'progent'})
  finally:base.PolicyClient=original_client
  return init
 def invoke(self,p):
  if self.baseline_arm!='progent':return super().invoke(p)
  # Execute the same common broker path, then only replace update selection.
  result=base.ref.Broker.invoke(self,p);value,error=self.runtime.last_result
  params=[{'name':p['name'],'args':p['args']}];text=str([base.tool_result_to_str(value)])
  update=update_policy(base.progent,self.policy_client,self.refinement_arm,params,text,eligible=error is None and p['name'] in PURE_READS);self.update_records.append(update)
  self.policy_history.append({'stage':'after_tool','tool':p['name'],'had_native_error':error is not None,'policy':copy.deepcopy(base.progent.security_policy)})
  return result
 def finish(self,p):
  r=super().finish(p);r['result']['refinement_arm']=self.refinement_arm;r['result']['update_records']=self.update_records;return r

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
     with b.policy_client.journal.open('a') as f:f.write(json.dumps({'stage':'broker_error','error':type(e).__name__,'traceback':traceback.format_exc()})+'\n')
    print(json.dumps({'id':ident,'ok':False,'error':type(e).__name__}),flush=True)
 finally:b.close()
if __name__=='__main__':main()
