"""Model-free checks for the precise update interventions and coupling contract."""
import argparse,contextlib,copy,hashlib,io,json,os,socket,sys,tempfile,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[os.environ['BASELINE_VENDOR'],os.environ['PROGENT_SOURCE'],str(ROOT/'intent_guard'),str(ROOT/'pi'),str(ROOT),str(Path(__file__).parent)]
os.environ.update(SECAGENT_POLICY_MODEL='gpt-6-luna',SECAGENT_GENERATE='True',SECAGENT_UPDATE='True',SECAGENT_IGNORE_UPDATE_ERROR='True',SECAGENT_ONLY_ALLOW_NARROW='False')
def deny(*x,**k):raise RuntimeError('Qualification network disabled')
socket.create_connection=deny;socket.socket.connect=deny
from secagent import tool as p
from controllers import CoupledPolicyClient,update_policy,digest
from collections import Counter

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path);a=ap.parse_args();out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True);checks=[]
 params=[{'name':'get_most_recent_transactions','args':{'n':100}}];observed='[{"recipient":"fixture-recipient","amount":10}]';initial={'send_money':[(100,0,{'recipient':{'type':'string'},'amount':{'type':'number'}},0)]};regenerated='[{"name":"send_money","args":{"recipient":{"enum":["fixture-recipient"]},"amount":{"enum":[10]}}}]'
 class Stub:
  def __init__(self,selector):self.selector=selector;self.calls=[];self.stage='initial';self.requests=[]
  def request(self,system,user,temperature=0):
   self.requests.append({'system':system,'user':user,'temperature':temperature,'stage':self.stage});self.calls.append({'ok':True,'coupling':{'stage':self.stage}});return self.selector if self.stage=='selector' else regenerated
 def run(variant,selector,eligible=True):
  p.available_tools=[{'name':'send_money','description':'fixture effect','args':{'recipient':{'type':'string'},'amount':{'type':'number'}}}];p.init_user_query='Send10 to the fixture recipient.';p.security_policy=copy.deepcopy(initial);c=Stub(selector);p.api_request=c.request
  with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):r=update_policy(p,c,variant,params,observed,eligible)
  return r,c,copy.deepcopy(p.security_policy)
 ro,co,po=run('optional','Yes');rf,cf,pf=run('forced','No');ra,ca,pa=run('result_aware','Yes')
 assert po==pf==pa;gens=lambda c:[q for q in c.requests if q['stage']=='regeneration'];assert gens(co)==gens(cf)==gens(ca);checks.append('equal_regeneration_inputs_and_outcomes_when_optional_yes')
 assert len(co.calls)==2 and len(cf.calls)==1 and len(ca.calls)==2;checks.append('forced_bypasses_selector_only')
 rn,cn,pn=run('optional','No');assert pn==initial and not rn['applied'] and rf['applied'];checks.append('optional_no_preserves_policy_forced_applies_generation')
 assert ca.requests[0]['system']==co.requests[0]['system'];assert ca.requests[0]['user'].startswith(co.requests[0]['user']);assert observed not in co.requests[0]['user'] and observed in ca.requests[0]['user'];checks.append('result_aware_changes_only_declared_selector_information')
 ri,ci,pi=run('forced','No',False);assert pi==initial and ci.requests[0]['stage']=='selector';checks.append('ineligible_boundary_retains_original_selector')
 class MemoryClient(CoupledPolicyClient):
  def __init__(self,directory,arm):self.directory=directory;self.journal=directory/(arm+'.journal');self.arm=arm;self.calls=[];self.occurrences=Counter();self.scope='fixture';self.stage='regeneration';self.draws=0
  def rpc(self,q):self.draws+=1;return {'ok':True,'text':'[]','meta':{'actual_network_call':True,'usage':{'input_tokens':1,'output_tokens':1}}}
 with tempfile.TemporaryDirectory() as tmp:
  d=Path(tmp);c1=MemoryClient(d,'a');c2=MemoryClient(d,'b');c1.request('system','user');c2.request('system','user');c1.request('system','user');c2.request('system','user');assert c1.draws==2 and c2.draws==0;assert [r['coupling']['occurrence'] for r in c1.calls]==[1,2];assert all(r['actual_network_call'] is False and 'cached_sample_usage' in r for r in c2.calls);checks.append('cross_arm_occurrence_coupling_without_within_arm_reuse')
 wire=subprocess.run(['node',str(Path(__file__).with_name('check_wire.mjs'))],capture_output=True,text=True,check=True);w=json.loads(wire.stdout);assert w['passed'] and w['network_requests']==0 and w['model_requests']==0;checks.append('pi_http_serialization_roles_and_sse_response')
 result={'passed':len(checks),'checks':checks,'wire':w,'model_requests':0,'network_requests':0,'scope':'Original library update branches with deterministic boundary stubs; no efficacy or oracle correctness claim.','source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()};(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
if __name__=='__main__':main()
