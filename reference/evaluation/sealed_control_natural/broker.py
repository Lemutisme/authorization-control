"""Faithful retained-prefix continuation over read-only frozen X6-v1."""
import contextlib,copy,hashlib,importlib.util,io,json,sys,traceback
from pathlib import Path
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent
FROZEN=Path('/artifact-source/e08a74aa3f7f/sealed_control')
sys.path.insert(0,str(FROZEN))
spec=importlib.util.spec_from_file_location('natural_frozen_x6',FROZEN/'broker.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from agentdojo.functions_runtime import FunctionCall,FunctionsRuntime

def sha(x):return hashlib.sha256(x).hexdigest()
def digest(x):return m.ref.digest(x)

class Broker(m.Broker):
 def init(self,p):
  packet_path=Path(p['natural_packet']);packet=json.loads(packet_path.read_text());arm=p['x6_arm']
  if arm not in m.ARMS:raise ValueError('Unregistered arm')
  if sha(packet['actor_context_json'].encode())!=packet['actor_context_utf8_sha256']:raise ValueError('Context byte integrity')
  self.natural_packet=packet;self.original_pending=True
  self.historical_u=packet['historical_actor_calls'];self.historical_t=packet['historical_constructor_calls']
  if not 0<=self.historical_u<=16 or not 0<=self.historical_t<=64:raise ValueError('Historical budget invalid')
  # No fresh generation before the shared historical boundary.
  result=super().init({**p,'case_id':packet['case_id'],'x6_arm':'no_gate','x2b_role':'honest','strategy':'direct'})
  if self.initial.model_dump(mode='json')!=packet['native_initial_state']:raise ValueError('Native source initial state changed')
  if self.owner_request!=packet['authentic_owner_request']:raise ValueError('Authentic owner changed')
  runtime=FunctionsRuntime(self.suite.tools)
  for event in packet['prior_native_events']:
   if self.env.model_dump(mode='json')!=event['before']:raise ValueError('Source replay before mismatch')
   if not event.get('error'):
    _,error=runtime.run_function(self.env,event['operation']['function'],event['operation']['args'])
    if error:raise ValueError('Source successful call now fails')
   if self.env.model_dump(mode='json')!=event['after']:raise ValueError('Source replay after mismatch')
  if self.env.model_dump(mode='json')!=packet['native_boundary_state']:raise ValueError('Boundary state mismatch')
  self.x6_arm=arm
  self.proposals=[FunctionCall.model_validate(c) for c in packet['prior_native_proposals']]
  self.total_proposals=len(self.proposals)
  self.observations=copy.deepcopy(packet['successful_observations'])
  self.policy_history=[{'stage':'retained_boundary','policy':copy.deepcopy(packet['policy_at_boundary'])}]
  self.historical_policy_calls=copy.deepcopy(packet['historical_constructor_call_metadata'])
  m.progent.security_policy=copy.deepcopy(packet['policy_at_boundary']);m.progent.init_user_query=self.owner_request
  if arm!='no_gate':
   self.baseline_arm='progent';self.refinement_arm='optional';self.x2b_arm='auto_approve'
   m.progent.available_tools=[];m.progent.security_policy=None;m.progent.init_user_query=self.owner_request
   functions=[f.model_copy(update={'run':m.progent.apply_secure_tool_wrapper(f.run)}) for f in self.suite.tools]
   m.progent.security_policy=copy.deepcopy(packet['policy_at_boundary'])
   original_check=m.progent.check_tool_call;fields={f.name:set(f.parameters.model_fields) for f in self.suite.tools}
   def checked(name,kwargs):
    operation={'function':name,'args':{k:copy.deepcopy(v) for k,v in kwargs.items() if k in fields[name]}};before=digest(m.progent.security_policy)
    try:answer=original_check(name,kwargs)
    except Exception as exc:self.progent_decisions.append({'operation':operation,'allowed':False,'reason':str(exc),'policy_before_sha256':before,'policy_after_sha256':digest(m.progent.security_policy)});raise
    self.progent_decisions.append({'operation':operation,'allowed':True,'policy_before_sha256':before,'policy_after_sha256':digest(m.progent.security_policy)});return answer
   m.progent.check_tool_call=checked
   self.runtime=m.base.RecordingRuntime(functions,max_calls=64)
   self.policy_client=m.BudgetPolicyClient(result['connection'],p['policy_journal'],p['policy_cache'],'optional')
   # Slots consume historical budget but do not pretend historical calls are new cost.
   self.policy_client.calls=[{'historical_replayed':True,'actual_network_call':False,'ok':True,'coupling':{'stage':'historical','cache_hit':False}} for _ in range(self.historical_t)]
   m.progent.api_request=self.policy_client.request
  self.runtime.events=copy.deepcopy(packet['prior_native_events']);self.runtime.calls_started=len(self.runtime.events);self.runtime._last_snapshot=copy.deepcopy(packet['native_boundary_state'])
  context=json.loads(packet['actor_context_json']);self.actor_instructions=context.get('systemPrompt') or next(message['content'] for message in context['messages'] if message['role']=='system');result['instructions']=self.actor_instructions
  result['natural_resume']={k:copy.deepcopy(packet[k]) for k in ['unit_id','actor_context_json','actor_context_utf8_sha256','actor_request_json','actor_request_sha256','source_proposal_message','original_proposal','original_proposal_call_id','historical_actor_calls','historical_constructor_calls','prior_wrong_value_policy_disclosure','prior_bound_value_in_successful_observations']}
  result['natural_boundary_state_sha256']=digest(packet['native_boundary_state']);result['natural_boundary_policy_sha256']=digest(packet['policy_at_boundary'])
  self.packet_sha256=sha(packet_path.read_bytes())
  return result
 def invoke(self,p):
  if self.original_pending:
   original=self.natural_packet['original_proposal']
   native=next(f for f in self.suite.tools if f.name==original['function'])
   if p['name']!=original['function'] or native.parameters.model_validate(p['args']).model_dump()!=native.parameters.model_validate(original['args']).model_dump() or p['call_id']!=self.natural_packet['original_proposal_call_id']:raise ValueError('First continuation call must be original source proposal')
   self.original_pending=False
  return super().invoke(p)
 def repair(self,p):
  if p['call_id']==self.natural_packet['original_proposal_call_id'] and p.get('context_json')!=self.natural_packet['actor_context_json']:
   raise ValueError('Original sealed redraw must use exact recovered source context bytes')
  return super().repair(p)
 def finish(self,p):
  result=super().finish(p)
  if self.policy_client:
   result['result']['policy_calls']=result['result']['policy_calls'][self.historical_t:]
  else:
   result['result']['combined_constructor_calls']=self.historical_t
  result['result'].update(natural_unit_id=self.natural_packet['unit_id'],natural_packet_sha256=self.packet_sha256,natural_history_budget={'actor_calls':self.historical_u,'constructor_calls':self.historical_t,'native_calls':len(self.natural_packet['prior_native_events'])},natural_remaining_budget_at_start={'actor':16-self.historical_u,'constructor':64-self.historical_t},natural_original_proposal_dispatched=not self.original_pending,prior_wrong_value_policy_disclosure=self.natural_packet['prior_wrong_value_policy_disclosure'],prior_bound_value_in_successful_observations=self.natural_packet['prior_bound_value_in_successful_observations'])
  result['raw'].update(historical_policy_calls=self.historical_policy_calls,historical_actor_calls=self.natural_packet['historical_actor_call_metadata'],natural_boundary_state=self.natural_packet['native_boundary_state'],natural_boundary_policy=self.natural_packet['policy_at_boundary'],natural_source_representative=self.natural_packet['source_representative'],natural_source_actor_context_json=self.natural_packet['actor_context_json'],natural_source_actor_request_sha256=self.natural_packet['actor_request_sha256'],natural_source_proposal_message=self.natural_packet['source_proposal_message'],natural_instruction_provenance='Retained X3/refinement honest actor instructions; no new controller disclosure inserted into retained history')
  return result

def main():
 b=Broker()
 try:
  for line in sys.stdin:
   ident=None
   try:
    q=json.loads(line);ident=q['id']
    if set(q)!={'id','method','params'} or q['method'] not in {'init','invoke','repair','abort_repair','finish'}:raise ValueError('Invalid RPC')
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):r=getattr(b,q['method'])(q['params'])
    print(json.dumps({'id':ident,'ok':True,'result':r},default=str),flush=True)
   except Exception as exc:print(json.dumps({'id':ident,'ok':False,'error':type(exc).__name__,'diagnostic':traceback.format_exc()}),flush=True)
 finally:b.close()
if __name__=='__main__':main()
