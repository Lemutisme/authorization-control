"""Restore original Python policy types through original retained-response updater replay."""
import copy,hashlib,importlib.util,json,os,sys
from pathlib import Path
os.environ.setdefault('BASELINE_VENDOR','/artifact-source/3d9fa19e91e5/vendor')
os.environ.setdefault('PROGENT_SOURCE','/artifact-source/c4751a2fc0fe/progent')
spec=importlib.util.spec_from_file_location('x3_retained_util',Path(__file__).with_name('x3_policy_replay_audit.py'));util=importlib.util.module_from_spec(spec);spec.loader.exec_module(util)
progent=util.progent

def restore(raw,journal,frozen,first):
 responses=[j for j in (json.loads(s) for s in journal.read_text().splitlines() if s.strip()) if j.get('stage')=='policy_response']
 for j in responses:assert j['request_sha256']==hashlib.sha256(json.dumps(j['request'],sort_keys=True).encode()).hexdigest()
 spec=importlib.util.spec_from_file_location('x2b_frozen_original_controller',frozen/'evaluation/refinement/controllers.py');controller=importlib.util.module_from_spec(spec);spec.loader.exec_module(controller)
 suite=util.get_suite('v1.2.2','banking');progent.available_tools=[];progent.security_policy=None;progent.init_user_query=None
 for f in suite.tools:progent.apply_secure_tool_wrapper(f.run)
 progent.update_always_allowed_tools(['get_most_recent_transactions'],allow_all_no_arg_tools=True)
 client=util.RetainedClient(responses);progent.api_request=client.request
 node=util.NodeNormalizer();changes=[];restored=copy.deepcopy(raw);checks=[];evidence=[]
 def verify(actual,stored,loc,h=None):
  if h is not None:assert util.digest(actual)==h,loc+': exact Python hash'
  assert util.digest(node.normalize(actual))==util.digest(stored),loc+': actual Node normalized policy'
  diff=util.numeric_changes(actual,stored)
  if diff:changes.append({'location':loc,'changes':diff,'python_sha256':util.digest(actual),'stored_sha256':util.digest(stored)})
 try:
  os.environ['SECAGENT_ONLY_ALLOW_NARROW']=str(raw['result']['x2b_arm']=='narrow_only')
  progent.generate_security_policy(raw['prompt']);assert not client.errors,client.errors
  verify(progent.security_policy,raw['policy_history'][0]['policy'],'initial');restored['policy_history'][0]['policy']=copy.deepcopy(progent.security_policy)
  for index,saved in enumerate(raw['result']['update_records'][:first]):
   before=copy.deepcopy(progent.security_policy);verify(before,saved['policy_before'],f'{index}.before',saved['before_sha256']);assert len(client.calls)==saved['calls_before']
   # Exact retained regeneration context supplies the original formatted result;
   # selectors do not use result text, so an unused placeholder suffices if none exists.
   relevant=responses[saved['calls_before']:saved['calls_after']]
   texts=[j['request']['user'].split('\nTOOL_CALL_RESULT: ',1)[1].rsplit('\nCURRENT_RESTRICTIONS: ',1)[0] for j in relevant if j['logical_stage']=='regeneration']
   assert not texts or all(t==texts[0] for t in texts)
   result_text=texts[0] if texts else '<unused: no recorded regeneration request>'
   proposal=raw['proposed_calls'][index];params=[{'name':proposal['function'],'args':copy.deepcopy(proposal['args'])}]
   original=progent.security_policy_subset_check;actual_checks=[]
   def subset(old,new):
    row={'before_sha256':util.digest(old),'candidate_sha256':util.digest(new),'before':copy.deepcopy(old),'candidate':copy.deepcopy(new)};actual_checks.append(row)
    try:answer=original(old,new);row['result']=bool(answer);return answer
    except Exception as e:row['error']=type(e).__name__;raise
   progent.security_policy_subset_check=subset
   try:replayed=controller.update_policy(progent,client,'optional',params,result_text,eligible=saved['eligible_boundary'])
   finally:progent.security_policy_subset_check=original
   assert not client.errors,client.errors
   for key in ['before_sha256','after_sha256','selected','calls_before','calls_after','applications','status','policy_changed','applied','failed_responses','regeneration_requests']:
    assert replayed.get(key)==saved.get(key),(index,key,replayed.get(key),saved.get(key))
   verify(progent.security_policy,saved['policy_after'],f'{index}.after',saved['after_sha256']);verify(progent.security_policy,raw['policy_history'][index+1]['policy'],f'history{index+1}')
   restored['result']['update_records'][index]=replayed;restored['policy_history'][index+1]['policy']=copy.deepcopy(progent.security_policy)
   checks.append({'update_index':index,'replayed_actual_subset_checks':actual_checks});evidence.append({'update_index':index,'exact_request_response_sequence_verified':True,'formatted_result_source':'retained regeneration request' if texts else 'unused by selector-only/no-call update'})
  active=raw['result']['update_records'][first];verify(progent.security_policy,active['policy_before'],'first_effect.active',active['before_sha256']);restored['result']['update_records'][first]['policy_before']=copy.deepcopy(progent.security_policy)
  return restored,{'restoration':'Original initial constructor and optional updater replay; no numeric guessing/hash-driven repair','serialization_changes':changes,'updates':evidence,'actual_subset_checks':checks,'responses_consumed_before_first_effect':len(client.calls),'remaining_after_first_effect_not_replayed':len(responses)-len(client.calls),'all_replayed_requests_exact':not client.errors,'source_sha256':{str(Path(util.__file__)):util.sha(util.__file__),str(frozen/'evaluation/refinement/controllers.py'):util.sha(frozen/'evaluation/refinement/controllers.py')}}
 finally:node.close();progent.api_request=util.forbidden
