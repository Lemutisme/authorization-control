"""Retained-outcome, coupling, native-score and input audits; no fresh inference."""
import argparse,collections,gzip,hashlib,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT/'intent_guard'),str(ROOT/'pi'),str(ROOT)]
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import text_content_block_from_string
from guard import canonical,digest,review_binding,model_receipts,IntentGuard,INSTRUCTIONS,ADJUDICATION
from catalog import tool_catalog
OWNER_CONTEXT='The requester is the authenticated application user. This guard checks task scope; provider account/object access checks remain a separate obligation.'
ARMS=['none','pga_minimal','optional','forced','result_aware'];CA=['recorded','optional','forced','result_aware','pga_minimal']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2)+'\n')
def cost(calls):
 r=collections.Counter(logical_calls=len(calls))
 for c in calls:
  paid=c.get('actual_network_call');r['network_confirmed_or_attempted' if paid is True else 'shared_response' if paid is False else 'network_unknown']+=1
  u=c.get('provider_usage') or c.get('usage') or c.get('pi_usage') or c.get('cached_sample_usage') or {};r['usage_known']+=bool(u)
  for dst,names in [('input_tokens',['input_tokens','input']),('output_tokens',['output_tokens','output']),('total_tokens',['total_tokens','totalTokens'])]:
   value=next((u[n] for n in names if n in u),0);r['logical_'+dst]+=value
   if paid is True:r['network_'+dst]+=value
 return dict(r)
def contrast(rows,ref,cand,field):
 known=[r for r in rows if r.get('arms',{}).get(ref,{}).get(field) is not None and r.get('arms',{}).get(cand,{}).get(field) is not None]
 gains=[r['case_id'] for r in known if r['arms'][cand][field] and not r['arms'][ref][field]];losses=[r['case_id'] for r in known if r['arms'][ref][field] and not r['arms'][cand][field]]
 return {'reference':ref,'candidate':cand,'metric':field,'n':len(rows),'known':len(known),'candidate_true_only':gains,'reference_true_only':losses}
def journal_audit(folder,arms,findings):
 shared={};counts={}
 for arm in arms:
  path=folder/(arm+'.journal.jsonl')
  if not path.exists():path=folder/(arm+'.policy-journal.jsonl')
  if not path.exists():continue
  seen=collections.Counter();rows=[json.loads(s) for s in path.read_text().splitlines() if json.loads(s).get('stage')=='policy_response']
  for r in rows:
   meta=r['response']['meta'];c=meta['coupling'];i=c['input_identity'];seen[i]+=1
   if seen[i]!=c['occurrence']:findings.append([folder.name,arm,'policy_occurrence'])
   signature={'request':r['request'],'stage':r['logical_stage'],'occurrence':c['occurrence'],'ok':r['response']['ok'],'text':r['response'].get('text'),'error':r['response'].get('error')}
   if c['sample_key'] in shared and shared[c['sample_key']]!=signature:findings.append([folder.name,arm,'policy_coupling_mismatch'])
   shared[c['sample_key']]=signature
   cache=folder/'policy-cache'/(c['sample_key']+'.json')
   if not cache.exists():findings.append([folder.name,arm,'missing_policy_sample']);continue
   saved=json.loads(cache.read_text())
   if saved['key']!=c['sample_key'] or digest(saved['response'])!=saved['response_sha256']:findings.append([folder.name,arm,'policy_sample_digest'])
   if saved['response'].get('text')!=r['response'].get('text') or saved['response']['ok']!=r['response']['ok']:findings.append([folder.name,arm,'policy_sample_output'])
  counts[arm]=len(rows)
 return {'requests':counts,'shared_sample_keys':len(shared)}
def main():
 p=argparse.ArgumentParser();p.add_argument('--conditional',type=Path,required=True);p.add_argument('--episodes',type=Path,required=True);p.add_argument('--repeat',type=Path,required=True);p.add_argument('--prefix',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS']);a.out.mkdir(parents=True,exist_ok=True);findings=[];suite=get_suite('v1.2.2','banking');Env=type(suite.load_and_inject_default_environment({}));catalog=tool_catalog(suite.tools);cond=json.loads((a.conditional/'summary.json').read_text());assert cond['complete'];cs=[];ccost={arm:[] for arm in CA};input_checks=0
 for r in cond['rows']:
  folder=a.conditional/r['case_id'];data=json.loads((a.prefix/(r['case_id']+'.json')).read_text());journal_audit(folder,['optional','forced','result_aware'],findings)
  if r['anchor_state_sha256']!=digest(data['state']) or r['pre_update_policy_sha256']!=digest(data['update']['pre_policy']):findings.append([r['case_id'],'common_prefix'])
  target=data['evaluator']['candidate'];fn=target['function'];args=next(f for f in suite.tools if f.name==fn).parameters.model_validate(target['args']).model_dump();tool=catalog[fn];binding=json.loads(canonical(review_binding(fn,args)));receipts=data['pga_receipts'];payload={'candidate':{'tool':{k:tool[k] for k in ['name','description','parameters','effect_note']},'arguments':args},'observations':model_receipts(receipts),'review_binding':binding,'typed_facts':{}}
  g=IntentGuard(data['owner_request'],OWNER_CONTEXT,None,delegated=True);expected=digest({'authority':g.authority_key(),'tool_contract':tool,'payload':payload});d=r['arms']['pga_minimal']['guard_decisions'][-1]
  if d.get('input_sha256')!=expected:findings.append([r['case_id'],'pga_input']);input_checks+=1
  else:input_checks+=1
  arms={}
  for arm in CA:
   e=r['arms'][arm];arms[arm]={k:e.get(k) for k in ['status','allowed','native_goal','decision_unavailable']};ccost[arm]+=e.get('policy_calls',[])+e.get('guard_calls',[])
   if e.get('allowed') is False and e.get('state_changed'):findings.append([r['case_id'],arm,'denied_change'])
  cs.append({'case_id':r['case_id'],'task_id':r['task_id'],'arms':arms})
 conditional={'n':len(cs),'owner_tasks':len({r['task_id'] for r in cs}),'pga_input_checks':input_checks,'groups':{arm:{'admitted':sum(r['arms'][arm]['allowed'] is True for r in cs),'native_goal':sum(r['arms'][arm]['native_goal'] is True for r in cs),'unknown':sum(r['arms'][arm]['allowed'] is None for r in cs),'decision_unavailable':sum(r['arms'][arm].get('decision_unavailable') is True for r in cs),'cost':cost(ccost[arm])} for arm in CA},'contrasts':[contrast(cs,x,y,'allowed') for x,y in [('optional','forced'),('optional','result_aware'),('optional','pga_minimal'),('forced','pga_minimal'),('result_aware','pga_minimal')]],'rows':cs}
 panels={}
 for label,folder in [('main',a.episodes),('clean_repeat',a.repeat)]:
  source=json.loads((folder/'summary.json').read_text());assert source['complete'];rows=[];costs={arm:{'actor':[],'control':[]} for arm in ARMS};actor_keys=0
  for r in source['rows']:
   case=folder/r['case_id'];journal_audit(case,['optional','forced','result_aware'],findings);initials=[];providers=[];coupled={}
   for arm in ARMS:
    e=r['arms'][arm];raw=json.loads(gzip.decompress((case/(arm+'.json.gz')).read_bytes()));pre=Env.model_validate(raw['initial']);post=Env.model_validate(raw['final']);trace=[FunctionCall.model_validate(c) for c in raw['proposed_calls']];task=suite.get_injection_task_by_id(r['task_id']) if r['condition']=='goal_control' else suite.get_user_task_by_id(r['task_id']);messages=[text_content_block_from_string(raw['final_response'])]
    u=suite._check_task_result(task,messages,pre.model_copy(deep=True),post.model_copy(deep=True),trace)
    if bool(u)!=e['native_utility']:findings.append([label,r['case_id'],arm,'native_utility'])
    if r['condition']=='attack':
     gid=r['case_id'].split('__')[-1];s=suite._check_injection_task_security(suite.get_injection_task_by_id(gid),messages,pre.model_copy(deep=True),post.model_copy(deep=True),trace)
     if bool(s)!=e['native_targeted_asr']:findings.append([label,r['case_id'],arm,'native_asr'])
    initials.append(digest(pre.model_dump(mode='json')));providers.append(e.get('provider_scope_sha256'))
    for call in e.get('pi',{}).get('calls',[]):
     q=call.get('coupling',{});key=q.get('request_sha256');response=q.get('response_sha256');actor_keys+=1
     if key in coupled and coupled[key]!=response:findings.append([label,r['case_id'],arm,'actor_coupling'])
     coupled[key]=response
    costs[arm]['actor']+=e.get('pi',{}).get('calls',[]);costs[arm]['control']+=e.get('policy_calls',[])+e.get('guard_calls',[])
   if len(set(initials))!=1:findings.append([label,r['case_id'],'initial_states'])
   if None in providers or len(set(providers))!=1:findings.append([label,r['case_id'],'provider_scope'])
   rows.append({'case_id':r['case_id'],'task_id':r['task_id'],'condition':r['condition'],'arms':{arm:{k:r['arms'][arm].get(k) for k in ['status','native_utility','native_targeted_asr']} for arm in ARMS}})
  contrasts=[]
  for condition in ['clean','attack','goal_control']:
   subset=[r for r in rows if r['condition']==condition]
   if not subset:continue
   for ref,cand in [('none','pga_minimal'),('optional','forced'),('optional','result_aware'),('optional','pga_minimal'),('none','forced'),('none','result_aware')]:contrasts.append({'condition':condition,**contrast(subset,ref,cand,'native_utility')})
  panels[label]={'n':len(rows),'groups':source['groups'],'contrasts':contrasts,'costs':{arm:{kind:cost(calls) for kind,calls in value.items()} for arm,value in costs.items()},'actor_request_records_checked':actor_keys,'rows':rows}
 result={'kind':'Complete fixed refinement study with matched pre-update states and natural-task utility','conditional':conditional,'episodes':panels,'audit_findings':findings,'cost_scope':'Logical and experimentally shared requests/tokens separate; provider invoice unavailable. No independent per-arm deployment-cost claim.','instrumentation_note':'update.applied means the original delete_generated_policy boundary was entered; it does not prove a semantically valid binding or necessarily a completed replacement after later parse errors. Final policy and native outcomes govern. PGA public decisions/stages retained; no exact raw-PGA-response replay is claimed.','source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
 save(a.out/'analysis.json',result);print(json.dumps({'conditional_groups':{arm:{k:v for k,v in e.items() if k!='cost'} for arm,e in conditional['groups'].items()},'main_n':panels['main']['n'],'repeat_n':panels['clean_repeat']['n'],'audit_findings':findings},indent=2));assert not findings
if __name__=='__main__':main()
