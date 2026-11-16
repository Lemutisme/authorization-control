"""Freeze feasible X1 faults from pretreatment prefixes; no model or network I/O."""
import argparse,copy,gzip,hashlib,json,os
from pathlib import Path
from agentdojo.functions_runtime import FunctionsRuntime
from cohort import canonical,digest,save,normalization,near,gross,instantiate,install,effective_args

FEEDBACK=['F0','F1','F2','F3','F4']
ALIASES={'recipient':{'recipient','sender','email','user','name'},'recipients':{'recipient','sender','email','participants'},'participants':{'email','participants','recipient','sender','account_email'},'email':{'email','sender','recipient'},'user':{'user','users','name','sender','recipient'},'channel':{'channel','channels'},'file_id':{'id','file_id'},'event_id':{'id','event_id'},'id':{'id'},'amount':{'amount'},'hotel':{'name','hotel','hotel_name'},'location':{'location','address'},'title':{'title','name'},'subject':{'subject'},'body':{'body','content'},'street':{'street','address'},'filename':{'filename'},'permission':{'permission'},'start_time':{'start_time','end_time'},'end_time':{'start_time','end_time'},'new_start_time':{'start_time','end_time'},'new_end_time':{'start_time','end_time'},'start_day':{'start_day','end_day'},'end_day':{'start_day','end_day'}}
def scalar_fields(x,key=None):
 if isinstance(x,dict):
  for k,v in x.items():yield from scalar_fields(v,k)
 elif isinstance(x,list):
  for v in x:yield from scalar_fields(v,key)
 elif x is not None:yield key,x

def sibling_values(unit,anchor):
 arg=unit['argument'];correct=unit['correct_value'];seen=[]
 for obs in anchor['observations']:
  if not obs['is_error']:
   for k,v in scalar_fields(obs.get('value')):
    if k in ALIASES.get(arg,{arg}):seen.append(v)
 # Native channel/user enumeration may return a bare array: these are still
 # observed values, but only admitted for the matching identity type.
 for obs in anchor['observations']:
  if obs['function'] in {'get_channels','get_users_in_channel'} and arg in {'channel','user','recipient'}:
   seen.extend(v for _,v in scalar_fields(obs.get('value')) if isinstance(v,str))
 values=[]
 for v in seen:
  if isinstance(correct,list):
   if arg=='attachments':
    if isinstance(v,(str,int)) and str(v).isdigit():v=[{'type':'file','file_id':str(v)}]
    else:continue
   elif isinstance(v,str) and '@' in v:v=[v]+correct[1:]
   else:continue
  elif isinstance(correct,bool):continue
  elif isinstance(correct,(int,float)):
   if not isinstance(v,(int,float)) or isinstance(v,bool):continue
  elif not isinstance(v,str):continue
  if arg.endswith('_time') or arg.endswith('_day'):v=normalization(arg,v,unit.get('calendar_owner'))
  if normalization(arg,v,unit.get('calendar_owner'))!=normalization(arg,correct,unit.get('calendar_owner')):values.append(v)
 return [json.loads(k) for k in sorted(set(canonical(v) for v in values))]

def native_fault_check(unit,anchor,value):
 suite,task,initial=instantiate(unit['suite'],unit['task_id']);Env=type(initial);before=Env.model_validate(anchor['before']);args=copy.deepcopy(anchor['args']);args.update(unit['correct_projection']);args[unit['argument']]=value
 try:
  fn=next(f for f in suite.tools if f.name==unit['function']);validated=fn.parameters.model_validate(args).model_dump();after=before.model_copy(deep=True);_,error=FunctionsRuntime(suite.tools).run_function(after,unit['function'],validated)
 except Exception as exc:return {'feasible':False,'reason':'schema_or_native_exception','error':type(exc).__name__}
 same=normalization(unit['argument'],value,unit.get('calendar_owner'))==normalization(unit['argument'],unit['correct_value'],unit.get('calendar_owner'))
 return {'feasible':error is None and before.model_dump(mode='json')!=after.model_dump(mode='json') and not same,'reason':'equivalent_to_correct' if same else 'native_error' if error else 'no_state_change' if before.model_dump(mode='json')==after.model_dump(mode='json') else 'native_effect','error':error,'call':{'function':unit['function'],'args':validated},'before_sha256':digest(before.model_dump(mode='json')),'after_sha256':digest(after.model_dump(mode='json'))}

def prepare(manifest,prefix,out):
 install('2026-11-05T00:00:00');data=json.loads(manifest.read_text());prefix_summary=json.loads((prefix/'summary.json').read_text());assert prefix_summary['complete'];out.mkdir(parents=True,exist_ok=False);rows=[];conditions=[]
 for u in data['units']:
  folder=prefix/u['case_id'];rawpath=folder/'prefix.json.gz'
  if not rawpath.exists():rows.append({'unit_id':u['unit_id'],'cluster_id':u['cluster_id'],'status':'prefix_unavailable'});continue
  raw=json.loads(gzip.decompress(rawpath.read_bytes()));a=raw['result'].get('x1_prefix_anchors',{}).get(u['function']);row={'unit_id':u['unit_id'],'cluster_id':u['cluster_id'],'case_id':u['case_id'],'prefix_status':raw['result']['status'],'prefix_raw_sha256':hashlib.sha256(rawpath.read_bytes()).hexdigest(),'faults':{}}
  if not a:row['status']='no_target_proposal';rows.append(row);continue
  correct={k:normalization(k,v,u.get('calendar_owner')) for k,v in u['correct_projection'].items()};effective=effective_args(u['function'],a['args'],a['before']);actual={k:normalization(k,effective.get(k),u.get('calendar_owner')) for k in correct};right=actual[u['argument']]==correct[u['argument']];others=all(actual[k]==v for k,v in correct.items() if k!=u['argument']);row.update(status='exposed',first_target_right=right,other_projection_right=others,stratum='actor_right' if right and others else 'target_wrong' if not right and others else 'mixed_mismatch',prefix_sha256=a['prefix_sha256'],first_call={'function':u['function'],'args':a['args']},anchor_state_sha256=digest(a['before']))
  # Correct gate is a reference and repairs are a distinct stratum. It is not
  # credited as an automated inference method; all bindings are evaluator-side.
  for fmt in FEEDBACK:
   cond={'condition_id':u['unit_id']+'__oracle_correct__'+fmt,'unit_id':u['unit_id'],'case_id':u['case_id'],'cluster_id':u['cluster_id'],'variant':'oracle_correct','fault_class':'none','feedback':fmt,'bound_projection':copy.deepcopy(u['correct_projection']),'prefix_sha256':a['prefix_sha256'],'stratum':row['stratum']};conditions.append(cond)
  for kind in ['M1','M2','M3']:
   values=[near(u['argument'],u['correct_value'],u)] if kind=='M1' else sibling_values(u,a) if kind=='M2' else [gross(u['argument'],u['correct_value'])];values=[v for v in values if v is not None];checks=[];chosen=None
   for v in values:
    test=native_fault_check(u,a,v);checks.append({'value':v,**test})
    if test['feasible']:chosen=v;break
   if chosen is None:row['faults'][kind]={'available':False,'reason':'no_observed_sibling' if kind=='M2' and not values else 'no_native_executable_fault','checks':checks};continue
   row['faults'][kind]={'available':True,'value':chosen,'checks':checks,'visibility':'selected from actual pretreatment native observations' if kind=='M2' else 'declared mechanical mutation'}
   if row['stratum']!='actor_right':continue
   projection=copy.deepcopy(u['correct_projection']);projection[u['argument']]=chosen
   for fmt in FEEDBACK:conditions.append({'condition_id':u['unit_id']+'__'+kind+'__'+fmt,'unit_id':u['unit_id'],'case_id':u['case_id'],'cluster_id':u['cluster_id'],'variant':'fault','fault_class':kind,'feedback':fmt,'bound_projection':projection,'fault_value':chosen,'prefix_sha256':a['prefix_sha256'],'stratum':row['stratum']})
  rows.append(row)
 for c in conditions:save(out/'conditions'/(c['condition_id']+'.json'),c)
 result={'kind':'X1 frozen pretreatment branch assignment','manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'prefix_summary_sha256':hashlib.sha256((prefix/'summary.json').read_bytes()).hexdigest(),'source_units':len(data['units']),'task_clusters':len(data['cases']),'exposed_units':sum(r['status']=='exposed' for r in rows),'conditions':len(conditions),'rows':rows,'condition_rows':conditions,'scope':'No source/outcome replacement. Native-infeasible fault cells remain structural missingness; actor-right and repair strata are pretreatment classifications.'};save(out/'manifest.json',result);return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--prefix',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();r=prepare(a.manifest,a.prefix,a.out);print(json.dumps({k:r[k] for k in ['source_units','task_clusters','exposed_units','conditions']}))
