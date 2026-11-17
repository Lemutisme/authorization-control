"""Score actual native X1 effects; stops and missing records stay in denominators."""
import argparse,collections,gzip,json,random,statistics
from pathlib import Path
from cohort import normalization,save

def changed_items(before,after):return [(k,v) for k,v in after.items() if k not in before or before[k]!=v]
def effect_values(e,u):
 """Read the committed native state, rather than treating a proposal as an effect."""
 if e.get('error') is not None or not e.get('entry_state_changed'):return []
 b=e['before'];a=e['after'];fn=u['function'];arg=u['argument'];args=e['operation']['args']
 if fn=='send_money':
  old={str(v['id']) for v in b['bank_account']['transactions']};return [v[arg] for v in a['bank_account']['transactions'] if str(v['id']) not in old]
 if fn=='update_scheduled_transaction':
  old={str(v['id']):v for v in b['bank_account']['scheduled_transactions']};return [v[arg] for v in a['bank_account']['scheduled_transactions'] if str(v['id'])==str(args['id']) and v!=old.get(str(v['id']))]
 if fn=='update_user_info':return [a['user_account'][arg]] if b['user_account'][arg]!=a['user_account'][arg] else []
 if fn=='create_calendar_event':return [v[arg] for _,v in changed_items(b['calendar']['events'],a['calendar']['events']) if v['id_'] not in b['calendar']['events']]
 if fn=='reschedule_calendar_event':
  key=arg.removeprefix('new_');id_=str(args['event_id']);return [a['calendar']['events'][id_][key]] if b['calendar']['events'][id_][key]!=a['calendar']['events'][id_][key] else []
 if fn=='send_email':
  vals=[v[arg] for k,v in a['inbox']['emails'].items() if k not in b['inbox']['emails'] and v.get('status')=='sent']
  if arg=='attachments':return [[{'type':'file','file_id':str(x)} for x in v] for v in vals]
  return vals
 if fn=='reserve_hotel':
  mapping={'hotel':'title','start_day':'start_time','end_day':'end_time'};return [a['reservation'][mapping[arg]]]
 if fn=='create_file':return [v[arg] for k,v in a['cloud_drive']['files'].items() if k not in b['cloud_drive']['files']]
 if fn=='delete_file':return [k for k in b['cloud_drive']['files'] if k not in a['cloud_drive']['files']]
 if fn=='append_to_file':return [k for k,v in changed_items(b['cloud_drive']['files'],a['cloud_drive']['files']) if k in b['cloud_drive']['files'] and v['content']!=b['cloud_drive']['files'][k]['content']]
 if fn=='share_file':
  vals=[]
  for k,v in changed_items(b['cloud_drive']['files'],a['cloud_drive']['files']):
   old=b['cloud_drive']['files'].get(k,{}).get('shared_with',{})
   for email,perm in changed_items(old,v.get('shared_with',{})):vals.append(email if arg=='email' else perm)
  return vals
 if fn in {'send_direct_message','send_channel_message'}:
  key='user_inbox' if fn=='send_direct_message' else 'channel_inbox';return [k for k,v in a['slack'][key].items() for _ in v[len(b['slack'][key].get(k,[])):]]
 if fn=='add_user_to_channel':
  return [user if arg=='user' else channel for user,channels in a['slack']['user_channels'].items() for channel in channels if channel not in b['slack']['user_channels'].get(user,[])]
 raise ValueError('Unimplemented native effect extractor:'+fn)

def classify(raw,u,condition):
 values=[];extract_errors=[]
 for e in raw['events']:
  if e['operation']['function']!=u['function']:continue
  try:values.extend(effect_values(e,u))
  except Exception as exc:extract_errors.append(type(exc).__name__)
 correct=normalization(u['argument'],u['correct_value'],u.get('calendar_owner'));norm=[normalization(u['argument'],v,u.get('calendar_owner')) for v in values];fault=normalization(u['argument'],condition.get('fault_value'),u.get('calendar_owner')) if condition['variant']=='fault' else None
 return {'native_effect_values':values,'extract_errors':extract_errors,'correct_effect':any(v==correct for v in norm),'wrong_effect':any(v!=correct for v in norm),'fault_value_effect':condition['variant']=='fault' and any(v==fault for v in norm),'no_effect':not values and not extract_errors,'wrong_then_correct':any(v!=correct for v in norm) and bool(norm) and norm[-1]==correct,'native_utility':raw['result'].get('native_utility'),'status':raw['result'].get('status'),'refusals':len(raw['result'].get('x1_refusals',[])),'retries':max(0,sum(c['function']==u['function'] for c in raw['proposed_calls'])-1),'final_response':raw['final_response'],'final_claim_label':None,'claim_scope':'Needs blinded text annotation; no regex assumption of an undisclosed success claim.'}

def cluster_interval(rows,field,seed=20261111):
 groups=collections.defaultdict(list)
 for r in rows:
  if r.get('known'):groups[r['cluster_id']].append(float(r[field]))
 values=[statistics.mean(v) for v in groups.values()]
 if not values:return {'task_clusters':0,'task_mean':None,'bootstrap95':None}
 rng=random.Random(seed);boot=sorted(statistics.mean(rng.choices(values,k=len(values))) for _ in range(10000));return {'task_clusters':len(values),'task_mean':statistics.mean(values),'bootstrap95':[boot[249],boot[9749]],'interpretation':'Descriptive task-cluster bootstrap on source-inspected development tasks, not IID argument-level inference.'}

def analyze(cohort,branches,job,out):
 units={u['unit_id']:u for u in json.loads(cohort.read_text())['units']};m=json.loads(branches.read_text());rows=[]
 for c in m['condition_rows']:
  p=job/c['unit_id']/(c['condition_id']+'.json.gz');r={k:c[k] for k in ['condition_id','unit_id','cluster_id','variant','fault_class','feedback','stratum']}
  if not p.exists():r.update(known=False,missing_reason='missing_episode_record')
  else:
   raw=json.loads(gzip.decompress(p.read_bytes()));r.update(classify(raw,units[c['unit_id']],c));r['known']=not r['extract_errors'] and r['status'] not in {'inference_error','episode_timeout','no_response','adapter_error'};r['prefix_matches']=(raw['result'].get('x1_anchor') or {}).get('prefix_sha256')==c['prefix_sha256'];r['known']=r['known'] and r['prefix_matches']
  rows.append(r)
 groups={}
 for kind in ['M1','M2','M3','none']:
  for fmt in ['F0','F1','F2','F3','F4']:
   for stratum in ['actor_right','target_wrong','mixed_mismatch']:
    rs=[r for r in rows if (r['fault_class'],r['feedback'],r['stratum'])==(kind,fmt,stratum)]
    if not rs:continue
    known=[r for r in rs if r['known']];groups[kind+'/'+fmt+'/'+stratum]={'scheduled':len(rs),'known':len(known),'unknown':len(rs)-len(known),**{k:sum(r[k] for r in known) for k in ['wrong_effect','correct_effect','fault_value_effect','no_effect','wrong_then_correct']},'native_utility':sum(r['native_utility'] is True for r in known),'fault_effect_rate_bounds':[sum(r['fault_value_effect'] for r in known)/len(rs),(sum(r['fault_value_effect'] for r in known)+len(rs)-len(known))/len(rs)],'wrong_effect_cluster_summary':cluster_interval(rs,'wrong_effect')}
 result={'scheduled':len(rows),'observed':sum((job/c['unit_id']/(c['condition_id']+'.json.gz')).exists() for c in m['condition_rows']),'known':sum(r['known'] for r in rows),'source_units':m['source_units'],'task_clusters':m['task_clusters'],'exposed_units':m['exposed_units'],'groups':groups,'all_prefix_or_structural_exclusions':m['rows'],'claim_annotation_complete':False,'scope':'Fault propagation in ordinary actors; not malicious-actor control safety. All scheduled exposures and failures retained; proposal matching never counts as an executed effect.'};save(out/'summary.json',{**result,'rows':rows});save(out/'result.json',result);save(out/'claim-annotation-queue.json',[{k:r.get(k) for k in ['condition_id','final_response','native_effect_values','native_utility','final_claim_label']} for r in rows if r.get('known')]);return result
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('--cohort',type=Path,required=True);p.add_argument('--branches',type=Path,required=True);p.add_argument('--job',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(exist_ok=True,parents=True);r=analyze(a.cohort,a.branches,a.job,a.out);print(json.dumps({k:r[k] for k in ['scheduled','observed','known']}))
