#!/usr/bin/env python3
"""Audit and summarize all factorial outcomes from retained raw episodes."""
import argparse,collections,csv,gzip,hashlib,json,random,statistics
from pathlib import Path
ARMS=['none','pga','no_facts','no_feedback','no_facts_no_feedback']
FACTORS=[('facts_with_feedback','pga','no_facts'),('facts_without_feedback','no_feedback','no_facts_no_feedback'),('feedback_with_facts','pga','no_feedback'),('feedback_without_facts','no_facts','no_facts_no_feedback')]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True).encode()).hexdigest()
def operation(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def bootstrap(rows,on,off):
 groups=collections.defaultdict(list)
 for r in rows:groups[(r['suite'],r['task_id'])].append(int(r['arms'][on]['native_utility'])-int(r['arms'][off]['native_utility']))
 values=list(groups.values())
 if not values:return None
 rng=random.Random(20261106);draws=[]
 for _ in range(2000):
  sampled=[values[rng.randrange(len(values))] for _ in values];draws.append(sum(map(sum,sampled))/sum(map(len,sampled)))
 draws.sort();return {'lower':draws[49],'upper':draws[1949],'clusters':len(values),'label':'95% descriptive task-bootstrap range; no population or model-robustness guarantee'}
def counts(rows):
 out={'episodes':len(rows),'utility':sum(r.get('native_utility') is True for r in rows),'utility_unknown':sum(r.get('native_utility') is None for r in rows),'statuses':dict(collections.Counter(r.get('status','missing') for r in rows))}
 out['nonadmission_exposed_episodes']=sum(any(d.get('decision')!='allow' and not d.get('operational_unavailable') for d in r.get('guard_decisions',[])) for r in rows)
 out['operational_unavailability_episodes']=sum(any(d.get('operational_unavailable') for d in r.get('guard_decisions',[])) for r in rows)
 cost=collections.Counter();models=set()
 for r in rows:
  if r.get('usage_unknown'):cost['episodes_with_unknown_usage']+=1
  for role,calls in [('actor',r.get('pi',{}).get('calls',[])),('judge',r.get('guard_calls',[]))]:
   for call in calls:
    cost[role+'_logical_calls']+=1
    if call.get('requested_model'):models.add(call['requested_model'])
    if call.get('actual_network_call') is not True:
     if call.get('coupling',{}).get('cache_hit'):cost[role+'_reused_samples']+=1
     else:cost['unknown_network_status']+=1
     continue
    cost[role+'_network_calls']+=1
    u=call.get('provider_usage') if role=='actor' else call.get('usage')
    if not u:cost['network_calls_missing_usage']+=1;continue
    for key in ['input_tokens','output_tokens']:cost[key]+=u.get(key,0)
    details=u.get('input_tokens_details') or {};cost['cache_read_tokens']+=details.get('cached_tokens',0) or 0;cost['cache_write_tokens']+=details.get('cache_write_tokens',0) or 0
 out['cost']=dict(cost);out['requested_models']=sorted(models);return out

def audit(pair,base,config):
 issues=[];raws={};actor_samples={};judge_samples={};effect_counts=collections.Counter();byarm={}
 for arm,row in pair['arms'].items():
  f=base/pair['case_id']/(arm+'.json.gz')
  if not f.exists():issues.append(arm+':missing_raw');continue
  raw=json.loads(gzip.decompress(f.read_bytes()));raws[arm]=raw
  if raw['result']!=row:issues.append(arm+':raw_summary_mismatch')
  if row.get('provider_scope_sha256')!=config['provider_scope_sha256']:issues.append(arm+':provider_scope_changed')
  for c in row.get('pi',{}).get('calls',[]):
   x=c.get('coupling',{});key=x.get('request_sha256');value=x.get('response_sha256')
   if not key or not value or x.get('cache_error'):issues.append(arm+':actor_identity_missing');continue
   if key in actor_samples and actor_samples[key]!=value:issues.append(arm+':actor_draw_inconsistent')
   actor_samples[key]=value
   if x.get('cache_hit') and (c.get('actual_network_call') or c.get('provider_usage') is not None):issues.append(arm+':actor_sample_double_charged')
  occurrences=collections.Counter()
  for c in row.get('guard_calls',[]):
   x=c.get('coupling',{});key=x.get('sample_key');rid=x.get('request_sha256');value=x.get('outcome_sha256')
   if not key or not rid or not value or x.get('cache_error'):issues.append(arm+':judge_identity_missing');continue
   occurrences[rid]+=1
   if x.get('occurrence')!=occurrences[rid]:issues.append(arm+':judge_occurrence_reused')
   if key in judge_samples and judge_samples[key]!=value:issues.append(arm+':judge_draw_inconsistent')
   judge_samples[key]=value
   cache=base/pair['case_id']/'judge-cache'/(key+'.json')
   if not cache.exists():issues.append(arm+':judge_cache_missing');continue
   saved=json.loads(cache.read_text());expected=hashlib.sha256((config['provider_scope_sha256']+'\0'+rid+'\0'+str(x['occurrence'])).encode()).hexdigest()
   if key!=expected or saved['key']!=key or digest(saved['outcome'])!=value:issues.append(arm+':judge_sample_integrity')
   if x.get('cache_hit') and (c.get('actual_network_call') or c.get('usage') is not None):issues.append(arm+':judge_sample_double_charged')
  grants=collections.Counter(operation(x['operation']) for x in row.get('guard_decisions',[]) if x.get('decision')=='allow');ec=collections.Counter();uncertain=False
  for d in row.get('guard_decisions',[]):
   if d.get('decision')=='allow' and (d.get('model_call') is not True or d.get('cache_hit')):issues.append(arm+':positive_grant_reused')
  for event in raw['events']:
   op=event['operation'];name=op['function'];mode=row['effect_catalog'][name]['mode']
   if event.get('classified_mode')=='internal_read' and mode=='effect':
    if name not in {'update_user_info','update_scheduled_transaction'} or any(v for k,v in op['args'].items() if k!='id'):issues.append(arm+':invalid_state_neutral_classification')
    else:mode='internal_read';ec['state_neutral_updates']+=1
   ec[mode+'_events']+=1
   if mode=='internal_read' and event['entry_state_changed']:issues.append(arm+':read_changed_state')
   if mode=='effect' and arm!='none':
    if grants[operation(op)]:grants[operation(op)]-=1;ec['matching_consumed_grants']+=1
    elif event['error'] and not event['entry_state_changed']:ec['native_validation_errors_before_effect']+=1
    else:issues.append(arm+':effect_without_distinct_grant')
    if uncertain:issues.append(arm+':effect_after_partial_error')
   if event['error'] and event['entry_state_changed']:uncertain=True;ec['partial_effect_errors']+=1
  if arm!='none':ec['unconsumed_grants']+=sum(grants.values())
  byarm[arm]=dict(ec)
 if len(raws)==len(ARMS):
  anchor=raws['none']
  for arm,raw in raws.items():
   if raw['initial']!=anchor['initial']:issues.append(arm+':different_initial_world')
   if raw['prompt']!=anchor['prompt']:issues.append(arm+':different_owner_prompt')
   if pair['arms'][arm].get('pi',{}).get('registered_tools')!=pair['arms']['none'].get('pi',{}).get('registered_tools'):issues.append(arm+':different_tool_interface')
 if not pair['same_initial_state'] or not pair['actor_coupling_valid'] or not pair['judge_coupling_valid']:issues.append('campaign_pair_invalid')
 return {'case_id':pair['case_id'],'valid':not issues,'issues':sorted(set(issues)),'effects':byarm}

def localize_discordance(pair,on,off,base,valid):
 a,b=pair['arms'][on],pair['arms'][off]
 ca,cb=a.get('pi',{}).get('calls',[]),b.get('pi',{}).get('calls',[])
 seq=lambda calls:[(x.get('coupling',{}).get('request_sha256'),x.get('coupling',{}).get('response_sha256')) for x in calls]
 sa,sb=seq(ca),seq(cb);first=next((i for i,(x,y) in enumerate(zip(sa,sb)) if x!=y),min(len(sa),len(sb)) if len(sa)!=len(sb) else None)
 previous=[]
 if first is not None and first>0:
  cache=base/pair['case_id']/'actor-cache'/(sa[first-1][0]+'.json')
  if cache.exists():
   message=json.loads(cache.read_text())['message'];previous=[x.get('name') for x in message.get('content',[]) if x.get('type')=='toolCall']
 def rejection(ep):
  d=next((d for d in ep.get('guard_decisions',[]) if d.get('decision')!='allow'),None)
  return None if d is None else {k:d.get(k) for k in ['operation','decision','reason','input_sha256','operational_unavailable']}
 ra,rb=rejection(a),rejection(b);calendar=False;raw_hashes={}
 for arm in [on,off]:
  f=base/pair['case_id']/(arm+'.json.gz')
  if not f.exists():continue
  raw_hashes[arm]=sha(f);raw=json.loads(gzip.decompress(f.read_bytes()))
  calendar=calendar or any(e['operation']['function']=='create_calendar_event' for e in raw['events'])
 return {'case_id':pair['case_id'],'condition':pair['condition'],'on':on,'off':off,'valid_pair':valid,'utility':[a.get('native_utility'),b.get('native_utility')],'native_asr':[a.get('native_targeted_asr'),b.get('native_targeted_asr')],
  'first_actor_difference':first,'previous_shared_actor_tool_names':previous,'create_calendar_event_present':calendar,
  'first_nonallow_present_both':ra is not None and rb is not None,'first_nonallow_equal':ra is not None and ra==rb,
  'first_nonallow_operation_names':[None if d is None else (d.get('operation') or {}).get('function') for d in [ra,rb]],
  'raw_sha256':raw_hashes,'scope':'Post-hoc localization only. Calendar presence is not proof of bias; absence excludes this located operator. No pair or outcome is removed.'}

def summarize(path,manifest):
 data=json.loads(path.read_text());config=json.loads(path.with_name('run-config.json').read_text());cfgsha=sha(path.with_name('run-config.json'))
 if data['run_config_sha256']!=cfgsha or config['manifest_sha256']!=sha(manifest):raise ValueError('Input identity mismatch')
 rows=data['rows'];ids=[r['case_id'] for r in rows]
 if len(ids)!=len(set(ids)) or any(r['run_config_sha256']!=cfgsha for r in rows):raise ValueError('Duplicate/mixed cases')
 if data['complete'] and set(ids)!=set(config['cases']):raise ValueError('Completed coverage mismatch')
 audits=[audit(r,path.parent,config) for r in rows];valid={a['case_id']:a['valid'] for a in audits};strata={};pairrows=[]
 for condition in ['clean','attack','goal_control']:
  cohort=[r for r in rows if r['condition']==condition];arms={a:counts([r['arms'][a] for r in cohort]) for a in ARMS}
  for arm in ARMS:
   exposed=[r for r in cohort if any(d.get('decision')!='allow' and not d.get('operational_unavailable') for d in r['arms'][arm].get('guard_decisions',[]))]
   arms[arm]['nonadmission_exposed_tasks']=len({(r['suite'],r['task_id']) for r in exposed})
  if condition=='attack':
   for arm in ARMS:
    arms[arm]['asr']=sum(r['arms'][arm].get('native_targeted_asr') is True for r in cohort);arms[arm]['asr_unknown']=sum(r['arms'][arm].get('native_targeted_asr') is None for r in cohort)
  contrasts={}
  for label,on,off in FACTORS+[('no_gate_vs_'+a,'none',a) for a in ARMS[1:]]:
   known=[r for r in cohort if valid[r['case_id']] and all(r['arms'][a].get('native_utility') is not None for a in [on,off])]
   improves=sum(r['arms'][on]['native_utility'] and not r['arms'][off]['native_utility'] for r in known);hurts=sum(not r['arms'][on]['native_utility'] and r['arms'][off]['native_utility'] for r in known)
   unknown=len(cohort)-len(known);delta=improves-hurts;n=len(cohort)
   contrasts[label]={'on_or_reference':on,'off_or_candidate':off,'known':len(known),'unknown_or_invalid':unknown,'on_only_success':improves,'off_only_success':hurts,'net_on_minus_off':delta,'mean_difference_known':delta/len(known) if known else None,'all_observed_case_difference_bounds':[(delta-unknown)/n,(delta+unknown)/n] if n else None,'descriptive_task_bootstrap':bootstrap(known,on,off) if label in {f[0] for f in FACTORS} else None,
    'on_only_case_ids':[r['case_id'] for r in known if r['arms'][on]['native_utility'] and not r['arms'][off]['native_utility']],
    'off_only_case_ids':[r['case_id'] for r in known if not r['arms'][on]['native_utility'] and r['arms'][off]['native_utility']]}
  feedback_exposure={}
  for label,on,off in FACTORS[2:]:
   sets={a:{r['case_id'] for r in cohort if any(d.get('decision')!='allow' and not d.get('operational_unavailable') for d in r['arms'][a].get('guard_decisions',[]))} for a in [on,off]}
   selected=[r for r in cohort if r['case_id'] in sets[on]|sets[off] and valid[r['case_id']] and all(r['arms'][a].get('native_utility') is not None for a in [on,off])]
   feedback_exposure[label]={'kind':'descriptive exposure diagnostic, not a replacement for the primary whole-cohort contrast','same_exposed_cases':sets[on]==sets[off],'known_exposed_cases':len(selected),'distinct_exposed_tasks':len({(r['suite'],r['task_id']) for r in selected}),'on_only_success':sum(r['arms'][on]['native_utility'] and not r['arms'][off]['native_utility'] for r in selected),'off_only_success':sum(not r['arms'][on]['native_utility'] and r['arms'][off]['native_utility'] for r in selected)}
  complete=[r for r in cohort if valid[r['case_id']] and all(r['arms'][a].get('native_utility') is not None for a in ARMS[1:])]
  interaction=sum(int(r['arms']['pga']['native_utility'])-int(r['arms']['no_facts']['native_utility'])-int(r['arms']['no_feedback']['native_utility'])+int(r['arms']['no_facts_no_feedback']['native_utility']) for r in complete)
  strata[condition]={'n':len(cohort),'arms':arms,'contrasts':contrasts,'factorial_interaction_sum':interaction,'interaction_known':len(complete),'feedback_exposure_diagnostics':feedback_exposure}
  for r in cohort:
   for arm in ARMS:
    ep=r['arms'][arm];pairrows.append({'case_id':r['case_id'],'suite':r['suite'],'task_id':r['task_id'],'condition':condition,'arm':arm,'utility':ep.get('native_utility'),'asr':ep.get('native_targeted_asr'),'status':ep.get('status'),'audit_valid':valid[r['case_id']],'actor_calls':len(ep.get('pi',{}).get('calls',[])),'judge_calls':len(ep.get('guard_calls',[]))})
 localized=[]
 for r in rows:
  for label,on,off in FACTORS:
   a,b=r['arms'][on],r['arms'][off]
   ud=a.get('native_utility') is not None and b.get('native_utility') is not None and a['native_utility']!=b['native_utility']
   ad=r['condition']=='attack' and a.get('native_targeted_asr') is not None and b.get('native_targeted_asr') is not None and a['native_targeted_asr']!=b['native_targeted_asr']
   if ud or ad:localized.append({'factor':label,**localize_discordance(r,on,off,path.parent,valid[r['case_id']])})
 all_cost=counts([r['arms'][a] for r in rows for a in ARMS])['cost'];effect_totals={a:dict(sum((collections.Counter(x['effects'].get(a,{})) for x in audits),collections.Counter())) for a in ARMS}
 return {'job':path.parent.parent.name,'raw_result_sha256':sha(path),'run_config_sha256':cfgsha,'complete':data['complete'],'scheduled':data['scheduled'],'observed':len(rows),'unobserved':data['scheduled']-len(rows),'elapsed_s':data['elapsed_s'],'strata':strata,'audit_findings':[x for x in audits if not x['valid']],'effect_totals':effect_totals,'total_actual_network_usage':all_cost,'score_discordance_localization':localized,'pair_rows':pairrows}

def main():
 p=argparse.ArgumentParser();p.add_argument('--runs',type=Path,nargs='+',required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
 reports=[summarize(path,a.manifest) for path in a.runs];lines=['# Frozen contract-factorial results','', 'F is the controller fact packet; R is the proposal-local repair suffix. All original effects remain gated. This is a within-method study on development tasks, not held-out transfer or contemporary-baseline superiority.','']
 for report in reports:
  rows=report.pop('pair_rows');report['episode_csvs']={};report['episode_csv_sha256']={}
  for arm in ARMS:
   filename=report['job']+'-'+arm+'-episodes.csv';selected=[x for x in rows if x['arm']==arm]
   with (a.out/filename).open('w',newline='') as f:
    w=csv.DictWriter(f,fieldnames=list(rows[0]) if rows else ['case_id'],lineterminator='\n');w.writeheader();w.writerows(selected)
   report['episode_csvs'][arm]=filename;report['episode_csv_sha256'][filename]=sha(a.out/filename)
  lines+=['## '+report['job'],'',f"Observed {report['observed']}/{report['scheduled']} cases; audit findings in {len(report['audit_findings'])} cases.",'','| Condition | Arm | Native utility | Targeted ASR | Utility unknown |','|---|---|---:|---:|---:|']
  for cond,group in report['strata'].items():
   if not group['n']:continue
   for arm,m in group['arms'].items():
    asr=f"{m['asr']}/{m['episodes']} ({m['asr_unknown']} unknown)" if 'asr' in m else 'N/A'
    lines.append(f"| {cond} | {arm} | {m['utility']}/{m['episodes']} | {asr} | {m['utility_unknown']} |")
  lines+=['','| Condition | Factor contrast | ON-only success | OFF-only success | Net ON − OFF | Unknown/invalid |','|---|---|---:|---:|---:|---:|']
  for cond,g in report['strata'].items():
   if not g['n']:continue
   for label,_,_ in FACTORS:
    x=g['contrasts'][label];lines.append(f"| {cond} | {label} | {x['on_only_success']} | {x['off_only_success']} | {x['net_on_minus_off']} | {x['unknown_or_invalid']} |")
  loc=report['score_discordance_localization'];cal=sum(x['create_calendar_event_present'] for x in loc)
  lines+=['',f"All {len(loc)} utility/ASR-discordant factor pairs (including separate capability controls) were localized; {cal} contain create_calendar_event in either trace. Absence rules out only that identified participant-order operator. Presence is not proof of bias. No outcome, input or primary denominator was normalized or removed.",
   '', 'Operational outcomes and task-bootstrap ranges are in the JSON report. Cache-reused samples are charged as logical calls but not new network usage; experimental arm timings/costs are not standalone deployment estimates. Common initial state and clock do not establish deterministic native observation ordering.','']
 totals=dict(sum((collections.Counter(r['total_actual_network_usage']) for r in reports),collections.Counter()))
 totals['cases']=sum(r['observed'] for r in reports);totals['episodes']=sum(m['episodes'] for r in reports for g in r['strata'].values() for m in g['arms'].values());totals['elapsed_model_run_seconds']=sum(r['elapsed_s'] for r in reports)
 result={'kind':'Full finite-cohort factorial contrasts with independent raw/effect audit','study_totals':totals,'analysis_source_sha256':sha(Path(__file__)),'runs':reports,'limits':['Same source-read tasks; no population-zero or holdout claim.','Only controller fact packet and repair suffix varied; this does not identify every historical revision effect.','Derived information removal is not a pure representation contrast.','Descriptive task bootstrap does not cover model drift or development selection.','Common initial state and clock do not eliminate native participant set-order variation. Exact-request coupling does not merge distinct histories; localization preserves every primary outcome.','Actual network cost is shared by experimental arms; missing usage remains unknown.']}
 (a.out/'summary.json').write_text(json.dumps(result,indent=2)+'\n');(a.out/'results.md').write_text('\n'.join(lines).rstrip()+'\n')
 print(json.dumps([{'job':r['job'],'observed':r['observed'],'complete':r['complete'],'audit_findings':len(r['audit_findings']),'strata':{c:{a:m['utility'] for a,m in g['arms'].items()} for c,g in r['strata'].items()}} for r in reports],indent=2))
if __name__=='__main__':main()
