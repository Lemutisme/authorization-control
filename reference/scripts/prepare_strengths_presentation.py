"""Recompute the presentation's finite claims from retained, versioned evidence.

No model/provider calls or old result edits. Task clusters, losses and gains
remain separate; the selected minimal configuration is not a new holdout.
"""
import ast,collections,csv,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'evidence/strengths-presentation'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
inputs={}
def read(name):
 p=ROOT/name;inputs[name]=sha(p)
 if p.suffix=='.csv':
  with p.open(newline='') as f:return list(csv.DictReader(f))
 return json.loads(p.read_text())
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n')
def main():
 OUT.mkdir(parents=True,exist_ok=True);(ROOT/'presentation').mkdir(exist_ok=True)
 contract=read('evidence/contract-study/summary.json');minimal='no_facts_no_feedback';points=[];components=[]
 for run in contract['runs']:
  by={}
  for arm,name in run['episode_csvs'].items():
   rows=read('evidence/contract-study/'+name);assert sha(ROOT/'evidence/contract-study'/name)==run['episode_csv_sha256'][name]
   assert len(rows)==run['observed'] and len({r['case_id'] for r in rows})==len(rows)
   by[arm]={r['case_id']:r for r in rows}
  for condition,g in run['strata'].items():
   if not g['n']:continue
   pairs=[(r,by[minimal][cid]) for cid,r in by['none'].items() if r['condition']==condition]
   assert len(pairs)==g['n'] and all(r['audit_valid']==s['audit_valid']=='True' and r['utility'] in {'True','False'} and s['utility'] in {'True','False'} for r,s in pairs)
   losses=[s for r,s in pairs if r['utility']=='True' and s['utility']=='False'];gains=[s for r,s in pairs if r['utility']=='False' and s['utility']=='True']
   c=g['contrasts']['no_gate_vs_'+minimal];assert len(losses)==c['on_only_success'] and len(gains)==c['off_only_success']
   counter=lambda rows:dict(collections.Counter(r['suite']+'/'+r['task_id'] for r in rows))
   point={'job':run['job'],'condition':condition,'n':len(pairs),'reference_success':sum(r['utility']=='True' for r,s in pairs),'minimal_success':sum(s['utility']=='True' for r,s in pairs),'paired_losses':len(losses),'paired_gains':len(gains),'loss_clusters':counter(losses),'gain_clusters':counter(gains),'task_clusters':len({(r['suite'],r['task_id']) for r,s in pairs})}
   assert point['reference_success']==g['arms']['none']['utility'] and point['minimal_success']==g['arms'][minimal]['utility']
   if condition=='attack':
    assert all(r['asr'] in {'True','False'} and s['asr'] in {'True','False'} for r,s in pairs)
    positives=[r for r,s in pairs if r['asr']=='True'];point.update(reference_asr=len(positives),minimal_asr=sum(s['asr']=='True' for r,s in pairs),baseline_asr_clusters=counter(positives))
    assert point['reference_asr']==g['arms']['none']['asr'] and point['minimal_asr']==g['arms'][minimal]['asr']
   points.append(point)
   for label in ['facts_with_feedback','facts_without_feedback','feedback_with_facts','feedback_without_facts']:
    x=g['contrasts'][label];on=by[x['on_or_reference']];off=by[x['off_or_candidate']];selected=[(a,off[k]) for k,a in on.items() if a['condition']==condition]
    plus=sum(a['utility']=='True' and b['utility']=='False' for a,b in selected);minus=sum(a['utility']=='False' and b['utility']=='True' for a,b in selected)
    assert plus==x['on_only_success'] and minus==x['off_only_success']
    components.append({'job':run['job'],'condition':condition,'contrast':label,'on_gains':plus,'on_losses':minus,'task_bootstrap':x['descriptive_task_bootstrap']})
 cross=read('evidence/diagnostic-crossover/summary.json');crossrows=read('evidence/diagnostic-crossover/episodes.csv');assert sha(ROOT/'evidence/diagnostic-crossover/episodes.csv')==cross['episode_csv_sha256'] and len(crossrows)==54
 crossover=[]
 for cid,label in [('banking__user_task_3__injection_task_0','Refund'),('banking__user_task_12__injection_task_4','Rent update'),('banking__user_task_10__injection_task_8','Underspecified bill')]:
  cell={'case_id':cid,'label':label}
  for message in ['minimal_reason','late_reason','status_only']:
   values=[]
   for bg in ['minimal','late_facts']:
    selected=[r for r in crossrows if (r['case_id'],r['background'],r['message'])==(cid,bg,message)];assert len(selected)==3
    n=sum(r['native_utility']=='True' for r in selected);old=next(c for c in cross['cells'] if (c['case_id'],c['background'],c['message'])==(cid,bg,message));assert n==old['utility'];values.append(n)
   assert values[0]==values[1];cell[message]=values[0]
  crossover.append(cell)
 exposure=read('evidence/diagnostic-crossover/exposure-audit.json')
 multi=read('evidence/multibench/summary.json');transfer={}
 for run in multi['runs']:
  if run['job'] not in {'multibench-asb-main-v1','multibench-injecagent-main-v1'}:continue
  allrows=[]
  for name,h in run['episode_csv_sha256'].items():
   rows=read('evidence/multibench/'+name);assert sha(ROOT/'evidence/multibench'/name)==h;allrows.extend(rows)
  assert len(allrows)==run['episodes'] and not run['audit_findings']
  for group,arms in run['groups'].items():
   for arm,entry in arms.items():
    selected=[r for r in allrows if r['benchmark']+'_'+r['stratum']==group and r['arm']==arm];assert len(selected)==entry['n']
    for metric in ['dispatch_asr','native_marker_utility']:
     m=entry['metrics'][metric]
     if not m['eligible']:continue
     assert sum(r.get(metric)=='True' for r in selected)==m['positive'] and m['unknown_or_incomplete']==0
     key=('injecagent' if group.startswith('injecagent') else group)+'/'+arm+'/'+metric
     cell=transfer.setdefault(key,{'positive':0,'n':0});cell['positive']+=m['positive'];cell['n']+=m['eligible']
 audit=read('evidence/intent-guard/effect-audit.json');local_binding=[]
 for run in audit['runs']:
  c=run['counts'];assert c['intent_guard:effect:events']==c['consumed_matching_grants'] and c['unconsumed_grants']==0 and not run['findings']
  local_binding.append({'job':run['job'],'matching_effect_grants':c['consumed_matching_grants'],'scope':'Separate v16 local audit; not a main-factorial denominator or semantic/production guarantee.'})
 source_files=['evaluation/intent_guard/broker.py','evaluation/pi_full/broker.py','evaluation/pga_oracle.py','evaluation/intent_guard/runtime.py','evaluation/intent_guard/guard.py']
 for name in source_files:inputs[name]=sha(ROOT/name)
 tree=ast.parse((ROOT/'evaluation/pga_oracle.py').read_text());ids=sorted({node.comparators[0].value for node in ast.walk(tree) if isinstance(node,ast.Compare) and isinstance(node.left,ast.Name) and node.left.id=='task_id' and len(node.comparators)==1 and isinstance(node.comparators[0],ast.Constant)})
 assert ids==['user_task_32','user_task_6','user_task_7']
 profile={'authorization_component':'Generic task-scope reviewer; no task-ID-indexed policy argument.','shared_actor_profiles':ids,'profile_source':'Reviewed grammars parse only the public user prompt, not expected answers.','fairness':'Both no-gate and guard actors receive the same profiles for these three workspace tasks.','scope_limit':'The evaluated full stack is not profile-free; strict held-out generalization remains unmeasured.','source_locations':['evaluation/intent_guard/broker.py:38','evaluation/pi_full/broker.py:32','evaluation/pi_full/broker.py:44','evaluation/pga_oracle.py:37']}
 report={'kind':'Read-only recheck of presentation claims; no new performance samples','parent_commit':'0b46bd7c16ad5b1780a8cb632d58d6e217d6a291','analysis_source_sha256':sha(Path(__file__)),'input_sha256':inputs,'minimal_configuration':'F-R-; removes optional derived fact packet and extended repair suffix, retaining ordinary denial reasons and the effect gate.','operating_points':points,'factorial_components':components,'crossover':crossover,'crossover_scope':{'selected_cases':3,'suffix_episodes':54,'late_fact_exposed_suffixes':exposure['groups']['late_facts']['exposed_episodes'],'late_fact_total_suffixes':27},'transfer':transfer,'separate_local_binding_audit':local_binding,'profile_scope':profile,'interpretation_limits':['Finite source-read development cohorts; repeated tasks are not independent new tasks.','Native utility is not an independently established complete owner-policy oracle.','Low observed ASR and clean preservation do not remove attacked or capability losses.','All-call transfer ports have different read treatment and proxy endpoints; causal transfer attribution is unestablished.','Prior components and one Progent smoke do not establish full-system equivalence or contemporary superiority.']}
 save(OUT/'checked-evidence.json',report)
 main=next(p for p in points if p['condition']=='clean' and p['job']=='contract-factorial-main-v1');repeat=next(p for p in points if p['condition']=='clean' and p['job']=='contract-factorial-clean-repeat-v1');attack=next(p for p in points if p['condition']=='attack');goal=next(p for p in points if p['condition']=='goal_control')
 tex=['% Generated by scripts/prepare_strengths_presentation.py from retained evidence.']
 for prefix,p in [('MainClean',main),('RepeatClean',repeat),('Attack',attack),('Goal',goal)]:
  for suffix,key in [('N','n'),('Base','reference_success'),('Guard','minimal_success'),('Loss','paired_losses'),('Gain','paired_gains')]:tex.append('\\newcommand{\\'+prefix+suffix+'}{'+str(p[key])+'}')
 tex+=['\\newcommand{\\ASRBase}{'+str(attack['reference_asr'])+'}','\\newcommand{\\ASRGuard}{'+str(attack['minimal_asr'])+'}']
 tex.append('\\newcommand{\\CrossoverRows}{'+''.join(c['label']+' & '+str(c['minimal_reason'])+'/3 & '+str(c['late_reason'])+'/3 & '+str(c['status_only'])+'/3\\\\' for c in crossover)+'}')
 for prefix,group,metric in [('Injec','injecagent','dispatch_asr'),('ASB','asb_opi_context_ignoring','dispatch_asr'),('ASBClean','asb_clean','native_marker_utility')]:
  for suffix,arm in [('Base','none'),('Reminder','repeat_task'),('Guard','minimal')]:
   cell=transfer[group+'/'+arm+'/'+metric];tex.append('\\newcommand{\\'+prefix+suffix+'}{'+str(cell['positive'])+'}')
  tex.append('\\newcommand{\\'+prefix+'N}{'+str(cell['n'])+'}')
 (ROOT/'presentation/strengths-data.tex').write_text('\n'.join(tex)+'\n')
 print(json.dumps({'operating_points':points,'crossover':crossover,'shared_actor_profiles':ids,'input_files_checked':len(inputs)},indent=2))
if __name__=='__main__':main()
