"""Frozen-endpoint readback for the matched reconstruction diagnostic; no inference."""
import argparse,collections,hashlib,json,statistics
from pathlib import Path
ARMS=['all_tools_complete','known_function_complete','known_function_protected']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--result',type=Path,required=True);ap.add_argument('--out',type=Path,required=True);a=ap.parse_args()
 d=json.loads(a.result.read_text());rows=d['rows'];groups=collections.defaultdict(list)
 for r in rows:groups[(r['arm'],r['replicate'],r['context_group'])].append(r)
 findings=[];fresh=[]
 for key,vals in groups.items():
  originals=[r for r in vals if not r.get('matched_sample_reuse')]
  if len(originals)!=1:findings.append({'group':key,'error':'nonunique_original','n':len(originals)});continue
  ref=originals[0];fresh.append(ref)
  for r in vals:
   if r.get('scientific_status')=='known':
    for field in ['constructor_context_sha256','constructor_reply']:
     if r.get(field)!=ref.get(field):findings.append({'group':key,'error':'coupling_mismatch','field':field})
    if not r.get('endpoint_evaluation',{}).get('source_proposal_tuple',{}).get('intended_tuple_match'):
     findings.append({'unit':r['source']['unit_id'],'error':'source_proposal_relation_mismatch'})
    if r['arm']=='all_tools_complete' and r.get('original_constructor_context_equal') is not True:findings.append({'group':key,'error':'baseline_context_changed'})
 metrics={};context_metrics={}
 for arm in ARMS:
  context_metrics[arm]={}
  for context in ['tax','refund']:
   vals=[r for r in fresh if r['arm']==arm and r['context_group']==context]
   known=[r for r in vals if r.get('scientific_status')=='known'];ev=[r['endpoint_evaluation'] for r in known]
   n=len(vals);good=sum(e.get('packet_valid') and e.get('first_candidate_intended_tuple') for e in ev)
   context_metrics[arm][context]={'n':n,'known':len(known),'unknown':n-len(known),'valid_packet_first_tuple':good,
     'rate':good/n if n and len(known)==n else None,'rate_bounds':[good/n,(good+n-len(known))/n] if n else None,
     'raw_first_tuple_content':sum(e.get('first_candidate_intended_tuple') is True for e in ev),
     'any_candidate_tuple_coverage':sum(e.get('any_candidate_intended_tuple_coverage') is True for e in ev),
     'valid_packets':sum(e.get('packet_valid') is True for e in ev),'parse_status':dict(collections.Counter(r.get('parse_status','missing') for r in vals)),
     'first_native_tuple_on_representative':sum(e.get('first_candidate_intended_native_effect') is True for e in ev),
     'recipient_classes':dict(collections.Counter((e.get('candidates') or [{}])[0].get('content',{}).get('recipient_class','no_candidate') for e in ev))}
  rates=[context_metrics[arm][c]['rate'] for c in ['tax','refund']]
  metrics[arm]={'macro_first_tuple_rate':statistics.mean(rates) if all(r is not None for r in rates) else None,
    'fresh_samples':sum(context_metrics[arm][c]['n'] for c in ['tax','refund'])}
 contrasts={}
 for b,c in [('known_function_complete','all_tools_complete'),('known_function_protected','known_function_complete'),('known_function_protected','all_tools_complete')]:
  x,y=metrics[b]['macro_first_tuple_rate'],metrics[c]['macro_first_tuple_rate'];contrasts[b+'_minus_'+c]=x-y if x is not None and y is not None else None
 delta=contrasts['known_function_protected_minus_all_tools_complete']
 known_all=d.get('unknown')==0 and not findings and len(rows)==168 and len(fresh)==48
 verdict='indeterminate' if not known_all or delta is None or 0<delta<.25 else 'supported' if delta>=.25 else 'refuted'
 policy_groups={}
 for arm in ARMS:
  policy_groups[arm]={}
  for group in sorted({r['source']['context_equivalence_group'] for r in rows}):
   vals=[r for r in rows if r['arm']==arm and r['source']['context_equivalence_group']==group]
   ev=[r['endpoint_evaluation'] for r in vals if r.get('scientific_status')=='known']
   policy_groups[arm][group]={'rows':len(vals),'source_prefixes':len({r['source']['unit_id'] for r in vals}),'known':len(ev),
    'residual_allowed':sum(e.get('first_candidate_residual_allowed') is True for e in ev),
    'intended_native_effect':sum(e.get('first_candidate_intended_native_effect') is True for e in ev),
    'immediate_native_utility':sum(e.get('immediate_native_utility') is True for e in ev),
    'selected_effect_categories':dict(collections.Counter((e.get('first_candidate_selected_effect') or {}).get('category','unknown') for e in ev))}
 usage={'actual_network_calls':sum(r.get('constructor_meta',{}).get('actual_network_call') is True for r in fresh),'fresh_samples':len(fresh),'logical_rows':len(rows),'by_arm':{}}
 for arm in ARMS:
  vals=[r for r in fresh if r['arm']==arm];totals=collections.Counter();unknown=0
  for r in vals:
   u=r.get('constructor_meta',{}).get('usage')
   if not isinstance(u,dict):unknown+=1;continue
   for k,v in u.items():
    if isinstance(v,(int,float)) and not isinstance(v,bool):totals[k]+=v
  usage['by_arm'][arm]={'fresh_draws':len(vals),'reported_usage_sum':dict(totals),'usage_unknown':unknown,'sum_draw_elapsed_s':sum(r.get('elapsed_s',0) for r in vals)}
 out={'result_sha256':sha(a.result),'analysis_sha256':sha(__file__),'logical_rows':len(rows),'fresh_samples':len(fresh),'contexts':2,'policy_groups':3,
      'unknown_rows':d.get('unknown'),'findings':findings,'primary':{'metric':'valid-packet first intended financial tuple, macro average over tax/refund','delta':delta,'threshold':.25,'verdict':verdict},
      'arms':metrics,'by_context':context_metrics,'contrasts':contrasts,'by_policy_group':policy_groups,'resources':usage,
      'scope':'Two reused semantic contexts; no actor continuation; matched sample copies are not independent observations.'}
 a.out.mkdir(parents=True,exist_ok=True);(a.out/'summary.json').write_text(json.dumps(out,indent=2)+'\n')
 lines=['# Matched reconstruction diagnostic','',f"Primary delta: {delta}; verdict: {verdict}.",'','| Arm | Tax first tuple | Refund first tuple | Macro |','|---|---:|---:|---:|']
 for arm in ARMS:
  t,f=context_metrics[arm]['tax'],context_metrics[arm]['refund'];lines.append(f"| {arm} | {t['valid_packet_first_tuple']}/{t['n']} | {f['valid_packet_first_tuple']}/{f['n']} | {metrics[arm]['macro_first_tuple_rate']} |")
 lines+=['',out['scope'],f"{len(rows)} rows; {len(fresh)} fresh samples; {d.get('unknown')} unknown rows; {len(findings)} consistency findings."]
 (a.out/'RESULTS.md').write_text('\n'.join(lines)+'\n');print(json.dumps({k:out[k] for k in ['logical_rows','fresh_samples','unknown_rows','findings','primary','arms','contrasts']}))
if __name__=='__main__':main()
