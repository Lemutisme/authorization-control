"""Reconstruct relation scores and compiler invariants from retained raw programs."""
import argparse,collections,hashlib,json,sys
from decimal import Decimal
from pathlib import Path
from kernel import Resolver,digest
MODES=['values','refs','query']
def normal(x):
    if type(x) in (int,float):return ('number',str(Decimal(str(x)).normalize()))
    if isinstance(x,list):return ('list',tuple(map(normal,x)))
    if isinstance(x,dict):return ('object',tuple((k,normal(v)) for k,v in sorted(x.items())))
    return (type(x).__name__,x)
def bag(rows):return collections.Counter(normal({'function':r['function'],'arguments':r['arguments']}) for r in rows)
def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    cfg=json.loads((a.run/'run-config.json').read_text());scheduled=json.loads((a.run/'results.json').read_text());manifest=json.loads(a.manifest.read_text());fixtures={c['case_id']:json.loads((a.manifest.parent/c['path']).read_text()) for c in manifest['cases']}
    issues=[];rows=[];by_mode={m:collections.Counter() for m in MODES};usage={m:collections.Counter() for m in MODES};materializations=0
    for job in cfg['jobs']:
      case=job['case_id'];rep=job['replicate'];f=fixtures[case];view=f['view'];expected=bag(f['oracle']['expected_effects']);trip={}
      for mode in MODES:
        pre=a.run/case/f'replicate-{rep}'/mode;rawpath=Path(str(pre)+'.raw.json')
        if not rawpath.exists():issues.append([case,rep,mode,'missing_raw']);by_mode[mode]['missing_raw']+=1;continue
        raw=json.loads(rawpath.read_text());r=raw['result'];policy=raw['policy'];attempts=raw['attempts'];error=None;compiled=None
        if json.loads(raw['input']['user'])!=view:issues.append([case,rep,mode,'public_view_mismatch'])
        if r['public_view_sha256']!=digest(view):issues.append([case,rep,mode,'view_hash'])
        for index,att in enumerate(attempts):
          if att['response'].get('ok'):
            try:compiled,_=Resolver(view).materialize(att['response']['program'],mode);error=None;materializations+=1
            except Exception as e:error=type(e).__name__+': '+str(e)[:180];compiled=None
            if (error is not None)!=('compiler_error' in att):issues.append([case,rep,mode,index,'compiler_error_mismatch'])
          if index:
            if 'compiler_error' not in attempts[index-1]:issues.append([case,rep,mode,'noncompiler_retry'])
            prev=attempts[index-1];canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
            user=raw['input']['user']+'\nCompiler feedback: '+prev['compiler_error']+'\nPrevious proposed program: '+canonical(prev['response']['program'])+'\nReturn a corrected proposal using the same task and facts.'
            if att['input_sha256']!=digest({'system':raw['input']['system'],'user':user}):issues.append([case,rep,mode,'repair_context_mismatch'])
          meta=att['response'].get('meta') or {};u=meta.get('usage') or {};usage[mode]['requests']+=1;usage[mode]['network_prepared']+=meta.get('actual_network_call') is True;usage[mode]['usage_known']+=bool(u)
          for k in ['input_tokens','output_tokens','total_tokens']:usage[mode][k]+=u.get(k,0)
          if meta.get('requested_model')!='gpt-6-luna':issues.append([case,rep,mode,'model_mismatch'])
        if len(attempts)>2:issues.append([case,rep,mode,'budget_exceeded'])
        if r['status']=='constructed' and compiled!=policy:issues.append([case,rep,mode,'lowering_mismatch'])
        if r['status']!='constructed' and policy['allowed_effects']:issues.append([case,rep,mode,'invalid_not_closed'])
        if digest(policy)!=r['policy_sha256']:issues.append([case,rep,mode,'policy_hash'])
        if r['compiler_repairs']!=max(0,len(attempts)-1):issues.append([case,rep,mode,'repair_count'])
        actual=bag(policy['allowed_effects']);exact=r['status']=='constructed' and actual==expected;missing=sum((expected-actual).values());extra=sum((actual-expected).values())
        if (exact,missing,extra)!=(r['exact_grounding'],r['missing_rows'],r['extra_rows']):issues.append([case,rep,mode,'score_mismatch'])
        by_mode[mode].update({'n':1,'exact':int(exact),'missing_effects':missing,'extra_effects':extra,r['status']:1,'repairs':r['compiler_repairs']})
        trip[mode]=exact;rows.append({'case_id':case,'domain':f['domain'],'replicate':rep,'mode':mode,'exact':exact,'status':r['status'],'missing':missing,'extra':extra,'repairs':r['compiler_repairs'],'policy_sha256':digest(policy),'raw_sha256':hashlib.sha256(rawpath.read_bytes()).hexdigest()})
    comparisons={}
    for base in ['values','refs']:
      gains=[];losses=[]
      for job in cfg['jobs']:
        rr={r['mode']:r for r in rows if r['case_id']==job['case_id'] and r['replicate']==job['replicate']}
        if len(rr)!=3:continue
        if rr['query']['exact'] and not rr[base]['exact']:gains.append({'case_id':job['case_id'],'domain':rr['query']['domain'],'replicate':job['replicate']})
        if rr[base]['exact'] and not rr['query']['exact']:losses.append({'case_id':job['case_id'],'domain':rr['query']['domain'],'replicate':job['replicate']})
      comparisons[base]={'gains':gains,'losses':losses,'net_exact':len(gains)-len(losses),'gain_families':sorted(set(g['domain'] for g in gains))}
    by_task={c:{m:sum(r['exact'] for r in rows if r['case_id']==c and r['mode']==m) for m in MODES} for c in sorted(set(j['case_id'] for j in cfg['jobs']))}
    result={'scope':'Fixed source-inspected developmental tasks; repeated construction calls are not independent task samples. This is reconstruction by a distinct scoring routine, not an independently authored review.','phase':cfg['phase'],'scheduled_triples':len(cfg['jobs']),'raw_constructions':len(rows),'by_mode':{k:dict(v) for k,v in by_mode.items()},'by_task':by_task,'query_vs':comparisons,'query_advantage_threshold_met':all(c['net_exact']>=3 and len(c['gain_families'])>=2 for c in comparisons.values()) and not issues,'usage':{k:dict(v) for k,v in usage.items()},'cost_limit':'Provider invoice unavailable; tokens only. Network-prepared count is not a guarantee of server receipt.','reconstructed_materializations':materializations,'audit_findings':issues,'rows':rows}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({k:result[k] for k in ['phase','raw_constructions','by_mode','by_task','query_advantage_threshold_met','audit_findings']},indent=2))
if __name__=='__main__':main()
