"""All scheduled rows, task-paired contrasts, missingness and measured API usage."""
import argparse,collections,gzip,json,random,statistics
from fractions import Fraction
from pathlib import Path
HERE=Path(__file__).resolve().parent

def contrast(rows,metric,armkey,positive,negative):
    tasks=collections.defaultdict(lambda:collections.defaultdict(dict))
    for r in rows:
        unit=r['source']['packet']
        rep=r['source']['repetition']
        tasks[r['source']['task']][(unit,rep)][r['source'][armkey]]=r['metrics'].get(metric)
    taskrows=[]
    for task,units in sorted(tasks.items()):
        low=high=Fraction()
        for values in units.values():
            for arm,c in [(positive,1),(negative,-1)]:
                v=values.get(arm)
                low+=c*v if v is not None else min(0,c)
                high+=c*v if v is not None else max(0,c)
        taskrows.append({'task':task,'units_draws':len(units),'lower':float(low/len(units)),'upper':float(high/len(units))})
    if not taskrows:return None
    lo=statistics.mean(r['lower'] for r in taskrows);hi=statistics.mean(r['upper'] for r in taskrows)
    loto=[{'removed':r['task'],'lower':statistics.mean(q['lower'] for q in taskrows if q is not r),
           'upper':statistics.mean(q['upper'] for q in taskrows if q is not r)} for r in taskrows] if len(taskrows)>1 else []
    ci=None
    if lo==hi:
        rng=random.Random(20261114);v=[r['lower'] for r in taskrows]
        samples=sorted(statistics.mean(rng.choices(v,k=len(v))) for _ in range(10000))
        ci=[samples[249],samples[9749]]
    return {'lower':lo,'upper':hi,'tasks':taskrows,'leave_one_task_out':loto,'descriptive_task_bootstrap95':ci,
            'uncertainty_scope':'Missing-outcome bounds; bootstrap describes this inspected task panel, not a randomly sampled deployment population.'}

def main():
    p=argparse.ArgumentParser();p.add_argument('--phase',choices=['pilot','main'],default='main');p.add_argument('--version',default='v1');p.add_argument('--out',default='analysis');a=p.parse_args()
    protocol=json.loads((HERE/f'protocol-{a.phase}.json').read_text());rows=[];missing=[];usage=collections.defaultdict(collections.Counter)
    statuses=collections.defaultdict(collections.Counter)
    for source in protocol['rows']:
        kind=source['kind'] if a.phase=='main' else 'all'
        path=HERE/'outputs'/f"{a.phase}-{source['model']}-{kind}-{a.version}"/'raw'/(source['id']+'.json.gz')
        raw=None;error=None
        try:
            raw=json.loads(gzip.decompress(path.read_bytes()))
            if raw.get('dry'):raise ValueError('Dry result cannot enter efficacy analysis')
        except Exception as exc:error=type(exc).__name__;missing.append(source['id'])
        metrics={'admission':None,'correct_selected_effect':None,'wrong_selected_effect':None,'native_utility':None}
        if raw:
            if source['kind']=='update':metrics['admission']=raw.get('admission')
            else:metrics.update(raw.get('metrics',{}))
            statuses[source['model']][raw.get('status','update_returned')]+=1
            for req in raw.get('requests',[]):
                usage[source['model']]['network_requests']+=req.get('network_requests',1)
                usage[source['model']]['identity_mismatches']+=bool(req.get('ok') and not req.get('model_label_matches'))
                u=req.get('usage')
                if not u:usage[source['model']]['usage_missing_requests']+=1;continue
                usage[source['model']]['input_tokens']+=u.get('input_tokens',u.get('prompt_tokens',0))
                usage[source['model']]['output_tokens']+=u.get('output_tokens',u.get('completion_tokens',0))
                usage[source['model']]['cache_read_tokens']+=u.get('cache_read_input_tokens',0)
                usage[source['model']]['cache_write_tokens']+=u.get('cache_creation_input_tokens',0)
                usage[source['model']]['reasoning_tokens']+=(u.get('completion_tokens_details') or {}).get('reasoning_tokens',0)+(u.get('output_tokens_details') or {}).get('reasoning_tokens',(u.get('output_tokens_details') or {}).get('thinking_tokens',0))
        rows.append({'source':source,'raw_path':str(path),'present':raw is not None,'error':error,'metrics':metrics,
                     'status':raw.get('status','update_returned') if raw else 'missing',
                     'first_action':raw.get('first_action') if raw and source['kind']=='unforced' else None})
    result={'scheduled':len(rows),'observed':sum(r['present'] for r in rows),'missing':missing,'phase':a.phase,
            'usage':{k:dict(v) for k,v in usage.items()},'statuses':{k:dict(v) for k,v in statuses.items()},'contrasts':{},'counts':[]}
    for model in protocol['models']:
        for direction,metric in [('corruption','wrong_selected_effect'),('correction','correct_selected_effect')]:
            selected=[r for r in rows if r['source']['kind']=='actor' and r['source']['model']==model and r['source']['direction']==direction]
            c=contrast(selected,metric,'feedback','value_stating','value_free');result['contrasts'][model+'_'+direction]=c
            if c:
                result[model+'_'+direction+'_delta_lower']=c['lower'];result[model+'_'+direction+'_delta_upper']=c['upper']
            for f in ['value_stating','value_free']:
                cell=[r for r in selected if r['source']['feedback']==f]
                result['counts'].append({'model':model,'panel':direction,'arm':f,'n':len(cell),
                    **{m:sum(r['metrics'][m]==1 for r in cell) for m in ['wrong_selected_effect','correct_selected_effect','native_utility']},
                    'unknown':sum(r['metrics'][metric] is None for r in cell)})
        for panel in ['attack','honest_fault','honest_natural']:
            selected=[r for r in rows if r['source']['kind']=='update' and r['source']['model']==model and r['source']['panel']==panel]
            c=contrast(selected,'admission','visible',True,False);name=model+('_permission' if panel=='attack' else '_'+panel+'_permission')
            result['contrasts'][name]=c
            if c:result[name+'_delta_lower']=c['lower'];result[name+'_delta_upper']=c['upper']
            for visible in [False,True]:
                cell=[r for r in selected if r['source']['visible']==visible]
                result['counts'].append({'model':model,'panel':'update_'+panel,'arm':'visible' if visible else 'hidden',
                    'n':len(cell),'admitted':sum(r['metrics']['admission']==1 for r in cell),'unknown':sum(r['metrics']['admission'] is None for r in cell)})
    out=HERE/a.out;out.mkdir(parents=True,exist_ok=True)
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n');(out/'rows.json').write_text(json.dumps(rows,indent=2)+'\n')
    lines=[f"{a.phase}: {result['observed']}/{result['scheduled']} raw records. Missing rows remain unknown.",
           '', '|Model|Panel|Arm|N|Wrong|Correct|Utility|Admitted|Unknown|','|---|---|---|---:|---:|---:|---:|---:|---:|']
    for r in result['counts']:
        lines.append('|'+ '|'.join(str(r.get(k,'—')) for k in ['model','panel','arm','n','wrong_selected_effect','correct_selected_effect','native_utility','admitted','unknown'])+'|')
    lines+=['','Task-macro contrasts (missing-outcome bounds, not confidence intervals):']
    for name,c in result['contrasts'].items():
        if c:lines.append(f"- {name}: {100*c['lower']:.3f} to {100*c['upper']:.3f} pp; {len(c['tasks'])} task clusters.")
    (out/'RESULTS.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k.endswith('_delta_lower') or k in ['scheduled','observed','usage']},indent=2))
if __name__=='__main__':main()
