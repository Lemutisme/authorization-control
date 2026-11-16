#!/usr/bin/env python3
"""Derive all exploratory PGA figures/tables from scheduled native episode records."""
from __future__ import annotations
import argparse,csv,hashlib,json,statistics
from collections import Counter
from pathlib import Path

LABELS={'none':'No added gate','delimiting':'Output delimiting','repeat_prompt':'Repeat prompt','static':'Static gate','acquire_all':'Acquire-all','adaptive_sop':'Adaptive SOP','pga':'PGA active'}

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def mean(values):
    v=[x for x in values if isinstance(x,(int,float)) and not isinstance(x,bool)]
    return statistics.mean(v) if v else None

def counts(rows,field):
    return {'true':sum(r.get(field) is True for r in rows),'false':sum(r.get(field) is False for r in rows),'unknown':sum(r.get(field) not in (True,False) or r.get(field) is None for r in rows),'n':len(rows)}

def group(rows):
    effects=[r.get('effect_score') for r in rows]
    v=[bool(s and s.get('violation')) for s in effects]
    a=[s is None or bool(s.get('unknown')) for s in effects]
    calls=[c for r in rows for c in r.get('calls',[])]
    return {'n':len(rows),'completed':sum(r.get('status')=='completed' for r in rows),
            'utility':counts(rows,'native_utility'),'asr':counts([r for r in rows if r.get('condition')=='attack'],'native_targeted_asr'),
            'structural_violations':sum(v),'assessment_unknown':sum(a),'violation_or_unknown':sum(x or y for x,y in zip(v,a)),
            'authorization_unresolved_episodes':sum(any(d.get('verdict')=='unresolved' for d in r.get('gate_decisions',[])) for r in rows),
            'blocked_episodes':sum(any(d.get('verdict')!='allow' for d in r.get('gate_decisions',[])) for r in rows),
            'attack_exposed_episodes':sum(r.get('injection_exposure_outputs',0)>0 for r in rows),
            'mean_collectors':mean([r.get('collector_invocations') for r in rows]),
            'mean_model_calls':mean([r.get('model_calls') for r in rows]),'mean_seconds':mean([r.get('elapsed_s') for r in rows]),
            'input_tokens_known':sum((c.get('usage') or {}).get('input_tokens',0) or 0 for c in calls),
            'output_tokens_known':sum((c.get('usage') or {}).get('output_tokens',0) or 0 for c in calls),
            'cached_input_tokens_known':sum(((c.get('usage') or {}).get('input_tokens_details') or {}).get('cached_tokens',0) or 0 for c in calls),
            'calls_missing_usage':sum(c.get('usage') is None for c in calls),
            'status_counts':dict(Counter(r.get('status') for r in rows))}

def fraction(v):
    if not v['n']:return 'unmeasured'
    if v['unknown']:return f"{v['true']}/{v['n']-v['unknown']} scored; {v['unknown']} unscored ({v['n']} scheduled)"
    return f"{v['true']}/{v['n']}"
def value(v):return f'{v:.2f}' if v is not None else 'unmeasured'

def main():
    p=argparse.ArgumentParser();p.add_argument('--runs',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--allow-partial',action='store_true');a=p.parse_args()
    manifest=json.loads(a.manifest.read_text());cases={c['case_id']:c for c in manifest['cases']};all_rows=[];inputs={};arm_rows=[];seen=set()
    for arm in manifest['arms']:
        f=a.runs/arm/'results.json';rows=[]
        if f.exists():
            d=json.loads(f.read_text());inputs[arm+'/results.json']=sha(f)
            if d['manifest_sha256']!=sha(a.manifest):raise ValueError('Manifest identity changed: '+arm)
            rows=d['rows']
            for r in rows:
                k=(arm,r['case_id'])
                if k in seen or r['case_id'] not in cases:raise ValueError('Unexpected/duplicate case')
                seen.add(k);c=cases[r['case_id']]
                if r['arm']!=arm or r['task_id']!=c['task_id'] or r['condition']!=c['condition'] or r['injection_id']!=c['injection_id']:raise ValueError('Cohort mismatch')
                if c['condition']!='attack' and r.get('native_targeted_asr') is not None:raise ValueError('Non-attack included in ASR')
                raw=a.runs/arm/(r['case_id']+'.json.gz')
                if raw.exists():r['raw_sha256']=sha(raw)
                else:r['raw_sha256']=None
            all_rows.extend(rows)
        if not a.allow_partial and len(rows)!=len(cases):raise ValueError('Incomplete arm: '+arm)
        arm_rows.append({'arm':arm,'label':LABELS[arm],'scheduled':len(cases),'observed':len(rows),
                         'all':group(rows),'clean':group([r for r in rows if r['condition']=='clean']),
                         'attack':group([r for r in rows if r['condition']=='attack']),
                         'sham':group([r for r in rows if r['condition']=='sham']),
                         'by_task':{t:group([r for r in rows if r['task_id']==t]) for t in manifest['tasks']}})
    models=sorted({r.get('transport',{}).get('requested_model') for r in all_rows if r.get('transport')})
    config_hashes=sorted({r.get('transport',{}).get('provider_config_sha256') for r in all_rows if r.get('transport',{}).get('provider_config_sha256')})
    if len(models)>1 or len(config_hashes)>1:raise ValueError('Model/provider configuration drift; do not pool automatically')
    summary={'kind':'Exploratory source-read AgentDojo DEVELOPMENT results; no population or selector-superiority claim',
             'manifest_sha256':sha(a.manifest),'source_pin':manifest['source_pin'],'scheduled':len(manifest['arms'])*len(cases),'observed':len(all_rows),
             'input_sha256':inputs,'models':models,'provider_config_sha256':config_hashes,'arms':arm_rows,'all':group(all_rows),
             'scope':'independent structural mutation envelope only; reads/final disclosures/content semantics not certified',
             'independence':'three source-read task types; no blinded holdout; equivalent-policy SOP/PGA repetitions are not a causal selector contrast',
             'execution':'directly owned native foreground processes; AROS main attempts were stopped by historical holder registration before execution',
             'cost_limit':'reported tokens and wall time; monetary price unavailable'}
    a.out.mkdir(parents=True,exist_ok=True);(a.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    fields=['arm','case_id','task_id','condition','status','native_utility','native_targeted_asr','structural_violation','assessment_unknown','auth_unresolved','collector_invocations','model_calls','actual_invocations','elapsed_s','injection_exposure_outputs','input_tokens','output_tokens','raw_sha256']
    with (a.out/'episodes.csv').open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=fields,lineterminator="\n");writer.writeheader()
        for r in all_rows:
            s=r.get('effect_score');calls=r.get('calls',[])
            row={k:r.get(k) for k in fields};row.update(structural_violation=bool(s and s.get('violation')),assessment_unknown=s is None or bool(s.get('unknown')),
                auth_unresolved=any(d.get('verdict')=='unresolved' for d in r.get('gate_decisions',[])),input_tokens=sum((c.get('usage') or {}).get('input_tokens',0) or 0 for c in calls),output_tokens=sum((c.get('usage') or {}).get('output_tokens',0) or 0 for c in calls))
            writer.writerow(row)
    lines=['# Exploratory AgentDojo results','',f"Accounted episodes: {len(all_rows)}/{summary['scheduled']}. Three source-read development tasks; one run per arm/case. Native utility is shown as counts, not independent-task statistics.",'',
           '| Arm | Clean utility | Attack utility | Sham utility | Targeted ASR | Attack PV / unknown | Mean collectors (attack) | Mean seconds (all) |',
           '|---|---:|---:|---:|---:|---:|---:|---:|']
    for r in arm_rows:
        b=r['attack'];lines.append(f"| {r['label']} | {fraction(r['clean']['utility'])} | {fraction(b['utility'])} | {fraction(r['sham']['utility'])} | {fraction(b['asr'])} | {b['structural_violations']}/{b['n']} / {b['assessment_unknown']}/{b['n']} | {value(b['mean_collectors'])} | {value(r['all']['mean_seconds'])} |")
    lines+=['','PGA and adaptive SOP have the same query choice in these profiles. This study cannot establish a nontrivial selector advantage. Zero targeted ASR in a comparator is an attack-floor limitation, not proof of universal robustness. Task7 binding unknowns and refused tasks remain in the counts.','',
            f"Known model usage: {summary['all']['input_tokens_known']} input tokens, {summary['all']['output_tokens_known']} output tokens; {summary['all']['calls_missing_usage']} calls lack usage. Monetary cost unavailable."]
    (a.out/'results.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'scheduled':summary['scheduled'],'observed':summary['observed'],'models':models,'input_tokens':summary['all']['input_tokens_known'],'output_tokens':summary['all']['output_tokens_known'],'completed':summary['all']['completed']},indent=2))
if __name__=='__main__':main()
