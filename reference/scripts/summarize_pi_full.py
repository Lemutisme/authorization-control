#!/usr/bin/env python3
"""Full-scope summary with explicit scheduled, observed, unsupported and unknown."""
import argparse,csv,hashlib,json
from pathlib import Path

RATES={'input':0.10,'cache_read':0.01,'cache_write':0.125,'output':0.50}

def usage(rows):
    total={'model_calls':0,'actor_calls':0,'grounding_calls':0,'input_tokens':0,'cached_input_tokens':0,
        'cache_write_tokens':0,'output_tokens':0,'missing_usage_calls':0,'episodes_without_call_records':0,
        'known_usage_standard_price_usd':0.0,'provider_cost_subtotal':0.0,'calls_with_provider_cost':0}
    requested=set();returned=set()
    for row in rows:
        if 'pi' not in row:total['episodes_without_call_records']+=1
        for role,items in [('actor',row.get('pi',{}).get('calls',[])),('grounding',row.get('grounding_calls',[]))]:
            for call in items:
                total['model_calls']+=1;total[role+'_calls']+=1
                if call.get('requested_model'):requested.add(call['requested_model'])
                if call.get('returned_model'):returned.add(call['returned_model'])
                u=call.get('provider_usage') if role=='actor' else call.get('usage')
                if not u:total['missing_usage_calls']+=1;continue
                details=u.get('input_tokens_details') or {};inp=u['input_tokens'];out=u['output_tokens']
                cached=details.get('cached_tokens') or 0;written=details.get('cache_write_tokens') or 0
                if cached+written>inp:raise ValueError('Cache categories do not partition input')
                total['input_tokens']+=inp;total['cached_input_tokens']+=cached;total['cache_write_tokens']+=written;total['output_tokens']+=out
                in_factor,out_factor=(2,1.5) if inp>272000 else (1,1)
                total['known_usage_standard_price_usd']+=(in_factor*((inp-cached-written)*RATES['input']+cached*RATES['cache_read']+written*RATES['cache_write'])+out_factor*out*RATES['output'])/1e6
                if isinstance(u.get('cost'),(int,float)):total['provider_cost_subtotal']+=u['cost'];total['calls_with_provider_cost']+=1
    total.update(requested_models=sorted(requested),returned_models=sorted(returned),
        complete_usage_records=total['missing_usage_calls']==0 and total['episodes_without_call_records']==0)
    return total

def group(rows):
    return {'observed':len(rows),'native_success':sum(r.get('native_utility') is True for r in rows),
        'utility_unknown':sum(r.get('native_utility') is None for r in rows),
        'asr_true':sum(r.get('native_targeted_asr') is True for r in rows),
        'asr_unknown':sum(r.get('native_targeted_asr') is None for r in rows if r['condition']=='attack'),
        'supported':sum(r['profile_supported'] for r in rows),
        'native_success_with_zero_invocations':sum(r.get('native_utility') is True and r.get('native_invocations')==0 for r in rows),
        'native_success_zero_invocation_ids':[r['case_id'] for r in rows if r.get('native_utility') is True and r.get('native_invocations')==0],
        'payload_marker_exposed':sum(r.get('injection_exposure_outputs',0)>0 for r in rows),
        'asr_true_with_payload_marker':sum(r.get('native_targeted_asr') is True and r.get('injection_exposure_outputs',0)>0 for r in rows),
        'native_invocations':sum(r.get('native_invocations',0) for r in rows),
        'tool_proposals':sum(r.get('tool_proposals',0) for r in rows),
        'policy_oracle_unknown':sum(r.get('structural_assessment',{}).get('unknown') is not False for r in rows),
        'status_counts':{s:sum(r['status']==s for r in rows) for s in sorted({r['status'] for r in rows})}}

def main():
    p=argparse.ArgumentParser();p.add_argument('--inventory',type=Path,required=True);p.add_argument('--runs',type=Path,nargs='*',default=[]);p.add_argument('--out',type=Path,required=True);p.add_argument('--require-complete',action='store_true');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    inventory=json.loads(a.inventory.read_text());arms=[]
    for path in a.runs:
        data=json.loads(path.read_text());rows=data['rows']
        if len({r['case_id'] for r in rows})!=len(rows):raise ValueError('Duplicate cases')
        config=json.loads(path.with_name('run-config.json').read_text())
        if data['manifest_sha256']!=inventory['manifest_sha256']:raise ValueError('Manifest mismatch')
        if a.require_complete and (not data['complete'] or len(rows)!=data['scheduled'] or {r['case_id'] for r in rows}!=set(config['case_ids'])):raise ValueError('Incomplete scheduled coverage')
        result={'arm':data['arm'],'scheduled':data['scheduled'],'complete':data['complete'],'observed':len(rows),
            'source_result_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'conditions':{},'suites':{},
            'usage':usage(rows),'elapsed_s':data['elapsed_s'],'status_counts':group(rows)['status_counts'],
            'source_job':path.parent.parent.name,
            'supported_conditions':{},'unsupported_conditions':{}}
        for condition in ['clean','attack','goal_control']:result['conditions'][condition]=group([r for r in rows if r['condition']==condition])
        for condition in ['clean','attack']:
            result['supported_conditions'][condition]=group([r for r in rows if r['condition']==condition and r['profile_supported']])
            result['unsupported_conditions'][condition]=group([r for r in rows if r['condition']==condition and not r['profile_supported']])
        for suite in ['workspace','travel','banking','slack']:
            result['suites'][suite]={c:group([r for r in rows if r['suite']==suite and r['condition']==c]) for c in ['clean','attack','goal_control']}
        arms.append(result)
        fields=['case_id','suite','task_id','condition','injection_id','profile_supported','status','native_utility','native_targeted_asr','tool_proposals','native_invocations','injection_exposure_outputs','policy_oracle_verdict','elapsed_s','model_calls','input_tokens','cached_input_tokens','cache_write_tokens','output_tokens','missing_usage_calls','episodes_without_call_records','known_usage_standard_price_usd']
        with (a.out/(data['arm']+'-episodes.csv')).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore',lineterminator='\n');w.writeheader()
            for row in rows:w.writerow({**row,**usage([row]),'policy_oracle_verdict':row.get('structural_assessment',{}).get('verdict')})
    report={'kind':'Full-scope native results; missing/unsupported retained',
        'inventory_sha256':hashlib.sha256(a.inventory.read_bytes()).hexdigest(),'planned_counts':inventory['counts'],
        'main_results_available':bool(arms),'all_main_runs_complete':bool(arms) and all(x['complete'] for x in arms),'arms':arms,
        'rates_per_million_usd':RATES,'cost_interpretation':'Known-usage standard price estimate, not verified invoice; missing episodes/calls are excluded from this monetary subtotal and remain unknown.',
        'limits':['Goal controls are not ordinary user utility or attacked ASR.','Only three workspace policy profiles and owner-policy oracle are supported.','Native trace predicates may count proposals without invoked effects.','One existing attack family; not all attack methods.']}
    (a.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'main_results_available':bool(arms),'arms':len(arms),'planned':report['planned_counts']},indent=2))
    if arms:
        lines=['# Full-registry Pi/Luna evaluation','',
            'Fixed AgentDojo v1.2.2 registry at the recorded source pin; one existing NoNames attack family. Official Pi Agent/Pi AI 1.5.0; gpt-6-luna with reasoning none. All profile coverage and failed/missing outcomes remain in the record.','',
            '| Arm | Clean native utility | Attacked native utility | Native targeted ASR | Separate goal controls | Attacked score unknown |',
            '|---|---:|---:|---:|---:|---:|']
        for arm in arms:
            c=arm['conditions'];fmt=lambda name:f"{c[name]['native_success']}/{c[name]['observed']}"
            lines.append(f"| Pi {arm['arm']} | {fmt('clean')} | {fmt('attack')} | {c['attack']['asr_true']}/{c['attack']['observed']} | {fmt('goal_control')} | {c['attack']['asr_unknown']} |")
        lines+=['','Native ASR counts use all scheduled attacked pairs, including explicit unknowns; the confirmed count is a lower bound when scores are missing. Goal controls do not enter clean utility or ASR. An adapter error has unknown consequences and cost, not a safe outcome.','',
            '| Suite | Arm | Clean utility | Attack utility | Native ASR | Attack score unknown |','|---|---|---:|---:|---:|---:|']
        for arm in arms:
            for suite,c in arm['suites'].items():
                lines.append(f"| {suite} | {arm['arm']} | {c['clean']['native_success']}/{c['clean']['observed']} | {c['attack']['native_success']}/{c['attack']['observed']} | {c['attack']['asr_true']}/{c['attack']['observed']} | {c['attack']['asr_unknown']} |")
        lines+=['','Only three workspace user-task profiles are supported. Native scores from unsupported tasks do not demonstrate policy coverage. The companion scoring review explains zero-invocation banking successes, distinguishing permissive predicates from deliberate no-op criteria.','',
            '| Arm | Recorded calls | Input / output tokens | Cache read / write tokens | Known-usage price estimate | Episodes with unknown call records |',
            '|---|---:|---:|---:|---:|---:|']
        for arm in arms:
            u=arm['usage'];lines.append(f"| {arm['arm']} | {u['model_calls']} | {u['input_tokens']} / {u['output_tokens']} | {u['cached_input_tokens']} / {u['cache_write_tokens']} | ${u['known_usage_standard_price_usd']:.6f} | {u['episodes_without_call_records']} |")
        lines+=['','Prices use the documented standard rates including cache writes, with long-context adjustment where applicable. Shared provider load/cache history and different rejection behavior prevent attributing monetary differences to a more efficient algorithm. No invoice is verified.','',
            'The original development studies, separate pilots and rejected launch attempts are retained. This is neither a held-out profile-learning experiment nor a comparison against an independently implemented, equally equipped SOP. Native trace-based predicates and accepted effects remain distinct; final-response confidentiality is outside the three-profile oracle.']
        (a.out/'results.md').write_text('\n'.join(lines)+'\n')

if __name__=='__main__':main()
