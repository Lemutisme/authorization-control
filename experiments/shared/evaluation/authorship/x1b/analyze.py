"""Native scores and empirical factorial contrasts; field conclusions await source audit."""
import argparse
import json
from pathlib import Path
import random
from run import ARMS

def interval(values):
    rng=random.Random(20261112)
    draws=sorted(sum(rng.choices(values,k=len(values)))/len(values) for _ in range(10000))
    return [draws[249],draws[9749]]

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    raw=json.loads((a.run/'summary.json').read_text());assert raw.get('phase','main')=='main','Smoke is exploratory and must not enter main analysis';rows=raw['rows'];a.out.mkdir(parents=True,exist_ok=True)
    summary={'complete':raw['complete'],'scheduled_episodes':384,'observed_episodes':len(rows)*6,'arms':{},'contrasts':{},'field_effect_status':'indeterminate_pending_complete_source_qualified_manual_audit','competence_sign_status':'not_identified_by_end_to_end_factorial'}
    for arm,_,_ in ARMS:
        es=[r['arms'][arm] for r in rows];success=sum(e.get('native_utility') is True for e in es);unknown=sum(e.get('native_utility') is None for e in es)
        summary['arms'][arm]={'n':len(es),'native_utility':success,'unknown':unknown,'scheduled_n':64,'success_bounds_over_scheduled':[success/64,(success+unknown+64-len(es))/64],'statuses':{s:sum(e.get('status')==s for e in es) for s in sorted(set(e.get('status','missing') for e in es))},'actor_network_calls':sum(c.get('actual_network_call') is True for e in es for c in e.get('pi',{}).get('calls',[])),'constructor_network_calls':sum(c.get('actual_network_call') is True for e in es for c in e.get('policy_calls',[]))}
    for arm,_,_ in ARMS:
        es=[r['arms'][arm] for r in rows]
        calls=[c for e in es for c in e.get('pi',{}).get('calls',[])]+[c for e in es for c in e.get('policy_calls',[])]
        network=[c for c in calls if c.get('actual_network_call') is True]
        costs=[(c.get('pi_usage') or c.get('usage') or {}).get('cost',{}).get('total') for c in network]
        summary['arms'][arm].update(standard_list_price_estimate_usd=sum(c for c in costs if isinstance(c,(int,float))),network_calls_missing_standard_cost=sum(c is None for c in costs),actor_batch_violations=sum(e.get('actor_batch_violations',0) for e in es),cost_limit='Standard list-price estimate only; missing and failed-process usage stays unknown; provider invoice unavailable')
    comparisons={}
    for u in ('none','medium'):
        comparisons[f'constructor_medium_minus_none_at_actor_{u}']={f'forced_u{u}_cmedium':1,f'forced_u{u}_cnone':-1}
        for c in ('none','medium'):comparisons[f'gate_minus_nogate_u{u}_c{c}']={f'forced_u{u}_c{c}':1,f'nogate_u{u}':-1}
    for c in ('none','medium'):comparisons[f'actor_medium_minus_none_at_constructor_{c}']={f'forced_umedium_c{c}':1,f'forced_unone_c{c}':-1}
    comparisons['no_gate_actor_medium_minus_none']={'nogate_umedium':1,'nogate_unone':-1}
    comparisons['interaction']={'forced_umedium_cmedium':1,'forced_umedium_cnone':-1,'forced_unone_cmedium':-1,'forced_unone_cnone':1}
    for name,weights in comparisons.items():
        tasks={}
        for r in rows:
            if all(r['arms'][arm].get('native_utility') in (True,False) for arm in weights):tasks.setdefault(r['task_id'],[]).append(sum(w*int(r['arms'][arm]['native_utility']) for arm,w in weights.items()))
        complete=[sum(v)/4 for v in tasks.values() if len(v)==4]
        summary['contrasts'][name]={'complete_owner_tasks':len(complete),'mean':sum(complete)/len(complete) if complete else None,'task_bootstrap_95':interval(complete) if complete else None,'limit':'complete-task descriptive contrast; failures remain in arm bounds'}
    (a.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    (a.out/'results.md').write_text('X1b native outcomes\n\n'+ '\n'.join(f"- {arm}: {s['native_utility']}/64 successful; {s['unknown']} observed unknown." for arm,s in summary['arms'].items())+'\n\nField repairs/induced effects remain indeterminate until the complete native-source audit. Reasoning profiles do not identify a constructor/actor competence ordering.\n')
    (a.out/'table.tex').write_text('\n'.join(f"{arm.replace('_',r'\_')} & {s['native_utility']} & 64 & {s['unknown']} \\\\" for arm,s in summary['arms'].items())+'\n')
if __name__=='__main__':main()
