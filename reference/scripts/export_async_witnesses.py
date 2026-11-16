#!/usr/bin/env python3
"""Export selected synthetic counterhistories, not raw incident/host evidence."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True)
    p.add_argument('--case',action='append',required=True);p.add_argument('--out',type=Path,required=True)
    p.add_argument('--table',type=Path,help='Label the summary table inclusive and add a disjoint-count explanation.')
    args=p.parse_args();witnesses=[]
    for name in args.case:
        path=(args.run/name/'trace.json').resolve()
        if not path.is_relative_to(args.run.resolve()):raise ValueError('case leaves run directory')
        trace=json.loads(path.read_text());observations=[row for row in trace if 'observation' in row]
        final=observations[-1]['view'];outcome=json.loads(path.with_name('outcome.json').read_text())
        witnesses.append({'case':name,'source_trace_sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
            'outcome':{k:outcome[k] for k in ['bookkeeping','profile','family','seed','expectation_met','violations','applied','effect_after_local_withdraw']},
            'provider_events':final['events'],'provider_jobs':final['jobs'],'actual_registry':final['registry'],
            'observations':[{'label':row['observation'],'local_admission_standing':row['view']['contracts']['request-1:admission']['standing'],
                             'local_admission_version':row['view']['contracts']['request-1:admission']['version'],
                             'external_revocation':row['view']['controls'],
                             'provider_fences':row['view']['invalidations'],
                             'provider_job_status':row['view']['jobs'][0]['status'] if row['view']['jobs'] else 'not_found',
                             'violations':row['violations']} for row in observations],
            'worker_results':[{key:row.get(key) for key in ['action','fault','returncode']} for row in trace if 'action' in row]})
    outcomes=args.run/'outcomes.jsonl';rows=[json.loads(line) for line in outcomes.read_text().splitlines()]
    groups=defaultdict(list)
    for row in rows:groups[row['bookkeeping'],row['profile']].append(row)
    boundaries=[]
    for (book,profile),values in sorted(groups.items()):
        # This fixture has one operation/effect and always starts local Withdraw
        # before provider fencing. Assert the subset relation before subtracting.
        for row in values:
            if 'effect_after_provider_revocation' in row['violations']:
                assert row['effect_after_local_withdraw'] and row['applied']
        post=sum('effect_after_provider_revocation' in row['violations'] for row in values)
        inclusive=sum(row['effect_after_local_withdraw'] for row in values)
        boundaries.append({'bookkeeping':book,'profile':profile,'cases':len(values),
            'post_provider_fence_violations':post,'pre_provider_propagation_gap_effects':inclusive-post,
            'local_withdraw_effects_inclusive':inclusive})
    args.out.write_text(json.dumps({'scope':'Illustrative selected synthetic witnesses plus disjoint main boundary counts. Causal snapshots/audit are trusted local observations, not authentication or root-independent proofs.','run':args.run.name,
        'outcomes_sha256':hashlib.sha256(outcomes.read_bytes()).hexdigest(),'boundary_counts':boundaries,'witnesses':witnesses},indent=2)+'\n')
    if args.table:
        table=args.table.read_text().replace('LocalWithdraw后效果 |','LocalWithdraw后效果（含ProviderFence后） |')
        if '两列效果统计重叠' not in table:
            table+='\n两列效果统计重叠，不能相加；互斥的后端撤销前传播窗口效果与撤销后违例由async-counterexamples.json记录。\n'
        args.table.write_text(table)
    print(json.dumps({'exported_witnesses':len(witnesses),'boundary_counts':boundaries}))

if __name__=='__main__':main()
