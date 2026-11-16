#!/usr/bin/env python3
"""Export path-free counters and source identities; retain raw experiments outside."""
import argparse,hashlib,json,shutil
from pathlib import Path
from summarize_intent_guard import usage

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--jobs',type=Path,required=True);p.add_argument('--frozen',type=Path,required=True)
    p.add_argument('--checks',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    names=['pga-intent-qualification-v1','intent-guard-clean-replay-v1','intent-guard-positive-attacks-replay-v1',
        'intent-coupling-check-v1','intent-paired-pilot-v2']
    for v in range(3,17):
        names+=['intent-qualification-v'+str(v),'intent-clean-paired-main-v'+str(v),'intent-positive-replay-v'+str(v)]
    names+=['intent-qualification-v8-blind','intent-full-paired-main-v8','intent-qualification-v9-facts','intent-clean-controls-main-v9',
        'intent-qualification-v10-noop','intent-full-paired-main-v10','intent-clean-repeat-main-v10',
        'intent-full-paired-main-v11','intent-qualification-v11-projection',
        'intent-qualification-v12-final','intent-qualification-v12-focus','intent-qualification-v12-minimal',
        'intent-role-replay-v12','intent-security-replay-v12','intent-role-replay-v13','intent-role-replay-v14',
        'intent-full-paired-main-v14','intent-clean-repeat-main-v14','intent-three-arm-pilot-v15',
        'intent-full-comparison-main-v15','intent-clean-comparison-repeat-v15',
        'intent-query-repair-pilot-v16','intent-seeded-repair-v16','intent-qualification-v16-frozen','intent-full-paired-main-v16','intent-clean-repeat-main-v16']
    ledger=[]
    for name in names:
        folder=a.jobs/name
        if not folder.exists():continue
        job=json.loads((folder/'job.json').read_text());result=folder/'artifacts/result.json'
        if not result.exists():result=folder/'artifacts/results.json'
        row={'job':name,'started':job['started'],'finished':job.get('finished'),'exit_code':job.get('returncode'),
            'raw_result_sha256':sha(result) if result.exists() else None,'source_inputs':{}}
        seed=folder/'artifacts/seed-record.json'
        if seed.exists():row.update(retained_baseline_actor_samples=True,not_independent_baseline=True,seed_record_sha256=sha(seed))
        for entry in job['inputs']:
            path=Path(entry['source']);parts=path.parts
            logical='/'.join(parts[parts.index('evaluation'):]) if 'evaluation' in parts else path.name
            row['source_inputs'][logical]=entry.get('sha256')
        if result.exists():
            data=json.loads(result.read_text());row['kind']=data.get('kind');row['scheduled']=data.get('scheduled',data.get('n'))
            if 'checks' in data:row.update(passed=data['passed'],n=data['n'])
            elif data.get('kind','').startswith('retained-plan'):
                rows=data['rows'];row.update(observed=len(rows),baseline_utility=sum(r.get('baseline_native_utility') is True for r in rows),
                    guard_utility=sum(r.get('native_utility') is True for r in rows),
                    retained_plan_losses=sum(r.get('baseline_native_utility') is True and r.get('native_utility') is False for r in rows),
                    unknown_utility=sum(r.get('native_utility') is None for r in rows),
                    native_asr=sum(r.get('native_targeted_asr') is True for r in rows),
                    not_fresh_actor_efficacy=True,usage=usage([{**r,'pi':{'calls':[]}} for r in rows]))
            elif 'rows' in data:
                row.update(observed=len(data['rows']),complete=data.get('complete'),
                    unobserved_scheduled=data.get('scheduled',len(data['rows']))-len(data['rows']),
                    original_campaign_loss_count=sum(r.get('utility_regression',False) for r in data['rows']),
                    audit_location='summary.json and the associated per-run pairs CSV')
        ledger.append(row)
    frozen=[]
    for folder in sorted(a.frozen.glob('frozen-guard-v*')):
        file=folder/'source-identities.json'
        if file.exists():frozen.append({'revision':folder.name,'manifest_sha256':sha(file),'source_sha256':json.loads(file.read_text())})
    result={'kind':'All retained development revisions, pilots and diagnostic replays; not pooled efficacy',
        'historical_original_run':'See evidence/pi-full; the original measured sources and scores are unchanged.',
        'raw_storage':'Research run store indexed by job name; raw task/provider data is not copied into this publication bundle.',
        'runs':ledger,'frozen_revisions':frozen}
    (a.out/'development-ledger.json').write_text(json.dumps(result,indent=2)+'\n')
    for source,name in [(a.jobs/'intent-qualification-v16-frozen/artifacts/result.json','qualification.json'),
        (a.checks/'coupling-v7/result.json','coupling-checks.json'),(a.checks/'measurement-check-v15/result.json','measurement-checks.json'),
        (a.checks/'protocol-check-v16/result.json','protocol-checks.json')]:
        shutil.copyfile(source,a.out/name)
    print(json.dumps({'retained_runs':len(ledger),'frozen_revisions':len(frozen),'raw_records_exported':False}))
if __name__=='__main__':main()
