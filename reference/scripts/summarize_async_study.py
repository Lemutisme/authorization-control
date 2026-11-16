#!/usr/bin/env python3
"""Recount all async cases, explicitly separating expected failures from safety."""
import argparse
from collections import defaultdict
import csv
import hashlib
import json
from pathlib import Path


def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,action='append',required=True)
    p.add_argument('--record',type=Path,action='append',required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--csv',type=Path,required=True)
    p.add_argument('--table',type=Path,required=True);args=p.parse_args();assert len(args.run)==len(args.record)
    result={'scope':'forced-order async provider qualification; local_snapshot is a named ablation','runs':[]}
    fields=['run','bookkeeping','profile','family','seed','expectation_met','applied','provider_auth_violation',
            'effect_after_local_withdraw','pending_without_backend_fence','caller_sigkills','provider_sigkills',
            'worker_calls','fixture_rpc_calls','elapsed_seconds','violations','error_kind']
    table=['# 异步provider研究：原始结果重算','',
           'expectation命中包括预先预测的违例，不代表case安全。两个授权时间点分别统计。','',
           '| Run | Bookkeeping | Profile | Seed | Cases | Unexpected | ProviderFence后效果 | LocalWithdraw后效果 | Caller / provider SIGKILL |',
           '|---|---|---|---:|---:|---:|---:|---:|---:|']
    with args.csv.open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields,lineterminator='\n');writer.writeheader()
        for root,record_path in zip(args.run,args.record):
            record=json.loads(record_path.read_text());raw=json.loads((root/'summary.json').read_text())
            rows=[json.loads(line) for line in (root/'outcomes.jsonl').read_text().splitlines()]
            entry={'name':root.name,'run_id':record['id'],'exit_code':record.get('returncode'),
                   'seed_start':raw['seed_start'],'seeds':raw['seeds'],'families':raw['families'],
                   'started':record.get('started'),'finished':record.get('finished'),
                   'expected_cases':4*raw['seeds']*len(raw['families']),'observed_cases':len(rows),
                   'unexpected':sum(not row['expectation_met'] for row in rows),
                   'elapsed_seconds':raw['elapsed_seconds'],'model_calls':raw['model_calls'],'gpu_used':raw['gpu_used'],
                   'worker_calls':sum(row['worker_calls'] for row in rows),'fixture_rpc_calls':sum(row['fixture_rpc_calls'] for row in rows),
                   'caller_sigkills':sum(row['caller_sigkills'] for row in rows),'provider_sigkills':sum(row['provider_sigkills'] for row in rows),
                   'outcomes_sha256':hashlib.sha256((root/'outcomes.jsonl').read_bytes()).hexdigest(),
                   'arm_seed_rows':[],'arm_rows':[],
                   'input_hashes':{row['path'].split('/SP27/',1)[1]:row['sha256'] for row in record['inputs'] if '/SP27/' in row['path']}}
            grouped=defaultdict(list);arms=defaultdict(list)
            for row in rows:
                grouped[row['bookkeeping'],row['profile'],row['seed']].append(row);arms[row['bookkeeping'],row['profile']].append(row)
                data={key:row.get(key,'') for key in fields}
                data.update(run=root.name,expectation_met=int(row['expectation_met']),applied=int(row['applied']) if row['applied'] is not None else '',
                            provider_auth_violation=int('effect_after_provider_revocation' in row['violations']),
                            effect_after_local_withdraw=int(row['effect_after_local_withdraw']),pending_without_backend_fence=int(row['pending_without_backend_fence']),
                            violations='|'.join(row['violations']),error_kind=(row['error'] or '').split(':',1)[0])
                writer.writerow(data)
            def counts(group):
                return {'cases':len(group),'unexpected':sum(not x['expectation_met'] for x in group),
                        'provider_auth_violations':sum('effect_after_provider_revocation' in x['violations'] for x in group),
                        'effects_after_local_withdraw':sum(x['effect_after_local_withdraw'] for x in group),
                        'caller_sigkills':sum(x['caller_sigkills'] for x in group),'provider_sigkills':sum(x['provider_sigkills'] for x in group)}
            for (book,profile,seed),group in sorted(grouped.items()):
                c=counts(group);entry['arm_seed_rows'].append(dict(bookkeeping=book,profile=profile,seed=seed,**c))
                table.append(f'| {root.name} | {book} | {profile} | {seed} | {c["cases"]} | {c["unexpected"]} | {c["provider_auth_violations"]} | {c["effects_after_local_withdraw"]} | {c["caller_sigkills"]} / {c["provider_sigkills"]} |')
            for (book,profile),group in sorted(arms.items()):entry['arm_rows'].append(dict(bookkeeping=book,profile=profile,**counts(group)))
            result['runs'].append(entry)
            print(json.dumps({key:entry[key] for key in ['name','exit_code','observed_cases','unexpected','elapsed_seconds','worker_calls','caller_sigkills','provider_sigkills','arm_rows']}))
    result['interpretation']='ProviderFence and local Kernel Withdraw differ. Correct fenced arms can still have effects during pending revocation. Local snapshot failures are mechanism ablations, not a strong baseline defeat. Same controlled provider and trusted host; no authentication/artifact-source/4db6c4c07acb/production guarantees or IID efficacy claim.'
    args.out.write_text(json.dumps(result,indent=2)+'\n');args.table.write_text('\n'.join(table)+'\n')


if __name__=='__main__':main()
