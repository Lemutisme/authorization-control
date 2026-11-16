#!/usr/bin/env python3
"""Compute all publication counts from recorded outcomes, including failed rows."""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import statistics


def main():
    p=argparse.ArgumentParser();p.add_argument('--run',action='append',type=Path,required=True)
    p.add_argument('--record',action='append',type=Path,required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--table',type=Path,required=True)
    args=p.parse_args();assert len(args.run)==len(args.record)
    report={'scope':'local paired process-fault study; not statistical defense efficacy or a Temporal evaluation','runs':[]}
    table=['# 进程故障研究：由原始 outcome 重算的结果','',
           '同一机制族中的多个 seed 不是独立攻击族；所有失败保留。原始 trace/DB 在实验存储中，发布摘要不含机器路径。','',
           '| Run | Arm | Seed | Passed / cases | SIGKILL | Worker calls | Sum case wall seconds |',
           '|---|---|---:|---:|---:|---:|---:|']
    for run,record_path in zip(args.run,args.record):
        record=json.loads(record_path.read_text());summary=json.loads((run/'summary.json').read_text())
        rows=[json.loads(line) for line in (run/'outcomes.jsonl').read_text().splitlines()]
        expected_cases=2*summary['seeds']*len(summary['families'])
        groups=defaultdict(list);families=defaultdict(list)
        for row in rows:
            groups[row['arm'],row['seed']].append(row)
            families[row['arm'],row['family']].append(row)
        entry={'name':run.name,'run_id':record['id'],'exit_code':record.get('returncode'),
               'started':record.get('started'),'finished':record.get('finished'),
               'expected_cases':expected_cases,'observed_cases':len(rows),'missing_cases':expected_cases-len(rows),
               'passed':sum(row['passed'] for row in rows),'failed':sum(not row['passed'] for row in rows),
               'process_crashes':sum(row['process_crashes'] for row in rows),
               'worker_calls':sum(row['worker_calls'] for row in rows),
               'elapsed_seconds':summary['elapsed_seconds'],'model_calls':summary['model_calls'],'gpu_used':summary['gpu_used'],
               'seed_start':summary['seed_start'],'seeds':summary['seeds'],'families':summary['families'],
               'outcomes_sha256':hashlib.sha256((run/'outcomes.jsonl').read_bytes()).hexdigest(),
               'controls':[{k:control[k] for k in ['control','detected','violations','worker_calls']} for control in summary['controls']],
               'arm_seed_rows':[],'family_rows':[],
               'failures':[{'arm':row['arm'],'family':row['family'],'seed':row['seed'],'violations':row['violations'],
                            'infrastructure_error':row['error'] is not None} for row in rows if not row['passed']]}
        for (arm,seed),values in sorted(groups.items()):
            row={'arm':arm,'seed':seed,'cases':len(values),'passed':sum(x['passed'] for x in values),
                 'process_crashes':sum(x['process_crashes'] for x in values),'worker_calls':sum(x['worker_calls'] for x in values),
                 'sum_case_wall_seconds':sum(x['elapsed_seconds'] for x in values)}
            entry['arm_seed_rows'].append(row)
            table.append(f'| {run.name} | {arm} | {seed} | {row["passed"]}/{row["cases"]} | {row["process_crashes"]} | {row["worker_calls"]} | {row["sum_case_wall_seconds"]:.3f} |')
        for (arm,family),values in sorted(families.items()):
            entry['family_rows'].append({'arm':arm,'family':family,'cases':len(values),'passed':sum(x['passed'] for x in values),
                                        'median_case_wall_seconds':statistics.median(x['elapsed_seconds'] for x in values)})
        entry['input_hashes']={x['path'].split('/SP27/',1)[1]:x['sha256'] for x in record['inputs'] if '/SP27/' in x['path']}
        report['runs'].append(entry)
        print(json.dumps({key:entry[key] for key in ['name','exit_code','expected_cases','observed_cases','passed','failed','missing_cases','process_crashes','worker_calls','elapsed_seconds']}))
    report['interpretation']='Matched safety and final progress on these schedules does not prove equivalence, superiority, natural defect rates or production readiness. Shared effect adapter limits independence. SIGKILL is not power/storage failure. Wall times include different bridge/process architectures and are not production performance comparisons.'
    args.out.write_text(json.dumps(report,indent=2)+'\n')
    table+=['','墙钟列是各 case 时间的和，包含重叠运行，不能相加后当作整批耗时或 CPU 秒。整批耗时见 JSON。',
            'Rust reducer 经进程 bridge，SOP 在 Python worker 内；此处不据墙钟比较生产效率。','']
    args.table.write_text('\n'.join(table))


if __name__=='__main__':main()
