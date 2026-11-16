#!/usr/bin/env python3
"""Export all synthetic case metrics for independent recounting; exclude raw paths."""
import argparse
import csv
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--run',type=Path,action='append',required=True)
    p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    fields=['run','phase','arm','family','seed','control','passed','effects','process_crashes','worker_calls','elapsed_seconds','violations','error_kind']
    with args.out.open('w',newline='') as out:
        writer=csv.DictWriter(out,fieldnames=fields);writer.writeheader()
        for root in args.run:
            normals=[json.loads(line) for line in (root/'outcomes.jsonl').read_text().splitlines()]
            controls=json.loads((root/'summary.json').read_text())['controls']
            for phase,rows in [('normal',normals),('control',controls)]:
                for row in rows:
                    data={key:row.get(key,'') for key in fields}
                    data.update(run=root.name,phase=phase,passed=int(row['passed']),
                                violations='|'.join(row['violations']),error_kind=(row.get('error') or '').split(':',1)[0])
                    writer.writerow(data)
            races={}
            for row in normals:
                if row['family']=='withdraw_race':races.setdefault(row['seed'],{})[row['arm']]=row['effects']
            different=sum(values.get('procontract')!=values.get('durable_sop') for values in races.values())
            print(json.dumps({'run':root.name,'normal_rows':len(normals),'control_rows':len(controls),
                              'withdraw_race_pairs':len(races),'pairs_with_different_effect_counts':different}))

if __name__=='__main__':main()
