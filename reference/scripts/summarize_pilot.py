#!/usr/bin/env python3
"""Derive the publication summary from every declared pilot attempt, including failures."""
import argparse
import hashlib
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--experiments',type=Path,required=True)
    p.add_argument('--records',type=Path,required=True)
    p.add_argument('--attempt',action='append',required=True,help='attempt-directory:run-id')
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();rows=[]
    for spec in a.attempt:
        name,run_id=spec.split(':',1);root=a.experiments/name
        record=json.loads((a.records/run_id/'job.json').read_text())
        result_path=root/'cases/results.json';build_path=root/'build/build-metadata.json'
        row={'attempt':name,'run_id':run_id,'exit_code':record.get('returncode'),
             'started':record.get('started'),'finished':record.get('finished')}
        if result_path.exists():
            result=json.loads(result_path.read_text())
            # Compute counts afresh from individual outcomes, not the candidate total.
            row.update(results=result,normal_total=len(result['normal_cases']),
                       normal_passed=sum(x['passed'] for x in result['normal_cases']),
                       controls_total=len(result['negative_controls']),
                       controls_detected=sum(x['detected'] for x in result['negative_controls']),
                       result_sha256=hashlib.sha256(result_path.read_bytes()).hexdigest())
        else:row['missing_result']='Command failed or ended without results; retained in accounting.'
        if build_path.exists():row['build']=json.loads(build_path.read_text())
        row['published_input_hashes']={}
        for entry in record['inputs']:
            path=entry['path'];marker='/SP27/'
            if marker in path:
                row['published_input_hashes'][path.split(marker,1)[1]]=entry['sha256']
        rows.append(row)
    report={'kind':'adaptive local semantic qualification, not general defense efficacy',
            'prelaunch_event':{'status':'not launched','reason':'30 s preparation timeout while whole directory references were declared; reduced to bounded source/toolchain references; no semantic case executed'},
            'attempts':rows,
            'review_amendment':'Attempt1 checked counts but inadequately checked actual artifact identity. Attempt2 adds fixture-owned intent/history/direct registry checks and a wrong-artifact control. Both attempts retained; not independent confirmatory replications.',
            'publication_boundary':'No raw databases, toolchain, binary, machine paths or incident materials included.'}
    a.out.write_text(json.dumps(report,indent=2)+'\n')
    for row in rows:
        print(json.dumps({key:row.get(key) for key in ['attempt','exit_code','normal_passed','normal_total','controls_detected','controls_total','missing_result']}))

if __name__=='__main__':main()
