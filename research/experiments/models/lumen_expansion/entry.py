"""Run fixed Lumen schedules after operational qualification, never efficacy selection."""
import argparse, gzip, json, os, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
MODELS=['lumen_qwen','lumen_glm']

def qualify(folder):
    result=json.loads((folder/'result.json').read_text())
    if result['scheduled']!=22 or result['completed']!=22 or result['process_successes']!=22:
        raise ValueError('Native pilot processes incomplete; preserve and diagnose before main')
    errors=[]
    for row in result['rows']:
        raw=json.loads(gzip.decompress(Path(row['raw']).read_bytes()))
        if raw.get('dry') or raw.get('status') in {'infrastructure_failure','model_identity_mismatch','transport_or_conversion_failure'} or raw.get('transport_failed'):
            errors.append([row['id'],'operational_failure',raw.get('status')])
        strict=(raw.get('selected_effect_recomputation')or{}).get('strict')
        if strict and strict.get('extraction_errors'):
            errors.append([row['id'],'extraction_failure'])
        for request in raw.get('requests',[]):
            if not request.get('ok') or not request.get('model_label_matches'):
                errors.append([row['id'],'request_or_identity_failure',request.get('http_status'),request.get('error')])
    if errors:
        raise ValueError('Pilot requires diagnosis; no main requests: '+json.dumps(errors))
    return {'passed':True,'rows':22,'pilot':str(folder),'efficacy_used_as_gate':False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--phase',choices=['pilot','main'],required=True)
    p.add_argument('--model',choices=MODELS,required=True)
    p.add_argument('--runtime',default='runtime-v1')
    p.add_argument('--version',default='v1')
    p.add_argument('--pilot-version',default='v1')
    a=p.parse_args()
    out=HERE/'outputs'/f'{a.phase}-{a.model}-all-{a.version}'
    if a.phase=='main':
        receipt=qualify(HERE/'outputs'/f'pilot-{a.model}-all-{a.pilot_version}')
        out.mkdir(parents=True,exist_ok=True)
        (out/'qualification.json').write_text(json.dumps(receipt,indent=2)+'\n')
    cmd=['python3','-B',str(HERE/a.runtime/'campaign.py'),'--protocol',str(HERE/f'protocol-{a.phase}.json'),
         '--model',a.model,'--kind','all','--workers','1','--out',str(out)]
    raise SystemExit(subprocess.run(cmd,cwd=HERE,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','CUDA_VISIBLE_DEVICES':''}).returncode)

if __name__=='__main__':main()
