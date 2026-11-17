"""Pilot or main entry, with operational qualification kept separate from efficacy."""
import argparse,gzip,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
def qualify(pilot):
    result=json.loads((pilot/'result.json').read_text())
    if result['completed']!=result['scheduled'] or result['process_successes']!=result['scheduled']:raise ValueError('Incomplete pilot processes; no main inference')
    errors=[]
    for row in result['rows']:
        raw=json.loads(gzip.decompress(Path(row['raw']).read_bytes()))
        if raw.get('status') in {'infrastructure_failure','model_identity_mismatch'}:errors.append([row['id'],'runtime_or_identity'])
        strict=(raw.get('selected_effect_recomputation') or {}).get('strict')
        if strict and strict.get('extraction_errors'):errors.append([row['id'],'strict_extraction'])
        for request in raw.get('requests',[]):
            if request.get('ok') and not request.get('model_label_matches'):errors.append([row['id'],'returned_model_mismatch'])
            if not request.get('ok'):errors.append([row['id'],'request_failed',request.get('http_status'),request.get('error')])
    # Every failure remains in pilot artifacts; root diagnoses it before admitting
    # a replacement configuration. No task-success or effect threshold is used.
    if errors:raise ValueError('Pilot operational issues require diagnosis: '+json.dumps(errors))
    return {'passed':True,'rows':result['scheduled'],'pilot':str(pilot),'efficacy_used_as_gate':False}
def main():
    p=argparse.ArgumentParser();p.add_argument('--phase',choices=['pilot','main'],required=True);p.add_argument('--model',choices=['glm','minimax','mimo','qwen'],required=True);p.add_argument('--runtime',default='runtime-v1');a=p.parse_args()
    name=f'{a.phase}-{a.model}-all-v1';out=HERE/'outputs'/name
    if a.phase=='main':
        receipt=qualify(HERE/'outputs'/f'pilot-{a.model}-all-v1')
        out.mkdir(parents=True,exist_ok=True);(out/'qualification.json').write_text(json.dumps(receipt,indent=2)+'\n')
    cmd=['python3','-B',str(HERE/a.runtime/'campaign.py'),'--protocol',str(HERE/f'protocol-{a.phase}.json'),
         '--model',a.model,'--kind','all','--workers','1','--out',str(out)]
    raise SystemExit(subprocess.run(cmd,cwd=HERE,env={**os.environ,'PYTHONDONTWRITEBYTECODE':'1','CUDA_VISIBLE_DEVICES':''}).returncode)
if __name__=='__main__':main()
