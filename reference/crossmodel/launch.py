"""Register and launch isolated provider/role runs on the local AROS board."""
import argparse,hashlib,json,os,shutil,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
AROS='/artifact-source/6dcae92b61d0/aros.py'
PREFIX='codex-01a1db70-686f-7c11-90ba-6850d7668014--'
REFERENCE=[
 '/artifact-source/398180b38ed7/venv',
 '/artifact-source/9c9de9c2a04c/frozen-x1-branch-v1',
 '/artifact-source/3d9fa19e91e5/vendor',
 '/artifact-source/c4751a2fc0fe/progent',
 '/artifact-source/7defb8251014/channels.py',
 '/artifact-source/ec5d02833076/node_modules']

def main():
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['pilot','main']);p.add_argument('--version',default='v1')
    p.add_argument('--model',choices=['luna','haiku','deepseek']);p.add_argument('--kind',choices=['actor','update','unforced']);p.add_argument('--after');p.add_argument('--qualify-pilot');a=p.parse_args()
    models=[a.model] if a.model else ['luna','haiku','deepseek']
    kinds=[a.kind] if a.kind else (['all'] if a.phase=='pilot' else ['actor','update','unforced'])
    runtime=HERE/'runtimes'/f'{a.phase}-{a.version}'
    if not runtime.exists():
        runtime.mkdir(parents=True)
        sources=[HERE/n for n in ['actor_trial.py','update_trial.py','campaign.py','launch.py','analyze.py','test_analysis.py']]
        sources += [p for p in (HERE/'provider').glob('*') if p.suffix in {'.py','.mjs'}]
        sources += [HERE/'correctness/native.py']
        for src in sources:
            dst=runtime/src.relative_to(HERE);dst.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dst)
        (runtime/'source-sha256.json').write_text(json.dumps({str(p.relative_to(runtime)):hashlib.sha256(p.read_bytes()).hexdigest() for p in runtime.rglob('*') if p.is_file()},indent=2)+'\n')
    files=[p for p in runtime.rglob('*') if p.is_file()]
    files += [HERE/f'protocol-{a.phase}.json',HERE/f'{a.phase}-prediction.md',HERE/'correctness/frozen-v1/manifest.json']
    files += list((HERE/'correctness/frozen-v1/packets').glob('*.json'))
    files += list((HERE/'updates/packets').glob('*.json'))+[HERE/'updates/index.json']
    receipts=[]
    for model in models:
        for kind in kinds:
            name=f'{a.phase}-{model}-{kind}-{a.version}'
            cmd=['python3','-B',AROS,'run','start','--name',name,'--question',PREFIX+'haiku-crossmodel.md',
                 '--predict',PREFIX+f'three-family-{a.phase}.md','--memory','6']
            if a.phase=='main':cmd+=['--main']
            if a.after:cmd+=['--after',a.after]
            for path in sorted(set(files)):cmd+=['--input',str(path)]
            for path in REFERENCE:cmd+=['--reference',path]
            workers='1' if model=='deepseek' else '2' if a.phase=='pilot' else '1' if kind=='unforced' else '4'
            cmd+=['--','python3','-B',str(runtime/'campaign.py'),'--protocol',str(HERE/f'protocol-{a.phase}.json'),
                  '--model',model,'--kind',kind,'--workers',workers,'--out',str(HERE/'outputs'/name)]
            if a.qualify_pilot:cmd+=['--qualify-pilot',str((HERE/a.qualify_pilot).resolve())]
            r=subprocess.run(cmd,cwd=HERE,env={**os.environ,'CUDA_VISIBLE_DEVICES':'','PYTHONDONTWRITEBYTECODE':'1',
                            'HAIKU_STUDY_RATE_DIR':str(HERE/'transport-state')},text=True,capture_output=True)
            receipt={'name':name,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
            receipts.append(receipt);print(json.dumps(receipt),flush=True)
            (HERE/f'launch-{a.phase}-{a.version}.json').write_text(json.dumps(receipts,indent=2)+'\n')
            if r.returncode:raise SystemExit(r.returncode)
if __name__=='__main__':main()
