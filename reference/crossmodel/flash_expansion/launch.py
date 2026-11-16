"""Queue each complete new configuration after the promised full original study."""
import json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
AROS='/artifact-source/6dcae92b61d0/aros.py'
PREFIX='codex-01a1db70-686f-7c11-90ba-6850d7668014--'
def main():
    smoke=json.loads((HERE/'qualification/provider-smoke-v1/result.json').read_text());assert smoke['passed']
    assert json.loads((HERE/'qualification/runtime-v1/result.json').read_text())['known_existing_field_noop_legacy1_strict0']
    previous='full-analysis-v1';receipts=[]
    for model in ['glm','minimax','mimo','qwen']:
        for phase in ['pilot','main']:
            name=f'flash-{phase}-{model}-v1'
            cmd=['python3','-B',AROS,'run','start','--name',name,'--after',previous,
                 '--question',PREFIX+'flash-expansion.md','--predict',PREFIX+'flash-transfer-main.md','--memory','6']
            if phase=='main':cmd+=['--main']
            files=[p for p in (HERE/'runtime-v1').rglob('*') if p.is_file() and '__pycache__' not in p.parts]
            files += [HERE/'entry.py',HERE/'launch.py',HERE/'prediction.md',HERE/f'protocol-{phase}.json',HERE/'model-configs.json']
            proto=json.loads((HERE/f'protocol-{phase}.json').read_text())
            files += [Path(r['packet']) for r in proto['rows'] if r['model']==model]
            for path in sorted(set(files)):cmd+=['--input',str(path)]
            for path in ['/artifact-source/398180b38ed7/venv',
                         '/artifact-source/9c9de9c2a04c/frozen-x1-branch-v1',
                         '/artifact-source/3d9fa19e91e5/vendor',
                         '/artifact-source/c4751a2fc0fe/progent',
                         '/artifact-source/7defb8251014/channels.py']:cmd+=['--reference',path]
            cmd+=['--','python3','-B',str(HERE/'entry.py'),'--phase',phase,'--model',model]
            r=subprocess.run(cmd,cwd=ROOT,env={**os.environ,'CUDA_VISIBLE_DEVICES':'','PYTHONDONTWRITEBYTECODE':'1',
                             'HAIKU_STUDY_RATE_DIR':str(ROOT/'transport-state')},text=True,capture_output=True)
            receipts.append({'name':name,'after':previous,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
            (HERE/'launch-campaign-v1.json').write_text(json.dumps(receipts,indent=2)+'\n');print(json.dumps({'name':name,'after':previous,'returncode':r.returncode,'stdout':r.stdout[:350],'stderr':r.stderr[:200]}),flush=True)
            if r.returncode:raise SystemExit(r.returncode)
            previous=name
if __name__=='__main__':main()
