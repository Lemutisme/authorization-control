"""Register the bounded Lumen infrastructure qualification before inference."""
import json, os, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
AROS='/artifact-source/6dcae92b61d0/aros.py'
PREFIX='codex-01a1db70-686f-7c11-90ba-6850d7668014--'
def main():
    cmd=['python3','-B',AROS,'run','start','--name','lumen-provider-smoke-v2',
         '--question',PREFIX+'lumen-expansion.md','--predict',PREFIX+'lumen-provider-smoke-v2.md','--memory','2']
    files=list((HERE/'provider-v2').glob('*.py'))+[HERE/'smoke-v2-prediction.md',HERE/'launch_smoke_v2.py',HERE/'provider/models-discovery.json']
    for path in sorted(files): cmd+=['--input',str(path)]
    cmd+=['--','python3','-B',str(HERE/'provider-v2/smoke.py'),'--live','--out',str(HERE/'qualification/provider-smoke-v2')]
    result=subprocess.run(cmd,cwd=ROOT,env={**os.environ,'CUDA_VISIBLE_DEVICES':'','PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True)
    receipt={'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
    (HERE/'launch-smoke-v2.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    raise SystemExit(result.returncode)
if __name__=='__main__':main()
