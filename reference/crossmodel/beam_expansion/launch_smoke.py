"""Register the bounded Beam qualification; no other model requests."""
import json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
AROS='/artifact-source/6dcae92b61d0/aros.py'
PREFIX='codex-01a1db70-686f-7c11-90ba-6850d7668014--'
def main():
    cmd=['python3','-B',AROS,'run','start','--name','beam-provider-smoke-v1','--question',PREFIX+'beam-expansion.md','--predict',PREFIX+'beam-provider-smoke.md','--memory','2']
    files=list((HERE/'provider').glob('*.py'))+[HERE/'launch_smoke.py',HERE/'smoke-prediction.md',HERE/'provider/models-discovery.json']
    for path in sorted(files):cmd+=['--input',str(path)]
    cmd+=['--','python3','-B',str(HERE/'provider/smoke.py'),'--live','--out',str(HERE/'qualification/provider-smoke-v1')]
    r=subprocess.run(cmd,cwd=ROOT,env={**os.environ,'CUDA_VISIBLE_DEVICES':'','PYTHONDONTWRITEBYTECODE':'1'},text=True,capture_output=True)
    receipt={'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
    (HERE/'launch-smoke-v1.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt));raise SystemExit(r.returncode)
if __name__=='__main__':main()
