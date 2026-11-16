"""Register model-free final analysis after the two Lumen main runs."""
import json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
AROS='/artifact-source/6dcae92b61d0/aros.py'
PREFIX='codex-01a1db70-686f-7c11-90ba-6850d7668014--'
def main():
    cmd=['python3','-B',AROS,'run','start','--name','lumen-common-analysis-v1','--after','lumen-main-glm-v1',
         '--question',PREFIX+'lumen-expansion.md','--predict',PREFIX+'lumen-common-analysis-v1-prediction.md','--memory','4']
    files=[HERE/name for name in ['finalize.py','launch_finalize.py','finalize-prediction.md','analyze_common.py','strict_effects.py','protocol-main.json','protocol-reference-main.json','protocol-canopy-main.json','model-configs.json']]
    files += [ROOT/'flash_expansion'/name for name in ['protocol-main.json','model-configs.json']]
    for path in files:cmd+=['--input',str(path)]
    # Mutable result directories are references, not source snapshots.
    for path in [HERE/'outputs',ROOT/'outputs',ROOT/'flash_expansion/outputs']:
        path.mkdir(parents=True,exist_ok=True)
        cmd+=['--reference',str(path)]
    cmd+=['--','python3','-B',str(HERE/'finalize.py')]
    result=subprocess.run(cmd,cwd=ROOT,env={**os.environ,'CUDA_VISIBLE_DEVICES':'','PYTHONDONTWRITEBYTECODE':'1'},capture_output=True,text=True)
    receipt={'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
    (HERE/'launch-finalize-v1.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))
    raise SystemExit(result.returncode)
if __name__=='__main__':main()
