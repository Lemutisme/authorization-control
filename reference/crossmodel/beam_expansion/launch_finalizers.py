"""Register replacement Canopy and new Beam finalizers after their own branches."""
import json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
AROS='/artifact-source/6dcae92b61d0/aros.py'
PREFIX='codex-01a1db70-686f-7c11-90ba-6850d7668014--'
def main():
    jobs=[('flash-common-analysis-route-v2','flash-main-mimo-v1','finalize_canopy.py'),('beam-common-analysis-v1','lumen-main-beam-v1','finalize.py')]
    receipts=[]
    for name,after,entry in jobs:
        cmd=['python3','-B',AROS,'run','start','--name',name,'--after',after,'--question',PREFIX+'beam-expansion.md','--predict',PREFIX+'beam-route-analysis.md','--memory','4']
        files=[HERE/n for n in ['finalization.py',entry,'launch_finalizers.py','finalize-prediction.md','analyze_common.py','strict_effects.py','model-configs.json']]
        files+=list(HERE.glob('protocol-*.json'))
        helper=Path('/artifact-source/9efadf13d615/x1')
        files += [helper/'cohort.py',helper/'analyze.py']
        for f in sorted(set(files)):cmd+=['--input',str(f)]
        refs={ROOT/'outputs',ROOT/'flash_expansion/outputs',ROOT/'lumen_expansion/outputs',HERE/'outputs'}
        for f in HERE.glob('protocol-*.json'):
            refs.update(Path(row['packet']).parent for row in json.loads(f.read_text()).get('rows',[]))
        for ref in sorted(refs):
            ref.mkdir(parents=True,exist_ok=True);cmd+=['--reference',str(ref)]
        cmd+=['--','python3','-B',str(HERE/entry)]
        r=subprocess.run(cmd,cwd=ROOT,env={**os.environ,'CUDA_VISIBLE_DEVICES':'','PYTHONDONTWRITEBYTECODE':'1'},text=True,capture_output=True)
        receipts.append({'name':name,'after':after,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        (HERE/'launch-finalizers-v1.json').write_text(json.dumps(receipts,indent=2)+'\n')
        print(json.dumps({'name':name,'after':after,'returncode':r.returncode,'stdout':r.stdout[:350],'stderr':r.stderr[:250]}),flush=True)
        if r.returncode:raise SystemExit(r.returncode)
if __name__=='__main__':main()
