"""Analyze completed Lumen schedules alongside available frozen common panels."""
import json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
    output=Path(os.environ.get('AROS_ARTIFACTS',str(HERE/'finalization')))
    output.mkdir(parents=True,exist_ok=True)
    command=['python3','-B',str(HERE/'analyze_common.py'),'--scope','combined','--out',str(HERE/'analysis-combined')]
    result=subprocess.run(command,cwd=HERE.parent,text=True,capture_output=True)
    (output/'analysis-command.json').write_text(json.dumps({'command':command,'returncode':result.returncode,'stdout':result.stdout,'stderr':result.stderr},indent=2)+'\n')
    if result.returncode:raise RuntimeError('Common-panel readback failed; preserve traces')
    coverage=[]
    for model in ['lumen_qwen','lumen_glm']:
        path=HERE/'outputs'/f'main-{model}-all-v1'/'result.json'
        try:data=json.loads(path.read_text())
        except(OSError,ValueError):data={}
        coverage.append({'model':model,'scheduled':429,'completed':data.get('completed',0),'process_successes':data.get('process_successes',0)})
    summary={'analysis_complete':True,'models':coverage,'full_lumen_schedules_complete':all(r['completed']==429 for r in coverage),
             'outside_check_pending':True,'other_providers_may_be_incomplete':True,
             'scope':'Provider/model/mode/budget strata; target mismatch is not an authorization-violation label.'}
    (output/'result.json').write_text(json.dumps(summary,indent=2)+'\n')
    print(json.dumps(summary))
if __name__=='__main__':main()
