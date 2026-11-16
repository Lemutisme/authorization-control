"""Model-free common-panel readback after the queued Flash batch settles."""
import json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
    output=Path(os.environ.get('AROS_ARTIFACTS',str(HERE/'finalization')));output.mkdir(parents=True,exist_ok=True)
    command=['python3','-B',str(HERE/'analyze_common.py'),'--scope','combined','--flash-layout','all','--out',str(HERE/'analysis-combined')]
    r=subprocess.run(command,cwd=HERE.parent,text=True,capture_output=True)
    (output/'analysis-command.json').write_text(json.dumps({'command':command,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr},indent=2)+'\n')
    if r.returncode:raise RuntimeError('Common-panel analysis failed; original traces retained')
    coverage=[]
    for model in ['glm','minimax','mimo','qwen']:
        p=HERE/'outputs'/f'main-{model}-all-v1'/'result.json'
        try:d=json.loads(p.read_text())
        except (OSError,ValueError):d={}
        coverage.append({'model':model,'scheduled':429,'completed':d.get('completed',0),'raw_process_successes':d.get('process_successes',0)})
    result={'analysis_complete':True,'models':coverage,'full_schedules_complete':all(c['completed']==429 for c in coverage),
            'interpretation_pending':True,'scope':'Common-panel configuration comparison; native target mismatch is not automatically an authorization violation.'}
    (output/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
if __name__=='__main__':main()
