"""Read-only run check for the own-thread continuation callback; no inference."""
import json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
RUNS=[f'main-{m}-{kind}-{v}' for m,v in [('luna','v1'),('haiku','v1'),('deepseek','v4')] for kind in ['actor','update','unforced']]+['prompt-followup-main-v1','recovery-ack-main-v1','ack-salience-main-v1']
def main():
    rows=[];issues=[]
    for name in RUNS:
        out=HERE/'outputs'/name;done=(out/'result.json').exists()
        try:progress=json.loads((out/('result.json' if done else 'progress.json')).read_text())
        except (OSError,ValueError):progress={}
        done=bool(done and progress.get('scheduled') and progress.get('completed')==progress.get('scheduled'))
        try:job=json.loads((HERE/'research/jobs'/name/'job.json').read_text())
        except (OSError,ValueError):job={}
        if job.get('finished') and not done:issues.append(name+': finished without complete result')
        if any(r.get('model_identity_mismatches',0) for r in progress.get('rows',[])):issues.append(name+': model identity mismatch')
        rows.append({'run':name,'complete':done,'completed':progress.get('completed',0),'scheduled':progress.get('scheduled')})
    complete=all(r['complete'] for r in rows)
    finalizer=HERE/'research/jobs/full-analysis-v1'
    try:analysis_ready=json.loads((finalizer/'artifacts/result.json').read_text()).get('analysis_complete') is True
    except (OSError,ValueError):analysis_ready=False
    try:final_job=json.loads((finalizer/'job.json').read_text())
    except (OSError,ValueError):final_job={}
    if final_job.get('finished') and not analysis_ready:issues.append('full-analysis-v1: final analysis did not complete')
    result={'all_runs_complete':complete,'analysis_ready':analysis_ready,'needs_attention':bool(issues),'issues':issues,'rows':rows,'updated_epoch':time.time()}
    folder=HERE/'callback';folder.mkdir(exist_ok=True)
    (folder/'state.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'trigger':(complete and analysis_ready) or bool(issues),'all_runs_complete':complete,'analysis_ready':analysis_ready,'needs_attention':bool(issues),'issues':issues}))
if __name__=='__main__':main()
