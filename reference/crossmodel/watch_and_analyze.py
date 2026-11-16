"""Persistently finish the full registered analysis after every run settles.

This process makes no model/API requests and never shortens a schedule. It keeps
a progress artifact and performs model-free analysis only after all fixed runs
finish; failed/missing traces remain the analyzer's unknown outcomes.
"""
import json,os,subprocess,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
RUNS=[f'main-{m}-{kind}-{v}' for m,v in [('luna','v1'),('haiku','v1'),('deepseek','v4')] for kind in ['actor','update','unforced']]
RUNS+=['prompt-followup-main-v1']

def main():
    artifacts=Path(os.environ.get('AROS_ARTIFACTS',str(HERE/'final-analysis')));artifacts.mkdir(parents=True,exist_ok=True)
    began=time.monotonic()
    while True:
        rows=[]
        for name in RUNS:
            path=HERE/'outputs'/name
            report=path/('result.json' if (path/'result.json').exists() else 'progress.json')
            try:d=json.loads(report.read_text())
            except (OSError,ValueError):d={}
            rows.append({'run':name,'complete':(path/'result.json').exists(),'completed':d.get('completed',0),'scheduled':d.get('scheduled')})
        state={'rows':rows,'all_complete':all(r['complete'] for r in rows),'wait_wall_s':time.monotonic()-began,'updated_epoch':time.time()}
        (artifacts/'progress.json').write_text(json.dumps(state,indent=2)+'\n')
        line='; '.join(f"{r['run']}:{r['completed']}/{r['scheduled'] or '?'}" for r in rows)
        (artifacts/'status.md').write_text(line+'\n')
        if state['all_complete']:break
        time.sleep(45)
    commands=[['python3','-B',str(HERE/'analyze.py'),'--model-versions','{"deepseek":"v4"}','--out','analysis'],
              ['/artifact-source/01b8ea88deeb/python','-B',str(HERE/'correctness/score_spontaneous.py'),'--model-versions','{"deepseek":"v4"}','--out','analysis-spontaneous'],
              [str(HERE/'plot-venv/bin/python'),str(HERE/'figures.py'),'--analysis','analysis/result.json','--out','figures']]
    results=[]
    for command in commands:
        r=subprocess.run(command,cwd=HERE,text=True,capture_output=True)
        results.append({'command':command,'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr})
        (artifacts/'analysis-commands.json').write_text(json.dumps(results,indent=2)+'\n')
        if r.returncode:raise RuntimeError('A model-free final analysis failed; inputs/outcomes retained')
    summary=json.loads((HERE/'analysis/result.json').read_text())
    (artifacts/'result.json').write_text(json.dumps({'main_scheduled':summary['scheduled'],'main_observed':summary['observed'],'analysis_complete':True,'human_interpretation_pending':True,'scope':'Final data analysis; not paper acceptance or publication.'},indent=2)+'\n')
    print(json.dumps({'main_scheduled':summary['scheduled'],'main_observed':summary['observed'],'analysis_complete':True}))
if __name__=='__main__':main()
