"""Read-only per-model milestones for own-thread continuation; no inference."""
import json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
MODELS=['glm','minimax','mimo','qwen']
def read(path):
    try:return json.loads(path.read_text())
    except (OSError,ValueError):return {}
def main():
    state=read(HERE/'callback/notified.json');notified=set(state.get('milestones',[]));candidates=[];coverage=[]
    active=read(HERE/'callback/active.json')
    for model in MODELS:
        if model in active.get('excluded_models',[]):continue
        done=False
        for phase in ['pilot','main']:
            plan=active.get(model,{})
            jobname=plan.get(phase+'_job',f'flash-{phase}-{model}-v1');job=read(ROOT/'research/jobs'/jobname/'job.json')
            out=HERE/'outputs'/plan.get(phase+'_output',f'{phase}-{model}-all-v1');report=read(out/'result.json')
            if job.get('finished') and (job.get('returncode')!=0 or not report):candidates.append({'key':jobname+'-issue','kind':'attention','model':model,'run':jobname})
            progress=report or read(out/'progress.json')
            if any(r.get('model_identity_mismatches',0) or r.get('status')=='infrastructure_failure' or r.get('ok') is False for r in progress.get('rows',[])):
                candidates.append({'key':jobname+'-premise-issue','kind':'attention','model':model,'run':jobname})
            if phase=='main':
                done=bool(report.get('completed')==429 and report.get('scheduled')==429)
                coverage.append({'model':model,'complete':done,'completed':progress.get('completed',0),'scheduled':429})
                if done:candidates.append({'key':jobname+'-complete','kind':'model_complete','model':model,'run':jobname})
    final=read(ROOT/'research/jobs'/active.get('finalizer_job','flash-common-analysis-v1')/'artifacts/result.json')
    if final.get('analysis_complete'):candidates.append({'key':'flash-batch-analysis-complete','kind':'batch_analysis_complete'})
    ready=[x for x in candidates if x['key'] not in notified]
    result={'ready':ready[:4],'unnotified_milestones':len(ready),'coverage':coverage,'withdrawn_configurations':active.get('withdrawn_configurations',{}),'all_models_complete':all(x['complete'] for x in coverage),
            'batch_analysis_complete':bool(final.get('analysis_complete')),'updated_epoch':time.time()}
    folder=HERE/'callback';folder.mkdir(exist_ok=True);(folder/'state.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
if __name__=='__main__':main()
