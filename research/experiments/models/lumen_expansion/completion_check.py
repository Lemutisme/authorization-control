"""Read-only campaign check with small own-thread continuation milestones."""
import json,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
MODELS=['lumen_qwen','lumen_glm']
def read(path):
    try:return json.loads(path.read_text())
    except (OSError,ValueError):return {}
def main():
    notified=set(read(HERE/'callback/notified.json').get('milestones',[]))
    active=read(HERE/'callback/active.json')
    candidates=[];coverage=[]
    for model in MODELS:
        plan=active.get(model,{})
        for phase in ['pilot','main']:
            name=plan.get(phase+'_job',f"lumen-{phase}-{model.removeprefix('lumen_')}-v1")
            job=read(ROOT/'research/jobs'/name/'job.json')
            folder=HERE/'outputs'/plan.get(phase+'_output',f'{phase}-{model}-all-v1')
            report=read(folder/'result.json');progress=report or read(folder/'progress.json')
            scheduled=22 if phase=='pilot' else 429
            if job.get('finished') and (job.get('returncode')!=0 or not report or report.get('completed')!=scheduled):
                candidates.append({'key':name+'-issue','kind':'attention','model':model,'run':name})
            if any(r.get('terminal_provider_halt') or r.get('model_identity_mismatches') or r.get('ok') is False or r.get('status')=='infrastructure_failure' for r in progress.get('rows',[])):
                candidates.append({'key':name+'-premise-issue','kind':'attention','model':model,'run':name})
            if phase=='main':
                done=report.get('completed')==429 and report.get('scheduled')==429
                coverage.append({'model':model,'completed':progress.get('completed',0),'scheduled':429,'complete':done})
                if done:candidates.append({'key':name+'-complete','kind':'model_complete','model':model,'run':name})
    final=read(ROOT/'research/jobs'/active.get('finalizer_job','lumen-common-analysis-v1')/'artifacts/result.json')
    if final.get('analysis_complete'):candidates.append({'key':'lumen-batch-analysis-complete','kind':'batch_analysis_complete'})
    ready=[c for c in candidates if c['key']not in notified]
    result={'ready':ready[:4],'unnotified_milestones':len(ready),'coverage':coverage,
            'all_models_complete':all(c['complete'] for c in coverage),'batch_analysis_complete':bool(final.get('analysis_complete')),'updated_epoch':time.time()}
    folder=HERE/'callback';folder.mkdir(exist_ok=True)
    (folder/'state.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result))
if __name__=='__main__':main()
