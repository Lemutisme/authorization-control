"""Model-free snapshots for the revised active route set; preserve each branch."""
import json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parent
def run(branch):
    if branch not in ['beam','canopy']:raise ValueError('Unknown finalization branch')
    artifacts=Path(os.environ.get('AROS_ARTIFACTS',str(HERE/'finalization'/branch)))
    artifacts.mkdir(parents=True,exist_ok=True)
    out=HERE/('analysis-after-'+branch+'-v1')
    command=['python3','-B',str(HERE/'analyze_common.py'),'--scope','combined','--out',str(out)]
    process=subprocess.run(command,cwd=ROOT,text=True,capture_output=True)
    (artifacts/'analysis-command.json').write_text(json.dumps({'command':command,'returncode':process.returncode,'stdout':process.stdout,'stderr':process.stderr},indent=2)+'\n')
    if process.returncode:raise RuntimeError('Route-corrected common analysis failed')
    targets=[('lumen_beam',HERE/'outputs/main-lumen_beam-all-v1')]if branch=='beam'else[(m,ROOT/'flash_expansion/outputs'/f'main-{m}-all-v1')for m in ['glm','minimax','mimo']]
    coverage=[]
    for model,folder in targets:
        try:data=json.loads((folder/'result.json').read_text())
        except (OSError,ValueError):data={}
        coverage.append({'model':model,'completed':data.get('completed',0),'scheduled':429,'process_successes':data.get('process_successes',0)})
    result={'analysis_complete':True,'branch':branch,'models':coverage,
            'full_branch_schedules_complete':all(r['completed']==429 for r in coverage),
            'other_active_routes_may_be_incomplete':True,'independent_native_check_pending':True,
            'withdrawn_canopy_qwen':'User routing choice before native sampling; retained separately, not missing/safe/failed efficacy.',
            'scope':'Original3+activeCanopy3+completedLumen2+Beam; no provider relabeling or duplicate Qwen draws.'}
    (artifacts/'result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
