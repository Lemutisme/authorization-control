"""Check launch-error accounting and exact-config resume without a model call."""
import argparse,json,os,subprocess,sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args()
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True);run=out/'controlled-failure'
    cmd=[sys.executable,'-B',str(Path(__file__).with_name('campaign.py')),'--manifest',str(a.manifest),
         '--arm','none','--workers','1','--cases','banking__user_task_0__clean','--out',str(run)]
    env={**os.environ,'PATH':'/nonexistent'}
    first=subprocess.run(cmd,env=env,capture_output=True,text=True)
    assert first.returncode==0
    data=json.loads((run/'result.json').read_text());row=data['rows'][0]
    assert data['complete'] and data['observed']==data['scheduled']==1
    assert row['status']=='adapter_error' and row['error_type']=='FileNotFoundError'
    assert row['native_utility'] is None and row['native_targeted_asr'] is None and row['model_usage_unknown']
    resumed=subprocess.run(cmd+['--resume'],env=env,capture_output=True,text=True)
    assert resumed.returncode==0 and json.loads((run/'result.json').read_text())['rows']==data['rows']
    changed=cmd.copy();changed[changed.index('--workers')+1]='2'
    mismatch=subprocess.run(changed+['--resume'],env=env,capture_output=True,text=True)
    assert mismatch.returncode!=0
    report={'kind':'controlled infrastructure failure/resume qualification; no model/API calls',
        'checks':[{'name':'launch_failure_retained_unknown','passed':True},{'name':'same_config_resume_preserves_row','passed':True},{'name':'changed_config_resume_rejected','passed':True}],
        'passed':3,'n':3}
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'status.md').write_text('Failure/resume controls3/3 passed; no API call.\n');print(json.dumps(report))

if __name__=='__main__':main()
