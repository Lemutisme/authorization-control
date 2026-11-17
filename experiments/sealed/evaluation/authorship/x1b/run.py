"""Registered X1b launch: fresh task/replicate caches, six profiles, no replacement."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time
HERE = Path(__file__).resolve().parent
ARMS = [(f'forced_u{u}_c{c}', u, c) for u in ('none','medium') for c in ('none','medium')] + [(f'nogate_u{u}',u,'none') for u in ('none','medium')]

def save(path, value):
    temp=path.with_suffix('.tmp');temp.write_text(json.dumps(value,indent=2)+'\n');temp.replace(path)

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path);p.add_argument('--phase',choices=['smoke','main'],required=True);p.add_argument('--registration',required=True);a=p.parse_args()
    assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261106'
    cases=[c for c in json.loads(a.manifest.read_text())['cases'] if c['suite']=='banking' and c['condition']=='clean'];assert len(cases)==16
    if a.out is None:
        if not os.environ.get('AROS_ARTIFACTS'):p.error('--out or AROS_ARTIFACTS is required')
        a.out=Path(os.environ['AROS_ARTIFACTS'])
    a.out=a.out.resolve()
    a.out.mkdir(parents=True,exist_ok=True);assert not (a.out/'config.json').exists()
    if a.phase=='smoke':
        cases=[c for c in cases if c['case_id']=='banking__user_task_11__clean'];assert len(cases)==1
    replicates=1 if a.phase=='smoke' else 4
    scheduled_units=len(cases)*replicates
    scheduled_episodes=scheduled_units*len(ARMS)
    save(a.out/'config.json',dict(registration=a.registration,phase=a.phase,exploratory=a.phase=='smoke',smoke_limit='Provider lifecycle check only; cannot select methods or prompts from smoke outcomes; never pool with main',scheduled_episodes=scheduled_episodes,scheduled_task_replicates=scheduled_units,owner_tasks=len(cases),case_ids=[c['case_id'] for c in cases],arms=ARMS,replicates=replicates,manifest_sha256=hashlib.sha256(a.manifest.read_bytes()).hexdigest(),source_sha256={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in HERE.iterdir() if f.suffix in {'.py','.mjs','.json','.md'}}))
    units=[(r,c) for r in range(replicates) for c in cases];random.Random(20261112).shuffle(units)
    def one(index,unit):
        rep,case=unit;folder=a.out/f'replicate-{rep}'/case['case_id'];folder.mkdir(parents=True)
        order=ARMS[index%6:]+ARMS[:index%6];episodes={}
        for arm,u,c in order:
            cmd=['node',str(HERE/'agent.mjs'),'--python',sys.executable,'--manifest',str(a.manifest.resolve()),'--case',case['case_id'],'--arm',arm,'--actor',u,'--constructor',c,'--out',str(folder/arm),'--actor-cache',str(folder/'actor-cache'),'--policy-cache',str(folder/'policy-cache'),'--judge-cache',str(folder/'judge-cache')]
            process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
            try:
                stdout,stderr=process.communicate(timeout=720)
                (folder/(arm+'.process.txt')).write_text(stdout+stderr)
                if process.returncode:raise RuntimeError('episode_process_error')
                episodes[arm]=json.loads((folder/(arm+'.json')).read_text())
            except Exception as error:
                if process.poll() is None:os.killpg(process.pid,signal.SIGTERM);process.communicate()
                episodes[arm]=dict(status='adapter_error',error=type(error).__name__,usage_unknown=True)
                save(folder/(arm+'.failure.json'),episodes[arm])
        row=dict(replicate=rep,case_id=case['case_id'],task_id=case['task_id'],arms=episodes)
        save(folder/'case.json',row);return row
    rows=[];started=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1 if a.phase=='smoke' else 4) as pool:
        for future in concurrent.futures.as_completed([pool.submit(one,i,u) for i,u in enumerate(units)]):
            rows.append(future.result());save(a.out/'summary.json',dict(phase=a.phase,exploratory=a.phase=='smoke',complete=len(rows)==scheduled_units,scheduled_task_replicates=scheduled_units,scheduled_episodes=scheduled_episodes,observed_episodes=len(rows)*6,elapsed_s=time.monotonic()-started,rows=rows));print(f'{a.phase}: {len(rows)}/{scheduled_units} task-replicates',flush=True)
if __name__=='__main__':main()
