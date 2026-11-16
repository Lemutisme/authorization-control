import argparse,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument('phase',choices=['pilot','main']);a=p.parse_args();frozen=HERE/'runtimes/ack-salience-v1'
    name='ack-salience-'+a.phase+'-v1';previous='recovery-ack-main-v1' if a.phase=='pilot' else 'ack-salience-pilot-v1'
    cmd=['python3','-B','/artifact-source/6dcae92b61d0/aros.py','run','start','--name',name,'--after',previous,
         '--question','codex-01a1db70-686f-7c11-90ba-6850d7668014--haiku-crossmodel.md','--predict','codex-01a1db70-686f-7c11-90ba-6850d7668014--ack-salience.md','--memory','6']
    if a.phase=='main':cmd+=['--main']
    files=list(p for p in frozen.rglob('*') if p.is_file())+[HERE/'ack-salience-protocol.json',HERE/'ack-salience-prediction.md',Path(__file__).resolve()]+list((HERE/'recovery_ack/frozen-v1/packets').glob('*.json'))
    for path in files:cmd+=['--input',str(path)]
    for path in ['/artifact-source/398180b38ed7/venv','/artifact-source/9c9de9c2a04c/frozen-x1-branch-v1','/artifact-source/7436ef2b7b44/x2b','/artifact-source/ec5d02833076/node_modules']:cmd+=['--reference',path]
    cmd+=['--','python3','-B',str(frozen/'ack_campaign.py'),'--protocol',str(HERE/'ack-salience-protocol.json'),'--phase',a.phase,'--out',str(HERE/'outputs'/name)]
    r=subprocess.run(cmd,env={**os.environ,'CUDA_VISIBLE_DEVICES':''},text=True,capture_output=True);(HERE/('launch-'+name+'.json')).write_text(json.dumps({'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr},indent=2)+'\n');print(r.stdout[:400],r.stderr[:400]);raise SystemExit(r.returncode)
if __name__=='__main__':main()
