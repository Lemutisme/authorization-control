"""Run exact Pi source resume/first refusal for all selected packets using fake terminal replies."""
import concurrent.futures,json,os,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
manifest=Path(sys.argv[1]);out=Path(sys.argv[2]);out.mkdir(parents=True,exist_ok=True)
rows=json.loads(manifest.read_text())['packets']
def one(row):
 folder=out/row['unit_id'];folder.mkdir(exist_ok=True)
 env={**os.environ,'CHANNELS_QUALIFICATION_PACKET':str(Path(row['packet']).resolve()),
  'CHANNELS_QUALIFICATION_JOURNAL':str(folder/'http.jsonl'),'CHANNELS_QUALIFICATION_TERMINAL':'1',
  'NODE_OPTIONS':'--import='+str(HERE/'fake_fetch.mjs')}
 with (folder/'run.log').open('w') as log:
  p=subprocess.run(['node',str(HERE/'qualify_one.mjs'),'--python',sys.executable,'--packet',row['packet'],'--out',str(folder)],env=env,stdout=log,stderr=log)
 try:result=json.loads((folder/'result.json').read_text())
 except Exception:result={'unit_id':row['unit_id'],'passed':False,'exit_code':p.returncode}
 result['panel']=row['panel'];return result
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(one,rows))
report={'scheduled':len(rows),'passed':sum(r['passed'] for r in results),'model_calls':0,'external_network_calls':0,'rows':results}
(out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k!='rows'}))
if report['passed']!=len(rows):raise SystemExit(1)
