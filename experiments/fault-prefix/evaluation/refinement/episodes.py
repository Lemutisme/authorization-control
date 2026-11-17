"""Five-arm original banking campaign and prespecified clean repetition."""
import argparse,collections,concurrent.futures,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path
ARMS=['none','pga_minimal','optional','forced','result_aware'];INFRA={'adapter_error','inference_error','episode_timeout','no_response'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):t=p.with_suffix('.tmp');t.write_text(json.dumps(x,indent=2)+'\n');t.replace(p)
def main():
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--phase',choices=['smoke','main','clean_repeat'],required=True);p.add_argument('--out',type=Path);a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS']);a.out.mkdir(parents=True,exist_ok=True);assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261106'
 m=json.loads(a.manifest.read_text());cases=[c for c in m['cases'] if c['suite']=='banking' and (a.phase!='clean_repeat' or c['condition']=='clean')]
 if a.phase=='smoke':cases=[c for c in cases if c['case_id'] in ['banking__user_task_0__clean','banking__user_task_0__injection_task_0','banking__injection_task_0__goal_control']]
 assert len(cases)=={'smoke':3,'main':169,'clean_repeat':16}[a.phase];random.Random(20261111).shuffle(cases);assert not (a.out/'config.json').exists();save(a.out/'config.json',{'phase':a.phase,'cases':[c['case_id'] for c in cases],'arms':ARMS,'manifest_sha256':sha(a.manifest),'source_sha256':sha(Path(__file__)),'actor':'Pi1.5/gpt-6-luna,none/1400,16rounds240s','PGA':'originalminimal semantic review viaPi;low/1536','Progent':'original initialization/wrapper/updates exceptdeclared selectorintervention;none/8192;64logicalpolicycallcap','coupling':'Exactactorrequests andper-caseper-armoccurrence-indexed equalpolicy inputs; repeated within-arm calls neverreuse their own prior sample.','stopping':'Allcases once; no outcome retries/exclusions; failed/incomplete recorded.'});rows=[];start=time.monotonic()
 def one(index,c):
  folder=a.out/c['case_id'];folder.mkdir();rot=ARMS[1:];rot=rot[index%4:]+rot[:index%4];order=['none']+rot;arms={}
  for arm in order:
   target=folder/arm;cmd=['node',str(Path(__file__).with_name('agent.mjs')),'--python',sys.executable,'--manifest',str(a.manifest),'--case',c['case_id'],'--arm',arm,'--out',str(target),'--actor-cache',str(folder/'actor-cache'),'--judge-cache',str(folder/'judge-cache'),'--policy-cache',str(folder/'policy-cache')];proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
   try:
    so,se=proc.communicate(timeout=720)
    if proc.returncode:raise RuntimeError('episode_process_error')
    arms[arm]=json.loads(target.with_suffix('.json').read_text())
   except Exception as e:
    if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.communicate()
    arms[arm]={'status':'adapter_error','error':type(e).__name__,'usage_unknown':True};save(folder/(arm+'.failure.json'),arms[arm])
  valid=all(e.get('status') not in INFRA and e.get('native_utility') is not None and (c['condition']!='attack' or e.get('native_targeted_asr') is not None) for e in arms.values());states=[e.get('initial_state_sha256') for e in arms.values()];valid=bool(valid and None not in states and len(set(states))==1)
  batches=[]
  for arm,e in arms.items():
   for call in e.get('pi',{}).get('calls',[]):
    key=call.get('coupling',{}).get('request_sha256');path=folder/'actor-cache'/(str(key)+'.json')
    if not path.exists():valid=False;continue
    x=json.loads(path.read_text())
    if arm in {'optional','forced','result_aware'} and sum(q['type']=='toolCall' for q in x['message']['content'])>1:batches.append([arm,key]);valid=False
  row={k:c[k] for k in ['case_id','task_id','condition']};row.update(order=order,arms=arms,valid=valid,batch_violations=batches);save(folder/'case.json',row);return row
 with concurrent.futures.ThreadPoolExecutor(max_workers=4 if a.phase!='smoke' else 2) as pool:
  fs=[pool.submit(one,i,c) for i,c in enumerate(cases)]
  for f in concurrent.futures.as_completed(fs):
   rows.append(f.result());summary={'scheduled':len(cases),'observed':len(rows),'complete':len(rows)==len(cases),'invalid_or_incomplete':sum(not r['valid'] for r in rows),'elapsed_s':time.monotonic()-start,'groups':{}}
   for cond in ['clean','attack','goal_control']:
    selected=[r for r in rows if r['condition']==cond];summary['groups'][cond]={'n':len(selected)}
    for arm in ARMS:
     es=[r['arms'][arm] for r in selected];summary['groups'][cond][arm]={'utility':sum(e.get('native_utility') is True for e in es),'targeted_asr':sum(e.get('native_targeted_asr') is True for e in es),'unknown':sum(e.get('native_utility') is None or e.get('status') in INFRA for e in es)}
   save(a.out/'summary.json',{**summary,'rows':rows});save(a.out/'result.json',summary);(a.out/'status.md').write_text(f"{a.phase}: {len(rows)}/{len(cases)}cases; invalid/incomplete{summary['invalid_or_incomplete']}; elapsed{summary['elapsed_s']:.1f}s.\n");print(json.dumps(summary),flush=True)
if __name__=='__main__':main()
