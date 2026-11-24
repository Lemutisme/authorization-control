"""Complete X1 static-fault continuation panel on frozen pretreatment anchors."""
import argparse,concurrent.futures,copy,gzip,hashlib,json,os,random,shutil,signal,subprocess,sys,time
from pathlib import Path
from cohort import save
from analyze import classify
HERE=Path(__file__).resolve().parent
INFRA={'adapter_error','inference_error','episode_timeout','no_response'}

def one(unit,conditions,args):
 folder=args.out/unit['unit_id'];folder.mkdir();prefix=args.prefix/unit['case_id'];cache=folder/'actor-cache';shutil.copytree(prefix/'actor-cache',cache);shutil.copyfile(prefix/'prefix.json.gz',folder/'none.json.gz');source=json.loads(gzip.decompress((prefix/'prefix.json.gz').read_bytes()));rows=[]
 # Control is a copied, shared baseline outcome. It is never counted as a new
 # model trajectory or as an independent task observation.
 save(folder/'baseline-reference.json',{'reused_no_gate':True,'source_raw_sha256':hashlib.sha256((prefix/'prefix.json.gz').read_bytes()).hexdigest(),'native_utility':source['result']['native_utility'],'source_case_id':unit['case_id']})
 order=conditions[:];random.Random('20261111/'+unit['unit_id']).shuffle(order)
 for c in order:
  target=folder/c['condition_id'];cmd=['node',str(HERE/'agent.mjs'),'--python',sys.executable,'--manifest',str(args.cohort),'--case',unit['case_id'],'--variant',c['variant'],'--unit',unit['unit_id'],'--condition',str(args.branches.parent/'conditions'/(c['condition_id']+'.json')),'--out',str(target),'--actor-cache',str(cache)]
  proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  try:
   so,se=proc.communicate(timeout=360)
   if proc.returncode:raise RuntimeError('episode_process_error:'+se[-300:])
   raw=json.loads(gzip.decompress(target.with_suffix('.json.gz').read_bytes()));metric=classify(raw,unit,c);anchor=raw['result'].get('x1_anchor');prefix_match=bool(anchor and anchor['prefix_sha256']==c['prefix_sha256']);known=prefix_match and not metric['extract_errors'] and metric['status'] not in INFRA
   r={**c,**metric,'known':known,'prefix_match':prefix_match,'no_gate_native_utility':source['result']['native_utility'],'logical_actor_requests':len(raw['result']['pi']['calls'])}
  except Exception as exc:
   if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.communicate()
   r={**c,'known':False,'status':'adapter_error','error':str(exc),'no_gate_native_utility':source['result']['native_utility']};save(folder/(c['condition_id']+'.failure.json'),r)
  rows.append(r);save(folder/'case.json',{'unit':unit,'condition_order':[c['condition_id'] for c in order],'rows':rows})
 return rows

def main():
 p=argparse.ArgumentParser();p.add_argument('--cohort',type=Path,required=True);p.add_argument('--prefix',type=Path,required=True);p.add_argument('--branches',type=Path,required=True);p.add_argument('--phase',choices=['smoke','main'],required=True);p.add_argument('--out',type=Path);a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS']);a.out.mkdir(parents=True,exist_ok=True);assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261106';assert not (a.out/'config.json').exists()
 cohort=json.loads(a.cohort.read_text());branches=json.loads(a.branches.read_text());units={u['unit_id']:u for u in cohort['units']};conditions=branches['condition_rows']
 if a.phase=='smoke':conditions=[c for c in conditions if c['unit_id']=='banking__user_task_11__send_money__amount' and (c['fault_class'],c['feedback']) in {('none','F0'),('M1','F0'),('M1','F3')}]
 if a.phase=='smoke' and not conditions:raise ValueError('Smoke unit has no valid pretreatment anchor; declare another smoke separately, do not silently choose after outcomes')
 byunit={k:[c for c in conditions if c['unit_id']==k] for k in units};byunit={k:v for k,v in byunit.items() if v};save(a.out/'config.json',{'phase':a.phase,'cohort_sha256':hashlib.sha256(a.cohort.read_bytes()).hexdigest(),'branches_sha256':hashlib.sha256(a.branches.read_bytes()).hexdigest(),'scheduled_conditions':len(conditions),'exposed_units_with_conditions':len(byunit),'conditions':[c['condition_id'] for c in conditions],'actor':'Pi1.5/gpt-6-luna none/1400,16rounds','controller':'No model: evaluator-provided static binding and original Progent checker, explicit feedback transform','baseline':'Per-task no-gate result is reused reference, not newly generated per unit'});rows=[];start=time.monotonic()
 with concurrent.futures.ThreadPoolExecutor(max_workers=4 if a.phase=='main' else 1) as pool:
  futures=[pool.submit(one,units[k],cs,a) for k,cs in byunit.items()]
  for f in concurrent.futures.as_completed(futures):
   rows.extend(f.result());r={'scheduled':len(conditions),'observed':len(rows),'complete':len(rows)==len(conditions),'known':sum(r['known'] for r in rows),'unknown':sum(not r['known'] for r in rows),'fault_value_effects':sum(r.get('fault_value_effect',False) for r in rows if r['known']),'wrong_effects':sum(r.get('wrong_effect',False) for r in rows if r['known']),'correct_effects':sum(r.get('correct_effect',False) for r in rows if r['known']),'native_utility':sum(r.get('native_utility') is True for r in rows),'elapsed_s':time.monotonic()-start};save(a.out/'summary.json',{**r,'rows':rows});save(a.out/'result.json',r);(a.out/'status.md').write_text(f"X1 {a.phase} {len(rows)}/{len(conditions)}; unknown{r['unknown']}; native wrong effects{r['wrong_effects']}; elapsed{r['elapsed_s']:.1f}s\n");print(json.dumps(r),flush=True)
if __name__=='__main__':main()
