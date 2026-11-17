"""Run one no-gate clean trajectory per declared task, retaining first-effect anchors."""
import argparse,concurrent.futures,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
from cohort import save
HERE=Path(__file__).resolve().parent

def one(case,manifest,out):
 folder=out/case['case_id'];folder.mkdir();target=folder/'prefix';cmd=['node',str(HERE/'agent.mjs'),'--python',sys.executable,'--manifest',str(manifest),'--case',case['case_id'],'--variant','prefix','--out',str(target),'--actor-cache',str(folder/'actor-cache')]
 proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
 try:
  stdout,stderr=proc.communicate(timeout=360)
  if proc.returncode:raise RuntimeError('episode_process_error:'+stderr[-300:])
  row=json.loads(target.with_suffix('.json').read_text())
 except Exception as exc:
  if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.communicate()
  row={'case_id':case['case_id'],'status':'adapter_error','error':str(exc),'native_utility':None,'x1_prefix_anchors':{}};save(folder/'failure.json',row)
 return row

def main():
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--phase',choices=['smoke','main'],required=True);p.add_argument('--out',type=Path);a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS']);a.out.mkdir(exist_ok=True,parents=True);assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261106';assert not (a.out/'config.json').exists()
 m=json.loads(a.manifest.read_text());cases=m['cases'] if a.phase=='main' else [c for c in m['cases'] if c['case_id']=='banking__user_task_11__clean'];save(a.out/'config.json',{'phase':a.phase,'manifest_sha256':hashlib.sha256(a.manifest.read_bytes()).hexdigest(),'cases':[c['case_id'] for c in cases],'units':m['unit_count'],'sampling':'One source-selected clean trajectory per owner task; anchors captured before first selected function. All statuses retained. Branch eligibility selected solely from this pretreatment prefix.','actor':'Pi1.5/gpt-6-luna none/1400,16 rounds','no_controller_model_requests':True});rows=[];start=time.monotonic()
 with concurrent.futures.ThreadPoolExecutor(max_workers=4 if a.phase=='main' else 1) as pool:
  futures=[pool.submit(one,c,a.manifest,a.out) for c in cases]
  for future in concurrent.futures.as_completed(futures):
   rows.append(future.result());summary={'scheduled':len(cases),'observed':len(rows),'complete':len(rows)==len(cases),'native_utility':sum(r.get('native_utility') is True for r in rows),'unknown':sum(r.get('native_utility') is None for r in rows),'available_function_anchors':sum(len(r.get('x1_prefix_anchors',{})) for r in rows),'elapsed_s':time.monotonic()-start};save(a.out/'summary.json',{**summary,'rows':rows});save(a.out/'result.json',summary);(a.out/'status.md').write_text(f"X1 prefixes {len(rows)}/{len(cases)}; anchors{summary['available_function_anchors']}; utility{summary['native_utility']}; unknown{summary['unknown']}; elapsed{summary['elapsed_s']:.1f}s\n");print(json.dumps(summary),flush=True)
if __name__=='__main__':main()
