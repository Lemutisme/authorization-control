"""One clean lifecycle per arm; feasibility only, no efficacy estimate."""
import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path);p.add_argument('--arms',nargs='+',choices=['none','pga_minimal','progent'],default=['none','pga_minimal','progent']);a=p.parse_args();out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
 assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261106'
 root=Path(__file__).resolve().parents[1];config={'case_id':'banking__user_task_3__clean','arms':['none','pga_minimal','progent'],'manifest_sha256':sha(a.manifest),'model':'gpt-6-luna','pi_version':'1.5.0','native_version':'v1.2.2','source_sha256':{str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file() and 'node_modules' not in p.parts and p.suffix in {'.py','.mjs','.json'}},'progent_pin':'b02783b896d4bf01a2adf24738015e258db8d35b','adaptations':['Pi1.5.0 actor loop and gpt-6-luna replace the upstream model/driver.','Original function wrapper, initial/update policy generation, fallback text and banking read registration are retained.','Upstream Chat Completions is replaced by Pi Responses text calls with reasoning=none; requested temperature is logged but omitted.','Actor cap16requests/1400outputtokens; policy cap64requests/8192outputtokens. Original library parse/error retry control remains intact.','Per-call update matches upstream per-batch update only for single-tool assistant messages; this is checked in the retained smoke.','Same pinned AgentDojo task/scorers as our study; not an exact upstream benchmark-score reproduction.'],'scope':'One clean case qualifies integration and measured cost, not comparative efficacy.'}
 config['arms']=a.arms;config['recovery']='V2 added failure journaling; v3 restores the omitted Progent system prompt via Pi normalizeContext and checks privileged payload preservation before network dispatch. Source policy text/algorithm/task are unchanged.'
 if (out/'run-config.json').exists():raise RuntimeError('Do not overwrite an old smoke')
 (out/'run-config.json').write_text(json.dumps(config,indent=2)+'\n');rows=[];started=time.monotonic()
 for arm in config['arms']:
  target=out/arm;command=['node',str(Path(__file__).with_name('agent.mjs')),'--python',sys.executable,'--manifest',str(a.manifest.resolve()),'--case',config['case_id'],'--arm',arm,'--out',str(target),'--actor-cache',str(out/'actor-cache'),'--judge-cache',str(out/'judge-cache')]
  proc=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
  try:
   stdout,stderr=proc.communicate(timeout=420)
   if proc.returncode or not target.with_suffix('.json').exists():raise RuntimeError('Episode failed: '+stderr[:150])
   row=json.loads(target.with_suffix('.json').read_text())
  except Exception as e:
   if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.communicate(timeout=10)
   row={'baseline_arm':arm,'status':'adapter_error','error':str(e)[:200],'usage_unknown':True}
  rows.append(row);report={'scheduled':len(config['arms']),'observed':len(rows),'complete':len(rows)==len(config['arms']),'rows':rows,'elapsed_s':time.monotonic()-started,'run_config_sha256':sha(out/'run-config.json')};(out/'results.json').write_text(json.dumps(report,indent=2)+'\n');(out/'status.md').write_text(f'Baseline smoke {len(rows)}/{report["scheduled"]}, errors {sum(r["status"]=="adapter_error" for r in rows)}, elapsed {report["elapsed_s"]:.1f}s.\n');print(json.dumps({'arm':arm,'status':row['status'],'utility':row.get('native_utility'),'policy_calls':None if row.get('usage_unknown') else len(row.get('policy_calls',[]))}),flush=True)
 if any(r['status']=='adapter_error' for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
