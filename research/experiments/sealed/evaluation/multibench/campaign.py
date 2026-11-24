"""Owned finite benchmark campaign; errors and all scheduled cases retained."""
import argparse,concurrent.futures,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'intent_guard'),str(ROOT/'pi'),str(ROOT),str(ROOT/'contract_study')]
from transport import AuthorizationTransport
from coupled_authorizer import provider_scope
ARMS=['none','repeat_task','minimal','scope_only','late_facts']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,d):
 t=p.with_suffix(p.suffix+'.tmp');t.write_text(json.dumps(d,indent=2)+'\n');t.replace(p)
def summarize(rows,arms):
 out={}
 for group in sorted({r['benchmark']+'_'+r['stratum'] for r in rows}):
  selected=[r for r in rows if r['benchmark']+'_'+r['stratum']==group];out[group]={}
  for arm in arms:
   eps=[r['arms'][arm] for r in selected];scores=[e.get('scores',{}) for e in eps]
   out[group][arm]={'n':len(eps),'dispatch_asr':sum(s.get('dispatch_asr') is True for s in scores),'native_marker_asr':sum(s.get('native_marker_asr') is True for s in scores),'native_marker_utility':sum(s.get('native_marker_utility') is True for s in scores),'native_proposal_asr':sum(s.get('native_proposal_asr') is True for s in scores),'errors':sum(e['status'] in {'adapter_error','inference_error','episode_timeout','no_response'} for e in eps),'actor_calls':sum(len(e.get('pi',{}).get('calls',[])) for e in eps),'judge_calls':sum(len(e.get('guard_calls',[])) for e in eps),'invalid_first_step':sum(s.get('native_first_step_label')=='invalid' for s in scores)}
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path);p.add_argument('--phase',choices=['smoke','pilot','injecagent','asb'],required=True);p.add_argument('--arms',nargs='+',default=['none','repeat_task','minimal']);p.add_argument('--workers',type=int,default=4);a=p.parse_args()
 assert 1<=a.workers<=8 and set(a.arms)<=set(ARMS) and a.arms[0]=='none'
 assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261107'
 manifest=json.loads(a.manifest.read_text());
 for source in manifest['sources'].values():
  for name,expected in source['files'].items():
   if sha(Path(source['path'])/name)!=expected:raise ValueError('Native source drift')
 out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
 ids=manifest.get(a.phase) if a.phase in {'smoke','pilot'} else [c['case_id'] for c in manifest['cases'] if c['benchmark']==a.phase]
 cases=[c for c in manifest['cases'] if c['case_id'] in set(ids)];random.Random(20261107).shuffle(cases)
 transport=AuthorizationTransport();scope=provider_scope(transport.endpoint,transport.key)
 config={'manifest_sha256':sha(a.manifest),'cases':[c['case_id'] for c in cases],'arms':a.arms,'phase':a.phase,'model':'gpt-6-luna','provider_scope_sha256':scope,'provider_config_sha256':transport.config_hash,'workers':a.workers,'hash_seed':'20261107','source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in ROOT.rglob('*') if p.is_file() and p.suffix in {'.py','.mjs','.json'} and 'node_modules' not in p.parts},'scope':'Pi adaptations with native scoring functions and separate simulator-dispatch audit. No new attacks, external tool effects or DS-stage2 result.','failure_rule':'No automatic provider or episode retries. All failures retained.','budgets':{'injec_actor_calls':1,'asb_actor_calls':16,'judge_calls':64,'actor_output_tokens':1400,'judge_output_tokens':1536}}
 if (out/'run-config.json').exists():raise ValueError('Output already has a run; no success-driven resume')
 save(out/'run-config.json',config);cfgsha=sha(out/'run-config.json');start=time.monotonic()
 def run(case):
  folder=out/case['case_id'];folder.mkdir();order=a.arms[1:].copy();random.Random(int(hashlib.sha256(case['case_id'].encode()).hexdigest(),16)).shuffle(order);order=['none']+order;arms={}
  for arm in order:
   target=folder/arm;cmd=['node',str(Path(__file__).with_name('agent.mjs')),'--manifest',str(a.manifest.resolve()),'--case',case['case_id'],'--arm',arm,'--python',sys.executable,'--out',str(target),'--cache',str(folder/'actor-cache'),'--judge-cache',str(folder/'judge-cache'),'--provider-scope',scope]
   proc=None
   try:
    proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);stdout,stderr=proc.communicate(timeout=420)
    if proc.returncode or not target.with_suffix('.json').exists():raise RuntimeError('episode_failed')
    arms[arm]=json.loads(target.with_suffix('.json').read_text())
   except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as e:
    if proc and proc.poll() is None:
     os.killpg(proc.pid,signal.SIGTERM)
     try:proc.communicate(timeout=5)
     except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()
    arms[arm]={'status':'adapter_error','error_type':type(e).__name__,'scores':{},'usage_unknown':True}
  initials=[r.get('initial_state_sha256') for r in arms.values()];actor={};judge={};valid=True
  for row in arms.values():
   if not row.get('pi',{}).get('calls'):valid=False
   for c in row.get('pi',{}).get('calls',[]):
    x=c.get('coupling',{});k=x.get('request_sha256');v=x.get('response_sha256')
    if not k or not v or x.get('cache_error') or k in actor and actor[k]!=v:valid=False
    actor[k]=v
   for c in row.get('guard_calls',[]):
    x=c.get('coupling',{});k=x.get('sample_key');v=x.get('outcome_sha256')
    if not k or not v or x.get('cache_error') or k in judge and judge[k]!=v:valid=False
    judge[k]=v
  row={k:case[k] for k in ['case_id','benchmark','condition','stratum','scenario']};row.update(arms=arms,arm_order=order,run_config_sha256=cfgsha,same_initial_state=None not in initials and len(set(initials))==1,coupling_valid=valid)
  save(folder/'pair.json',row);return row
 rows=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
  futures=[pool.submit(run,c) for c in cases]
  for future in concurrent.futures.as_completed(futures):
   row=future.result();rows.append(row);elapsed=time.monotonic()-start
   report={'scheduled':len(cases),'observed':len(rows),'complete':len(rows)==len(cases),'run_config_sha256':cfgsha,'rows':rows,'elapsed_s':elapsed}
   if len(rows)%10==0 or len(rows)==len(cases):save(out/'results.json',report)
   view=summarize(rows,a.arms);save(out/'summary.json',view)
   invalid=sum(not r['same_initial_state'] or not r['coupling_valid'] for r in rows)
   (out/'status.md').write_text(f'{a.phase}: {len(rows)}/{len(cases)} cases; invalid pairs {invalid}; elapsed {elapsed:.1f}s; ETA {elapsed/max(1,len(rows))*(len(cases)-len(rows)):.1f}s.\n'+json.dumps(view,indent=2)+'\n')
   print(json.dumps({'completed':len(rows),'total':len(cases),'case_id':row['case_id'],'invalid_pairs':invalid}),flush=True)
 save(out/'result.json',report)

if __name__=='__main__':main()
