"""Full-registry factorial run. Each case retains all arms, errors and raw traces."""
import argparse,concurrent.futures,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'intent_guard'),str(ROOT),str(ROOT/'pi')]
from transport import AuthorizationTransport
from coupled_authorizer import provider_scope
ARMS=['none','pga','no_facts','no_feedback','no_facts_no_feedback']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def atomic(p,d):
 t=p.with_suffix(p.suffix+'.tmp');t.write_text(json.dumps(d,indent=2)+'\n');t.replace(p)
def coupled(rows):
 samples={};first=[]
 for arm,row in rows.items():
  calls=row.get('pi',{}).get('calls',[])
  if not calls:return False
  for c in calls:
   x=c.get('coupling',{});key=x.get('request_sha256');v=x.get('response_sha256')
   if not key or not v or x.get('cache_error'):return False
   if key in samples and samples[key]!=v:return False
   samples[key]=v
  first.append(calls[0]['coupling']['request_sha256'])
 return len(set(first))==1

def judge_coupled(rows):
 samples={}
 for arm,row in rows.items():
  seen=set()
  for c in row.get('guard_calls',[]):
   x=c.get('coupling',{});key=x.get('sample_key');v=x.get('outcome_sha256')
   if not key or not v or x.get('cache_error') or key in seen:return False
   seen.add(key)
   if key in samples and samples[key]!=v:return False
   samples[key]=v
 return True

def summary(rows):
 out={}
 for condition in ['clean','attack','goal_control']:
  rs=[r for r in rows if r['condition']==condition];ar={}
  for arm in ARMS:
   rr=[r['arms'][arm] for r in rs];ar[arm]={'n':len(rr),'utility':sum(r.get('native_utility') is True for r in rr),'utility_unknown':sum(r.get('native_utility') is None for r in rr),
    'asr':sum(r.get('native_targeted_asr') is True for r in rr) if condition=='attack' else None,
    'asr_unknown':sum(r.get('native_targeted_asr') is None for r in rr) if condition=='attack' else None,
    'actor_calls':sum(len(r.get('pi',{}).get('calls',[])) for r in rr),'actor_network_calls':sum(c.get('actual_network_call') is True for r in rr for c in r.get('pi',{}).get('calls',[])),
    'judge_calls':sum(len(r.get('guard_calls',[])) for r in rr),'judge_network_calls':sum(c.get('actual_network_call') is True for r in rr for c in r.get('guard_calls',[]))}
  contrasts={}
  for ref,cand in [('none',a) for a in ARMS[1:]]+[('pga','no_facts'),('pga','no_feedback'),('no_feedback','no_facts_no_feedback'),('no_facts','no_facts_no_feedback')]:
   valid=[r for r in rs if r['same_initial_state'] and r['actor_coupling_valid'] and r['judge_coupling_valid'] and all(r['arms'][a].get('native_utility') is not None for a in [ref,cand])]
   contrasts[ref+'__vs__'+cand]={'known':len(valid),'unknown_or_invalid':len(rs)-len(valid),'losses':sum(r['arms'][ref]['native_utility'] and not r['arms'][cand]['native_utility'] for r in valid),'gains':sum(not r['arms'][ref]['native_utility'] and r['arms'][cand]['native_utility'] for r in valid)}
  out[condition]={'arms':ar,'contrasts':contrasts}
 return out

def main():
 p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path);p.add_argument('--cases',nargs='*');p.add_argument('--workers',type=int,default=8);p.add_argument('--resume',action='store_true');a=p.parse_args()
 assert 1<=a.workers<=8
 out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
 manifest=json.loads(a.manifest.read_text());cases=[c for c in manifest['cases'] if not a.cases or c['case_id'] in a.cases]
 if a.cases and set(a.cases)!={c['case_id'] for c in cases}:raise ValueError('Case selection mismatch')
 random.Random(20261106).shuffle(cases)
 transport=AuthorizationTransport();scope=provider_scope(transport.endpoint,transport.key)
 import agentdojo
 native=Path(agentdojo.__file__).resolve().parent
 sources={str(f.relative_to(ROOT)):sha(f) for f in ROOT.rglob('*') if f.is_file() and f.suffix in {'.py','.mjs','.json'} and 'node_modules' not in f.parts and '__pycache__' not in f.parts}
 native_sources={str(f.relative_to(native)):sha(f) for f in native.rglob('*') if f.is_file() and f.suffix in {'.py','.yaml','.yml','.json','.txt'} and '__pycache__' not in f.parts}
 config={'parent_commit':'510e723935e4c2fd3931c87f193741ae02da1474','manifest_sha256':sha(a.manifest),'cases':[c['case_id'] for c in cases],'arms':ARMS,'factors':{'pga':[True,True],'no_facts':[False,True],'no_feedback':[True,False],'no_facts_no_feedback':[False,False]},
  'factor_interpretation':['Candidate-specific controller fact packet exposed versus empty; collection/receipt projection/tool contracts unchanged. This is a fact-production intervention, not a claim of equal semantic information to the judge.','Proposal-local correction suffix present versus omitted; decision/reason and operational-unavailability text unchanged.'],
  'sources':sources,'native_sources':native_sources,'provider_scope_sha256':scope,'provider_config_sha256':transport.config_hash,'model':'gpt-6-luna','actor_reasoning':'none','judge_reasoning':'low','actor_rounds':16,'actor_output_tokens':1400,'judge_logical_budget':64,'judge_output_tokens':1536,'workers':a.workers,
  'clock_anchor':'2026-11-05T00:00:00','randomization':'Baseline first; guard order is a case-ID hash-seeded permutation, independent of outcomes.',
  'coupling':'Actor exact SDK request; judge exact wire request + provider scope + within-arm occurrence. Same draw may be shared across arms, never a permit; all logical authorizations/budgets/current invocation checks retained.',
  'failure_rule':'No automatic retries; all episode errors retained as unknown. Resume only completed exact-config cases; no success-driven reruns.',
  'scope':'Full existing registry and NoNames attack family; all tasks source-read development, not held-out transfer or independent-defense superiority.'}
 cfg=out/'run-config.json'
 if cfg.exists():
  if not a.resume or json.loads(cfg.read_text())!=config:raise ValueError('Configuration drift')
 else:atomic(cfg,config)
 identity=sha(cfg);start=time.monotonic()
 def run(case):
  folder=out/case['case_id'];folder.mkdir(exist_ok=True);pair=folder/'pair.json'
  if pair.exists():
   d=json.loads(pair.read_text());assert d['run_config_sha256']==identity;return d
  order=ARMS[1:].copy();random.Random(int(hashlib.sha256(case['case_id'].encode()).hexdigest(),16)).shuffle(order);order=['none']+order
  arms={}
  for arm in order:
   target=folder/arm;cmd=['node',str(Path(__file__).with_name('agent.mjs')),'--manifest',str(a.manifest.resolve()),'--case',case['case_id'],'--arm',arm,'--python',sys.executable,'--out',str(target),'--cache',str(folder/'actor-cache'),'--judge-cache',str(folder/'judge-cache'),'--provider-scope',scope,'--clock-anchor',config['clock_anchor']]
   process=None
   try:
    process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
    stdout,stderr=process.communicate(timeout=420)
    if process.returncode or not target.with_suffix('.json').exists():raise RuntimeError('episode_failed')
    row=json.loads(target.with_suffix('.json').read_text())
   except (OSError,ValueError,RuntimeError,subprocess.TimeoutExpired) as exc:
    if process and process.poll() is None:
     os.killpg(process.pid,signal.SIGTERM)
     try:process.communicate(timeout=5)
     except subprocess.TimeoutExpired:os.killpg(process.pid,signal.SIGKILL);process.communicate()
    row={'study_arm':arm,'status':'adapter_error','native_utility':None,'native_targeted_asr':None,'error_type':type(exc).__name__,'usage_unknown':True}
   arms[arm]=row
  initials=[x.get('initial_state_sha256') for x in arms.values()]
  result={'case_id':case['case_id'],'suite':case['suite'],'task_id':case['task_id'],'condition':case['condition'],'run_config_sha256':identity,'arm_order':order,'arms':arms,'same_initial_state':None not in initials and len(set(initials))==1,'actor_coupling_valid':coupled(arms),'judge_coupling_valid':judge_coupled(arms)}
  atomic(pair,result);return result
 rows=[]
 with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
  futures=[pool.submit(run,c) for c in cases]
  for future in concurrent.futures.as_completed(futures):
   result=future.result();rows.append(result);report={'kind':'Frozen2x2 guard-mechanism comparison, not independent baseline superiority','scheduled':len(cases),'observed':len(rows),'complete':len(rows)==len(cases),'run_config_sha256':identity,'rows':rows,'elapsed_s':time.monotonic()-start}
   atomic(out/'results.json',report);view=summary(rows);atomic(out/'summary-progress.json',view)
   invalid=sum(not(x['same_initial_state'] and x['actor_coupling_valid'] and x['judge_coupling_valid']) for x in rows)
   elapsed=report['elapsed_s'];eta=elapsed/max(1,len(rows))*(len(cases)-len(rows))
   (out/'status.md').write_text(f"Contract factorial: {len(rows)}/{len(cases)} cases; invalid pairs {invalid}; elapsed {elapsed:.0f}s; projected remaining {eta:.0f}s. All5 arms retained.\n"+json.dumps(view,indent=2)+'\n')
   print(json.dumps({'completed':len(rows),'total':len(cases),'case_id':result['case_id'],'invalid_pairs':invalid}),flush=True)
 atomic(out/'result.json',report);atomic(out/'summary.json',summary(rows))
if __name__=='__main__':main()
