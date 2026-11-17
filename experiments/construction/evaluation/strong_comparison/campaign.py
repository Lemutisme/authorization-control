"""Whole banking comparison using the unchanged qualified baseline adapter."""
import argparse,collections,concurrent.futures,gzip,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ARMS=['none','pga_minimal','progent']
SMOKE=['banking__user_task_0__clean','banking__user_task_0__injection_task_0','banking__injection_task_0__goal_control']
INFRA={'adapter_error','inference_error','episode_timeout','no_response'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):
    tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(x,indent=2)+'\n');tmp.replace(p)
def brief(rows):
    result={'cases':len(rows),'invalid_or_incomplete':sum(not r['pair_valid'] for r in rows)}
    for condition in ['clean','attack','goal_control']:
        selected=[r for r in rows if r['condition']==condition];result[condition]={'n':len(selected)}
        for arm in ARMS:
            es=[r['arms'][arm] for r in selected];result[condition][arm]={'utility':sum(e.get('native_utility') is True for e in es),'asr':sum(e.get('native_targeted_asr') is True for e in es),'unknown':sum(e['status'] in INFRA or e.get('native_utility') is None for e in es)}
    return result
def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--phase',choices=['smoke','main'],required=True);p.add_argument('--workers',type=int,default=6);p.add_argument('--out',type=Path);a=p.parse_args()
    assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261106' and 1<=a.workers<=8
    m=json.loads(a.manifest.read_text());cases=[c for c in m['cases'] if c['suite']=='banking' and (a.phase=='main' or c['case_id'] in SMOKE)]
    assert len(cases)==(169 if a.phase=='main' else 3) and not any(c['profile_supported'] for c in cases)
    random.Random(20261109).shuffle(cases);out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True);assert not (out/'run-config.json').exists()
    source=Path(os.environ['PROGENT_SOURCE']);pin=subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip();assert pin=='b02783b896d4bf01a2adf24738015e258db8d35b'
    cfg={'phase':a.phase,'cases':[c['case_id'] for c in cases],'arms':ARMS,'manifest_sha256':sha(a.manifest),'model':'gpt-6-luna','pi_version':'1.5.0','progent_pin':pin,'progent_source_sha256':{str(p.relative_to(source)):sha(p) for p in (source/'secagent').rglob('*.py')},'source_sha256':{str(p.relative_to(ROOT)):sha(p) for p in ROOT.rglob('*') if p.is_file() and 'node_modules' not in p.parts and p.suffix in {'.py','.mjs','.json'}},'workers':a.workers,'actor_budget':{'requests':16,'output_tokens':1400,'episode_ms':240000},'policy_budget':{'requests':64,'output_tokens':8192},'sampling':'Fresh per-case exact-request actor response sharing. Reference first, defense order counterbalanced by case order. No policy-response sharing across methods.','adaptations':['Use the already qualified unchanged original Progent wrapper/generation/update and release settings through Pi Responses/gpt-6-luna.','Temperature requests retained in logs but omitted by transport. Policy sampling differs from the PGA judge; report whole-system results and cost, not a component-isolated mechanism advantage.','Single-tool assistant batches required for per-call update equivalence; verify from every cached message.','PGA-minimal is no_facts_no_feedback, not full pga. Banking has no shared task-specific profile.'],'failure_rule':'No episode retries/exclusions; native task failures retained; infrastructure failures and missing usage remain unknown.'}
    save(out/'run-config.json',cfg);cfgsha=sha(out/'run-config.json');started=time.monotonic()
    def run(index,case):
        folder=out/case['case_id'];folder.mkdir();arms={};order=['none']+(['pga_minimal','progent'] if index%2==0 else ['progent','pga_minimal'])
        for arm in order:
            target=folder/arm;proc=None
            try:
                cmd=['node',str(ROOT/'baseline_audit/agent.mjs'),'--python',sys.executable,'--manifest',str(a.manifest.resolve()),'--case',case['case_id'],'--arm',arm,'--out',str(target),'--actor-cache',str(folder/'actor-cache'),'--judge-cache',str(folder/'judge-cache')]
                proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);stdout,stderr=proc.communicate(timeout=720)
                if proc.returncode or not target.with_suffix('.json').exists():raise RuntimeError('episode_failed')
                arms[arm]=json.loads(target.with_suffix('.json').read_text())
            except Exception as e:
                if proc and proc.poll() is None:
                    os.killpg(proc.pid,signal.SIGTERM)
                    try:proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()
                arms[arm]={'baseline_arm':arm,'status':'adapter_error','error_type':type(e).__name__,'usage_unknown':True}
        seen={};valid=True;batch_violations=[]
        for arm,ep in arms.items():
            if ep['status'] in INFRA or ep.get('native_utility') is None:valid=False
            if case['condition']=='attack' and ep.get('native_targeted_asr') is None:valid=False
            if not ep.get('pi',{}).get('calls'):valid=False
            for call in ep.get('pi',{}).get('calls',[]):
                x=call.get('coupling',{});k=x.get('request_sha256');v=x.get('response_sha256')
                if not k or not v or x.get('cache_error') or k in seen and seen[k]!=v:valid=False
                seen[k]=v;cache=folder/'actor-cache'/(str(k)+'.json')
                if not cache.exists():valid=False;continue
                saved=json.loads(cache.read_text())
                if arm=='progent' and sum(c['type']=='toolCall' for c in saved['message']['content'])>1:batch_violations.append(k);valid=False
        initial=[ep.get('initial_state_sha256') for ep in arms.values()]
        valid=bool(valid and None not in initial and len(set(initial))==1)
        row={k:case[k] for k in ['case_id','suite','task_id','condition']};row.update(arms=arms,pair_valid=valid,arm_order=order,batch_violations=batch_violations,run_config_sha256=cfgsha)
        save(folder/'pair.json',row);return row
    rows=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as pool:
        fs=[pool.submit(run,i,c) for i,c in enumerate(cases)]
        for f in concurrent.futures.as_completed(fs):
            rows.append(f.result());metrics=brief(rows);elapsed=time.monotonic()-started
            save(out/'results.json',{'scheduled':len(cases),'observed':len(rows),'complete':len(rows)==len(cases),'rows':rows,'elapsed_s':elapsed,'run_config_sha256':cfgsha})
            save(out/'result.json',metrics);(out/'status.md').write_text(f'{a.phase}: {len(rows)}/{len(cases)} case triples; invalid/incomplete {metrics["invalid_or_incomplete"]}; elapsed {elapsed:.1f}s.\n')
            print(json.dumps(metrics),flush=True)
if __name__=='__main__':main()
