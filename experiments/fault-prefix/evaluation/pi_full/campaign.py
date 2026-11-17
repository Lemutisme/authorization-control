"""Owned, resumable all-suite evaluation; each case gets one fresh Pi process."""
import argparse,concurrent.futures,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path

def atomic(path,value):
    temporary=path.with_suffix(path.suffix+'.tmp');temporary.write_text(json.dumps(value,indent=2)+'\n');temporary.replace(path)
def digest(path):return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--arm',choices=['none','pga'],required=True);p.add_argument('--out',type=Path)
    p.add_argument('--workers',type=int,default=8);p.add_argument('--cases',nargs='*')
    p.add_argument('--resume',action='store_true');a=p.parse_args()
    if not 1<=a.workers<=8:raise ValueError('Worker ceiling8 per arm')
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    data=json.loads(a.manifest.read_text());cases=[c for c in data['cases'] if not a.cases or c['case_id'] in a.cases]
    if a.cases and {c['case_id'] for c in cases}!=set(a.cases):raise ValueError('Unknown case')
    if len({c['case_id'] for c in cases})!=len(cases):raise ValueError('Duplicate case')
    rng=random.Random(20261104);schedule=[]
    for condition in ['clean','goal_control','attack']:
        phase=[c for c in cases if c['condition']==condition];rng.shuffle(phase);schedule.extend(phase)
    root=Path(__file__).resolve().parents[1]
    sources=[Path(__file__).resolve(),Path(__file__).with_name('agent.mjs'),Path(__file__).with_name('broker.py'),
        *[root/'pi'/n for n in ['agent.mjs','luna_transport.py','package-lock.json']],
        *[root/n for n in ['pga_runtime.py','pga_bound_gate.py','pga_grounding.py','pga_gate.py','pga_oracle.py','pga_oracle_refined.py','pga_transport.py']]]
    config={'arm':a.arm,'manifest_sha256':digest(a.manifest),'case_ids':[c['case_id'] for c in schedule],
        'source_sha256':{str(f.relative_to(root)):digest(f) for f in sources},'model':'gpt-6-luna','reasoning_effort':'none',
        'actor_max_calls':16,'actor_max_output_tokens':1400,'automatic_retries':0,'workers':a.workers}
    config_path=out/'run-config.json'
    if config_path.exists():
        if not a.resume or json.loads(config_path.read_text())!=config:raise ValueError('Existing run/config mismatch')
    else:atomic(config_path,config)
    config_sha=digest(config_path);(out/'status.md').write_text('Starting full-scope case schedule.\n')
    def run(c):
        path=out/(c['case_id']+'.json')
        if path.exists():
            r=json.loads(path.read_text())
            if r.get('run_config_sha256')!=config_sha:raise ValueError('Old result identity mismatch')
            return r
        cmd=['node',str(Path(__file__).with_name('agent.mjs')),'--manifest',str(a.manifest.resolve()),
            '--case',c['case_id'],'--arm',a.arm,'--python',sys.executable,
            '--out',str(out/c['case_id']),'--delegate-reference','true']
        started=time.monotonic();proc=None
        try:
            proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
            stdout,stderr=proc.communicate(timeout=380)
            if proc.returncode or not path.exists():raise RuntimeError('episode_process_failed')
            r=json.loads(path.read_text())
        except (subprocess.TimeoutExpired,RuntimeError,OSError,ValueError) as exc:
            if proc and proc.poll() is None:
                os.killpg(proc.pid,signal.SIGTERM)
                try:proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()
            r={k:c[k] for k in ['case_id','suite','task_id','condition','profile_supported']}
            r.update(arm=a.arm,status='adapter_error',error_type=type(exc).__name__,native_utility=None,
                native_targeted_asr=None,elapsed_s=time.monotonic()-started,model_usage_unknown=True)
        r['injection_id']=c['injection_id'];r['run_config_sha256']=config_sha;r['manifest_sha256']=config['manifest_sha256'];atomic(path,r);return r
    start=time.monotonic();rows={};last_update=0
    def progress(final=False):
        ordered=[rows[c['case_id']] for c in schedule if c['case_id'] in rows]
        elapsed=time.monotonic()-start;remaining=len(schedule)-len(ordered)
        eta=elapsed*remaining/len(ordered) if ordered else None
        report={'kind':'full registry evaluation, frozen narrow PGA coverage','arm':a.arm,'scheduled':len(schedule),
            'observed':len(ordered),'rows':ordered,'elapsed_s':elapsed,'eta_s':eta,'run_config_sha256':config_sha,
            'manifest_sha256':config['manifest_sha256'],'complete':final}
        atomic(out/'results.json',report)
        if final:atomic(out/'result.json',report)
        status=f"{a.arm}: {len(ordered)}/{len(schedule)} accounted; native successes {sum(r.get('native_utility') is True for r in ordered)}; elapsed {elapsed:.1f}s; ETA {eta if eta is not None else 'unknown'}s.\n"
        status+='Native scores include only their declared scope; unsupported PGA profiles and unknowns are retained.\n'
        (out/'status.md').write_text(status)
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as executor:
        futures={executor.submit(run,c):c for c in schedule}
        pending=set(futures)
        while pending:
            done,pending=concurrent.futures.wait(pending,timeout=5,return_when=concurrent.futures.FIRST_COMPLETED)
            for future in done:
                r=future.result();rows[r['case_id']]=r
                print(json.dumps({k:r.get(k) for k in ['case_id','status','native_utility','native_targeted_asr','profile_supported']}),flush=True)
            if time.monotonic()-last_update>=10 or not pending:progress();last_update=time.monotonic()
    progress(final=True)

if __name__=='__main__':main()
