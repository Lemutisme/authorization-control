"""Format-control follow-up on the same fixed task; no agent effects."""
import argparse,concurrent.futures,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):
    t=p.with_suffix('.tmp');t.write_text(json.dumps(x,indent=2)+'\n');t.replace(p)
def main():
    p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);p.add_argument('--phase',choices=['smoke','main'],required=True);p.add_argument('--out',type=Path);a=p.parse_args();assert os.environ.get('CUDA_VISIBLE_DEVICES')==''
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True);assert not (out/'run-config.json').exists();n=1 if a.phase=='smoke' else 3;start=time.monotonic();root=Path(__file__).resolve().parents[1]
    config={'phase':a.phase,'replicates':n,'arms':['flat','joint'],'fixture_sha256':sha(a.fixture),'source_sha256':{str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file() and 'node_modules' not in p.parts and p.suffix in {'.py','.mjs','.json'}},'model':'gpt-6-luna','policy_reasoning':'none','policy_output_tokens':8192,'policy_request_cap':64,'pairing':'same legitimate task/source information; interleaved independently sampled constructor outputs; no shared response across different prompts','scope':'One clarified existing task, component construction only, finite pure policy probes; no executed attack, actor rollout, or general efficacy estimate.'};save(out/'run-config.json',config)
    def run(i):
        folder=out/f'sample-{i:02d}';folder.mkdir();arms={};order=['flat','joint'] if i%2==0 else ['joint','flat']
        for arm in order:
            target=folder/arm;proc=None
            try:
                proc=subprocess.Popen([sys.executable,'-B',str(Path(__file__).with_name('construct.py')),'--fixture',str(a.fixture),'--arm',arm,'--out',str(target)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);so,se=proc.communicate(timeout=240)
                if proc.returncode:raise RuntimeError('constructor_failed')
                arms[arm]=json.loads(Path(str(target)+'.json').read_text())
            except Exception as e:
                if proc and proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.communicate(timeout=5)
                arms[arm]={'arm':arm,'status':'adapter_error','error':type(e).__name__,'usage_unknown':True}
        row={'sample':i,'arms':arms,'order':order};save(folder/'pair.json',row);return row
    rows=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4 if n>1 else 1) as pool:
        for row in pool.map(run,range(n)):
            rows.append(row);metrics={'samples':len(rows),'incomplete':sum(e['status']!='completed' for r in rows for e in r['arms'].values()),'flat_exact':sum(r['arms']['flat'].get('exact_conformance') is True for r in rows),'joint_exact':sum(r['arms']['joint'].get('exact_conformance') is True for r in rows)}
            save(out/'results.json',{'complete':len(rows)==n,'scheduled':n,'rows':rows,'elapsed_s':time.monotonic()-start,'config_sha256':sha(out/'run-config.json')});save(out/'result.json',metrics);(out/'status.md').write_text(f'{a.phase}: {len(rows)}/{n} pairs; exact flat {metrics["flat_exact"]}, joint {metrics["joint_exact"]}; incomplete {metrics["incomplete"]}.\n');print(json.dumps(metrics),flush=True)
if __name__=='__main__':main()
