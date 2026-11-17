"""Matched construction campaign with competent table and reference baselines."""
import argparse,concurrent.futures,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path
MODES=['values','refs','query']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):
    t=p.with_suffix('.tmp');t.write_text(json.dumps(x,indent=2)+'\n');t.replace(p)
def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--phase',choices=['smoke','main'],required=True);p.add_argument('--out',type=Path);a=p.parse_args();assert os.environ.get('CUDA_VISIBLE_DEVICES')==''
    m=json.loads(a.manifest.read_text());cases=m['cases'] if a.phase=='main' else [c for c in m['cases'] if c['case_id']=='dojo_workspace25'];reps=4 if a.phase=='main' else 1
    jobs=[(c,i) for c in cases for i in range(reps)];random.Random(20261110).shuffle(jobs);out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True);assert not (out/'run-config.json').exists();root=Path(__file__).resolve().parents[1]
    config={'phase':a.phase,'modes':MODES,'jobs':[{'case_id':c['case_id'],'replicate':i} for c,i in jobs],'manifest_sha256':sha(a.manifest),'model':'gpt-6-luna','reasoning':'none','output_tokens':8192,'max_policy_requests':2,'repair':'One deterministic compiler-error repair at most; no oracle feedback or repair of a well-typed wrong relation.','source_sha256':{str(p.relative_to(root)):sha(p) for p in root.rglob('*') if p.is_file() and 'node_modules' not in p.parts and p.suffix in {'.py','.mjs','.json'}},'scope':'Five source-inspected construction tasks; no heldout or independent-task claim for repeat samples. Native lifecycle is a separate study.'};save(out/'run-config.json',config);start=time.monotonic()
    def run(job):
        case,i=job;f=a.manifest.parent/case['path'];assert sha(f)==case['sha256'];folder=out/case['case_id']/f'replicate-{i}';folder.mkdir(parents=True);modes={};order=MODES[i%3:]+MODES[:i%3]
        for mode in order:
            target=folder/mode;proc=None
            try:
                proc=subprocess.Popen([sys.executable,'-B',str(Path(__file__).with_name('construct.py')),'--fixture',str(f),'--mode',mode,'--out',str(target)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);so,se=proc.communicate(timeout=240)
                if proc.returncode:raise RuntimeError('constructor_failed')
                modes[mode]=json.loads(Path(str(target)+'.json').read_text())
            except Exception as e:
                if proc and proc.poll() is None:
                    os.killpg(proc.pid,signal.SIGTERM)
                    try:proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()
                modes[mode]={'mode':mode,'status':'adapter_error','error_type':type(e).__name__,'usage_unknown':True}
        row={'case_id':case['case_id'],'domain':case['domain'],'replicate':i,'order':order,'arms':modes};save(folder/'pair.json',row);return row
    rows=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4 if a.phase=='main' else 1) as pool:
        for row in pool.map(run,jobs):
            rows.append(row);metrics={'triples':len(rows),'operational_errors':sum(e['status'] in {'adapter_error','transport_error'} for r in rows for e in r['arms'].values())}
            for mode in MODES:metrics[mode+'_exact']=sum(r['arms'][mode].get('exact_grounding') is True for r in rows);metrics[mode+'_invalid']=sum(r['arms'][mode]['status']=='invalid_program' for r in rows)
            save(out/'results.json',{'scheduled':len(jobs),'observed':len(rows),'complete':len(rows)==len(jobs),'rows':rows,'elapsed_s':time.monotonic()-start,'config_sha256':sha(out/'run-config.json')});save(out/'result.json',metrics);(out/'status.md').write_text(f'{a.phase}: {len(rows)}/{len(jobs)} task triples; exact values/ref/query {metrics["values_exact"]}/{metrics["refs_exact"]}/{metrics["query_exact"]}; operational errors {metrics["operational_errors"]}.\n');print(json.dumps(metrics),flush=True)
if __name__=='__main__':main()
