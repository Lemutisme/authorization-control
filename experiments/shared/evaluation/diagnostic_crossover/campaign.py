"""Bounded crossover; no outcome-dependent selection, retry or continuation."""
import argparse,concurrent.futures,hashlib,json,os,random,signal,subprocess,sys,time
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):
    tmp=p.with_suffix('.tmp');tmp.write_text(json.dumps(x,indent=2)+'\n');tmp.replace(p)
def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--phase',choices=['qualification','smoke','screen'],required=True);p.add_argument('--out',type=Path);a=p.parse_args()
    assert os.environ.get('CUDA_VISIBLE_DEVICES')=='' and os.environ.get('PYTHONHASHSEED')=='20261106'
    m=json.loads(a.manifest.read_text());out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    if (out/'run-config.json').exists():raise ValueError('Do not overwrite a prior run')
    replicas=range(m['replicates']) if a.phase=='screen' else [-1];groups=[(c,r) for c in m['cases'] for r in replicas]
    if a.phase=='smoke':groups=groups[:1]
    arms=[(g,t) for g in m['backgrounds'] for t in m['messages']]
    if a.phase=='smoke':arms=arms[:1]
    sources={str(p.relative_to(Path(__file__).parents[1])):sha(p) for p in Path(__file__).parents[1].rglob('*') if p.is_file() and 'node_modules' not in p.parts and p.suffix in {'.py','.mjs','.json'}}
    cfg={'phase':a.phase,'manifest_sha256':sha(a.manifest),'groups':[(c['case_id'],r) for c,r in groups],'arms':arms,'model':'gpt-6-luna','source_sha256':sources,'qualify':a.phase=='qualification','failure_rule':'No retries; preserve all failures.','budget':'16 actor and64 judge logical calls including the archived prefix; same native/tool budget as original.','selection':'Three previously discordant development cases; no prevalence or efficacy inference.'}
    save(out/'run-config.json',cfg);started=time.monotonic()
    def run_group(group):
        case,replicate=group;key=case['case_id']+'__rep'+str(replicate);folder=out/key;folder.mkdir();order=arms.copy();random.Random(20261108+replicate+int(hashlib.sha256(key.encode()).hexdigest()[:8],16)).shuffle(order);rows=[]
        for background,message in order:
            name=background+'__'+message;target=folder/name
            cmd=['node',str(Path(__file__).with_name('agent.mjs')),'--manifest',str(a.manifest.resolve()),'--case',case['case_id'],'--background',background,'--message',message,'--python',sys.executable,'--out',str(target),'--actor-cache',str(folder/'actor-cache'),'--judge-cache',str(folder/'judge-cache'),'--qualify','true' if a.phase=='qualification' else 'false']
            proc=None
            try:
                proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True);stdout,stderr=proc.communicate(timeout=420)
                if proc.returncode or not target.with_suffix('.json').exists():raise RuntimeError('Episode failed: '+stderr[:180])
                ep=json.loads(target.with_suffix('.json').read_text())
            except Exception as e:
                if proc and proc.poll() is None:
                    os.killpg(proc.pid,signal.SIGTERM)
                    try:proc.communicate(timeout=5)
                    except subprocess.TimeoutExpired:os.killpg(proc.pid,signal.SIGKILL);proc.communicate()
                ep={'case_id':case['case_id'],'background':background,'message':message,'status':'adapter_error','error':str(e)[:200],'usage_unknown':True}
            ep['replicate']=replicate;rows.append(ep)
        save(folder/'group.json',{'case_id':case['case_id'],'replicate':replicate,'rows':rows});return rows
    rows=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures=[pool.submit(run_group,g) for g in groups]
        for f in concurrent.futures.as_completed(futures):
            rows.extend(f.result());errors=sum(r['status']=='adapter_error' for r in rows)
            report={'phase':a.phase,'scheduled':len(groups)*len(arms),'observed':len(rows),'complete':len(rows)==len(groups)*len(arms),'elapsed_s':time.monotonic()-started,'run_config_sha256':sha(out/'run-config.json'),'rows':rows}
            save(out/'results.json',report);(out/'status.md').write_text(f'{a.phase}: {len(rows)}/{report["scheduled"]} episodes, adapter errors {errors}, elapsed {report["elapsed_s"]:.1f}s.\n')
            print(json.dumps({'complete':len(rows),'scheduled':report['scheduled'],'adapter_errors':errors}),flush=True)
    if any(r['status']=='adapter_error' for r in rows):raise SystemExit(1)
if __name__=='__main__':main()
