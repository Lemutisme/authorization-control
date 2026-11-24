"""Bounded, fresh Pi closed-loop episodes; old PGA measurements are untouched."""
import argparse,hashlib,json,os,subprocess,sys,time
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True)
    p.add_argument('--arm',choices=['none','pga','sop_equivalent'],required=True)
    p.add_argument('--cases',nargs='*');p.add_argument('--out',type=Path)
    p.add_argument('--delegate-reference',action='store_true');p.add_argument('--max-rounds',type=int,default=16)
    a=p.parse_args();out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    manifest=json.loads(a.manifest.read_text());cases=[c for c in manifest['cases'] if not a.cases or c['case_id'] in a.cases]
    if a.cases and {c['case_id'] for c in cases}!=set(a.cases):raise ValueError('Unknown case')
    start=time.monotonic();rows=[];consecutive_failure=0
    for i,c in enumerate(cases):
        (out/'status.md').write_text(f'Pi {a.arm}: {i}/{len(cases)} cases; {sum(r.get("native_utility") is True for r in rows)} successes; gpt-6-luna/none.\n')
        if consecutive_failure>=2:
            row={'case_id':c['case_id'],'task_id':c['task_id'],'condition':c['condition'],'arm':a.arm,
                 'status':'not_run_after_two_failures','native_utility':None,'native_targeted_asr':None}
        else:
            cmd=['node',str(Path(__file__).with_name('agent.mjs')),'--manifest',str(a.manifest.resolve()),
                '--case',c['case_id'],'--arm',a.arm,'--model','gpt-6-luna','--python',sys.executable,
                '--out',str(out/c['case_id']),'--delegate-reference',str(a.delegate_reference).lower(),
                '--max-rounds',str(a.max_rounds)]
            try:
                result=subprocess.run(cmd,capture_output=True,text=True,timeout=380)
                path=out/(c['case_id']+'.json')
                if result.returncode or not path.exists():raise RuntimeError('Pi adapter failed')
                row=json.loads(path.read_text())
            except (subprocess.TimeoutExpired,RuntimeError) as exc:
                row={'case_id':c['case_id'],'task_id':c['task_id'],'condition':c['condition'],'arm':a.arm,
                     'status':'adapter_error','native_utility':None,'native_targeted_asr':None,'error_type':type(exc).__name__}
            if row['status'] in {'inference_error','adapter_error','episode_timeout'}:consecutive_failure+=1
            else:consecutive_failure=0
        rows.append(row)
        report={'kind':'fresh Pi closed-loop development integration; not held-out efficacy',
            'arm':a.arm,'rows':rows,'scheduled':len(cases),'manifest_sha256':hashlib.sha256(a.manifest.read_bytes()).hexdigest(),
            'elapsed_s':time.monotonic()-start,'model':'gpt-6-luna','reasoning_effort':'none',
            'equivalent_sop_limit':'sop_equivalent reuses the same protected controller; not an independent algorithm comparison'}
        (out/'results.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({k:row.get(k) for k in ['case_id','status','native_utility','native_targeted_asr']}),flush=True)
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    (out/'status.md').write_text(f'Pi {a.arm}: {len(rows)}/{len(cases)} cases accounted; native utility {sum(r.get("native_utility") is True for r in rows)}/{len(rows)}; no generalization claim.\n')

if __name__=='__main__':main()
