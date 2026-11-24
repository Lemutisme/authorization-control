"""One isolated arm of the frozen exploratory AgentDojo cohort."""
from __future__ import annotations
import argparse,hashlib,json,os,time,traceback
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
from pga_benchmark import run_episode

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--manifest',type=Path,required=True);ap.add_argument('--arm',required=True);ap.add_argument('--out',type=Path)
    a=ap.parse_args();d=json.loads(a.manifest.read_text());out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    if a.arm not in d['arms']:raise ValueError('Unregistered arm')
    suite=get_suite(d['version'],d['suite']);rows=[];started=time.monotonic();consecutive_transport=0
    (out/'input-manifest.json').write_bytes(a.manifest.read_bytes())
    for index,c in enumerate(d['cases']):
        status=f"{a.arm}: {index}/{len(d['cases'])} exploratory episodes; {sum(r.get('native_utility') is True for r in rows)} native successes; elapsed {time.monotonic()-started:.1f}s\n"
        (out/'status.md').write_text(status)
        if consecutive_transport>=2:
            row={'task_id':c['task_id'],'arm':a.arm,'injection_id':c['injection_id'],'status':'not_run_transport_stop','native_utility':None,'native_targeted_asr':None,'effect_score':None,'model_calls':0,'errors':['two consecutive inference failures; scheduled row retained']}
        else:
            try:
                row=run_episode(suite,c['task_id'],a.arm,c['injections'],c['injection_id'],out/c['case_id'],max_steps=d['max_model_rounds'],max_output_tokens=d['max_output_tokens_per_round'],condition=c['condition'],reference_goal_id=c.get('reference_goal_id'))
            except Exception as e:
                row={'task_id':c['task_id'],'arm':a.arm,'injection_id':c['injection_id'],'status':'adapter_error','native_utility':None,'native_targeted_asr':None,'effect_score':None,'model_calls':None,'errors':[type(e).__name__]}
                (out/(c['case_id']+'.error.txt')).write_text(traceback.format_exc())
        if row['status']=='transport_error':consecutive_transport+=1
        elif row['status']!='not_run_transport_stop':consecutive_transport=0
        row['case_id']=c['case_id'];row['condition']=c['condition'];rows.append(row)
        (out/'results.json').write_text(json.dumps({'arm':a.arm,'rows':rows,'manifest_sha256':hashlib.sha256(a.manifest.read_bytes()).hexdigest(),'elapsed_s':time.monotonic()-started},indent=2,default=str)+'\n')
        print(json.dumps({k:row.get(k) for k in ['case_id','arm','status','native_utility','native_targeted_asr','model_calls','collector_invocations','injection_exposure_outputs']}),flush=True)
    (out/'status.md').write_text(f"{a.arm}: {len(rows)}/{len(d['cases'])} exploratory episodes accounted; native utility {sum(r.get('native_utility') is True for r in rows)}/{len(rows)}; elapsed {time.monotonic()-started:.1f}s; efficacy/generalization not established\n")
if __name__=='__main__':main()
