"""Fresh native Pi episodes with preselected replicate-zero constructed policies."""
import argparse,hashlib,json,os,signal,subprocess,time
from pathlib import Path
ARMS=['none','values','refs','query']
def main():
 p=argparse.ArgumentParser();p.add_argument('--construction',type=Path,required=True);p.add_argument('--runtime',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();assert os.environ.get('CUDA_VISIBLE_DEVICES')=='';a.out.mkdir(parents=True,exist_ok=True);assert not (a.out/'config.json').exists()
 policies={arm:a.construction/'toolsandbox_contact_message/replicate-0'/f'{arm}.policy.json' for arm in ARMS[1:]}
 config={'scenario':'send_message_with_contact_content_cellular_off','replicates':2,'arms':ARMS,'policy_selection':'Construction sample0, predeclared before all model outcomes. No best-of-N.','policy_hashes':{arm:hashlib.sha256(p.read_bytes()).hexdigest() for arm,p in policies.items()},'model':'gpt-6-luna','scope':'One benign native integration scenario; no attack efficacy or general task-preservation estimate. Native milestone and owner-literal effect endpoints separate. Source view is fixed under the four allowed tools, not a dynamic revalidation claim.'}
 (a.out/'config.json').write_text(json.dumps(config,indent=2)+'\n');rows=[];start=time.monotonic()
 for rep in range(2):
  order=ARMS[rep:]+ARMS[:rep]
  for arm in order:
   out=a.out/f'{arm}-{rep}.json';cmd=['node',str(a.runtime/'evaluation/witness_native/agent.mjs'),'--arm','none' if arm=='none' else 'gate','--max-rounds','16','--out',str(out)]
   if arm!='none':cmd+=['--policy',str(policies[arm])]
   proc=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
   try:
    so,se=proc.communicate(timeout=360)
    if proc.returncode:raise RuntimeError('native_adapter_error')
    report=json.loads(out.read_text());r=report['result'];row={'arm':arm,'replicate':rep,'status':r['pi']['status'],'native':r['native_utility'],'owner':r['owner_effect_oracle'],'model_calls':len(r['pi']['calls']),'output_sha256':hashlib.sha256(out.read_bytes()).hexdigest()}
   except Exception as e:
    if proc.poll() is None:os.killpg(proc.pid,signal.SIGTERM);proc.communicate()
    row={'arm':arm,'replicate':rep,'status':'adapter_error','error':type(e).__name__,'usage_unknown':True};(a.out/f'{arm}-{rep}.failure.json').write_text(json.dumps(row,indent=2)+'\n')
   rows.append(row);result={'completed':len(rows),'scheduled':8,'rows':rows,'elapsed_s':time.monotonic()-start};(a.out/'results.json').write_text(json.dumps(result,indent=2)+'\n');(a.out/'status.md').write_text(f'Native Pi lifecycle {len(rows)}/8 fresh episodes; one scenario, no attack.\n');print(json.dumps({'arm':arm,'replicate':rep,'status':row['status'],'native':row.get('native'),'owner':row.get('owner')}),flush=True)
if __name__=='__main__':main()
