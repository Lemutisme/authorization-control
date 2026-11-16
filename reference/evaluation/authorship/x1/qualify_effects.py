"""Check every declared unit against its actual native committed state."""
import argparse,copy,json,socket
from pathlib import Path
from cohort import instantiate,normalization,near,gross,save,install
from analyze import effect_values
from pga_runtime import AuditedRuntime

def main():
 p=argparse.ArgumentParser();p.add_argument('--cohort',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();install('2026-11-05T00:00:00');d=json.loads(a.cohort.read_text());checks=[];failures=[]
 for u in d['units']:
  for mode in ['correct','M1','M3']:
   s,t,env=instantiate(u['suite'],u['task_id']);runtime=AuditedRuntime(s.tools,max_calls=64);calls=copy.deepcopy(u['canonical_calls']);value=u['correct_value'] if mode=='correct' else near(u['argument'],u['correct_value'],u) if mode=='M1' else gross(u['argument'],u['correct_value'])
   if value is None:checks.append({'unit':u['unit_id'],'mode':mode,'status':'structural_no_mutation'});continue
   calls[u['canonical_call_index']]['args'][u['argument']]=value
   for c in calls[:u['canonical_call_index']+1]:runtime.run_function(env,c['function'],copy.deepcopy(c['args']))
   e=runtime.events[-1]
   if e['error'] is not None or not e['entry_state_changed']:
    status='native_unavailable'
    if mode=='correct':failures.append({'unit':u['unit_id'],'mode':mode,'error':e['error'],'state_changed':e['entry_state_changed']})
    checks.append({'unit':u['unit_id'],'mode':mode,'status':status,'error':e['error']});continue
   try:
    values=effect_values(e,u);matched=any(normalization(u['argument'],v,u.get('calendar_owner'))==normalization(u['argument'],value,u.get('calendar_owner')) for v in values)
    if not matched:failures.append({'unit':u['unit_id'],'mode':mode,'values':values,'expected':value})
    checks.append({'unit':u['unit_id'],'mode':mode,'status':'matched' if matched else 'mismatch','values':values})
   except Exception as exc:failures.append({'unit':u['unit_id'],'mode':mode,'exception':type(exc).__name__});checks.append({'unit':u['unit_id'],'mode':mode,'status':'extraction_error'})
 result={'units':len(d['units']),'checks':checks,'failures':failures,'matched':sum(c['status']=='matched' for c in checks),'structural_or_native_unavailable':sum(c['status'] in {'structural_no_mutation','native_unavailable'} for c in checks),'model_requests':0,'network_requests':0};save(a.out,result);print(json.dumps({k:v for k,v in result.items() if k!='checks'},indent=2));assert not failures
if __name__=='__main__':main()
