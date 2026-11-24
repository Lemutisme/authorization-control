"""Native effect-oracle sensitivity controls, separate from model evaluation.

Published injection reference actions are used only as evaluator controls, never
as defender inputs. All effects are confined to the native in-memory environment.
"""
import argparse,json,time
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
from pga_runtime import AuditedRuntime
from pga_oracle import parse_public_mandate,score_episode

p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--refined',action='store_true');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
if a.refined:
 from pga_oracle_refined import score_episode
s=get_suite('v1.2.2','workspace');rows=[];started=time.monotonic()
for task_id in ['user_task_6','user_task_7','user_task_32']:
 task=s.get_user_task_by_id(task_id);m=parse_public_mandate(task_id,task.PROMPT)
 for control in ['injection_task_0','injection_task_1','read_flag_mutation','safe_read','unattested_history']:
  e=task.init_environment(s.load_and_inject_default_environment({}));before=e.model_dump(mode='json');rt=AuditedRuntime(s.tools)
  if control.startswith('injection_task_'):
   calls=s.get_injection_task_by_id(control).ground_truth(e.model_copy(deep=True))
   for call in calls:rt.run_function(e,call.function,call.args,raise_on_error=True)
  elif control=='read_flag_mutation':rt.run_function(e,'get_unread_emails',{},raise_on_error=True)
  else:rt.run_function(e,'search_calendar_events',{'query':''},raise_on_error=True)
  result=score_episode(m,before,e.model_dump(mode='json'),rt.events,events_complete=control!='unattested_history')
  expected='unknown' if control=='unattested_history' else 'compliant' if control=='safe_read' else 'violation'
  rows.append({'task_id':task_id,'control':control,'expected':expected,'observed':result['verdict'],'passed':result['verdict']==expected,'result':result})
report={'kind':'native oracle sensitivity checks, not model episodes or ASR','refined':a.refined,'cases':rows,'passed':sum(r['passed'] for r in rows),'n':len(rows),'elapsed_s':time.monotonic()-started}
(a.out/'result.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ['passed','n','elapsed_s']}))
if report['passed']!=report['n']:raise SystemExit(1)
