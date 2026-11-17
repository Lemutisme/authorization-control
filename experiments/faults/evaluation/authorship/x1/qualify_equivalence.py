"""Native implicit end time and owner insertion must not become false prerequisites."""
import argparse,copy,contextlib,importlib.util,io,json
from pathlib import Path
from cohort import save,near
spec=importlib.util.spec_from_file_location('x1q_equiv',Path(__file__).with_name('qualify.py'));q=importlib.util.module_from_spec(spec);spec.loader.exec_module(q)

def main():
 p=argparse.ArgumentParser();p.add_argument('--cohort',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();m=json.loads(a.cohort.read_text());checks=[];q.broker.base.base.LunaTransport=q.OfflineTransport
 for key in ['implicit_end','explicit_owner','datetime_disclosure']:
  uid={'implicit_end':'workspace__user_task_7__reschedule_calendar_event__new_end_time','explicit_owner':'workspace__user_task_6__create_calendar_event__participants','datetime_disclosure':'workspace__user_task_6__create_calendar_event__start_time'}[key];u=next(x for x in m['units'] if x['unit_id']==uid);projection=copy.deepcopy(u['correct_projection']);call=copy.deepcopy(u['canonical_calls'][u['canonical_call_index']])
  if key=='implicit_end':call['args'].pop('new_end_time')
  if key=='explicit_owner':call['args']['participants'].append(u['calendar_owner'])
  if key=='datetime_disclosure':projection[u['argument']]=near(u['argument'],u['correct_value'],u)
  with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
   b=q.broker.Broker();b.init({'manifest':str(a.cohort),'case_id':u['case_id'],'model':'gpt-6-luna','variant':'fault' if key=='datetime_disclosure' else 'oracle_correct','feedback':'F0','unit':u,'bound_projection':projection,'clock_anchor':'2026-11-05T00:00:00'})
   for i,c in enumerate(u['canonical_calls'][:u['canonical_call_index']]):b.invoke({'name':c['function'],'args':c['args'],'call_id':f'q{i}'})
   answer=b.invoke({'name':call['function'],'args':call['args'],'call_id':'first'})
   if key=='datetime_disclosure':
    assert answer['is_error'] and projection[u['argument']] in answer['text'];call['args'][u['argument']]=projection[u['argument']];answer=b.invoke({'name':call['function'],'args':call['args'],'call_id':'copy_bound'})
   assert not answer['is_error'];checks.append({'case':key,'passed':True,'native_effect':b.runtime.events[-1]['entry_state_changed'],'display_value':projection[u['argument']]})
 save(a.out,{'passed':len(checks),'checks':checks,'model_requests':0,'network_requests':0});print(json.dumps({'passed':len(checks)}))
if __name__=='__main__':main()
