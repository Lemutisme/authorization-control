"""Reconstruct common exposed prefixes and the exact pre-update controller input."""
import argparse,concurrent.futures,contextlib,copy,gzip,hashlib,importlib.util,io,json,os,socket,subprocess,sys
from pathlib import Path
MARKER='This is an important message from me'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def norm(x):return json.loads(json.dumps(x,default=str))
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,default=str).encode()).hexdigest()
def save(p,x):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(x,indent=2)+'\n')
def prepare(a):
 def blocked(*x,**k):raise RuntimeError('Network disabled in prefix reconstruction')
 socket.create_connection=blocked;socket.socket.connect=blocked
 rawpath=a.original/a.case/'progent.json.gz';journal=a.original/a.case/'progent.policy-journal.jsonl';raw=json.loads(gzip.decompress(rawpath.read_bytes()));responses=[json.loads(s) for s in journal.read_text().splitlines() if json.loads(s)['stage']=='policy_response'];requests=[]
 spec=importlib.util.spec_from_file_location('retained_progent',a.frozen/'evaluation/baseline_audit/broker.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 class Connection:
  def __init__(self,*x,**k):self.endpoint='https://example.invalid/v1/responses';self.key=None;self.calls=[]
  def metadata(self):return {'mode':'offline'}
 class Replay:
  def __init__(self,*x):self.calls=[]
  def request(self,system,user,temperature=0):
   rec=responses[len(self.calls)];request={'system':system,'user':user,'temperature':temperature};h=hashlib.sha256(json.dumps(request,sort_keys=True).encode()).hexdigest();assert h==rec['request_sha256'];self.calls.append(rec['response']['meta']);requests.append(request)
   if not rec['response']['ok']:raise RuntimeError(rec['response']['error'])
   return rec['response']['text']
  def close(self):pass
 m.PolicyClient=Replay;m.ref.v16.base.LunaTransport=Connection
 from pga_gate import portable
 from catalog import tool_catalog,invocation_mode,PURE_READS
 from runtime import IntentRuntime
 from types import SimpleNamespace
 import threading
 updates=[];original_update=m.progent.generate_update_security_policy
 def update(params,result,manual_check=True):
  item={'pre_policy':copy.deepcopy(m.progent.security_policy),'tool_call_param':copy.deepcopy(params),'tool_call_result':result,'generated_before':copy.deepcopy(m.progent.get_generated_policy()),'request_start':len(requests)}
  answer=original_update(params,result,manual_check=manual_check);item.update(post_policy=copy.deepcopy(m.progent.security_policy),request_end=len(requests));updates.append(item);return answer
 m.progent.generate_update_security_policy=update
 captured=None;observations=[]
 with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
  b=m.Broker();b.init({'manifest':str(a.frozen/'manifest.json'),'case_id':a.case,'baseline_arm':'progent','model':'gpt-6-luna','delegate_reference':True,'clock_anchor':'2026-11-05T00:00:00','judge_cache':'unused','policy_journal':'unused'})
  receipt_runtime=IntentRuntime(b.suite.tools,SimpleNamespace(lock=threading.RLock()),tool_catalog(b.suite.tools))
  for i,p in enumerate(raw['proposed_calls']):
   response=b.invoke({'name':p['function'],'args':p['args'],'call_id':p['id']});value,error=b.runtime.last_result
   observations.append({'function':p['function'],'arguments':norm(p['args']),'value':portable(value),'error':error,'text':response['text']})
   normalized=receipt_runtime.functions[p['function']].parameters.model_validate(p['args']).model_dump();receipt_runtime._receipt(p['function'],normalized,value,error,mode=invocation_mode(p['function'],normalized))
   assert receipt_runtime.receipts[-1]['result']==response['text'] or any(r['result']==response['text'] for r in receipt_runtime.receipts),'Receipt text changed'
   if captured is None and not response['is_error'] and MARKER in response['text']:
    captured={'case_id':a.case,'task_id':b.case['task_id'],'injection_id':b.case['injection_id'],'owner_request':b.prompt,'anchor_index':i,'state':b.env.model_dump(mode='json'),'initial_state':b.initial.model_dump(mode='json'),'prefix':copy.deepcopy(raw['proposed_calls'][:i+1]),'observations':copy.deepcopy(observations),'pga_receipts':copy.deepcopy(receipt_runtime.receipts),'update':copy.deepcopy(updates[-1]),'tool_definitions':copy.deepcopy(m.progent.get_available_tools())}
  final=b.finish({'final_text':raw['final_response']})
 assert len(requests)==len(responses)
 for k in ['prompt','initial','final','proposed_calls','policy_history']:assert norm(final['raw'][k])==raw[k],k
 es=lambda xs:[{k:v for k,v in x.items() if k!='elapsed_s'} for x in norm(xs)];assert es(final['raw']['events'])==es(raw['events'])
 for k in ['progent_decisions','policy_calls','native_utility','native_targeted_asr']:assert norm(final['result'][k])==raw['result'][k],k
 assert captured is not None
 assert captured['update']['tool_call_param'][0]['name'] in PURE_READS
 old=json.loads((a.qualified/'packets'/f'{a.case}.json').read_text());assert captured['state']==old['anchor_state'];assert norm(captured['update']['post_policy'])==old['anchor_policy'];assert len(captured['prefix'])==len(old['anchor_prefix'])
 captured['evaluator']={'candidate':old['candidate'],'original_native_utility':raw['result']['native_utility'],'original_native_asr':raw['result']['native_targeted_asr'],'qualified_probe_sha256':sha(a.qualified/'packets'/f'{a.case}.json')}
 captured['recorded_update_requests']=requests[captured['update']['request_start']:captured['update']['request_end']]
 captured['source']={'raw_sha256':sha(rawpath),'journal_sha256':sha(journal),'replayed_policy_requests':len(requests),'preparation_source_sha256':sha(Path(__file__)),'model_requests':0,'network_requests':0}
 save(a.out/(a.case+'.json'),captured);return {'case_id':a.case,'path':a.case+'.json','sha256':sha(a.out/(a.case+'.json')),'passed':True,'prefix_calls':len(captured['prefix'])}
def main():
 p=argparse.ArgumentParser();p.add_argument('--original',type=Path,required=True);p.add_argument('--qualified',type=Path,required=True);p.add_argument('--frozen',type=Path,required=True);p.add_argument('--out',type=Path);p.add_argument('--case');a=p.parse_args();a.out=a.out or Path(os.environ['AROS_ARTIFACTS']);a.out.mkdir(parents=True,exist_ok=True)
 if a.case:print(json.dumps(prepare(a)));return
 old=json.loads((a.qualified/'summary.json').read_text());ids=sorted(r['case_id'] for r in old['rows'] if r['coverage']=='qualified_single_candidate');assert len(ids)==98
 def one(cid):
  r=subprocess.run([sys.executable,'-B',str(Path(__file__)),'--original',str(a.original),'--qualified',str(a.qualified),'--frozen',str(a.frozen),'--out',str(a.out),'--case',cid],capture_output=True,text=True,timeout=120)
  return json.loads(r.stdout.splitlines()[-1]) if not r.returncode else {'case_id':cid,'passed':False,'error':r.stderr[-1500:]}
 with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:rows=list(pool.map(one,ids))
 result={'cases':rows,'scheduled':98,'passed':sum(r['passed'] for r in rows),'input_qualification_sha256':sha(a.qualified/'summary.json'),'model_requests':0,'network_requests':0,'scope':'Original qualified exposed states and exact native pre-update context; evaluator target is separated from constructor inputs.'};save(a.out/'manifest.json',result);print(json.dumps({k:v for k,v in result.items() if k!='cases'}));assert result['passed']==98
if __name__=='__main__':main()
