"""Replay retained Progent policy responses offline, retaining original JSON types."""
import argparse,collections,concurrent.futures,contextlib,copy,gzip,hashlib,importlib.util,io,json,os,socket,subprocess,sys
from pathlib import Path
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def normalized(x):return json.loads(json.dumps(x,default=str))
def digest(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,default=str).encode()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def replay(a):
    def no_network(*args,**kwargs):raise RuntimeError('Network forbidden in policy replay')
    socket.create_connection=no_network;socket.socket.connect=no_network
    rawpath=a.job/a.case/'progent.json.gz';journal=a.job/a.case/'progent.policy-journal.jsonl';raw=json.loads(gzip.decompress(rawpath.read_bytes()))
    responses=[json.loads(s) for s in journal.read_text().splitlines() if json.loads(s)['stage']=='policy_response'];requests=[];policies={}
    spec=importlib.util.spec_from_file_location('replayed_baseline',a.frozen/'evaluation/baseline_audit/broker.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    class Connection:
        def __init__(self,*args,**kwargs):self.endpoint='https://example.invalid/v1/responses';self.key=None;self.calls=[]
        def metadata(self):return {'kind':'offline replay; network disabled'}
    class ReplayClient:
        def __init__(self,*args):self.calls=[]
        def request(self,system,user,temperature=0):
            if len(self.calls)>=64:raise RuntimeError('Policy request cap reached')
            item=responses[len(self.calls)];h=hashlib.sha256(json.dumps({'system':system,'user':user,'temperature':temperature},sort_keys=True).encode()).hexdigest()
            assert h==item['request_sha256'],'Policy request differs from recorded request'
            r=item['response'];self.calls.append(r['meta']);requests.append(h)
            if not r['ok']:raise RuntimeError(r['error'])
            return r['text']
        def close(self):pass
    original=module.progent.check_tool_call
    def capture(name,kwargs):
        policy=copy.deepcopy(module.progent.security_policy);policies[digest(policy)]=policy
        return original(name,kwargs)
    module.progent.check_tool_call=capture;module.PolicyClient=ReplayClient;module.ref.v16.base.LunaTransport=Connection
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        b=module.Broker();b.init({'manifest':str(a.frozen/'manifest.json'),'case_id':a.case,'baseline_arm':'progent','model':'gpt-6-luna','delegate_reference':True,'clock_anchor':'2026-11-05T00:00:00','judge_cache':'unused','policy_journal':'unused'})
        for p in raw['proposed_calls']:b.invoke({'name':p['function'],'args':p['args'],'call_id':p['id']})
        result=b.finish({'final_text':raw['final_response']})
    assert len(requests)==len(responses),'Unused recorded policy requests'
    for key in ['prompt','initial','final','proposed_calls','policy_history']:
        assert normalized(result['raw'][key])==raw[key],key+' mismatch'
    def events(xs):return [{k:v for k,v in x.items() if k!='elapsed_s'} for x in normalized(xs)]
    assert events(result['raw']['events'])==events(raw['events']),'Native event mismatch'
    for key in ['progent_decisions','policy_calls','native_utility','native_targeted_asr']:
        assert normalized(result['result'][key])==raw['result'][key],key+' mismatch'
    assert all(d['policy_before_sha256'] in policies for d in raw['result']['progent_decisions'])
    out={'case_id':a.case,'passed':True,'raw_sha256':sha(rawpath),'journal_sha256':sha(journal),'request_hashes':requests,'policy_count':len(policies),'policies':policies,'model_requests':0,'network_requests':0,'source_sha256':sha(Path(__file__))}
    save(a.out/(a.case+'.json'),out);return {'case_id':a.case,'passed':True,'policy_requests_replayed':len(requests),'policy_states':len(policies),'record_sha256':sha(a.out/(a.case+'.json'))}
def main():
    p=argparse.ArgumentParser();p.add_argument('--job',type=Path,required=True);p.add_argument('--frozen',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--case');a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    if a.case:print(json.dumps(replay(a)));return
    data=json.loads((a.job/'results.json').read_text());assert data['complete'];ids=[r['case_id'] for r in data['rows']]
    def one(cid):
        cmd=[sys.executable,'-B',str(Path(__file__)),'--job',str(a.job),'--frozen',str(a.frozen),'--out',str(a.out),'--case',cid]
        r=subprocess.run(cmd,capture_output=True,text=True,timeout=120)
        if r.returncode:return {'case_id':cid,'passed':False,'error':r.stderr[-1500:]}
        return json.loads(r.stdout.splitlines()[-1])
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:rows=list(pool.map(one,ids))
    result={'scheduled':len(ids),'passed':sum(r['passed'] for r in rows),'rows':rows,'source_sha256':sha(Path(__file__)),'input_results_sha256':sha(a.job/'results.json'),'model_requests':0,'network_requests':0,'scope':'Deterministic original-code replay with recorded policy responses and original proposals; no fresh policy accuracy or efficacy estimate.'};save(a.out/'summary.json',result);print(json.dumps({k:v for k,v in result.items() if k!='rows'},indent=2))
    if result['passed']!=len(ids):raise SystemExit(1)
if __name__=='__main__':main()
