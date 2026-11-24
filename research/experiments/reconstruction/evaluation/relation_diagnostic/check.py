"""Model-free checks of the source-defined correspondence endpoint and controls."""
import argparse,contextlib,copy,hashlib,io,json,os,socket,sys
from pathlib import Path
sys.path[:0]=[os.environ['BASELINE_VENDOR'],os.environ['PROGENT_SOURCE']]
from jsonschema import Draft202012Validator
from secagent import tool as progent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--fixture',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();f=json.loads(a.fixture.read_text());probes=f['evaluation_probes'];valid=[x for x in probes if x['allowed']]
    def blocked(*args,**kwargs):raise RuntimeError('Network forbidden')
    socket.create_connection=blocked;socket.socket.connect=blocked
    assert len(probes)==27 and len(valid)==3 and len({p['id'] for p in probes})==27
    exact=[{'recipients':{'const':p['args']['recipients']},'body':{'const':p['args']['body']}} for p in valid]
    marginal={'recipients':{'enum':[p['args']['recipients'] for p in valid]},'body':{'enum':[p['args']['body'] for p in valid]}}
    controls=[];progent.init_user_query=f['owner_prompt']
    for name,policy,expected_valid,expected_invalid in [('ordinary_relational_rules',[(99,0,x,0) for x in exact],3,0),('independent_marginals',[(100,0,marginal,0)],3,6),('multiple_generated_entries',[(100,0,x,0) for x in exact],1,0)]:
        ds=[]
        for q in probes:
            progent.security_policy={'send_email':copy.deepcopy(policy)}
            try:progent.check_tool_call('send_email',q['args']);admitted=True
            except Exception:admitted=False
            ds.append({'id':q['id'],'admitted':admitted,'expected':q['allowed']})
        tp=sum(d['expected'] and d['admitted'] for d in ds);fp=sum(not d['expected'] and d['admitted'] for d in ds);assert (tp,fp)==(expected_valid,expected_invalid)
        controls.append({'control':name,'valid_admitted':tp,'invalid_admitted':fp,'decisions':ds})
    schema={'anyOf':[{'type':'object','properties':x,'required':['recipients','body']} for x in exact]};v=Draft202012Validator(schema);ds=[{'id':p['id'],'admitted':v.is_valid(p['args']),'expected':p['allowed']} for p in probes];assert all(d['admitted']==d['expected'] for d in ds)
    controls.append({'control':'ordinary_whole_call_schema','valid_admitted':3,'invalid_admitted':0,'decisions':ds})
    out={'passed':4,'n':4,'controls':controls,'fixture_sha256':sha(a.fixture),'source_sha256':sha(Path(__file__)),'model_requests':0,'network_requests':0,'native_effects':0,'scope':'Finite qualification of a known representation condition and its ordinary controls, not learned policy efficacy.'};a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({k:v for k,v in out.items() if k!='controls'},indent=2))
if __name__=='__main__':main()
