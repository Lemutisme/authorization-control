"""All56 natural native continuations with model-free policy/constructor fixtures."""
import contextlib,io,json,sys
from pathlib import Path
import broker as n
HERE=Path(__file__).resolve().parent
class Policy:
 def __init__(self,connection,journal,directory,arm):self.calls=[];self.repair_reserved=0;self.stage='initial';self.journal=Path(journal)
 def request(self,system,user,temperature=0):
  if len(self.calls)+self.repair_reserved>=64:raise RuntimeError('Combined constructor budget exhausted')
  self.calls.append({'ok':True,'actual_network_call':False,'coupling':{'stage':self.stage}})
  return 'No' if self.stage=='selector' else '[]'
 def close(self):pass

def main():
 n.m.BudgetPolicyClient=Policy;rows=[]
 protocol=json.loads((HERE/'protocol.json').read_text())
 for unit in protocol['units']:
  packet=json.loads(Path(unit['runtime_packet']).read_text())
  for arm in n.m.ARMS:
   oldcheck=n.m.progent.check_tool_call;b=n.Broker()
   with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
    init=b.init({'natural_packet':unit['runtime_packet'],'manifest':str(n.m.HIST/'manifest-v1.json'),'x6_arm':arm,'model':'gpt-6-luna','delegate_reference':True,'clock_anchor':'2026-11-05T00:00:00','judge_cache':str(HERE/'qualification/unused'),'policy_cache':str(HERE/'qualification/unused'),'policy_journal':str(HERE/'qualification/unused.jsonl')})
    assert b.env.model_dump(mode='json')==packet['native_boundary_state']
    assert not b.update_records
    if b.policy_client:assert len(b.policy_client.calls)==packet['historical_constructor_calls']
    original=packet['original_proposal'];response=b.invoke({'name':original['function'],'args':original['args'],'call_id':packet['original_proposal_call_id']})
    if arm=='no_gate':assert not response['is_error']
    elif arm in {'originalauto','opaque_no_update'}:assert response['is_error'] and 'x6_repair_request' not in response
    else:
     assert 'x6_repair_request' in response
     proj=n.m.project(original['function'],original['args'],profile='all_writes')
     response=b.repair({'call_id':packet['original_proposal_call_id'],'candidate':original,'context_json':packet['actor_context_json'],'actor_meta':{'pre_proposal_context_sha256':packet['actor_context_utf8_sha256'],'feedback_disclosed':False},'constructor_reply':{'status':'bind','authorizations':[{'function':original['function'],'selector':proj['selector'],'assignments':proj['writes']}]},'constructor_meta':{'model_free':True}})
     assert not response['is_error'],(arm,b.repairs[-1])
    result=b.finish({'final_text':''})
    assert all(not c.get('historical_replayed') for c in result['result']['policy_calls'])
    rows.append({'unit':unit['unit_id'],'arm':arm,'historical_actor':packet['historical_actor_calls'],'historical_constructor':packet['historical_constructor_calls'],'new_base_calls':len(result['result']['policy_calls']),'new_repair_reservations':result['result']['repair_constructor_reservations'],'utility':result['result']['native_utility'],'passed':True})
    b.close();n.m.progent.check_tool_call=oldcheck
 out=HERE/'qualification';out.mkdir(exist_ok=True);(out/'native.json').write_text(json.dumps({'passed':True,'model_calls':0,'conditions':len(rows),'rows':rows},indent=2)+'\n')
 print(json.dumps({'passed':True,'model_calls':0,'conditions':len(rows)}))
if __name__=='__main__':main()
