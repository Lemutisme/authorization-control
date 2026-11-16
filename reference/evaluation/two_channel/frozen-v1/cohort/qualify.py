"""Check every runtime packet with pinned native code and assemble one manifest."""
from pathlib import Path
import contextlib,copy,io,json,sys
from inspect_sources import OUT,Env,FunctionsRuntime,load,sha,file_sha,digest,save,suite,normalize

PROGENT=Path('/artifact-source/c4751a2fc0fe/progent')
VENDOR=Path('/artifact-source/3d9fa19e91e5/vendor')
sys.path[:0]=[str(VENDOR),str(PROGENT)]
with contextlib.redirect_stderr(io.StringIO()):
 from secagent import tool as progent

def main():
 # Merge recovered wire bytes in Python. JavaScript reserialization of the
 # entire packet would erase schema floats (4.0 -> 4), recreating source loss.
 honest=load(OUT/'honest-runtime-manifest.json');wire=load(OUT/'honest-wire-recovery.json')
 assert wire['passed']==wire['scheduled']==len(honest['packets']),'honest_wire_qualification'
 byid={r['unit_id']:r for r in wire['rows']}
 for row in honest['packets']:
  packet=load(Path(row['packet']));recovered=byid[row['unit_id']]
  assert recovered['request_sha256']==packet['actor_request_sha256'],'honest_source_request'
  packet['actor_request_json']=recovered['request_json']
  packet['actor_wire_recovery']={'kind':'official Pi 1.5.0 deterministic payload serialization from exact retained context','source_hash_matches':True,'model_calls':0,'network_calls':0}
  save(Path(row['packet']),packet);row['packet_sha256']=file_sha(Path(row['packet']))
 honest['summary']['wire_hashes_verified']=wire['passed'];save(OUT/'honest-runtime-manifest.json',honest)
 manifests={name:load(OUT/f'{name}-runtime-manifest.json') for name in ('honest','attack','natural')}
 rows=[];packets=[]
 for panel,manifest in manifests.items():
  for row in manifest['packets']:
   p=load(Path(row['packet']));record={'unit_id':p['unit_id'],'panel':p['panel'],'passed':False}
   try:
    assert file_sha(Path(row['packet']))==row['packet_sha256'],'packet_sha256'
    assert sha(p['actor_context_json'])==p['actor_context_utf8_sha256'],'actor_context_hash'
    assert sha(p['actor_request_json'])==p['actor_request_sha256'],'actor_request_hash'
    assert digest(p['policy_at_boundary'])==p['policy_at_boundary_sha256'],'policy_hash'
    assert len(p['historical_actor_call_metadata'])==p['historical_actor_calls'],'historical_actor_budget'
    assert len(p['historical_constructor_call_metadata'])==p['historical_constructor_calls'],'historical_constructor_budget'
    calls=[c for c in p['source_proposal_message']['content'] if c.get('type')=='toolCall']
    assert len(calls)==1 and calls[0]['id']==p['original_proposal_call_id'],'single_source_call'
    assert normalize({'function':calls[0]['name'],'args':calls[0]['arguments']})==normalize(p['original_proposal']),'source_call_identity'
    env=Env.model_validate(copy.deepcopy(p['native_initial_state']));native=FunctionsRuntime(suite.tools)
    for event in p['prior_native_events']:
     assert env.model_dump(mode='json')==event['before'],'native_prefix_before'
     if not event.get('error'):
      _,error=native.run_function(env,event['operation']['function'],event['operation']['args'])
      assert error is None,('native_prefix_error',error)
     assert env.model_dump(mode='json')==event['after'],'native_prefix_after'
    assert env.model_dump(mode='json')==p['native_boundary_state'],'native_boundary'
    progent.security_policy=copy.deepcopy(p['policy_at_boundary']);progent.init_user_query=p['authentic_owner_request']
    op=normalize(p['original_proposal']);refusal=None
    try:progent.check_tool_call(op['function'],op['args'])
    except progent.ValidationError as exc:refusal=str(exc)
    assert refusal is not None,'original_proposal_not_refused'
    _,native_error=native.run_function(env,op['function'],op['args'])
    assert native_error is None,('original_proposal_native_error',native_error)
    record.update(passed=True,prior_events_replayed=len(p['prior_native_events']),original_proposal_refused=True,
     original_proposal_native_error=native_error,original_proposal_state_changed=env.model_dump(mode='json')!=p['native_boundary_state'],
     actor_context_sha256=p['actor_context_utf8_sha256'],actor_request_sha256=p['actor_request_sha256'],policy_sha256=p['policy_at_boundary_sha256'])
   except Exception as exc:record.update(error=str(exc),error_type=type(exc).__name__)
   rows.append(record);packets.append(row)
 summary={'scheduled_packets':len(rows),'passed':sum(r['passed'] for r in rows),'model_calls':0,'network_calls':0,
  'panels':{k:v['summary'] for k,v in manifests.items()},'scheduled_four_cell_continuations':len(rows)*4,
  'pinned_checker_source':str(PROGENT/'secagent/tool.py'),'pinned_checker_sha256':file_sha(PROGENT/'secagent/tool.py')}
 save(OUT/'qualification.json',{'summary':summary,'rows':rows})
 save(OUT/'runtime-manifest.json',{'version':'two-channel-cohort-v1','summary':summary,'packets':packets})
 # Wire recovery changes only honest runtime bytes, so update its private
 # selection references after the exact provider-hash checks have passed.
 honest=load(OUT/'honest-selection.json');byid={r['unit_id']:r for r in packets}
 for row in honest['rows']:row['packet_sha256']=byid[row['unit_id']]['packet_sha256']
 save(OUT/'honest-selection.json',honest)
 print(json.dumps({k:v for k,v in summary.items() if k!='panels'},indent=2))
 if summary['passed']!=summary['scheduled_packets']:raise SystemExit(1)

if __name__=='__main__':main()
