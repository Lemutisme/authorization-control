"""Choose an actual source representative with greatest consumed constructor budget."""
import gzip,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
p=HERE/'protocol.json';protocol=json.loads(p.read_text())
for unit in protocol['units']:
 for prov in unit['source_provenance']:
  a=json.loads((HERE/'prefixes'/prov['source_unit_id']/'offline-assessment.json').read_text());raw=json.loads(gzip.decompress(Path(prov['source_episode']).read_bytes()));i=a['target_event_index']
  prov['historical_constructor_calls']=raw['result']['update_records'][i-1]['calls_after'] if i else raw['result']['update_records'][0]['calls_before']
  prov['historical_actor_calls_including_original_proposal']=a['target_draw']+1
 chosen=sorted(unit['source_provenance'],key=lambda q:(-q['historical_constructor_calls'],q['source_unit_id']))[0]
 unit['representative_source']=chosen['source_unit_id'];unit['representative_rule']='greatest actual historical constructor-call count, tie lexical source unit ID; no extra remaining budget from deduplication'
 folder=HERE/'prefixes'/chosen['source_unit_id'];a=json.loads((folder/'offline-assessment.json').read_text());recovery=json.loads((folder/'actor-context-recovery.json').read_text())['captures'][-1];replay=json.loads((folder/'replay-input.json').read_text());raw=json.loads(gzip.decompress(Path(chosen['source_episode']).read_bytes()))
 target=Path(unit['runtime_packet']);runtime=json.loads(target.read_text());t=chosen['historical_constructor_calls'];u=chosen['historical_actor_calls_including_original_proposal']
 runtime.update(case_id=raw['result']['case_id'],task_id=raw['result']['task_id'],actor_context_json=recovery['context_json'],actor_context_utf8_sha256=recovery['context_utf8_sha256'],source_proposal_message=replay['source_messages'][-1],original_proposal_call_id=replay['target_call_id'],historical_actor_calls=u,historical_constructor_calls=t,historical_actor_call_metadata=raw['result']['pi']['calls'][:u],historical_constructor_call_metadata=raw['result']['policy_calls'][:t],source_representative=chosen['source_unit_id'],prior_wrong_value_policy_disclosure=unit['prior_wrong_value_policy_disclosure'],prior_bound_value_in_successful_observations=unit['prior_bound_value_in_successful_observations'])
 assert len(runtime['historical_constructor_call_metadata'])==t
 target.write_text(json.dumps(runtime)+'\n');unit['runtime_packet_sha256']=sha(target.read_bytes());unit['historical_actor_calls']=u;unit['historical_constructor_calls']=t
protocol['deduplication_budget_rule']='Select the real source prefix with greatest consumed constructor budget; retain all alternative histories/counts. No new budget is inferred from equivalent state.'
p.write_text(json.dumps(protocol,indent=2)+'\n')
print(json.dumps([(u['unit_id'],u['historical_actor_calls'],u['historical_constructor_calls'],u['representative_source']) for u in protocol['units']]))
