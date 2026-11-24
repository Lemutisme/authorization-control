"""Prospective revision: budgets are part of continuation state; keep all seven."""
import copy,gzip,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
p=HERE/'protocol.json';protocol=json.loads(p.read_text());units=[]
for group in protocol['units']:
 for prov in group['source_provenance']:
  folder=HERE/'prefixes'/prov['source_unit_id'];a=json.loads((folder/'offline-assessment.json').read_text());cap=json.loads((folder/'actor-context-recovery.json').read_text())['captures'][-1];replay=json.loads((folder/'replay-input.json').read_text());raw=json.loads(gzip.decompress(Path(prov['source_episode']).read_bytes()));i=a['target_event_index'];t=raw['result']['update_records'][i-1]['calls_after'];u=a['target_draw']+1
  runtime=copy.deepcopy(json.loads(Path(group['runtime_packet']).read_text()));uid='source-'+sha(prov['source_unit_id'].encode())[:16]
  runtime.update(unit_id=uid,context_equivalence_group=group['unit_id'],actor_context_json=cap['context_json'],actor_context_utf8_sha256=cap['context_utf8_sha256'],source_proposal_message=replay['source_messages'][-1],original_proposal_call_id=replay['target_call_id'],historical_actor_calls=u,historical_constructor_calls=t,historical_actor_call_metadata=raw['result']['pi']['calls'][:u],historical_constructor_call_metadata=raw['result']['policy_calls'][:t],source_representative=prov['source_unit_id'])
  out=HERE/'runtime'/f'{uid}.json';out.write_text(json.dumps(runtime)+'\n')
  units.append({**{k:v for k,v in group.items() if k not in {'representative_source','representative_rule','source_provenance','runtime_packet','runtime_packet_sha256','unit_id'}},'unit_id':uid,'context_equivalence_group':group['unit_id'],'source_provenance':[prov],'runtime_packet':str(out),'runtime_packet_sha256':sha(out.read_bytes()),'historical_actor_calls':u,'historical_constructor_calls':t})
protocol.update(version='natural-panel-continuation-v2',units=units,proposed_episodes=56,deduplication='No source-prefix deduplication: actual historical actor/constructor budgets are part of continuation state.',deduplication_budget_rule='Retain all seven exact source histories and each actual budget. Report clustering by three state/policy/wire equivalence groups.',revision_reason='Before any model calls, discovery found unequal historical constructor counts within equivalent native state/policy/wire contexts. Root revised3x8 to7x8 to preserve actual remaining budgets.',primary='Three source prefixes for two naturally wrong-binding mechanisms; dependent equivalents reported.',separate_control='Four source prefixes for one naturally absent-function context, with actual per-source budgets.',fresh_draw_limits={'actor_total_including_history':16,'constructor_total_including_history':64})
p.write_text(json.dumps(protocol,indent=2)+'\n')
print(json.dumps({'prefixes':len(units),'episodes':len(units)*8}))
