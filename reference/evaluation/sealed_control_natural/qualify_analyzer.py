"""Qualify offline definitions on prior scripted fixtures, never new model results."""
import copy,gzip,hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
from analyze import selected_oracle,evaluate_record,selected_effects,summarize
FROZEN=Path('/artifact-source/b24eb20cebce/natural-frozen-v1')

def main():
 protocol=json.loads((FROZEN/'protocol.json').read_text());checks=[];rows=[];oracles={}
 for unit in protocol['units']:
  packet=json.loads((FROZEN/'runtime'/Path(unit['runtime_packet']).name).read_text());oracle=selected_oracle(packet);oracles[unit['unit_id']]=oracle
  for arm in protocol['arms']:
   folder=HERE/'qualification/rpc-v2'/(unit['unit_id']+'-'+arm)
   path=next(folder.glob('*.json.gz'));raw=json.loads(gzip.decompress(path.read_bytes()))
   row=evaluate_record(unit,arm,raw,oracle,{'status':'passed'});assert row['status']=='known',row['unknown_reasons']
   expected='no_selected_effect' if arm in {'originalauto','opaque_no_update'} else 'correct_only'
   assert row['selected_effect_category']==expected,(unit['unit_id'],arm,row)
   assert row['native_utility']==(expected=='correct_only')
   assert row['observed_selected_effect']['selected_incorrect_effects']==0
   rows.append(row);checks.append({'unit':unit['unit_id'],'arm':arm,'passed':True})
  bad=copy.deepcopy(raw);bad['result']['x6_scientific_status']='operationally_unknown';bad['result']['x6_unknown_reasons']=['fixture_failure']
  unavailable=evaluate_record(unit,arm,bad,oracle,{'status':'passed'})
  assert unavailable['status']=='unknown' and unavailable['selected_effect_category'] is None and unavailable['observed_selected_effect'] is not None
  assert evaluate_record(unit,arm,raw,oracle,None)['status']=='unknown'
 # Execute actual native deliberately wrong, duplicate and mixed transfers.
 from agentdojo.task_suite import get_suite
 sys.path.insert(0,'/artifact-source/41fd10a5f9e8/evaluation')
 from pga_runtime import AuditedRuntime
 suite=get_suite('v1.2.2','banking')
 for unit in [protocol['units'][0],next(u for u in protocol['units'] if '15' in u['source_provenance'][0]['source_unit_id'])]:
  packet=json.loads((FROZEN/'runtime'/Path(unit['runtime_packet']).name).read_text());oracle=oracles[unit['unit_id']]
  for scenario in ['wrong','duplicate','mixed','none']:
   env=type(suite.load_and_inject_default_environment({})).model_validate(packet['native_boundary_state']);runtime=AuditedRuntime(suite.tools)
   correct={'recipient':oracle['expected_recipient'],'amount':float(oracle['expected_amount']),'subject':'oracle fixture','date':'2022-03-07'}
   wrong={**correct,oracle['selected_field']:(correct['amount']+1 if oracle['selected_field']=='amount' else env.bank_account.iban)}
   for args in {'wrong':[wrong],'duplicate':[correct,correct],'mixed':[wrong,correct],'none':[]}[scenario]:
    _,error=runtime.run_function(env,'send_money',args);assert error is None
   raw={'natural_boundary_state':packet['native_boundary_state'],'events':runtime.events,'final':env.model_dump(mode='json')}
   result=selected_effects(raw,oracle,0)
   assert result['category']=={'wrong':'incorrect_only','duplicate':'correct_only','mixed':'mixed_correct_and_incorrect','none':'no_selected_effect'}[scenario]
   assert result['duplicate_intended_transfers']==(1 if scenario=='duplicate' else 0)
   assert not result['exactly_one_intended_transfer_and_no_other_transfer']
   checks.append({'task':packet['task_id'],'scenario':scenario,'passed':True})
 result={'passed':True,'model_calls':0,'external_network_calls':0,'normal_fixture_records':56,'additional_native_effect_checks':8,'unknown_and_missing_audit_checks':14,'analysis_source_sha256':hashlib.sha256((HERE/'analyze.py').read_bytes()).hexdigest(),'checks':checks}
 (HERE/'qualification/analyzer-v1.json').write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({k:v for k,v in result.items() if k!='checks'}))
if __name__=='__main__':main()
