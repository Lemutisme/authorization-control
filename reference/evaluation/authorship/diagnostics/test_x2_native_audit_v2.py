"""Model-free native updater replay regressions with hand-specified final policies."""
import contextlib,copy,io,json
from pathlib import Path
import x2_native_audit_v2 as audit
p=audit.progent
old={'probe':[(100,0,{'x':{'enum':[1]}},0)]}
new={'probe':[(100,0,{'x':{'enum':[2]}},0)]}
valid=json.dumps([{'name':'probe','args':{'x':{'enum':[2]}}}])
bad_json='```json\n[{bad]\n```'
bad_shape=json.dumps([{'tool':'probe','args':{}}])
partial=json.dumps([{'name':'probe','args':{'x':{'enum':[2]}}},{'tool':'bad'}])
params=[{'name':'probe','args':{'x':2}}]

def example(name,arm,texts,after,deletes,expected_checks,parse_errors):
 p.available_tools=[];p.init_user_query='Qualification owner request';p.security_policy=copy.deepcopy(old)
 selector='TOOLS: '+json.dumps(p.get_available_tools())+'\nUSER_QUERY: '+p.init_user_query+'\nTOOL_CALL_PARAM: '+json.dumps(params)
 generation=selector+"\nTOOL_CALL_RESULT: ['']\nCURRENT_RESTRICTIONS: "+json.dumps(p.get_generated_policy())
 response=lambda stage,system,user,temp,text:{'logical_stage':stage,'request':{'system':system,'user':user,'temperature':temp},'response':{'ok':True,'text':text}}
 journal=[response('selector',p.SYS_PROMPT_UPDATE,selector,0.0,'Yes')]
 temperature=0.0
 for text in texts:
  journal.append(response('regeneration',p.get_SYS_PROMPT_2(),generation,temperature,text));temperature+=0.2
 update={'policy_before':copy.deepcopy(old),'policy_after':copy.deepcopy(after),'before_sha256':audit.digest(old),
         'after_sha256':audit.digest(after),'calls_before':0,'calls_after':len(journal),'stage':0,'selected':True,
         'applications':deletes,'applied':bool(deletes),'status':'completed','policy_changed':audit.digest(old)!=audit.digest(after),
         'tool_call_param':params,'tool_call_result':"['']",'subset_checks':expected_checks}
 with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
  result=audit.replay_update(update,journal,arm)
 assert sum(x['status']=='parse_error' for x in result['parse_events'])==parse_errors
 assert result['retained_responses_consumed']==len(journal)
 assert result['exact_native_after_hash_verified']
 return {'test':name,'passed':True,'parse_errors':parse_errors,'delete_calls':deletes,'responses':len(journal)}

checks=[{'before_sha256':audit.digest(old),'candidate_sha256':audit.digest(new),'result':False}]
rows=[
 example('invalid_json_retry_then_valid','auto_approve',[bad_json,valid],new,1,[],1),
 example('six_invalid_json_ignored_after_ceiling','auto_approve',[bad_json]*6,old,0,[],6),
 example('shape_error_deletes_policy_then_no','auto_approve',[bad_shape,'No.'],{},1,[],0),
 example('partial_replacement_then_no','auto_approve',[partial,'No.'],new,1,[],0),
 example('shape_error_then_valid','auto_approve',[bad_shape,valid],new,2,[],0),
 example('narrow_shape_error_before_delete','narrow_only',[bad_shape,'No.'],old,0,[],0),
 example('narrow_decode_retry_then_rejected_widening','narrow_only',[bad_json,valid],old,0,checks,1),
]
result={'passed':all(r['passed'] for r in rows),'tests':rows,'model_calls':0,'network_calls':0,'forbidden_attempts':len(audit.NETWORK_ATTEMPTS)}
path=Path(__file__).with_name('x2-native-audit-v2-tests.json');audit.save(path,result)
print(json.dumps(result,indent=2))
