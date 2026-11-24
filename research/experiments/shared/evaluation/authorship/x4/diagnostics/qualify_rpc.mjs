/** Complete production Node -> Python -> constructor Node RPC, without models. */
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';
import {spawnSync} from 'node:child_process';
import {Broker,episode} from '../agent.mjs';
import {textHash,semanticHash} from '../pi_draw.mjs';
const HERE=dirname(fileURLToPath(import.meta.url)),X4=resolve(HERE,'..');
const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
const out=resolve(a['--out']);await mkdir(out,{recursive:true});
const dataset=join(X4,'dataset-v1'),conditionId='banking__user_task_11__send_money__amount__M1__F0';
const condition=JSON.parse(await readFile(join(dataset,'conditions',conditionId+'.json'),'utf8'));
const fixtureCondition=join(out,'fixture-condition.json');await writeFile(fixtureCondition,JSON.stringify({...condition,prefix_sha256:null}));
const checks=[],rows=[];
const journalPath=join(out,'http-fixtures.jsonl');
process.env.X4_QUALIFICATION_JOURNAL=journalPath;
process.env.NODE_OPTIONS='--import='+join(HERE,'fake_fetch.mjs');
await import('./fake_fetch.mjs');

async function run(label,arm,amount=200.29,{tamper=false,constructorFailure=false}={}){
 const folder=join(out,label);await mkdir(folder,{recursive:true});
 process.env.X4_QUALIFICATION_ACTOR_AMOUNT=String(amount);
 process.env.X4_QUALIFICATION_CONSTRUCTOR_FAILURE=constructorFailure?'1':'0';
 const broker=new Broker(a['--python'],{script:join(HERE,'rpc_fixture_broker.py'),journal:join(folder,'episode.rpc-errors.jsonl')});
 if(tamper){const rpc=broker.rpc.bind(broker);broker.rpc=(method,params)=>rpc(method,method==='repair'?{...params,context_json:params.context_json+' '}:params);}
 const row=await episode({'--python':a['--python'],'--manifest':join(dataset,'cohort.json'),'--condition':fixtureCondition,'--arm':arm,'--out':join(folder,'episode'),'--actor-cache':join(folder,'ordinary'),'--repair-bank':join(folder,'repair'),'--audit-plan':join(dataset,'audit-plans/M1-actor_right-H0.json'),'--audit-ledger':join(folder,'audit.json')},{broker});
 const raw=JSON.parse(gunzipSync(await readFile(join(folder,'episode.json.gz'))));
 rows.push({label,status:row.status,actor_status:row.actor_status,scientific_status:row.x4_scientific_status,native_utility:row.native_utility,repairs:row.x4_records.length,repair_effects:row.x4_repaired_effects,actor_draws:row.x4_repair_actor_calls.length,constructor_draws:row.policy_calls.length});
 assert.equal(row.actor_status,'completed');assert.equal(row.x4_repair_actor_calls.length,1);
 assert.equal(raw.events.filter(event=>event.x4_repaired_effect).length,row.x4_repaired_effects);
 const stops=row.progent_decisions.filter(event=>event.x4_repair_budget_exhausted);
 assert.equal(stops.length,1);
 assert(stops.every(event=>event.x4_stop_scope==='exact_original_or_repaired_operation'));
 const distinct=row.progent_decisions.find(event=>event.operation.args.amount===5);
 assert.equal(distinct.allowed,false);assert.equal(distinct.x4_repair_budget_exhausted,undefined);
 assert.deepEqual(distinct.policy,raw.policy_history[0].policy);
 if(tamper){
  assert.equal(row.status,'operationally_unknown');assert.equal(row.policy_calls.length,0);assert.equal(row.x4_records.length,0);
  assert.equal(row.x4_transport_failures.length,1);assert.equal(row.x4_repaired_effects,0);
  assert.equal(row.x4_rpc_errors[0].method,'repair');assert(row.x4_rpc_errors[0].diagnostic.includes('context byte digest mismatch'));
  const durable=JSON.parse((await readFile(join(folder,'episode.rpc-errors.jsonl'),'utf8')).trim());
  assert.deepEqual(durable,row.x4_rpc_errors[0]);
 }else{
  assert.equal(row.policy_calls.length,1);assert.equal(row.x4_records.length,1);
  assert.equal(raw.x4_contexts.length,1);
  const captured=raw.x4_contexts[0];assert.equal(textHash(captured.context_json),captured.sha256);
  assert.equal(row.x4_records[0].pre_refusal_actor_context_sha256,captured.sha256);
  assert.equal(row.x4_records[0].resources.expert_audits,0);
  const context=JSON.parse(captured.context_json);assert(context.messages.some(message=>message.usage?.cost?.input>0&&message.usage.cost.input<1e-4));
  const py=spawnSync(a['--python'],['-B','-c','import sys,json,hashlib;s=sys.stdin.read();print(hashlib.sha256(json.dumps(json.loads(s),sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()).hexdigest())'],{input:captured.context_json,encoding:'utf8'});
  assert.equal(py.status,0);assert.notEqual(py.stdout.trim(),semanticHash(context));
  if(constructorFailure){assert.equal(row.status,'operationally_unknown');assert.equal(row.x4_repaired_effects,0);}
  else{assert.equal(row.status,'completed');assert.equal(row.x4_repaired_effects,1);assert.equal(row.native_utility,true);}
 }
 return {row,raw};
}
await run('primary','x4_projection_H0');checks.push('full_actual_Pi_RPC_with_realistic_numeric_metadata_and_native_repair');
checks.push('exact_duplicate_stopped_but_distinct_later_call_gets_unchanged_ordinary_authorizer');
await run('fresh-rebinding','fresh_rebinding_H0',200);checks.push('fresh_rebinding_ignores_paid_wrong_actor_with_equal_regrant');
await run('trusted-edit','extra_review_H0',200);checks.push('strong_trusted_review_edits_wrong_actor_with_equal_regrant');
await run('tampered-context','x4_projection_H0',200.29,{tamper:true});checks.push('rejected_RPC_is_awaited_durable_aborted_and_scientifically_unknown');
await run('constructor-failure','x4_projection_H0',200.29,{constructorFailure:true});checks.push('constructor_transport_failure_is_unknown_without_effect_or_retry');

// Replay the exact context and proposal implicated in the failed v1 smoke.
// This is a retained-response fixture, not another actor draw or efficacy run.
process.env.X4_QUALIFICATION_CONSTRUCTOR_FAILURE='0';
const folder=join(out,'retained-v1-context');await mkdir(folder,{recursive:true});
const broker=new Broker(a['--python'],{script:join(HERE,'rpc_fixture_broker.py'),journal:join(folder,'rpc-errors.jsonl')});
try{
 const cohort=JSON.parse(await readFile(join(dataset,'cohort.json'),'utf8'));
 const unit=cohort.units.find(row=>row.unit_id===condition.unit_id);
 const plan=JSON.parse(await readFile(join(dataset,'audit-plans/M1-actor_right-H0.json'),'utf8'));
 const sourceRaw=JSON.parse(gunzipSync(await readFile(join(a['--v1-job'],conditionId,'x4_projection_H0.json.gz'))));
 await broker.rpc('init',{manifest:join(dataset,'cohort.json'),case_id:condition.case_id,unit,model:'gpt-6-luna',clock_anchor:'2026-11-05T00:00:00',variant:'fault',bound_projection:condition.bound_projection,prefix_sha256:condition.prefix_sha256,x4_arm:'x4_projection_H0',audit_plan:plan,audit_ledger:join(folder,'audit.json'),repair_bank:join(folder,'repair'),constructor_journal:join(folder,'constructor.jsonl')});
 const contextJson=await readFile(join(HERE,'v1-rpc-replay/captured-context.json'),'utf8');
 const candidate={function:unit.function,args:sourceRaw.result.x1_anchor.args};
 broker.actor={resample:async()=>({candidate,context_json:contextJson,meta:{pre_proposal_context_sha256:textHash(contextJson),context_hash_kind:'utf8_json_sha256',feedback_disclosed:false,qualification_fixture:'retained-v1-context',actual_network_call:false}})};
 for(const [index,call] of sourceRaw.proposed_calls.entries()){
  const result=await broker.call('invoke',{name:call.function,args:call.args,call_id:call.id});
  if(call.function===unit.function){assert.equal(result.x4_repaired_effect,true);break;}
 }
 const result=await broker.rpc('finish',{final_text:'Manual retained-context repair qualification.'});
 assert.equal(result.result.x1_anchor.prefix_sha256,condition.prefix_sha256);assert.equal(result.result.x4_records.length,1);
 assert.equal(result.result.policy_calls.length,1);assert.equal(result.result.native_utility,true);assert.equal(broker.errors.length,0);
 assert.equal(result.raw.x4_contexts[0].context_json,contextJson);
 await writeFile(join(folder,'result.json'),JSON.stringify(result,null,2)+'\n');
 checks.push('exact_v1_failing_context_passes_real_RPC_with_frozen_native_prefix_and_one_constructor');
}finally{broker.close();}

// The sole prepared actor-wrong unit has a legitimate distinct later update.
// Replay its source calls, injecting explicitly manual correct repair replies.
const bank2Id='banking__user_task_2__update_scheduled_transaction__amount__oracle_correct__F0';
const bank2Condition=JSON.parse(await readFile(join(dataset,'conditions',bank2Id+'.json'),'utf8'));
const bank2Raw=JSON.parse(gunzipSync(await readFile(join(a['--prefix'],bank2Condition.case_id,'prefix.json.gz'))));
const bank2Folder=join(out,'bank2-continuation');await mkdir(bank2Folder,{recursive:true});
process.env.X4_QUALIFICATION_BINDING=JSON.stringify({function:'update_scheduled_transaction',args:{amount:1200}});
const bank2=new Broker(a['--python'],{script:join(HERE,'rpc_fixture_broker.py'),journal:join(bank2Folder,'rpc-errors.jsonl')});
try{
 const cohort=JSON.parse(await readFile(join(dataset,'cohort.json'),'utf8'));
 const unit=cohort.units.find(row=>row.unit_id===bank2Condition.unit_id);
 const plan=JSON.parse(await readFile(join(dataset,'audit-plans/none-target_wrong-H0.json'),'utf8'));
 const init=await bank2.rpc('init',{manifest:join(dataset,'cohort.json'),case_id:bank2Condition.case_id,unit,model:'gpt-6-luna',clock_anchor:'2026-11-05T00:00:00',variant:'fault',bound_projection:bank2Condition.bound_projection,prefix_sha256:bank2Condition.prefix_sha256,x4_arm:'x4_projection_H0',audit_plan:plan,audit_ledger:join(bank2Folder,'audit.json'),repair_bank:join(bank2Folder,'repair'),constructor_journal:join(bank2Folder,'constructor.jsonl')});
 const original=bank2Raw.proposed_calls.find(call=>call.function===unit.function);
 const contextJson=JSON.stringify({messages:[{role:'user',content:init.prompt,timestamp:0}],qualification_fixture:'manual-bank2-repair-context'});
 bank2.actor={resample:async()=>({candidate:{function:unit.function,args:{...original.args,amount:1200}},context_json:contextJson,meta:{pre_proposal_context_sha256:textHash(contextJson),context_hash_kind:'utf8_json_sha256',feedback_disclosed:false,qualification_fixture:true,actual_network_call:false}})};
 const replies=[];
 for(const call of bank2Raw.proposed_calls)replies.push(await bank2.call('invoke',{name:call.function,args:call.args,call_id:call.id}));
 const result=await bank2.rpc('finish',{final_text:bank2Raw.final_response});
 assert.equal(result.result.x1_anchor.prefix_sha256,bank2Condition.prefix_sha256);
 assert.equal(result.result.native_utility,true);assert.equal(result.result.x4_records.length,1);assert.equal(result.result.policy_calls.length,1);
 const decisions=result.result.progent_decisions.filter(row=>row.operation.function===unit.function);
 assert.equal(decisions.length,3);assert.equal(decisions[0].allowed,false);assert.equal(decisions[1].x4_repaired_effect,true);
 assert.equal(decisions[2].allowed,true);assert.equal(decisions[2].x4_repaired_effect,undefined);assert.equal(decisions[2].x4_repair_budget_exhausted,undefined);
 assert.deepEqual(decisions[2].policy,result.raw.policy_history[0].policy);assert.equal(bank2.errors.length,0);
 await writeFile(join(bank2Folder,'result.json'),JSON.stringify(result,null,2)+'\n');
 checks.push('bank2_kept_in_dataset_and_distinct_later_update_passes_original_policy_without_second_grant');
}finally{bank2.close();delete process.env.X4_QUALIFICATION_BINDING;}
const http=(await readFile(journalPath,'utf8')).trim().split('\n').map(line=>JSON.parse(line));
assert(http.filter(row=>row.role==='constructor').every(row=>row.body.reasoning.effort==='low'&&row.body.max_output_tokens===1536));
assert(http.every(row=>row.body.model==='gpt-6-luna'&&row.body.parallel_tool_calls===false&&row.body.store===false));
const result={passed:checks.length,checks,rows,fake_http_calls:http.length,model_requests:0,network_requests:0,
 scope:'Production Pi Agent, capture, Node/Python JSON-RPC, native simulator and Python/Node constructor client. Fixture endpoint and explicit scripted HTTP/SSE responses only. No inference; not method efficacy. Retained v1 context is a separate manual-response fixture.'};
await writeFile(join(out,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
