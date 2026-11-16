/** Exact retained Pi continuation and native RPC, entirely scripted HTTP/SSE. */
import assert from 'node:assert/strict';
import {appendFileSync} from 'node:fs';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gunzipSync} from 'node:zlib';
import {Broker,ARMS} from '/artifact-source/39fa1b622d22/agent.mjs';
import {textHash} from '/artifact-source/85be1a9dff5f/pi_draw.mjs';
import {episode} from './agent.mjs';
const HERE=dirname(fileURLToPath(import.meta.url));const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
const out=resolve(a['--out']);await mkdir(out,{recursive:true});const journal=join(out,'http.jsonl');let packet,profile='normal',serial=0;
async function fakeFetch(url,options){
 if(!String(url).startsWith('http://model-free.invalid/'))throw new Error('Qualification forbids non-fixture URL');
 const body=JSON.parse(options.body),constructor=(body.tools||[]).some(tool=>tool.name==='submit_authorizations');
 const role=constructor?'constructor':'actor';appendFileSync(journal,JSON.stringify({unit:packet.unit_id,role,profile,wire_json:options.body})+'\n');
 if(constructor&&profile==='constructor_failure')throw new Error('Scripted constructor failure');
 let name,args,text;
 if(constructor){name='submit_authorizations';args={status:'bind',authorizations:[{function:packet.original_proposal.function,selector:{},assignments:packet.original_proposal.args}]};}
 else if(options.body===packet.actor_request_json||profile==='budget'){
  name=packet.original_proposal.function;args={...packet.original_proposal.args};if(profile==='wrong_actor')args.amount+=1;
 }else{text='Native tool result received: '+String((body.input||[]).filter(item=>item.type==='function_call_output').at(-1)?.output);}
 const id='natural_fixture_'+(++serial),argumentText=JSON.stringify(args);
 const item=name?{id:'fc_'+id,type:'function_call',call_id:'call_'+id,name,arguments:argumentText}:{id:'msg_'+id,type:'message',role:'assistant',content:[{type:'output_text',text,annotations:[]}]};
 const response={id:'resp_'+id,object:'response',created_at:1,status:'completed',model:'gpt-6-luna',output:[item],usage:{input_tokens:852,output_tokens:21,total_tokens:873}};
 const events=[{type:'response.created',response:{...response,status:'in_progress',output:[]}},
  {type:'response.output_item.added',output_index:0,item:name?{...item,arguments:''}:{...item,content:[]}},
  ...(name?[{type:'response.function_call_arguments.delta',item_id:item.id,output_index:0,delta:argumentText},{type:'response.function_call_arguments.done',item_id:item.id,output_index:0,arguments:argumentText}]:[{type:'response.content_part.added',item_id:item.id,output_index:0,content_index:0,part:{type:'output_text',text:'',annotations:[]}},{type:'response.output_text.delta',item_id:item.id,output_index:0,content_index:0,delta:text},{type:'response.output_text.done',item_id:item.id,output_index:0,content_index:0,text}]),
  {type:'response.output_item.done',output_index:0,item},{type:'response.completed',response}];
 return new Response(events.map(event=>`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('')+'data: [DONE]\n\n',{status:200,headers:{'content-type':'text/event-stream'}});
}
const protocol=JSON.parse(await readFile(join(HERE,'protocol.json'),'utf8')),rows=[];
async function run(unit,arm,label,{mode='normal',tamper=false}={}){
 packet=JSON.parse(await readFile(unit.runtime_packet,'utf8'));profile=mode;const folder=join(out,label);await mkdir(folder,{recursive:true});
 const broker=new Broker(a['--python'],{script:join(HERE,'fixture_broker.py'),journal:join(folder,'episode.rpc-errors.jsonl')});
 if(tamper){const rpc=broker.rpc.bind(broker);broker.rpc=(method,params)=>rpc(method,method==='repair'?{...params,context_json:params.context_json+' '}:params);}
 const row=await episode({'--python':a['--python'],'--natural-packet':unit.runtime_packet,'--manifest':'/artifact-source/968854d6265c/manifest-v1.json','--arm':arm,'--out':join(folder,'episode'),'--actor-cache':join(folder,'actor'),'--constructor-cache':join(folder,'constructor'),'--policy-cache':join(folder,'policy'),'--judge-cache':join(folder,'judge')},{broker,fetchImpl:fakeFetch});
 const raw=JSON.parse(gunzipSync(await readFile(join(folder,'episode.json.gz'))));
 assert.equal(row.pi.retained_actor_message_replays,1,JSON.stringify(row.x6_unknown_reasons));
 assert.equal(row.natural_original_proposal_dispatched,true);
 assert.equal(raw.natural_actor_resume.context_json,packet.actor_context_json);
 assert.equal(raw.natural_actor_resume.request_json,packet.actor_request_json);
 assert.deepEqual(raw.natural_actor_resume.source_proposal_message,packet.source_proposal_message);
 assert.equal(raw.natural_actor_resume.actual_network_call,false);assert.equal(raw.natural_actor_resume.new_actor_budget_slots,0);
 assert.equal(row.pi.actor_draw_budget.historical,packet.historical_actor_calls);
 assert.equal(row.pi.actor_draw_budget.used,packet.historical_actor_calls+row.pi.calls.length+row.x6_repair_actor_calls.length);
 assert(row.pi.actor_draw_budget.used<=16);assert(row.combined_constructor_calls<=64);
 assert.equal(row.combined_constructor_calls,packet.historical_constructor_calls+row.policy_calls.length+row.repair_constructor_reservations);
 assert(row.policy_calls.every(call=>!call.historical_replayed));
 assert.equal(raw.pi_tool_events[0].call_id,packet.original_proposal_call_id);assert.equal(raw.pi_tool_events[0].name,packet.original_proposal.function);assert.deepEqual(raw.pi_tool_events[0].args,packet.original_proposal.args);
 assert.deepEqual(raw.x6_operations[0].proposal,{name:packet.original_proposal.function,args:packet.original_proposal.args,call_id:packet.original_proposal_call_id});
 assert.deepEqual(raw.events.slice(0,packet.prior_native_events.length),packet.prior_native_events);
 assert.deepEqual(raw.events[packet.prior_native_events.length].before,packet.native_boundary_state);
 for(const call of [...row.pi.calls,...row.x6_repair_actor_calls,...row.x6_constructor_calls]){assert.equal(textHash(call.context_json),call.context_sha256);assert.equal(call.request_json,call.wire_request_json);assert.equal(textHash(call.wire_request_json),call.wire_request_sha256);}
 const firstRepair=row.x6_repairs.find(record=>record.call_id===packet.original_proposal_call_id);
 if(firstRepair&&firstRepair.actor_meta){assert.equal(firstRepair.context_json,packet.actor_context_json);assert.equal(firstRepair.actor_meta.request_json,packet.actor_request_json);assert.equal(firstRepair.actor_meta.source_draw_index,packet.historical_actor_calls-1);assert.equal(firstRepair.actor_meta.feedback_disclosed,false);assert.equal(firstRepair.actor_meta.natural_original_context_exact,true);assert.equal(firstRepair.actor_meta.natural_original_wire_exact,true);}
 if(mode==='budget'){assert.equal(row.status,'model_round_limit');assert.equal(row.pi.actor_draw_budget.used,16);}
 else{
  assert.equal(row.status,'completed',JSON.stringify({unknown:row.x6_unknown_reasons,exception:row.pi.resume_exception}));
  if(tamper||mode==='constructor_failure'){assert.equal(row.x6_scientific_status,'operationally_unknown');assert.equal(row.x6_repairs[0].status,'operationally_unknown');}
  else{
   assert.equal(row.x6_scientific_status,'known',JSON.stringify(row.x6_unknown_reasons));
   if(['no_gate','originalauto','opaque_no_update'].includes(arm)){assert.equal(row.x6_repair_actor_calls.length,0);assert.equal(row.x6_constructor_calls.length,0);assert.equal(row.pi.calls.length,1);}
   else{assert.equal(row.x6_repair_actor_calls.length,1);assert.equal(row.x6_constructor_calls.length,1);assert.equal(row.x6_repairs[0].status,'executed',JSON.stringify(row.x6_repairs[0]));assert.equal(row.pi.calls.length,1);if(mode==='wrong_actor')assert.equal(row.x6_repairs[0].candidate.args.amount,packet.original_proposal.args.amount+1);}
  }
 }
 rows.push({unit:packet.unit_id,arm,label,status:row.status,scientific_status:row.x6_scientific_status,historical_actor:packet.historical_actor_calls,historical_constructor:packet.historical_constructor_calls,new_actor:row.x6_resources.new_actor_draws,new_constructor:row.x6_resources.new_constructor_draws,actor_cumulative:row.pi.actor_draw_budget.used,constructor_cumulative:row.combined_constructor_calls,repairs:row.x6_repairs.map(record=>record.status)});
 console.log(JSON.stringify(rows.at(-1)));
}
for(const unit of protocol.units)for(const arm of ARMS)await run(unit,arm,unit.unit_id+'-'+arm);
await run(protocol.units[0],'no_agreement','ignored-wrong-U-no-agreement',{mode:'wrong_actor'});
await run(protocol.units[0],'trusted_edit','ignored-wrong-U-trusted-edit',{mode:'wrong_actor'});
await run(protocol.units[0],'sealed_exact','tampered-original-context',{tamper:true});
await run(protocol.units[0],'sealed_exact','constructor-failure',{mode:'constructor_failure'});
await run(protocol.units[0],'sealed_exact','cumulative-actor-budget',{mode:'budget'});
const result={passed:true,conditions:56,additional_failure_budget_checks:5,model_requests:0,external_network_requests:0,checks:['exact_original_proposal_replayed_once_before_new_draw','source_draw_is_historical_not_new_network_or_budget','exact_normalized_source_context_and_wire_preserved','all7_historical_U_T_budgets_carried_to_all8_arms','actual_production_Pi_RPC_native_state_continuation','native_repair_result_then_ordinary_actor_continuation','all_roles_context_hashes_and_actual_wire_retained','ignored_extra_U_is_charged_and_ignored','tampered_original_context_rejected_and_aborted','constructor_failure_is_operationally_unknown','historical_plus_new_actor_budget_is_hard16'],rows};
await writeFile(join(out,'result.json'),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify({passed:true,conditions:56,additional_failure_budget_checks:5,model_requests:0,external_network_requests:0}));
