/** Official Pi continuation from a fixed historical proposal and cumulative budgets. */
import {Agent} from '@earendil-works/pi-agent-core';
import {brokerTools,makeModel,MODEL} from '/artifact-source/7b63e86b26d7/agent.mjs';
import {Broker,ARMS} from '/artifact-source/39fa1b622d22/agent.mjs';
import {CoupledBank,clone} from '/artifact-source/85be1a9dff5f/pi_draw.mjs';
import {NaturalActor} from './capture.mjs';
import {mkdir,writeFile} from 'node:fs/promises';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));

export async function runContinuation(init,broker,capture,{episodeTimeoutMs=900000}={}){
 const context=JSON.parse(init.natural_resume.actor_context_json),events=[];let timedOut=false,exception=null;
 const agent=new Agent({initialState:{messages:clone(context.messages),model:makeModel(init.connection),thinkingLevel:'off',tools:brokerTools(init.tools,broker)},toolExecution:'sequential',getApiKey:()=>init.connection.api_key||'unused-anonymous-endpoint-key',streamFn:capture.stream});
 agent.subscribe(event=>{if(event.type==='tool_execution_start')events.push({type:event.type,name:event.toolName,call_id:event.toolCallId,args:event.args});if(event.type==='tool_execution_end')events.push({type:event.type,call_id:event.toolCallId,is_error:event.isError});});
 const timer=setTimeout(()=>{timedOut=true;agent.abort();},episodeTimeoutMs);
 try{await agent.continue();await agent.waitForIdle();}catch(error){exception=error.message||error.name;}finally{clearTimeout(timer);}
 const last=agent.state.messages.filter(message=>message.role==='assistant').at(-1);
 const finalText=(last?.content||[]).filter(item=>item.type==='text').map(item=>item.text).join('\n');
 const status=capture.budget.exhausted?'model_round_limit':timedOut?'episode_timeout':exception||['error','aborted'].includes(last?.stopReason)?'inference_error':last?.stopReason==='length'?'output_limit':last?'completed':'no_response';
 return {status,finalText,calls:capture.main.records,events,registered_tools:agent.state.tools.map(tool=>tool.name),runtime:'@earendil-works/pi-agent-core Agent 1.5.0',tool_execution:'sequential',reasoning_effort:'none',automatic_retries:0,max_rounds:16,max_output_tokens:1400,retained_actor_message_replays:capture.sourceReplayed?1:0,resume_exception:exception,actor_draw_budget:{limit:16,used:capture.budget.used,historical:init.natural_resume.historical_actor_calls,new:capture.budget.used-init.natural_resume.historical_actor_calls,claims:capture.budget.claims,exhausted:capture.budget.exhausted}};
}

export async function episode(args,{broker:providedBroker,backend,fetchImpl}={}){
 const out=resolve(args['--out']);if(!ARMS.includes(args['--arm']))throw new Error('Unregistered natural arm');
 const broker=providedBroker||new Broker(args['--python'],{journal:out+'.rpc-errors.jsonl',script:join(HERE,'broker.py')});const started=performance.now();
 try{
  const init=await broker.rpc('init',{manifest:resolve(args['--manifest']),natural_packet:resolve(args['--natural-packet']),x6_arm:args['--arm'],model:MODEL,delegate_reference:true,clock_anchor:'2026-11-05T00:00:00',judge_cache:resolve(args['--judge-cache']),policy_cache:resolve(args['--policy-cache']),policy_journal:out+'.policy-journal.jsonl'});
  const capture=new NaturalActor(resolve(args['--actor-cache']),init.connection,init.natural_resume,{backend,fetchImpl});
  const constructors=new CoupledBank(resolve(args['--constructor-cache']),{...(backend?{backend}:{}),...(fetchImpl?{fetchImpl}:{})});broker.actor=capture;broker.constructorBank=constructors;
  const pi=await runContinuation(init,broker,capture);const finished=await broker.rpc('finish',{final_text:pi.finalText});
  const unknown=[];
  if(!capture.sourceReplayed||!finished.result.natural_original_proposal_dispatched)unknown.push('original_proposal_not_replayed_and_dispatched');
  if(broker.errors.length)unknown.push('rpc_or_capture_failure');
  if((finished.result.x6_repairs||[]).some(record=>record.status==='operationally_unknown'))unknown.push('repair_operational_failure');
  if([...capture.repair.records,...constructors.records].some(record=>record.error))unknown.push('repair_inference_failure');
  if(capture.batchViolations.length)unknown.push('multiple_tool_call_protocol_violation');
  if(pi.status!=='completed')unknown.push('actor_'+pi.status);
  const baseCalls=finished.result.policy_calls||[],reservations=finished.result.repair_constructor_reservations||0,historicalU=init.natural_resume.historical_actor_calls,historicalT=init.natural_resume.historical_constructor_calls;
  const resources={historical_actor_draws:historicalU,new_actor_draws:capture.budget.used-historicalU,actor_budget_slots:capture.budget.used,ordinary_actor_draws:capture.main.records.length,extra_actor_draws:capture.repair.records.length,actor_actual_network_calls:capture.bank.records.filter(record=>record.actual_network_call===true).length,actor_cache_hits:capture.bank.records.filter(record=>record.cache_hit).length,historical_constructor_draws:historicalT,base_constructor_draws:baseCalls.length,base_constructor_actual_network_calls:baseCalls.filter(record=>record.actual_network_call===true).length,base_constructor_cache_hits:baseCalls.filter(record=>record.coupling?.cache_hit).length,repair_constructor_reservations:reservations,repair_constructor_draws:constructors.records.length,repair_constructor_actual_network_calls:constructors.records.filter(record=>record.actual_network_call===true).length,repair_constructor_cache_hits:constructors.records.filter(record=>record.cache_hit).length,repair_constructor_reserved_but_undrawn:reservations-constructors.records.length,new_constructor_budget_slots:baseCalls.length+reservations,new_constructor_draws:baseCalls.length+constructors.records.length,total_constructor_budget_slots:historicalT+baseCalls.length+reservations,total_constructor_draws:historicalT+baseCalls.length+constructors.records.length,expert_audits:0};
  if(resources.total_constructor_budget_slots!==finished.result.combined_constructor_calls||resources.total_constructor_budget_slots>64||resources.actor_budget_slots>16)unknown.push('cumulative_budget_accounting_mismatch');
  const row={...finished.result,x6_resources:resources,status:pi.status,actor_status:pi.status,x6_scientific_status:unknown.length?'operationally_unknown':'known',x6_unknown_reasons:unknown,x6_rpc_errors:broker.errors,pi:{...pi,finalText:undefined,events:undefined},initial_state_sha256:init.initial_state_sha256,natural_boundary_state_sha256:init.natural_boundary_state_sha256,natural_boundary_policy_sha256:init.natural_boundary_policy_sha256,x6_repair_actor_calls:capture.repair.records,x6_constructor_calls:constructors.records,x6_context_captures:capture.captures,batch_violations:capture.batchViolations,elapsed_s:(performance.now()-started)/1000,new_closed_loop_episode:false,new_closed_loop_continuation:true};
  await mkdir(dirname(out),{recursive:true});
  await writeFile(out+'.json.gz',gzipSync(JSON.stringify({result:row,...finished.raw,actor_instructions:init.instructions,actor_prompt:init.prompt,pi_tool_events:pi.events,x6_actor_contexts:capture.captures,natural_actor_resume:capture.sourceReplay,natural_context_recovery_scope:'Historical provider-payload-equivalent reconstructed host context, retaining source ordinary history; excluded host timestamps are not claimed historically exact.'})));
  await writeFile(out+'.json',JSON.stringify(row)+'\n');return row;
 }finally{broker.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];try{const row=await episode(args);console.log(JSON.stringify({unit:row.natural_unit_id,arm:row.x6_arm,status:row.status,scientific_status:row.x6_scientific_status,utility:row.native_utility,repairs:row.x6_repairs.length}));}catch(error){console.error('Natural continuation failed: '+error.message);process.exitCode=1;}}
