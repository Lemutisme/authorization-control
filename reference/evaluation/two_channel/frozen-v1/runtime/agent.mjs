/** Official Pi continuation through the two-channel broker. No inference on import. */
import {Broker} from '/artifact-source/39fa1b622d22/agent.mjs';
import {runContinuation} from '/artifact-source/da241ada98ee/agent.mjs';
import {NaturalActor} from '/artifact-source/36c8a643725a/capture.mjs';
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));
export const ARMS=['f0_u0','f0_u1','f1_u0','f1_u1','f0_off','f1_off'];
const hash=x=>createHash('sha256').update(x,'utf8').digest('hex');

export async function episode(args,{broker:providedBroker,backend,fetchImpl}={}){
 const out=resolve(args['--out']);
 if(!ARMS.includes(args['--arm']))throw new Error('Unregistered factorial arm');
 const broker=providedBroker||new Broker(args['--python'],{journal:out+'.rpc-errors.jsonl',script:join(HERE,'broker.py')});
 const began=performance.now();
 try{
  const init=await broker.rpc('init',{manifest:resolve(args['--manifest']),prefix_packet:resolve(args['--packet']),packet_sha256:args['--packet-sha256'],
   factorial_arm:args['--arm'],model:'gpt-6-luna',delegate_reference:true,clock_anchor:'2026-11-05T00:00:00',
   judge_cache:resolve(args['--judge-cache']),policy_cache:resolve(args['--policy-cache']),policy_journal:out+'.policy-journal.jsonl'});
  const capture=new NaturalActor(resolve(args['--actor-cache']),init.connection,init.natural_resume,{backend,fetchImpl});
  const pi=await runContinuation(init,broker,capture);
  const completed=await broker.rpc('finish',{final_text:pi.finalText});
  const actorMessages=[];
  for(const item of capture.pending){
   let message=null,error=null;try{message=await item.stream.result();}catch(e){error=e.message||e.name;}
   actorMessages.push({draw_index:item.draw_index,historical_replayed:!!item.historical_replayed,
    context_json:item.context_json,context_sha256:hash(item.context_json),message,error});
  }
  const unknown=[];
  if(!capture.sourceReplayed||!completed.result.original_pending_dispatched)unknown.push('source_proposal_not_dispatched');
  if(broker.errors.length)unknown.push('rpc_failure');
  if(capture.batchViolations.length)unknown.push('multiple_call_protocol_violation');
  if(['inference_error','episode_timeout','no_response'].includes(pi.status))unknown.push('actor_'+pi.status);
  for(const record of capture.main.records)if(record.error)unknown.push('actor_transport_failure');
  const policyCalls=completed.result.policy_calls||[];
  if(policyCalls.some(record=>record.ok===false&&record.stop_reason!=='length'))unknown.push('policy_transport_failure');
  if(completed.result.factorial_records.some(record=>record.policy_refused&&record.refusal_state_unchanged!==true))unknown.push('refusal_changed_native_state');
  if(completed.result.factorial_records.some(record=>record.policy_refused&&(!record.same_call_before_update.known||!record.same_call_after_update.known)))unknown.push('permission_probe_unknown');
  if(completed.result.utility_error)unknown.push('native_utility_unavailable');
  if(completed.result.asr_error)unknown.push('native_target_unavailable');
  const hU=init.natural_resume.historical_actor_calls,hT=init.natural_resume.historical_constructor_calls;
  const firstNew=actorMessages.find(record=>!record.historical_replayed)||null;
  const resources={historical_actor_draws:hU,new_actor_draws:capture.budget.used-hU,actor_budget_slots:capture.budget.used,
   actor_actual_network_calls:capture.bank.records.filter(record=>record.actual_network_call===true).length,
   actor_cache_hits:capture.bank.records.filter(record=>record.cache_hit).length,
   historical_policy_draws:hT,new_policy_draws:policyCalls.length,total_policy_budget_slots:hT+policyCalls.length,
   policy_actual_network_calls:policyCalls.filter(record=>record.actual_network_call===true).length,
   policy_cache_hits:policyCalls.filter(record=>record.coupling?.cache_hit).length,
   policy_output_limits:policyCalls.filter(record=>record.stop_reason==='length').length,owner_audits:0};
  if(resources.actor_budget_slots>16||resources.total_policy_budget_slots>64)unknown.push('cumulative_budget_mismatch');
  const row={...completed.result,factorial_configuration:init.factorial_configuration,actor_status:pi.status,status:pi.status,
   factorial_scientific_status:unknown.length?'operationally_unknown':'known',factorial_unknown_reasons:[...new Set(unknown)],
   factorial_resources:resources,first_post_refusal_actor:firstNew,
   pi:{...pi,finalText:undefined,events:undefined},source_actor_replay:capture.sourceReplay,
   actor_batch_violations:capture.batchViolations,rpc_errors:broker.errors,elapsed_s:(performance.now()-began)/1000,
   runtime_scope:'Matched retained-prefix continuation; stock policy regeneration after forced refusal opportunities; no repair draws; no owner audits'};
  await mkdir(dirname(out),{recursive:true});
  await writeFile(out+'.json',JSON.stringify(row)+'\n');
  await writeFile(out+'.json.gz',gzipSync(JSON.stringify({result:row,...completed.raw,
   actor_instructions:init.instructions,actor_prompt:init.prompt,pi_tool_events:pi.events,all_actor_messages:actorMessages})));
  return row;
 }finally{broker.close();}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
 try{const row=await episode(args);console.log(JSON.stringify({unit:row.factorial_unit_id,arm:row.factorial_arm,status:row.status,
  scientific_status:row.factorial_scientific_status,utility:row.native_utility,target:row.native_targeted_asr,
  first_update_admission:row.factorial_first_refusal?.new_admission,resources:row.factorial_resources}));}
 catch(error){console.error('Factorial continuation failed: '+error.message);process.exitCode=1;}
}
