/** X6 official Pi actor loop and held-refusal RPC coordinator. */
import {Agent} from '@earendil-works/pi-agent-core';
import {brokerTools,makeModel,MODEL} from '../pi/agent.mjs';
import {CapturedActor} from './capture.mjs';
import {CoupledBank,constructorContext} from './pi_draw.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {appendFileSync,mkdirSync} from 'node:fs';
import {mkdir,writeFile} from 'node:fs/promises';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));
export const ARMS=['no_gate','originalauto','sealed_exact','no_agreement','unsealed_ctor_exact','opaque_no_update','trusted_edit','sealed_compatible'];

export class Broker {
 constructor(python,{journal,script=join(HERE,'broker.py')}={}){
  this.child=spawn(python,['-B',script],{stdio:['pipe','pipe','pipe']});this.pending=new Map();this.next=0;this.closed=false;this.actor=null;this.constructorBank=null;this.errors=[];this.journal=journal;
  if(journal)mkdirSync(dirname(journal),{recursive:true});
  this.child.stderr.on('data',()=>{});this.lines=createInterface({input:this.child.stdout});
  this.lines.on('line',line=>{let row;try{row=JSON.parse(line);}catch{return this.close('invalid_broker_protocol');}const p=this.pending.get(row.id);if(!p)return this.close('unexpected_broker_reply');this.pending.delete(row.id);clearTimeout(p.timer);if(row.ok){p.resolve(row.result);return;}const failure={id:row.id,method:p.method,error:row.error,diagnostic:row.diagnostic};this.record(failure);p.reject(Object.assign(new Error('broker_'+row.error),{rpc:failure}));});
  this.child.on('error',()=>this.close('broker_process_error'));this.child.on('exit',()=>this.close('broker_exited'));
 }
 record(failure){this.errors.push(failure);if(this.journal)appendFileSync(this.journal,JSON.stringify(failure)+'\n');}
 rpc(method,params){if(this.closed)return Promise.reject(new Error('broker_closed'));const id=++this.next;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>this.close('broker_timeout'),600000);this.pending.set(id,{resolve,reject,timer,method});this.child.stdin.write(JSON.stringify({id,method,params})+'\n',error=>{if(error)this.close('broker_write_failed');});});}
 async call(method,params){
  const result=await this.rpc(method,params);if(method!=='invoke'||!result.x6_repair_request)return result;
  const request=result.x6_repair_request;let stage='actor_capture';
  try{
   if(!this.actor||!this.constructorBank)throw new Error('missing_live_repair_coordinator');
   const fresh=await this.actor.resample(request.call_id);
   stage='constructor_draw';
   const draw=await this.constructorBank.draw({connection:this.actor.connection,context:constructorContext(request.constructor_packet),stage:'constructor',reasoning:'low',maxTokens:1536});
   if(draw.meta.error)throw Object.assign(new Error('repair_constructor_inference_failure'),{draw:draw.meta});
   const valid=draw.calls.length===1&&draw.calls[0].name==='submit_authorizations'&&draw.calls[0].arguments&&typeof draw.calls[0].arguments==='object';
   stage='python_repair';
   return await this.rpc('repair',{call_id:request.call_id,candidate:fresh.candidate,context_json:fresh.context_json,actor_meta:fresh.meta,constructor_reply:valid?draw.calls[0].arguments:null,constructor_meta:{...draw.meta,valid_reply:!!valid}});
  }catch(error){
   if(!error.rpc)this.record({method:stage,error:error.message||error.name,draw:error.draw});
   return await this.rpc('abort_repair',{call_id:request.call_id,stage,reason:error.rpc?.error||error.message||error.name});
  }
 }
 close(reason='broker_closed'){if(this.closed)return;this.closed=true;for(const [id,p] of this.pending){clearTimeout(p.timer);this.record({id,method:p.method,error:reason});p.reject(new Error(reason));}this.pending.clear();this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}

export async function runActor(init,broker,capture,{episodeTimeoutMs=900000}={}){
 const events=[];let timedOut=false,exception=false;
 const agent=new Agent({initialState:{systemPrompt:init.instructions,model:makeModel(init.connection),thinkingLevel:'off',tools:brokerTools(init.tools,broker)},toolExecution:'sequential',getApiKey:()=>init.connection.api_key||'unused-anonymous-endpoint-key',streamFn:capture.stream});
 agent.subscribe(event=>{if(event.type==='tool_execution_start')events.push({type:event.type,name:event.toolName,call_id:event.toolCallId,args:event.args});if(event.type==='tool_execution_end')events.push({type:event.type,call_id:event.toolCallId,is_error:event.isError});});
 const timer=setTimeout(()=>{timedOut=true;agent.abort();},episodeTimeoutMs);
 try{await agent.prompt(init.prompt);await agent.waitForIdle();}catch{exception=true;}finally{clearTimeout(timer);}
 const last=agent.state.messages.filter(message=>message.role==='assistant').at(-1);
 const finalText=(last?.content||[]).filter(item=>item.type==='text').map(item=>item.text).join('\n');
 const status=capture.budget.exhausted?'model_round_limit':timedOut?'episode_timeout':exception||['error','aborted'].includes(last?.stopReason)?'inference_error':last?.stopReason==='length'?'output_limit':last?'completed':'no_response';
 return {status,finalText,calls:capture.main.records,events,registered_tools:agent.state.tools.map(tool=>tool.name),runtime:'@earendil-works/pi-agent-core Agent 1.5.0',tool_execution:'sequential',reasoning_effort:'none',automatic_retries:0,max_rounds:16,max_output_tokens:1400,session_persistence:'none; no coding CLI, extensions, skills or host tools',actor_draw_budget:{limit:16,used:capture.budget.used,claims:capture.budget.claims,exhausted:capture.budget.exhausted}};
}

export async function episode(args,{broker:providedBroker,backend,fetchImpl}={}){
 const out=resolve(args['--out']);if(!ARMS.includes(args['--arm']))throw new Error('Unregistered X6 arm');
 const broker=providedBroker||new Broker(args['--python'],{journal:out+'.rpc-errors.jsonl'});const started=performance.now();
 try{
  const init=await broker.rpc('init',{manifest:resolve(args['--manifest']),case_id:args['--case'],x6_arm:args['--arm'],contract_profile:args['--contract-profile']||'banking_financial',x2b_role:args['--role'],strategy:args['--strategy']||'direct',model:MODEL,delegate_reference:true,clock_anchor:'2026-11-05T00:00:00',judge_cache:resolve(args['--judge-cache']),policy_cache:resolve(args['--policy-cache']),policy_journal:out+'.policy-journal.jsonl'});
  const capture=new CapturedActor(resolve(args['--actor-cache']),init.connection,{backend,fetchImpl});
  const constructors=new CoupledBank(resolve(args['--constructor-cache']),{...(backend?{backend}:{}),...(fetchImpl?{fetchImpl}:{})});broker.actor=capture;broker.constructorBank=constructors;
  const pi=await runActor(init,broker,capture);const finished=await broker.rpc('finish',{final_text:pi.finalText});
  const unknown=[];
  if(broker.errors.length)unknown.push('rpc_or_capture_failure');
  if((finished.result.x6_repairs||[]).some(record=>record.status==='operationally_unknown'))unknown.push('repair_operational_failure');
  if([...capture.repair.records,...constructors.records].some(record=>record.error))unknown.push('repair_inference_failure');
  if(capture.batchViolations.length)unknown.push('multiple_tool_call_protocol_violation');
  if(pi.status!=='completed')unknown.push('actor_'+pi.status);
  const baseCalls=finished.result.policy_calls||[],reservations=finished.result.repair_constructor_reservations||0;
  const resources={actor_budget_slots:capture.budget.used,ordinary_actor_draws:capture.main.records.length,extra_actor_draws:capture.repair.records.length,actor_actual_network_calls:capture.bank.records.filter(record=>record.actual_network_call===true).length,actor_cache_hits:capture.bank.records.filter(record=>record.cache_hit).length,base_constructor_draws:baseCalls.length,base_constructor_actual_network_calls:baseCalls.filter(record=>record.actual_network_call===true).length,base_constructor_cache_hits:baseCalls.filter(record=>record.coupling?.cache_hit).length,repair_constructor_reservations:reservations,repair_constructor_draws:constructors.records.length,repair_constructor_actual_network_calls:constructors.records.filter(record=>record.actual_network_call===true).length,repair_constructor_cache_hits:constructors.records.filter(record=>record.cache_hit).length,repair_constructor_reserved_but_undrawn:reservations-constructors.records.length,total_constructor_budget_slots:baseCalls.length+reservations,total_constructor_draws:baseCalls.length+constructors.records.length,expert_audits:0};
  const row={...finished.result,x6_resources:resources,status:pi.status,actor_status:pi.status,x6_scientific_status:unknown.length?'operationally_unknown':'known',x6_unknown_reasons:unknown,x6_rpc_errors:broker.errors,pi:{...pi,finalText:undefined,events:undefined},initial_state_sha256:init.initial_state_sha256,x6_repair_actor_calls:capture.repair.records,x6_constructor_calls:constructors.records,x6_context_captures:capture.captures,batch_violations:capture.batchViolations,elapsed_s:(performance.now()-started)/1000,new_closed_loop_episode:true};
  await mkdir(dirname(out),{recursive:true});
  await writeFile(out+'.json.gz',gzipSync(JSON.stringify({result:row,...finished.raw,actor_instructions:init.instructions,actor_prompt:init.prompt,pi_tool_events:pi.events,x6_actor_contexts:capture.captures})));
  await writeFile(out+'.json',JSON.stringify(row)+'\n');return row;
 }finally{broker.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
 try{const row=await episode(args);console.log(JSON.stringify({arm:row.x6_arm,role:row.x2b_role,status:row.status,scientific_status:row.x6_scientific_status,utility:row.native_utility,target:row.native_targeted_asr,repairs:row.x6_repairs.length}));}
 catch(error){console.error('X6 episode failed: '+error.message);process.exitCode=1;}
}
