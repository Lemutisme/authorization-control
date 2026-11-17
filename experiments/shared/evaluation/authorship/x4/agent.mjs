/** Live Pi X1 unit lifecycle with held denials and fresh captured-context repair. */
import {runPi,MODEL} from '../../pi/agent.mjs';
import {CapturedActor} from './capture.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {appendFileSync,mkdirSync} from 'node:fs';
import {mkdir,writeFile,readFile} from 'node:fs/promises';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));

export class Broker{
 constructor(python,{journal,script=join(HERE,'broker.py')}={}){
  this.child=spawn(python,['-B',script],{stdio:['pipe','pipe','pipe']});
  this.pending=new Map();this.next=0;this.closed=false;this.actor=null;this.errors=[];this.journal=journal;
  if(journal)mkdirSync(dirname(journal),{recursive:true});
  this.child.stderr.on('data',()=>{});
  this.lines=createInterface({input:this.child.stdout});
  this.lines.on('line',line=>{
   let x;try{x=JSON.parse(line);}catch{return this.close('invalid_broker_protocol');}
   const p=this.pending.get(x.id);if(!p)return this.close('unexpected_broker_reply');
   this.pending.delete(x.id);clearTimeout(p.timer);
   if(x.ok){p.resolve(x.result);return;}
   const failure={id:x.id,method:p.method,error:x.error,diagnostic:x.diagnostic};
   this.record(failure);
   const error=new Error('broker_'+x.error);Object.assign(error,{rpc:failure});p.reject(error);
  });
  this.child.on('exit',()=>this.close('broker_exited'));
  this.child.on('error',()=>this.close('broker_process_error'));
 }
 record(failure){
  this.errors.push(failure);
  // Persist before rejecting, even if a subsequent finish fails. Never log
  // RPC requests, connection details or credentials in this error journal.
  if(this.journal)appendFileSync(this.journal,JSON.stringify(failure)+'\n');
 }
 rpc(method,params){
  if(this.closed)return Promise.reject(new Error('broker_closed'));
  const id=++this.next;
  return new Promise((resolve,reject)=>{
   const timer=setTimeout(()=>this.close('broker_timeout'),600000);
   this.pending.set(id,{resolve,reject,timer,method});
   this.child.stdin.write(JSON.stringify({id,method,params})+'\n',error=>{if(error)this.close('broker_write_failed');});
  });
 }
 async call(method,params){
  const result=await this.rpc(method,params);
  if(method!=='invoke'||!result.x4_repair_request)return result;
  const request=result.x4_repair_request;let stage='actor_capture';
  try{
   if(!this.actor)throw new Error('Missing live actor capture');
   const fresh=await this.actor.resample(request.call_id,{reasoning:'none',refusal:request.disclose_refusal?request.refusal:null});
   stage='python_repair';
   // Await puts Python RPC rejection inside this catch and finalizes the hold.
   return await this.rpc('repair',{call_id:request.call_id,candidate:fresh.candidate,
    context_json:fresh.context_json,actor_meta:fresh.meta});
  }catch(error){
   if(!error.rpc)this.record({method:stage,error:error.name||'ContextCaptureError',diagnostic:error.message});
   return await this.rpc('abort_repair',{call_id:request.call_id,stage,reason:error.rpc?.error||error.name||'ContextCaptureError'});
  }
 }
 close(reason='broker_closed'){
  if(this.closed)return;this.closed=true;
  for(const [id,p] of this.pending){
   clearTimeout(p.timer);this.record({id,method:p.method,error:reason});p.reject(new Error(reason));
  }
  this.pending.clear();this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');
 }
}

export async function episode(args,{broker:providedBroker}={}){
 const out=resolve(args['--out']);
 const broker=providedBroker||new Broker(args['--python'],{journal:out+'.rpc-errors.jsonl'});
 try{
  const manifest=JSON.parse(await readFile(args['--manifest'],'utf8'));
  const condition=JSON.parse(await readFile(args['--condition'],'utf8'));
  const unit=manifest.units.find(item=>item.unit_id===condition.unit_id);if(!unit)throw new Error('Unknown source unit');
  const plan=JSON.parse(await readFile(args['--audit-plan'],'utf8'));
  const init=await broker.rpc('init',{manifest:resolve(args['--manifest']),case_id:condition.case_id,unit,model:MODEL,clock_anchor:'2026-11-05T00:00:00',variant:'fault',bound_projection:condition.bound_projection,prefix_sha256:condition.prefix_sha256,x4_arm:args['--arm'],audit_plan:plan,audit_ledger:resolve(args['--audit-ledger']),repair_bank:resolve(args['--repair-bank']),constructor_journal:out+'.constructor-journal.jsonl'});
  const capture=new CapturedActor(resolve(args['--actor-cache']),resolve(args['--repair-bank']),init.connection);broker.actor=capture;
  const pi=await runPi(init,broker,{maxRounds:16,maxOutputTokens:1400,episodeTimeoutMs:900000,streamFn:capture.stream});
  if(capture.main.records.length!==pi.calls.length)throw new Error('Main actor accounting mismatch');
  for(let i=0;i<pi.calls.length;i++){const info=capture.main.records[i];pi.calls[i].coupling=info;pi.calls[i].actual_network_call=info.network_requested;if(info.cache_hit){pi.calls[i].cached_sample_usage=pi.calls[i].usage;delete pi.calls[i].usage;delete pi.calls[i].provider_usage;pi.calls[i].missing_usage=false;}}
  const result=await broker.rpc('finish',{final_text:pi.finalText});
  const transportCalls=[...capture.repair.records,...(result.result.policy_calls||[])];
  const unknownReasons=[];
  if(broker.errors.length)unknownReasons.push('rpc_or_capture_failure');
  if(result.result.x4_transport_failures.length)unknownReasons.push('repair_transport_failure');
  if(transportCalls.some(call=>call.error||['error','aborted'].includes(call.stop_reason)))unknownReasons.push('repair_inference_failure');
  if(capture.batchViolations.length)unknownReasons.push('multiple_call_source_unqualified');
  if(pi.status!=='completed')unknownReasons.push('actor_'+pi.status);
  const row={...result.result,status:unknownReasons.length?'operationally_unknown':pi.status,actor_status:pi.status,
   x4_scientific_status:unknownReasons.length?'operationally_unknown':'known',x4_unknown_reasons:unknownReasons,
   x4_rpc_errors:broker.errors,pi:{...pi,finalText:undefined,events:undefined},initial_state_sha256:init.initial_state_sha256,
   x4_repair_actor_calls:capture.repair.records,x4_context_captures:capture.captures,batch_violations:capture.batchViolations};
  await mkdir(dirname(out),{recursive:true});
  await writeFile(out+'.json.gz',gzipSync(JSON.stringify({result:row,...result.raw,pi_tool_events:pi.events})));
  await writeFile(out+'.json',JSON.stringify(row)+'\n');
  return row;
 }finally{broker.close();}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
 try{
  const row=await episode(args);
  console.log(JSON.stringify({arm:row.x4_arm,status:row.status,utility:row.native_utility,repairs:row.x4_records.length,repair_effects:row.x4_repaired_effects}));
 }catch(error){console.error('X4 lifecycle failed: '+error.message);process.exitCode=1;}
}
