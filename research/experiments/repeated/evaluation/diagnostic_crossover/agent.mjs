/** Exact archived-prefix replay, then fresh Pi continuation. No host tools. */
import {runPi,MODEL} from '../pi/agent.mjs';
import {CoupledStream} from '../pi/coupling.mjs';
import {AssistantMessageEventStream} from '@earendil-works/pi-ai';
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdir,writeFile} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url)),hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
class Broker {
 constructor(python){this.child=spawn(python,['-B',join(HERE,'broker.py')],{stdio:['pipe','pipe','pipe']});this.next=0;this.pending=new Map();this.closed=false;this.child.stderr.on('data',()=>{});this.lines=createInterface({input:this.child.stdout});this.lines.on('line',s=>{const x=JSON.parse(s),p=this.pending.get(x.id);if(!p)return this.close();this.pending.delete(x.id);clearTimeout(p.timer);x.ok?p.resolve(x.result):p.reject(new Error(x.error));});this.child.on('exit',()=>this.close());this.child.on('error',()=>this.close());}
 call(method,params){if(this.closed)return Promise.reject(new Error('broker_closed'));const id=++this.next;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>this.close(),120000);this.pending.set(id,{resolve,reject,timer});this.child.stdin.write(JSON.stringify({id,method,params})+'\n');});}
 close(){if(this.closed)return;this.closed=true;for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error('broker_closed'));}this.pending.clear();this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}
class PrefixStream {
 constructor(prefix,cache,qualify){this.prefix=prefix;this.next=0;this.coupled=new CoupledStream(cache);this.records=[];this.qualify=qualify;}
 stream=(model,context,options)=>{
  if(this.next>=this.prefix.length){if(this.qualify)throw new Error('Fresh inference forbidden');return this.coupled.stream(model,context,options);}
  const entry=this.prefix[this.next++],out=new AssistantMessageEventStream();let matched=false;
  (async()=>{
   const inner=streamSimple(model,context,{...options,onPayload:async payload=>{const replacement=await options.onPayload?.(payload,model),actual=replacement===undefined?payload:replacement;
    if(hash(actual)!==entry.wire_request_sha256)throw new Error('Historical actor request mismatch');matched=true;throw new Error('HISTORICAL_REPLAY');}});
   for await(const _ of inner){};await inner.result();
   if(!matched||hash(entry.message)!==entry.response_sha256)throw new Error('Historical prefix identity mismatch');
   const message=structuredClone(entry.message);this.records.push({historical_replay:true,wire_request_sha256:entry.wire_request_sha256,response_sha256:entry.response_sha256});
   out.push({type:'start',partial:message});out.push({type:'done',reason:message.stopReason,message});out.end();
  })().catch(()=>{const m={role:'assistant',api:model.api,provider:model.provider,model:model.id,content:[],stopReason:'error',errorMessage:'historical_prefix_mismatch',timestamp:0,usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};out.push({type:'error',reason:'error',error:m});out.end();});return out;
 };
}
const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
const b=new Broker(a['--python']);
try{
 const init=await b.call('init',{crossover_manifest:resolve(a['--manifest']),case_id:a['--case'],background:a['--background'],message:a['--message'],judge_cache:resolve(a['--judge-cache']),model:MODEL,delegate_reference:true,qualify:a['--qualify']==='true'});
 const replay=new PrefixStream(init.actor_prefix,resolve(a['--actor-cache']),a['--qualify']==='true'),start=performance.now();
 const pi=await runPi(init,b,{maxRounds:a['--qualify']==='true'?init.actor_prefix.length:16,maxOutputTokens:1400,streamFn:replay.stream});
 if(replay.records.length!==init.actor_prefix.length)throw new Error('Incomplete historical prefix');
 for(let i=0;i<pi.calls.length;i++){
  const c=pi.calls[i];
  if(i<init.actor_prefix.length){c.historical_replay=true;c.actual_network_call=false;c.historical_sample_usage=c.usage;delete c.usage;delete c.provider_usage;c.missing_usage=false;c.replay=replay.records[i];}
  else {const x=replay.coupled.records[i-init.actor_prefix.length];if(!x)throw new Error('Suffix call accounting');c.coupling=x;c.actual_network_call=x.network_requested;if(x.cache_hit){c.cached_sample_usage=c.usage;delete c.usage;delete c.provider_usage;c.missing_usage=false;}}
 }
 if(replay.coupled.records.length!==pi.calls.length-init.actor_prefix.length)throw new Error('Suffix coupling accounting');
 const r=await b.call('finish',{final_text:pi.finalText});const row={...r.result,status:pi.status,pi:{...pi,events:undefined,finalText:undefined},initial_state_sha256:init.initial_state_sha256,elapsed_s:(performance.now()-start)/1000,qualify:a['--qualify']==='true'};
 const out=resolve(a['--out']);await mkdir(dirname(out),{recursive:true});await writeFile(out+'.json.gz',gzipSync(JSON.stringify({result:row,...r.raw,pi_tool_events:pi.events})));await writeFile(out+'.json',JSON.stringify(row)+'\n');
 console.log(JSON.stringify({case_id:row.case_id,background:row.background,message:row.message,status:row.status,utility:row.native_utility,asr:row.native_targeted_asr}));
}catch(e){console.error('Crossover failed: '+e.message);process.exitCode=1;}finally{b.close();}
