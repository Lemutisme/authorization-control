/** Plain-text policy completions through the existing Pi/Luna provider interface. */
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {normalizeContext} from '@earendil-works/pi-ai';
import {makeModel,MODEL} from '../pi/agent.mjs';
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';
import {readFile,writeFile,rename,mkdir} from 'node:fs/promises';
import {join} from 'node:path';
const hash=x=>createHash('sha256').update(x,'utf8').digest('hex');
const occurrences=new Map();
const actualFetch=globalThis.fetch;
const lines=createInterface({input:process.stdin});let connection=null;
for await(const line of lines){
 const q=JSON.parse(line);
 if(q.method==='init'){connection=q.connection;console.log(JSON.stringify({ok:true}));continue;}
 const meta={requested_model:MODEL,reasoning_effort:'none',actual_network_call:false,requested_upstream_temperature:q.temperature,sampling_adaptation:'Pi/Luna established sampling settings; upstream temperature is recorded but omitted.'};const started=performance.now();let cached=null,cacheFile=null;
 try{
  meta.context_json=JSON.stringify({systemPrompt:q.system,messages:[{role:'user',content:q.user,timestamp:0}]});meta.context_sha256=createHash('sha256').update(meta.context_json,'utf8').digest('hex');
  const model={...makeModel(connection),maxTokens:8192};
  const stream=streamSimple(model,normalizeContext({systemPrompt:q.system,messages:[{role:'user',content:q.user,timestamp:0}]}),{apiKey:connection.api_key||'unused-anonymous-endpoint-key',maxTokens:8192,maxRetries:0,timeoutMs:90000,cacheRetention:'none',
   fetch:async(url,init)=>{const body=typeof init?.body==='string'?init.body:await new Request(url,init).text();meta.wire_request_json=body;meta.wire_request_sha256=hash(body);meta.wire_request_utf8_bytes=Buffer.byteLength(body,'utf8');if(body!==meta.request_json)throw new Error('policy_payload_serialization_changed');meta.actual_network_call=true;return actualFetch(url,init);},
   onPayload:async payload=>{payload.model=MODEL;payload.reasoning={effort:'none'};payload.max_output_tokens=8192;payload.store=false;
    const texts=[payload.instructions,...(payload.input||[]).filter(m=>m.role==='system'||m.role==='developer').flatMap(m=>typeof m.content==='string'?[m.content]:(m.content||[]).map(c=>c.text))];
    if(!texts.includes(q.system))throw new Error('Policy instructions missing from privileged request fields');
    meta.policy_instruction_preserved=true;meta.policy_instruction_sha256=createHash('sha256').update(q.system).digest('hex');meta.request_json=JSON.stringify(payload);meta.request_sha256=createHash('sha256').update(meta.request_json,'utf8').digest('hex');const identity=hash(JSON.stringify({endpoint_hash:hash(model.baseUrl),principal_hash:hash(connection.api_key??''),request_json:meta.request_json}));const occurrence=(occurrences.get(identity)||0)+1;occurrences.set(identity,occurrence);const key=hash(JSON.stringify([identity,occurrence]));meta.coupling={sample_key:key,input_identity:identity,occurrence,stage:q.stage,cache_hit:false};
    if(q.cache_directory){await mkdir(q.cache_directory,{recursive:true});cacheFile=join(q.cache_directory,key+'.json');try{const saved=JSON.parse(await readFile(cacheFile,'utf8'));if(saved.key!==key||saved.request_json!==meta.request_json||saved.response_sha256!==hash(JSON.stringify(saved.response)))throw new Error('policy_cache_identity');cached=saved.response;}catch(error){if(error.code!=='ENOENT')throw error;}if(cached){meta.coupling.cache_hit=true;throw new Error('X6_POLICY_CACHE_READY');}}return payload;},
   onProviderStreamEvent:event=>{if(event?.response?.model)meta.returned_model=event.response.model;if(event?.response?.usage)meta.usage=event.response.usage;},onResponse:r=>{meta.http_status=r.status;}});
  const result=await stream.result();
  if(cached){const old=cached.meta;Object.assign(meta,{wire_request_json:old.wire_request_json,wire_request_sha256:old.wire_request_sha256,wire_request_utf8_bytes:old.wire_request_utf8_bytes,cached_sample_usage:old.usage,returned_model:old.returned_model,stop_reason:old.stop_reason,actual_network_call:false,elapsed_s:(performance.now()-started)/1000});console.log(JSON.stringify({ok:true,text:cached.text,meta}));continue;}
  meta.stop_reason=result.stopReason;meta.elapsed_s=(performance.now()-started)/1000;
  if(result.stopReason==='error'||result.stopReason==='aborted'||result.stopReason==='length')throw new Error('Policy completion did not finish');
  const text=result.content.filter(c=>c.type==='text').map(c=>c.text).join('\n');if(!text.trim())throw new Error('No policy text');const response={ok:true,text,meta};if(cacheFile){const entry={key:meta.coupling.sample_key,request_json:meta.request_json,response,response_sha256:hash(JSON.stringify(response))};const tmp=cacheFile+'.'+process.pid+'.tmp';await writeFile(tmp,JSON.stringify(entry)+'\n');await rename(tmp,cacheFile);}console.log(JSON.stringify(response));
 }catch{meta.elapsed_s=(performance.now()-started)/1000;console.log(JSON.stringify({ok:false,error:'policy_transport_failure',meta}));}
}
