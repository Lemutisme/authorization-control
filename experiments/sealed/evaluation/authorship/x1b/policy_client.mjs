/** Plain-text policy completions through the existing Pi/Luna provider interface. */
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {normalizeContext} from '@earendil-works/pi-ai';
import {makeModel,MODEL} from './pi_loop.mjs';
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';
import {CoupledStream} from './coupling.mjs';
let coupled,reasoning;
const lines=createInterface({input:process.stdin});let connection=null;
for await(const line of lines){
 const q=JSON.parse(line);
 if(q.method==='init'){connection=q.connection;reasoning=q.reasoning;if(!['none','medium'].includes(reasoning))throw new Error('invalid_reasoning');coupled=new CoupledStream(q.cache);console.log(JSON.stringify({ok:true}));continue;}
 const meta={requested_model:MODEL,reasoning_effort:reasoning,actual_network_call:false,requested_upstream_temperature:q.temperature,sampling_adaptation:'Pi/Luna established sampling settings; upstream temperature is recorded but omitted.'};const started=performance.now();
 try{
  const model={...makeModel(connection),maxTokens:8192};
  const stream=coupled.stream(model,normalizeContext({systemPrompt:q.system,messages:[{role:'user',content:q.user,timestamp:0}]}),{apiKey:connection.api_key||'unused-anonymous-endpoint-key',maxTokens:8192,maxRetries:0,timeoutMs:90000,cacheRetention:'none',
   onPayload:payload=>{payload.model=MODEL;payload.reasoning={effort:reasoning};payload.max_output_tokens=8192;payload.store=false;
    const texts=[payload.instructions,...(payload.input||[]).filter(m=>m.role==='system'||m.role==='developer').flatMap(m=>typeof m.content==='string'?[m.content]:(m.content||[]).map(c=>c.text))];
    if(!texts.includes(q.system))throw new Error('Policy instructions missing from privileged request fields');
    meta.policy_instruction_preserved=true;meta.policy_instruction_sha256=createHash('sha256').update(q.system).digest('hex');meta.request_sha256=createHash('sha256').update(JSON.stringify(payload)).digest('hex');meta.actual_network_call=true;return payload;},
   onProviderStreamEvent:event=>{if(event?.response?.model)meta.returned_model=event.response.model;if(event?.response?.usage)meta.usage=event.response.usage;},onResponse:r=>{meta.http_status=r.status;}});
  const result=await stream.result();meta.coupling=coupled.records.at(-1);meta.actual_network_call=meta.coupling.network_requested;if(!meta.actual_network_call){meta.cached_sample_usage=result.usage;delete meta.usage;}else meta.pi_usage=result.usage;meta.stop_reason=result.stopReason;meta.elapsed_s=(performance.now()-started)/1000;
  if(result.stopReason==='error'||result.stopReason==='aborted'||result.stopReason==='length')throw new Error('Policy completion did not finish');
  const text=result.content.filter(c=>c.type==='text').map(c=>c.text).join('\n');if(!text.trim())throw new Error('No policy text');console.log(JSON.stringify({ok:true,text,meta}));
 }catch{meta.elapsed_s=(performance.now()-started)/1000;console.log(JSON.stringify({ok:false,error:'policy_transport_failure',meta}));}
}
