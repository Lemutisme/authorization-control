/** One forced structured policy proposal; never executes native tools or model code. */
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {normalizeContext} from '@earendil-works/pi-ai';
import {makeModel,MODEL} from '../pi/agent.mjs';
import {createInterface} from 'node:readline';
import {createHash} from 'node:crypto';
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const lines=createInterface({input:process.stdin});let connection=null;
for await (const line of lines) {
 const q=JSON.parse(line);if(q.method==='init'){connection=q.connection;console.log(JSON.stringify({ok:true}));continue;}
 const meta={requested_model:MODEL,reasoning_effort:'none',actual_network_call:false,automatic_retries:0};const start=performance.now();
 try {
  const tool={name:'submit_policy',description:'Return the requested policy data only. This function executes no world operation.',parameters:q.output_schema};
  const model={...makeModel(connection),maxTokens:8192};
  const stream=streamSimple(model,normalizeContext({systemPrompt:q.system,messages:[{role:'user',content:q.user,timestamp:0}],tools:[tool]}),{apiKey:connection.api_key||'unused-anonymous-endpoint-key',maxTokens:8192,maxRetries:0,timeoutMs:90000,cacheRetention:'none',
   onPayload:payload=>{payload.model=MODEL;payload.reasoning={effort:'none'};payload.max_output_tokens=8192;payload.store=false;payload.parallel_tool_calls=false;payload.tool_choice={type:'function',name:'submit_policy'};for(const t of payload.tools||[])if(t.type==='function')t.strict=false;
    const texts=[payload.instructions,...(payload.input||[]).filter(m=>m.role==='system'||m.role==='developer').flatMap(m=>typeof m.content==='string'?[m.content]:(m.content||[]).map(c=>c.text))];if(!texts.includes(q.system))throw new Error('Missing policy instruction');meta.instructions_sha256=hash(q.system);meta.request_sha256=hash(payload);meta.actual_network_call=true;return payload;},
   onProviderStreamEvent:event=>{if(event?.response?.model)meta.returned_model=event.response.model;if(event?.response?.usage)meta.usage=event.response.usage;},onResponse:r=>{meta.http_status=r.status;}});
  const response=await stream.result();meta.stop_reason=response.stopReason;meta.elapsed_s=(performance.now()-start)/1000;meta.response_sha256=hash(response);
  const calls=response.content.filter(x=>x.type==='toolCall'&&x.name==='submit_policy');
  if(calls.length!==1||['error','aborted','length'].includes(response.stopReason))throw new Error('No complete structured proposal');
  console.log(JSON.stringify({ok:true,program:calls[0].arguments,meta}));
 } catch {meta.elapsed_s=(performance.now()-start)/1000;console.log(JSON.stringify({ok:false,error:'policy_transport_or_structure_failure',meta}));}
}
