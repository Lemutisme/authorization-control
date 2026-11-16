/** Serialize retained Pi contexts without model calls or network access. */
import {streamSimple} from '/artifact-source/eb60eb2c1694/openai-responses.js';
import {makeModel,MODEL} from '/artifact-source/9f6fe822e52a/agent.mjs';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
const HERE=dirname(fileURLToPath(import.meta.url));
const sha=value=>createHash('sha256').update(value).digest('hex');
const load=async path=>JSON.parse(await readFile(path,'utf8'));
const save=async(path,value)=>writeFile(path,JSON.stringify(value,null,2)+'\n');
globalThis.fetch=async()=>{throw new Error('Network prohibited in source serialization');};
const manifest=await load(join(HERE,'honest-runtime-manifest.json'));
const model=makeModel({base_url:'https://example.invalid/v1',api_key:null});
const rows=[];
for(const row of manifest.packets){
 const packet=await load(row.packet);let request_json=null;
 if(sha(packet.actor_context_json)!==packet.actor_context_utf8_sha256)throw new Error('Source context hash differs');
 if(sha(JSON.stringify(packet.source_proposal_message))!==packet.source_actor_response.response_sha256)throw new Error('Source response hash differs');
 const stream=streamSimple(model,JSON.parse(packet.actor_context_json),{
  apiKey:'unused-anonymous-endpoint-key',maxTokens:1400,maxRetries:0,timeoutMs:90000,cacheRetention:'none',fetch:globalThis.fetch,
  onPayload:payload=>{
   payload.model=MODEL;payload.reasoning={effort:'none'};payload.parallel_tool_calls=false;
   payload.max_output_tokens=1400;payload.store=false;
   request_json=JSON.stringify(payload);
   throw new Error('Captured payload; no provider request permitted');
  },
 });
 await stream.result();
 const actual=request_json===null?null:sha(request_json);
 const equal=actual===packet.actor_request_sha256;
 rows.push({unit_id:row.unit_id,passed:equal,request_json,request_sha256:actual,source_request_sha256:packet.actor_request_sha256,context_sha256:packet.actor_context_utf8_sha256});
 if(!equal)continue;
}
const summary={scheduled:rows.length,passed:rows.filter(r=>r.passed).length,model_calls:0,network_calls:0,rows};
await save(join(HERE,'honest-wire-recovery.json'),summary);
console.log(JSON.stringify({scheduled:summary.scheduled,passed:summary.passed,model_calls:0,network_calls:0}));
if(summary.passed!==summary.scheduled)process.exitCode=1;
