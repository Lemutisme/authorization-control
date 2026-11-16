/** Replay retained assistant messages and exact native tool outputs; no network. */
import {runPi} from '../pi/agent.mjs';
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {AssistantMessageEventStream} from '@earendil-works/pi-ai';
import {readFile,writeFile,readdir} from 'node:fs/promises';
import {dirname,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
const HERE=dirname(fileURLToPath(import.meta.url));
const sha=x=>createHash('sha256').update(x,'utf8').digest('hex');
globalThis.fetch=async()=>{throw new Error('Network prohibited in source replay');};
const rows=[];
for(const unit of await readdir(join(HERE,'prefixes'))){
 const folder=join(HERE,'prefixes',unit);const p=JSON.parse(await readFile(join(folder,'replay-input.json'),'utf8'));let index=0;const captures=[];let failure=null;
 const broker={call:async(method,args)=>{if(method!=='invoke'||!p.tool_results[args.call_id])throw new Error('Unexpected source replay tool');return p.tool_results[args.call_id];}};
 const streamFn=async(model,context,options)=>{
  const draw=index++;
  if(draw>p.target_draw)throw new Error('Stopped at selected boundary');
  const context_json=JSON.stringify(context);let request_json=null;
  const sourceMessage=p.source_messages[draw];
  const inner=streamSimple(model,context,{...options,fetch:globalThis.fetch,onPayload:payload=>{
   const actual=options.onPayload(payload)||payload;request_json=JSON.stringify(actual);throw new Error('Source replay: serialize only');}});
  await inner.result();
  const request_sha256=request_json?sha(request_json):null;
  const equal=request_sha256===p.source_request_hashes[draw];
  captures.push({draw,context_json,context_utf8_sha256:sha(context_json),context_utf8_bytes:Buffer.byteLength(context_json,'utf8'),request_json,request_sha256,source_request_sha256:p.source_request_hashes[draw],request_hash_equal:equal});
  if(!equal)failure='retained_request_hash_mismatch';
  if(draw===p.target_draw)throw new Error('Selected boundary captured; do not replay its proposal');
  const out=new AssistantMessageEventStream();out.push({type:'start',partial:sourceMessage});out.push({type:'done',reason:sourceMessage.stopReason,message:sourceMessage});out.end(sourceMessage);return out;
 };
 await runPi(p.init,broker,{maxRounds:16,maxOutputTokens:1400,streamFn});
 const complete=captures.length===p.target_draw+1;
 const result={unit_id:unit,model_calls:0,network_calls:0,faithful_wire_recovery:complete&&!failure,complete,failure,captures};
 await writeFile(join(folder,'actor-context-recovery.json'),JSON.stringify(result,null,2)+'\n');
 rows.push({unit_id:unit,faithful_wire_recovery:result.faithful_wire_recovery,draws:captures.length,target_draw:p.target_draw,failure});
}
await writeFile(join(HERE,'context-recovery-summary.json'),JSON.stringify({model_calls:0,network_calls:0,rows},null,2)+'\n');
console.log(JSON.stringify(rows));
