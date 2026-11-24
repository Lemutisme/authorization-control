/** Recorded-response replay through real frozen-v1 Pi and Python JSON-RPC. */
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {spawn,spawnSync} from 'node:child_process';
import {createInterface} from 'node:readline';
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';
import {AssistantMessageEventStream} from '@earendil-works/pi-ai';
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';

const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
const frozen=resolve(a['--frozen']),job=resolve(a['--job']),dataset=resolve(a['--dataset']),out=resolve(a['--out']);await mkdir(out,{recursive:true});
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const bytesHash=x=>createHash('sha256').update(x).digest('hex');
const clone=x=>JSON.parse(JSON.stringify(x));
const conditionId='banking__user_task_11__send_money__amount__M1__F0';
const folder=join(job,conditionId),rawFile=join(folder,'x4_projection_H0.json.gz');
const rawBytes=await readFile(rawFile),raw=JSON.parse(gunzipSync(rawBytes));
const config=JSON.parse(await readFile(join(job,'config.json'),'utf8'));
const brokerSource=await readFile(join(frozen,'evaluation/authorship/x4/broker.py'));
if(bytesHash(brokerSource)!==config.source_sha256['broker.py'])throw new Error('Frozen broker identity differs');
const {runPi,MODEL}=await import(pathToFileURL(join(frozen,'evaluation/pi/agent.mjs')).href);
const {semanticHash}=await import(pathToFileURL(join(frozen,'evaluation/authorship/x4/pi_draw.mjs')).href);
const sourceCalls=raw.result.pi.calls,records=[],contexts=[],rpc=[];let networkCalls=0,reproduced=null;
const backend=(model,context,options)=>{
 const index=records.length,source=sourceCalls[index],stream=new AssistantMessageEventStream();
 const record={index,context:clone(context)};records.push(record);contexts.push(record.context);
 (async()=>{
  if(!source)throw new Error('No recorded response at this request');
  const entry=JSON.parse(await readFile(join(folder,'actor-cache',source.coupling.request_sha256+'.json'),'utf8'));
  if(hash(entry.message)!==entry.response_sha256)throw new Error('Retained message identity failed');
  const inner=streamSimple(model,context,{...options,fetch:async()=>{networkCalls++;throw new Error('Offline replay forbids network');},onPayload:async payload=>{
   const actual=await options.onPayload(payload);record.wire_sha256=hash(actual);record.source_wire_sha256=source.request_sha256;
   if(record.wire_sha256!==record.source_wire_sha256)throw new Error('Recorded wire request differs');
   record.wire_matches=true;throw new Error('REPLAY_SERIALIZATION_ONLY');
  }});
  await inner.result();if(!record.wire_matches)throw new Error('Wire mismatch before replay');
  const message=clone(entry.message);record.response_sha256=entry.response_sha256;
  stream.push({type:'start',partial:message});stream.push({type:'done',reason:message.stopReason,message});stream.end(message);
 })().catch(error=>{record.error=error.message;const message={role:'assistant',api:model.api,provider:model.provider,model:MODEL,content:[],stopReason:'error',errorMessage:'offline_replay_error',timestamp:0,usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};stream.push({type:'error',reason:'error',error:message});stream.end(message);});
 return stream;
};
class Broker{
 constructor(){this.child=spawn(a['--python'],['-B',join(frozen,'evaluation/authorship/x4/broker.py')],{stdio:['pipe','pipe','pipe']});this.next=0;this.pending=new Map();this.child.stderr.on('data',()=>{});this.lines=createInterface({input:this.child.stdout});this.lines.on('line',line=>{const message=JSON.parse(line),pending=this.pending.get(message.id);this.pending.delete(message.id);rpc.push({method:pending.method,response:pending.method==='init'?{ok:message.ok,initial_state_sha256:message.result?.initial_state_sha256}:message});message.ok?pending.resolve(message.result):pending.reject(new Error(message.error));});}
 rpc(method,params){return new Promise((resolve,reject)=>{const id=++this.next;this.pending.set(id,{resolve,reject,method});this.child.stdin.write(JSON.stringify({id,method,params})+'\n');});}
 async call(method,params){const result=await this.rpc(method,params);if(method!=='invoke'||!result.x4_repair_request)return result;
  const context=clone(contexts.at(-1)),text=JSON.stringify(context),legacy=semanticHash(context);
  const python=spawnSync(a['--python'],['-B','-c','import sys,json,hashlib; s=sys.stdin.read(); x=json.loads(s); print(json.dumps({"python_digest":hashlib.sha256(json.dumps(x,sort_keys=True,separators=(\",\",\":\"),ensure_ascii=False).encode()).hexdigest(),"bytes_digest":hashlib.sha256(s.encode()).hexdigest(),"optimize":sys.flags.optimize}))'],{input:text,encoding:'utf8'});
  if(python.status!==0)throw new Error('Digest check failed');const check=JSON.parse(python.stdout);
  reproduced={legacy_js_digest:legacy,...check,js_bytes_digest:bytesHash(text),context_json_file:'captured-context.json',source_response_hashes:records.map(r=>r.response_sha256)};
  await writeFile(join(out,'captured-context.json'),text);
  // This guarantees the unmodified v1 broker rejects before creating any
  // constructor process; no possible model call is permitted in this replay.
  if(check.optimize!==0||legacy===check.python_digest)throw new Error('Expected v1 pre-constructor rejection is not guaranteed');
  const repairMeta=raw.result.x4_repair_actor_calls[0];
  const sample=JSON.parse(await readFile(join(folder,'repair-bank',repairMeta.sample_key+'.json'),'utf8'));
  if(hash(sample.message)!==sample.response_sha256)throw new Error('Retained repair response mismatch');
  const call=sample.message.content.filter(item=>item.type==='toolCall');if(call.length!==1)throw new Error('Recorded resample is not one call');
  return this.rpc('repair',{call_id:params.call_id,candidate:{function:call[0].name,args:call[0].arguments},context,actor_meta:{pre_proposal_context_sha256:legacy,feedback_disclosed:false,recorded_response_replay:true}});
 }
 close(){this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}
const broker=new Broker();
try{
 const manifest=JSON.parse(await readFile(join(dataset,'cohort.json'),'utf8'));
 const condition=JSON.parse(await readFile(join(dataset,'conditions',conditionId+'.json'),'utf8'));
 const unit=manifest.units.find(u=>u.unit_id===condition.unit_id);
 const plan=JSON.parse(await readFile(join(dataset,'audit-plans/M1-actor_right-H0.json'),'utf8'));
 const init=await broker.rpc('init',{manifest:join(dataset,'cohort.json'),case_id:condition.case_id,unit,model:MODEL,clock_anchor:'2026-11-05T00:00:00',variant:'fault',bound_projection:condition.bound_projection,prefix_sha256:condition.prefix_sha256,x4_arm:'x4_projection_H0',audit_plan:plan,audit_ledger:join(out,'audit.json'),repair_bank:join(out,'unused-repair'),constructor_journal:join(out,'no-constructor.jsonl')});
 const pi=await runPi(init,broker,{maxRounds:16,maxOutputTokens:1400,streamFn:backend});
 const final=await broker.rpc('finish',{final_text:pi.finalText});
 const rejection=rpc.find(row=>row.method==='repair'&&row.response.ok===false);
 const report={reproduced,repair_rejection:rejection,network_requests:networkCalls,model_requests:0,actor_status:pi.status,constructor_calls:final.result.policy_calls.length,python_repair_records:final.result.x4_records.length,source_raw_sha256:bytesHash(rawBytes),frozen_broker_sha256:bytesHash(brokerSource),wire_requests:records.map(({context,...row})=>row),scope:'Exact retained assistant responses replayed through actual frozen-v1 Pi and JSON-RPC. New local message timestamps may differ; serialized model inputs are checked against source hashes. No fresh responses or source outcomes replaced.'};
 await writeFile(join(out,'rpc.json'),JSON.stringify(rpc,null,2)+'\n');await writeFile(join(out,'result.json'),JSON.stringify(report,null,2)+'\n');
 console.log(JSON.stringify(report,null,2));
 if(!rejection||networkCalls||final.result.policy_calls.length)process.exitCode=1;
}finally{broker.close();}
