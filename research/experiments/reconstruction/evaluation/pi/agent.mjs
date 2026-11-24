/** Official Pi Agent loop with only broker-mediated AgentDojo tools. */
import { Agent } from '@earendil-works/pi-agent-core';
import { streamSimple } from '@earendil-works/pi-ai/api/openai-responses';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';
export const MODEL='gpt-6-luna';
const HERE=dirname(fileURLToPath(import.meta.url));
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');

export class BrokerClient {
  constructor(python=process.env.PGA_PYTHON || 'python3') {
    this.child=spawn(python,['-B',join(HERE,'broker.py')],{stdio:['pipe','pipe','pipe']});
    this.pending=new Map();this.next=0;this.stderrBytes=0;this.closed=false;
    this.child.stderr.on('data',b=>{this.stderrBytes+=b.length;});
    this.lines=createInterface({input:this.child.stdout});
    this.lines.on('line',line=>{
      let row;try{row=JSON.parse(line);}catch{this.fail('invalid_broker_protocol');return;}
      const waiting=this.pending.get(row.id);
      if(!waiting){this.fail('unexpected_broker_reply');return;}
      this.pending.delete(row.id);clearTimeout(waiting.timer);
      if(row.ok)waiting.resolve(row.result);else waiting.reject(new Error('broker_'+row.error));
    });
    this.child.on('error',()=>this.fail('broker_process_error'));
    this.child.on('exit',()=>{this.closed=true;this.fail('broker_exited');});
  }
  fail(reason){for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error(reason));}this.pending.clear();}
  call(method,params) {
    if(this.closed)return Promise.reject(new Error('broker_closed'));
    const id=++this.next;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending.delete(id);reject(new Error('broker_timeout'));this.close();},120000);
      this.pending.set(id,{resolve,reject,timer});
      this.child.stdin.write(JSON.stringify({id,method,params})+'\n',error=>{if(error)this.fail('broker_write_failed');});
    });
  }
  close(){this.closed=true;this.fail('broker_closed');this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}

export function brokerTools(specs,broker) {
  return specs.map(s=>({name:s.name,label:s.name,description:s.description,parameters:s.parameters,
    executionMode:'sequential',execute:async(callId,args,signal)=>{
      if(signal?.aborted)throw new Error('task_aborted_before_dispatch');
      const result=await broker.call('invoke',{name:s.name,args,call_id:callId});
      if(result.is_error)throw new Error(result.text);
      return {content:[{type:'text',text:result.text}],details:{broker_mediated:true}};
    }}));
}

export function makeModel(connection) {
  return {id:MODEL,name:MODEL,api:'openai-responses',provider:'openai',baseUrl:connection.base_url,
    reasoning:true,input:['text'],contextWindow:1050000,maxTokens:1400,
    // Source: official Luna standard prices; not the proxy's actual invoice.
    cost:{input:0.10,output:0.50,cacheRead:0.01,cacheWrite:0.125},
    ...(connection.api_key?{}:{headers:{Authorization:null}})};
}

export async function runPi(init,broker,{maxRounds=16,maxOutputTokens=1400,streamFn,episodeTimeoutMs=240000}={}) {
  if(!Number.isInteger(maxRounds) || maxRounds<1 || maxRounds>16 || !Number.isInteger(maxOutputTokens) || maxOutputTokens<16 || maxOutputTokens>1400)throw new Error('invalid_inference_budget');
  const calls=[];const events=[];let limitHit=false,timedOut=false;
  const agent=new Agent({initialState:{systemPrompt:init.instructions,model:makeModel(init.connection),
      thinkingLevel:'off',tools:brokerTools(init.tools,broker)},toolExecution:'sequential',
    getApiKey:()=>init.connection.api_key || 'unused-anonymous-endpoint-key',
    streamFn:async(model,context,options)=>{
      if(calls.length>=maxRounds){limitHit=true;throw new Error('model_round_limit');}
      const rec={requested_model:MODEL,reasoning_effort:'none',automatic_retries:0,
        model_identity_limit:'Requested model is fixed; provider-returned alias is recorded when supplied, not an immutable weights identity.'};
      calls.push(rec);const started=performance.now();
      const fn=streamFn || streamSimple;
      const stream=await fn(model,context,{...options,maxTokens:maxOutputTokens,maxRetries:0,timeoutMs:90000,
        cacheRetention:'none',onPayload:payload=>{
          payload.model=MODEL;payload.reasoning={effort:'none'};payload.parallel_tool_calls=false;
          payload.max_output_tokens=maxOutputTokens;payload.store=false;
          rec.request_sha256=hash(payload);return payload;
        },onResponse:response=>{rec.http_status=response.status;},
        onProviderStreamEvent:event=>{
          if(event?.response?.model)rec.returned_model=event.response.model;
          if(event?.response?.usage)rec.provider_usage=event.response.usage;
          if(event?.type==='response.completed')rec.provider_status=event.response.status;
        }});
      // Pi consumes this same stream; result() observes its terminal outcome.
      stream.result().then(message=>{rec.elapsed_s=(performance.now()-started)/1000;
        rec.usage=message.usage;rec.stop_reason=message.stopReason;
        rec.missing_usage=!(message.usage?.totalTokens>0);
      }).catch(()=>{rec.error='stream_result_error';rec.missing_usage=true;});
      return stream;
    }});
  agent.subscribe(e=>{
    if(e.type==='tool_execution_start')events.push({type:e.type,name:e.toolName,call_id:e.toolCallId,args:e.args});
    if(e.type==='tool_execution_end')events.push({type:e.type,call_id:e.toolCallId,is_error:e.isError});
  });
  const timer=setTimeout(()=>{timedOut=true;agent.abort();},episodeTimeoutMs);
  let exception=false;
  try{await agent.prompt(init.prompt);await agent.waitForIdle();}catch{exception=true;}finally{clearTimeout(timer);}
  const assistants=agent.state.messages.filter(x=>x.role==='assistant');const last=assistants.at(-1);
  const finalText=(last?.content || []).filter(x=>x.type==='text').map(x=>x.text).join('\n');
  const status=limitHit?'model_round_limit':timedOut?'episode_timeout':exception || last?.stopReason==='error' || last?.stopReason==='aborted'?'inference_error':last?.stopReason==='length'?'output_limit':last?'completed':'no_response';
  return {status,finalText,calls,events,registered_tools:agent.state.tools.map(t=>t.name),
    runtime:'@earendil-works/pi-agent-core Agent 1.5.0',tool_execution:'sequential',
    reasoning_effort:'none',automatic_retries:0,max_rounds:maxRounds,max_output_tokens:maxOutputTokens,
    session_persistence:'none; no Pi coding CLI, extensions, skills or host shell tools loaded'};
}

export async function episode(options) {
  const broker=new BrokerClient(options.python);const started=performance.now();
  try {
    const init=await broker.call('init',{manifest:resolve(options.manifest),case_id:options.caseId,
      arm:options.arm,model:MODEL,delegate_reference:options.delegateReference===true});
    const pi=await runPi(init,broker,{maxRounds:options.maxRounds,maxOutputTokens:options.maxOutputTokens});
    const complete=await broker.call('finish',{final_text:pi.finalText});
    const row={...complete.result,status:pi.status,pi:{...pi,finalText:undefined,events:undefined},elapsed_s:(performance.now()-started)/1000,
      new_closed_loop_episode:true,cost_status:'Standard list-price estimate only; provider invoice unavailable'};
    const raw={result:row,...complete.raw,pi_tool_events:pi.events};
    await mkdir(dirname(options.out),{recursive:true});
    await writeFile(options.out+'.json',JSON.stringify(row,null,2)+'\n');
    await writeFile(options.out+'.json.gz',gzipSync(JSON.stringify(raw)));
    return row;
  } finally {broker.close();}
}

if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
  if(args['--model'] && args['--model']!==MODEL)throw new Error('Expected gpt-6-luna; no fallback model');
  try {
    const row=await episode({manifest:args['--manifest'],caseId:args['--case'],arm:args['--arm'] || 'pga',
      out:resolve(args['--out']),python:args['--python'],delegateReference:args['--delegate-reference']==='true',
      maxRounds:Number(args['--max-rounds'] || 16),maxOutputTokens:Number(args['--max-output-tokens'] || 1400)});
    process.stdout.write(JSON.stringify({case_id:row.case_id,status:row.status,native_utility:row.native_utility,
      native_targeted_asr:row.native_targeted_asr,agent_calls:row.pi.calls.length,grounding_calls:row.grounding_calls.length})+'\n');
  } catch {process.stderr.write('Pi integration failed; no provider or credential details emitted.\n');process.exitCode=1;}
}
