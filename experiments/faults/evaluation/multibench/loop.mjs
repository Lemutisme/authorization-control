/** Pi loop; native InjecAgent first-step stopping is explicit. */
import {Agent} from '@earendil-works/pi-agent-core';
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {createHash} from 'node:crypto';
import {makeModel,brokerTools,MODEL} from '../pi/agent.mjs';
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
export async function runBench(init,broker,{maxRounds=16,maxOutputTokens=1400,streamFn,episodeTimeoutMs=240000,protocolOneStep=false}={}) {
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
  const status=limitHit?(protocolOneStep?'protocol_complete':'model_round_limit'):timedOut?'episode_timeout':exception || last?.stopReason==='error' || last?.stopReason==='aborted'?'inference_error':last?.stopReason==='length'?'output_limit':last?'completed':'no_response';
  const fresh=assistants.slice(init.seededAssistantCount || 0);const first=fresh[0];
  const firstText=(first?.content || []).filter(x=>x.type==='text').map(x=>x.text).join('\n');
  const firstToolCalls=(first?.content || []).filter(x=>x.type==='toolCall').map(x=>({id:x.id,type:'function',function:{name:x.name,arguments:JSON.stringify(x.arguments)}}));
  const assistantTexts=fresh.map(m=>m.content.filter(x=>x.type==='text').map(x=>x.text).join('\n'));
  const visibleToolTexts=agent.state.messages.filter(m=>m.role==='toolResult').map(m=>m.content.filter(x=>x.type==='text').map(x=>x.text).join('\n'));
  return {status,finalText,firstText,firstToolCalls,assistantTexts,visibleToolTexts,calls,events,registered_tools:agent.state.tools.map(t=>t.name),
    runtime:'@earendil-works/pi-agent-core Agent 1.5.0',tool_execution:'sequential',
    reasoning_effort:'none',automatic_retries:0,max_rounds:maxRounds,max_output_tokens:maxOutputTokens,
    session_persistence:'none; no Pi coding CLI, extensions, skills or host shell tools loaded'};
}

