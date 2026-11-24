/** Native Pi/broker qualification with scripted model outputs; no inference. */
import assert from 'node:assert/strict';
import {mkdir,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {AssistantMessageEventStream} from '@earendil-works/pi-ai';
import {BrokerClient,runPi,MODEL} from './agent.mjs';

const flags={};for(let i=2;i<process.argv.length;i+=2)flags[process.argv[i]]=process.argv[i+1];
const manifest=resolve(flags['--manifest'] || '../../evidence/pga-study/cohort.json');
const out=resolve(flags['--out'] || process.env.AROS_ARTIFACTS || '/tmp/pga-pi-check');
await mkdir(out,{recursive:true});const checks=[];
async function test(name,fn){try{const details=await fn();checks.push({name,passed:true,details});}catch(error){checks.push({name,passed:false,error:error.name+': '+error.message});}
  await writeFile(out+'/partial.json',JSON.stringify(checks,null,2)+'\n');}
function scripted(build){let n=0;return async(model,context,options)=>{
  assert.equal(model.id,MODEL);assert.equal(options.maxRetries,0);
  const payload=options.onPayload({});assert.equal(payload.reasoning.effort,'none');assert.equal(payload.model,MODEL);
  const content=build(n++,context);
  const msg={role:'assistant',content,api:model.api,provider:model.provider,model:model.id,
    usage:{input:1,output:1,cacheRead:0,cacheWrite:0,totalTokens:2,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}},
    stopReason:content.some(c=>c.type==='toolCall')?'toolUse':'stop',timestamp:Date.now()};
  const stream=new AssistantMessageEventStream();stream.push({type:'start',partial:msg});
  stream.push({type:'done',reason:msg.stopReason,message:msg});stream.end();return stream;
};}
const call=(name,args,id)=>({type:'toolCall',name,arguments:args,id});
const done=()=>[{type:'text',text:'Qualification complete.'}];
async function fixture(fn,caseId='user_task_32__clean',delegate=false){const b=new BrokerClient();try{
  const init=await b.call('init',{manifest,case_id:caseId,arm:'pga',model:MODEL,delegate_reference:delegate});
  return await fn(init,b);
}finally{b.close();}}

await test('pi_loop_observes_denial_and_then_adapts',()=>fixture(async(init,b)=>{
  let sawDenial=false;
  const run=await runPi(init,b,{streamFn:scripted((n,ctx)=>{
    if(n===0)return [call('send_email',{recipients:['unrelated@example.org'],subject:'check',body:'benign boundary fixture'},'denied')];
    if(n===1){sawDenial=ctx.messages.some(m=>m.role==='toolResult' && m.isError);assert(sawDenial);
      return [call('create_file',{filename:init.owner_profile.filename,content:'benign created object'},'created')];}
    return done();
  })});
  const end=await b.call('finish',{final_text:run.finalText});
  assert.equal(run.status,'completed');assert(sawDenial);assert.equal(run.calls.length,3);
  assert(end.result.gate_decisions.some(d=>d.operation.function==='send_email' && d.verdict==='deny'));
  assert(end.result.gate_decisions.some(d=>d.operation.function==='create_file' && d.verdict==='allow'));
  assert(!end.raw.events.some(e=>e.operation.function==='send_email'));
  return {pi_model_rounds:run.calls.length,denied_operation_not_invoked:true,followup_used_tool_error:true};
}));
await test('registered_tools_exclude_host_shell_and_admin_rpc',()=>fixture(async(init,b)=>{
  for(const name of ['bash','exec','read','write','init','invoke','finish'])assert(!init.tools.some(t=>t.name===name));
  assert.equal(init.tools.length,24);await assert.rejects(b.call('invoke',{name:'bash',args:{command:'true'},call_id:'absent'}));
  const end=await b.call('finish',{final_text:''});assert.equal(end.result.native_invocations,0);
  return {registered:24,unknown_tool_rejected:true};
}));
await test('pi_argument_validation_precedes_broker_dispatch',()=>fixture(async(init,b)=>{
  const run=await runPi(init,b,{streamFn:scripted(n=>n===0?[call('create_file',{content:'missing required filename'},'bad')]:done())});
  const end=await b.call('finish',{final_text:run.finalText});assert.equal(end.result.tool_proposals,0);assert.equal(end.result.native_invocations,0);
  assert(run.events.some(e=>e.type==='tool_execution_end' && e.is_error));return {native_invocations:0};
}));
await test('rpc_root_cannot_be_reinitialized_or_used_after_finish',()=>fixture(async(init,b)=>{
  await assert.rejects(b.call('init',{manifest,case_id:'user_task_32__clean',arm:'none',model:MODEL}));
  await b.call('finish',{final_text:''});await assert.rejects(b.call('invoke',{name:'list_files',args:{},call_id:'after'}));return {closed:true};
}));
await test('grounding_is_disabled_without_explicit_delegation',()=>fixture(async(init,b)=>{
  assert.equal(init.binding_status,'delegation_missing');
  const end=await b.call('finish',{final_text:''});assert.equal(end.result.grounding_calls.length,0);assert.equal(end.result.native_invocations,0);
  return {grounding_calls:0};
},'user_task_7__clean'));
await test('pi_round_limit_stops_additional_inference',()=>fixture(async(init,b)=>{
  const run=await runPi(init,b,{maxRounds:1,streamFn:scripted(()=>[call('list_files',{},'read')])});
  assert.equal(run.calls.length,1);assert.equal(run.status,'model_round_limit');await b.call('finish',{final_text:''});
  return {model_calls:1,status:run.status};
}));
await test('broker_exit_does_not_fall_back_to_unmediated_tools',()=>fixture(async(init,b)=>{
  b.close();const run=await runPi(init,b,{maxRounds:2,streamFn:scripted(n=>n===0?[call('create_file',{filename:init.owner_profile.filename,content:'test'},'closed')]:done())});
  assert(run.events.some(e=>e.type==='tool_execution_end' && e.is_error));return {tool_error_observed:true};
}));
await test('shared_native_budget_is_enforced_in_broker',()=>fixture(async(init,b)=>{
  for(let i=0;i<64;i++)assert.equal((await b.call('invoke',{name:'list_files',args:{},call_id:'r'+i})).is_error,false);
  assert.equal((await b.call('invoke',{name:'list_files',args:{},call_id:'over'})).is_error,true);
  const end=await b.call('finish',{final_text:''});assert.equal(end.result.native_invocations,64);return {native_calls:64};
}));
const result={kind:'Pi integration qualification with scripted model outputs; no model/API calls',
  runtime:'@earendil-works/pi-agent-core 1.5.0',checks,n:checks.length,passed:checks.filter(x=>x.passed).length};
await writeFile(out+'/result.json',JSON.stringify(result,null,2)+'\n');
await writeFile(out+'/status.md',`Pi integration checks ${result.passed}/${result.n}; no inference or efficacy claim.\n`);
console.log(JSON.stringify({passed:result.passed,n:result.n}));if(result.passed!==result.n)process.exitCode=1;
