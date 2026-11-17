/** No-inference coupling and native-clock qualification. */
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,readdir,mkdir} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {AssistantMessageEventStream} from '@earendil-works/pi-ai';
import {CoupledStream} from './coupling.mjs';
import {BrokerClient} from '../intent_guard/agent.mjs';
const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
const out=resolve(args['--out']||process.env.AROS_ARTIFACTS||'/tmp/pi-coupling-check');await mkdir(out,{recursive:true});
const folder=await mkdtemp(join(out,'cache-'));let draws=0;
const model={id:'gpt-6-luna',api:'openai-responses',provider:'openai',baseUrl:'https://example.org/api'};
function backend(model,context,options){const stream=new AssistantMessageEventStream();(async()=>{
  try{await options.onPayload({model:model.id,input:context});draws++;
    const message={role:'assistant',api:model.api,provider:model.provider,model:model.id,content:[{type:'text',text:'sample'+draws}],stopReason:'stop',timestamp:1,usage:{input:2,output:2,cacheRead:0,cacheWrite:0,totalTokens:4,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};
    stream.push({type:'start',partial:message});stream.push({type:'done',reason:'stop',message});stream.end();
  }catch{const error={role:'assistant',api:model.api,provider:model.provider,model:model.id,content:[],stopReason:'error',errorMessage:'test_error',timestamp:1,usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};stream.push({type:'error',reason:'error',error});stream.end();}
})();return stream;}
async function sample(coupler,context,options={}){const stream=coupler.stream(model,context,options);for await(const e of stream){}return stream.result();}
const checks=[];async function test(name,fn){try{const detail=await fn();checks.push({name,passed:true,detail});}catch(error){checks.push({name,passed:false,error:error.name+': '+error.message});}}
await test('identical_full_request_reuses_same_sample',async()=>{const c=new CoupledStream(folder,{backend});const a=await sample(c,{prompt:'same',tools:['a','b']});const b=await sample(c,{prompt:'same',tools:['a','b']});assert.deepEqual(a,b);assert.equal(draws,1);assert(c.records[1].cache_hit);return {network_draws:draws};});
await test('changed_history_gets_new_sample',async()=>{const c=new CoupledStream(folder,{backend});await sample(c,{prompt:'same',tools:['a','b'],result:'different'});assert.equal(draws,2);assert(!c.records[0].cache_hit);return {network_draws:draws};});
await test('changed_tool_order_is_not_normalized_away',async()=>{const c=new CoupledStream(folder,{backend});await sample(c,{prompt:'same',tools:['b','a']});assert.equal(draws,3);return {network_draws:draws};});
await test('changed_auth_scope_gets_new_sample',async()=>{const c=new CoupledStream(folder,{backend});const before=draws;await sample(c,{prompt:'same',tools:['a','b']},{apiKey:'test-scope-a'});await sample(c,{prompt:'same',tools:['a','b']},{apiKey:'test-scope-b'});assert.equal(draws-before,2);assert.notEqual(c.records[0].request_sha256,c.records[1].request_sha256);return {different_scope_not_shared:true};});
await test('corrupt_cache_never_executes_or_falls_back',async()=>{const c=new CoupledStream(folder,{backend});await sample(c,{prompt:'corruption'});const file=join(folder,c.records[0].request_sha256+'.json');const d=JSON.parse(await readFile(file,'utf8'));d.message.content=[{type:'text',text:'tampered'}];await writeFile(file,JSON.stringify(d));const before=draws;const r=await sample(c,{prompt:'corruption'});assert.equal(r.stopReason,'error');assert.equal(draws,before);assert(c.records[1].cache_error);return {new_network_draws:0};});
await test('native_writer_clock_matches_in_separate_worlds',async()=>{
  async function world(){const b=new BrokerClient(args['--python']||process.env.PGA_PYTHON||'python3');try{
    const init=await b.call('init',{manifest:args['--manifest'],case_id:'workspace__user_task_32__clean',arm:'none',model:'gpt-6-luna',clock_anchor:'2026-11-05T00:00:00'});
    const a=await b.call('invoke',{name:'create_file',args:{filename:'clock-fixture.txt',content:'benign'},call_id:'clock'});
    const end=await b.call('finish',{final_text:''});return {initial:init.initial_state_sha256,text:a.text,error:a.is_error,ticks:end.result.clock_profile.state.ticks};
  }finally{b.close();}}
  const a=await world(),b=await world();assert.equal(a.error,false);assert.deepEqual(a,b);assert.equal(a.ticks,1);return {same_initial:true,same_tool_result:true,ticks:a.ticks};
});
const result={kind:'controlled coupling/clock qualification; no inference or efficacy claim',checks,passed:checks.filter(x=>x.passed).length,n:checks.length};await writeFile(join(out,'result.json'),JSON.stringify(result,null,2)+'\n');await writeFile(join(out,'status.md'),`Coupling checks ${result.passed}/${result.n}; no API calls.\n`);console.log(JSON.stringify(result,null,2));if(result.passed!==result.n)process.exitCode=1;
