/** Capture actual SDK payloads without allowing a network request. */
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {normalizeContext} from '@earendil-works/pi-ai';
import {Agent} from '@earendil-works/pi-agent-core';
import {makeModel,MODEL} from '../pi/agent.mjs';
import {createHash} from 'node:crypto';
import {readFile,writeFile} from 'node:fs/promises';
const args={};for(let i=2;i<process.argv.length;i+=2)args[process.argv[i]]=process.argv[i+1];
const fixture=JSON.parse(await readFile(args['--fixture'],'utf8'));let network=0;
const model={...makeModel({base_url:'https://example.invalid/v1',api_key:'not-a-real-key'}),maxTokens:8192};
const hash=s=>createHash('sha256').update(s).digest('hex');
const preserved=(p,s)=>[p.instructions,...(p.input||[]).filter(m=>m.role==='system'||m.role==='developer').flatMap(m=>typeof m.content==='string'?[m.content]:(m.content||[]).map(c=>c.text))].includes(s);
async function capture(context){let payload=null;const stream=streamSimple(model,context,{apiKey:'not-a-real-key',maxTokens:8192,maxRetries:0,cacheRetention:'none',fetch:async()=>{network++;throw new Error('Network forbidden');},onPayload:p=>{p.model=MODEL;p.reasoning={effort:'none'};p.max_output_tokens=8192;p.store=false;payload=p;throw new Error('CAPTURE_ONLY');}});await stream.result();if(!payload)throw new Error('No payload captured');return payload;}
const context={systemPrompt:fixture.system,messages:[{role:'user',content:fixture.user,timestamp:0}]};
const old=await capture(context),fixed=await capture(normalizeContext(context));
if(preserved(old,fixture.system)||!preserved(fixed,fixture.system))throw new Error('Context diagnosis failed');
if(hash(JSON.stringify(old))!==fixture.old_wire_sha256)throw new Error('Did not reproduce exact failed wire request');
let agentPayload=null;const agent=new Agent({initialState:{systemPrompt:fixture.system,model,tools:[]},getApiKey:()=> 'not-a-real-key',streamFn:async(m,c,o)=>{agentPayload=await capture(c);throw new Error('CAPTURE_ONLY');}});
try{await agent.prompt(fixture.user);await agent.waitForIdle();}catch{}
if(!agentPayload||!preserved(agentPayload,fixture.system))throw new Error('Existing Agent path missing system prompt');
if(network)throw new Error('Unexpected network request');
const report={kind:'Exact request-construction diagnosis; zero inference',passed:3,n:3,old_wire_sha256:hash(JSON.stringify(old)),fixed_wire_sha256:hash(JSON.stringify(fixed)),old_adapter_dropped_system_prompt:true,normalized_adapter_preserves_system_prompt:true,existing_pi_agent_path_preserves_system_prompt:true,network_requests:network,model_requests:0,source_sha256:hash(await readFile(new URL(import.meta.url)))};
await writeFile(args['--out'],JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
