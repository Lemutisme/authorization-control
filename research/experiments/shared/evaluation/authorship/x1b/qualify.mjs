/** Loopback-only wire qualification; no model provider or credentials. */
import {createServer} from 'node:http';
import {mkdtemp,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import assert from 'node:assert/strict';
import {runPi} from './pi_loop.mjs';
import {CoupledStream} from './coupling.mjs';
const requests=[];
const server=createServer(async(req,res)=>{let body='';for await(const chunk of req)body+=chunk;requests.push(JSON.parse(body));res.writeHead(200,{'Content-Type':'text/event-stream'});
 const item={id:'msg_fixture',type:'message',role:'assistant',status:'completed',content:[{type:'output_text',text:'fixture complete',annotations:[]}]};
 for(const event of [{type:'response.created',response:{id:'resp_fixture',model:'fixture',status:'in_progress'}},{type:'response.output_item.added',output_index:0,item:{...item,status:'in_progress',content:[]}},{type:'response.content_part.added',output_index:0,content_index:0,part:{type:'output_text',text:'',annotations:[]}},{type:'response.output_text.delta',output_index:0,content_index:0,delta:'fixture complete'},{type:'response.output_item.done',output_index:0,item},{type:'response.completed',response:{id:'resp_fixture',model:'fixture',status:'completed',output:[item],usage:{input_tokens:10,output_tokens:2,total_tokens:12}}}])res.write('data: '+JSON.stringify(event)+'\n\n');res.end();});
await new Promise(r=>server.listen(0,'127.0.0.1',r));
const connection={base_url:`http://127.0.0.1:${server.address().port}/v1`,api_key:'fixture-only'},dir=await mkdtemp(join(tmpdir(),'x1b-'));
try{
 const actorCache=join(dir,'actor');
 for(const reasoning of ['none','medium','none']){const c=new CoupledStream(actorCache);const r=await runPi({connection,instructions:'Fixture system',prompt:'Fixture user',tools:[]},{},{reasoning,streamFn:c.stream});assert.equal(r.status,'completed');assert.equal(r.finalText,'fixture complete');assert.equal(c.records[0].payload.reasoning.effort,reasoning);}
 assert.equal(requests.length,2);assert.deepEqual(requests.map(p=>p.reasoning.effort),['none','medium']);assert(requests.every(p=>p.max_output_tokens===1400));
 const worker=async(reasoning)=>{const child=spawn('node',[new URL('./policy_client.mjs',import.meta.url).pathname],{stdio:['pipe','pipe','inherit']});const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();const rpc=async q=>{child.stdin.write(JSON.stringify(q)+'\n');return JSON.parse((await lines.next()).value)};
 await rpc({method:'init',connection,reasoning,cache:join(dir,'policy')});for(let i=0;i<2;i++){const r=await rpc({method:'complete',system:'Policy system',user:'Policy user',temperature:0});assert(r.ok);assert.equal(r.meta.coupling.occurrence,i+1);assert.equal(r.meta.coupling.payload.reasoning.effort,reasoning);}child.stdin.end();await new Promise(r=>child.on('exit',r));};
 await worker('none');await worker('medium');await worker('none');assert.equal(requests.length,6);assert(requests.slice(2).every(p=>p.max_output_tokens===8192));
 const repeated=new CoupledStream(actorCache);for(let i=0;i<2;i++){await runPi({connection,instructions:'Fixture system',prompt:'Fixture user',tools:[]},{},{streamFn:repeated.stream});assert.equal(repeated.records[i].occurrence,i+1);}assert.equal(requests.length,7);
 const c=new CoupledStream(join(dir,'fresh-replicate'));await runPi({connection,instructions:'Fixture system',prompt:'Fixture user',tools:[]},{},{streamFn:c.stream});assert.equal(requests.length,8);
 const result={passed:true,model_calls:0,loopback_http_requests:requests.length,checks:['actor none/medium actual HTTP payload','constructor none/medium actual HTTP payload','no cross-profile cache reuse','same-profile cross-arm response coupling','actor and constructor repeat occurrence remains fresh','separate replicate remains fresh','Pi final-response lifecycle'],requests};const path=process.argv[2]||join(dir,'qualification.json');await writeFile(path,JSON.stringify(result,null,2)+'\n');console.log(path);
}finally{server.close();}
