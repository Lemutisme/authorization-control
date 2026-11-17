/** Registry-control experiment: unchanged Pi loop and actor-visible success path. */
import {runBench} from '../multibench/loop.mjs';
import {MODEL} from '../pi/agent.mjs';
import {CoupledStream} from '../pi/coupling.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdir,writeFile,rename} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));
class BrokerClient {
  constructor(python){this.child=spawn(python,['-B',join(HERE,'broker.py')],{stdio:['pipe','pipe','pipe']});this.pending=new Map();this.next=0;this.closed=false;this.child.stderr.on('data',()=>{});
    this.lines=createInterface({input:this.child.stdout});this.lines.on('line',line=>{let x;try{x=JSON.parse(line);}catch{this.close();return;}const p=this.pending.get(x.id);if(!p){this.close();return;}this.pending.delete(x.id);clearTimeout(p.timer);if(x.ok)p.resolve(x.result);else p.reject(new Error('broker_'+x.error));});this.child.on('error',()=>this.close());this.child.on('exit',()=>{this.closed=true;this.fail();});}
  fail(){for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error('broker_closed'));}this.pending.clear();}
  call(method,params){if(this.closed)return Promise.reject(new Error('broker_closed'));const id=++this.next;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>this.close(),120000);this.pending.set(id,{resolve,reject,timer});this.child.stdin.write(JSON.stringify({id,method,params})+'\n',e=>{if(e)this.close();});});}
  close(){if(this.closed)return;this.closed=true;this.fail();this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}
export async function episode(o){
  const b=new BrokerClient(o.python);const coupling=new CoupledStream(o.cache);const start=performance.now();
  try{
    const init=await b.call('init',{control_manifest:resolve(o.manifest),case_id:o.caseId,arm:o.arm,judge_cache:resolve(o.judgeCache),provider_scope_sha256:o.providerScope});
    const one=init.benchmark==='injecagent';
    if(init.initial_observation){
      const s=init.initial_observation,id='call_benchmark_seed';
      // Preserve the native finetuned harness's historical argument value,
      // including its string-valued serialization. It is not executed again.
      init.prompt=[{role:'user',content:init.prompt,timestamp:0},
        {role:'assistant',content:[{type:'toolCall',id,name:s.tool,arguments:s.arguments}],api:'openai-responses',provider:'openai',model:MODEL,stopReason:'toolUse',timestamp:0,usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}},
        {role:'toolResult',toolCallId:id,toolName:s.tool,content:[{type:'text',text:s.text}],isError:false,timestamp:0}];init.seededAssistantCount=1;
    }
    const pi=await runBench(init,b,{maxRounds:one?1:16,maxOutputTokens:1400,streamFn:coupling.stream,protocolOneStep:one});
    if(coupling.records.length!==pi.calls.length)throw new Error('call_accounting');
    for(let i=0;i<pi.calls.length;i++){const c=coupling.records[i];pi.calls[i].coupling=c;pi.calls[i].actual_network_call=c.network_requested;if(c.cache_hit){pi.calls[i].cached_sample_usage=pi.calls[i].usage;delete pi.calls[i].usage;delete pi.calls[i].provider_usage;pi.calls[i].missing_usage=false;}}
    const result=await b.call('finish',{final_text:pi.finalText,first_text:pi.firstText,first_tool_calls:pi.firstToolCalls,assistant_texts:pi.assistantTexts,visible_tool_texts:pi.visibleToolTexts});
    const row={...result.result,status:pi.status,pi:{...pi,events:undefined,finalText:undefined,firstText:undefined,firstToolCalls:undefined,assistantTexts:undefined,visibleToolTexts:undefined},initial_state_sha256:init.initial_state_sha256,elapsed_s:(performance.now()-start)/1000};
    await mkdir(dirname(o.out),{recursive:true});await writeFile(o.out+'.json.gz',gzipSync(JSON.stringify({result:row,...result.raw,pi_tool_events:pi.events,first_text:pi.firstText,first_tool_calls:pi.firstToolCalls,assistant_texts:pi.assistantTexts,visible_tool_texts:pi.visibleToolTexts})));
    await writeFile(o.out+'.json.tmp',JSON.stringify(row)+'\n');await rename(o.out+'.json.tmp',o.out+'.json');return row;
  }finally{b.close();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
  try{const r=await episode({manifest:a['--manifest'],caseId:a['--case'],arm:a['--arm'],python:a['--python'],out:resolve(a['--out']),cache:a['--cache'],judgeCache:a['--judge-cache'],providerScope:a['--provider-scope']});console.log(JSON.stringify({case_id:r.case_id,status:r.status,scores:r.scores}));}
  catch{console.error('Benchmark episode failed; private details omitted.');process.exitCode=1;}
}
