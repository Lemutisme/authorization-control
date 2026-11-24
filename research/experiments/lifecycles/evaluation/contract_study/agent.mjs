/** Frozen Pi loop for factorial mechanism intervention, with experiment-only coupling. */
import {runPi,MODEL} from '../pi/agent.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdir,writeFile,rename} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {gzipSync} from 'node:zlib';
import {CoupledStream} from '../pi/coupling.mjs';
const HERE=dirname(fileURLToPath(import.meta.url));
export class BrokerClient {
  constructor(python){this.child=spawn(python,['-B',join(HERE,'broker.py')],{stdio:['pipe','pipe','pipe']});this.pending=new Map();this.next=0;this.closed=false;this.child.stderr.on('data',()=>{});
    this.lines=createInterface({input:this.child.stdout});this.lines.on('line',line=>{
      let x;try{x=JSON.parse(line);}catch{this.close();return;}const p=this.pending.get(x.id);if(!p){this.close();return;}
      this.pending.delete(x.id);clearTimeout(p.timer);if(x.ok)p.resolve(x.result);else p.reject(new Error('broker_'+x.error));
    });this.child.on('error',()=>this.close());this.child.on('exit',()=>{this.closed=true;this.fail();});}
  fail(){for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error('broker_closed'));}this.pending.clear();}
  call(method,params){if(this.closed)return Promise.reject(new Error('broker_closed'));const id=++this.next;return new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>this.close(),120000);this.pending.set(id,{resolve,reject,timer});this.child.stdin.write(JSON.stringify({id,method,params})+'\n',e=>{if(e)this.close();});});}
  close(){if(this.closed)return;this.closed=true;this.fail();this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}
export async function episode(o){
  const b=new BrokerClient(o.python);const started=performance.now();const coupling=o.cache?new CoupledStream(o.cache):null;
  try{
    const init=await b.call('init',{manifest:resolve(o.manifest),case_id:o.caseId,arm:'none',study_arm:o.arm,model:MODEL,delegate_reference:true,clock_anchor:o.clockAnchor,scope_mode:'direct',judge_cache:resolve(o.judgeCache),provider_scope_sha256:o.providerScope});
    const pi=await runPi(init,b,{maxRounds:16,maxOutputTokens:1400,streamFn:coupling?.stream});
    if(coupling){
      if(coupling.records.length!==pi.calls.length)throw new Error('actor_call_accounting_mismatch');
      for(let i=0;i<pi.calls.length;i++){
        const c=coupling.records[i];pi.calls[i].coupling=c;pi.calls[i].actual_network_call=c.network_requested;
        if(c.cache_hit){pi.calls[i].cached_sample_usage=pi.calls[i].usage;delete pi.calls[i].usage;delete pi.calls[i].provider_usage;pi.calls[i].missing_usage=false;}
      }
    }else for(const c of pi.calls)c.actual_network_call=true;
    const result=await b.call('finish',{final_text:pi.finalText});
    const row={...result.result,status:pi.status,pi:{...pi,finalText:undefined,events:undefined},
      initial_state_sha256:init.initial_state_sha256,elapsed_s:(performance.now()-started)/1000,
      evaluation_mode:coupling?'paired_exact_request_response_coupling':'independent_actor_requests'};
    await mkdir(dirname(o.out),{recursive:true});
    await writeFile(o.out+'.json.gz',gzipSync(JSON.stringify({result:row,...result.raw,pi_tool_events:pi.events})));
    await writeFile(o.out+'.json.tmp',JSON.stringify(row)+'\n');await rename(o.out+'.json.tmp',o.out+'.json');return row;
  }finally{b.close();}
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
  const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
  try{const r=await episode({manifest:a['--manifest'],caseId:a['--case'],arm:a['--arm'],python:a['--python'],out:resolve(a['--out']),cache:a['--cache'],clockAnchor:a['--clock-anchor'],judgeCache:a['--judge-cache'],providerScope:a['--provider-scope']});
    console.log(JSON.stringify({case_id:r.case_id,status:r.status,utility:r.native_utility,asr:r.native_targeted_asr,guard_requests:r.guard_requests}));
  }catch{console.error('Generic-guard episode failed; private details omitted.');process.exitCode=1;}
}
