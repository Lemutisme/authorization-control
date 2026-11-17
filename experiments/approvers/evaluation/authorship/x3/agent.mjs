import {runPi,MODEL} from '../../pi/agent.mjs';
import {CoupledStream} from '../../pi/coupling.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdir,writeFile} from 'node:fs/promises';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));
class Broker{
 constructor(python){this.child=spawn(python,['-B',join(HERE,'broker.py')],{stdio:['pipe','pipe','pipe']});this.pending=new Map();this.next=0;this.closed=false;this.child.stderr.on('data',()=>{});this.lines=createInterface({input:this.child.stdout});this.lines.on('line',line=>{const x=JSON.parse(line),p=this.pending.get(x.id);if(!p)return this.close();this.pending.delete(x.id);clearTimeout(p.timer);x.ok?p.resolve(x.result):p.reject(new Error(x.error));});this.child.on('exit',()=>this.close());this.child.on('error',()=>this.close());}
 call(method,params){if(this.closed)return Promise.reject(new Error('broker_closed'));const id=++this.next;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>this.close(),180000);this.pending.set(id,{resolve,reject,timer});this.child.stdin.write(JSON.stringify({id,method,params})+'\n');});}
 close(){if(this.closed)return;this.closed=true;for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error('broker_closed'));}this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}
const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];const b=new Broker(a['--python']);
try{
 const c=new CoupledStream(a['--actor-cache']);const init=await b.call('init',{manifest:resolve(a['--manifest']),case_id:a['--case'],x3_arm:a['--arm'],model:MODEL,delegate_reference:true,clock_anchor:'2026-11-05T00:00:00',judge_cache:resolve(a['--judge-cache']),policy_journal:resolve(a['--out'])+'.policy-journal.jsonl',policy_cache:resolve(a['--policy-cache'])});
 const pi=await runPi(init,b,{maxRounds:16,maxOutputTokens:1400,streamFn:c.stream});if(c.records.length!==pi.calls.length)throw new Error('Actor accounting mismatch');
 for(let i=0;i<pi.calls.length;i++){const x=c.records[i];pi.calls[i].coupling=x;pi.calls[i].actual_network_call=x.network_requested;if(x.cache_hit){pi.calls[i].cached_sample_usage=pi.calls[i].usage;delete pi.calls[i].usage;delete pi.calls[i].provider_usage;pi.calls[i].missing_usage=false;}}
 const r=await b.call('finish',{final_text:pi.finalText});const row={...r.result,status:pi.status,pi:{...pi,finalText:undefined,events:undefined},initial_state_sha256:init.initial_state_sha256};const out=resolve(a['--out']);await mkdir(dirname(out),{recursive:true});await writeFile(out+'.json.gz',gzipSync(JSON.stringify({result:row,...r.raw,pi_tool_events:pi.events})));await writeFile(out+'.json',JSON.stringify(row)+'\n');console.log(JSON.stringify({arm:row.refinement_arm,status:row.status,utility:row.native_utility,policy_calls:row.policy_calls.length}));
}catch(e){console.error('X3 episode failed: '+e.message);process.exitCode=1;}finally{b.close();}
