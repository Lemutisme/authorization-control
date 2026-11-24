/** X2b untrusted actor gets only ordinary tools/observations and public side-task text. */
import {runPi,MODEL} from '../../pi/agent.mjs';
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {mkdir,writeFile} from 'node:fs/promises';
import {dirname,resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));
class Broker {
 constructor(python){this.child=spawn(python,['-B',join(HERE,'broker.py')],{stdio:['pipe','pipe','pipe']});this.pending=new Map();this.next=0;this.closed=false;this.child.stderr.on('data',()=>{});this.lines=createInterface({input:this.child.stdout});this.lines.on('line',line=>{let x;try{x=JSON.parse(line);}catch{return this.close();}const p=this.pending.get(x.id);if(!p)return this.close();this.pending.delete(x.id);clearTimeout(p.timer);x.ok?p.resolve(x.result):p.reject(new Error(x.error));});this.child.on('exit',()=>this.close());this.child.on('error',()=>this.close());}
 call(method,params){if(this.closed)return Promise.reject(new Error('broker_closed'));const id=++this.next;return new Promise((resolve,reject)=>{const timer=setTimeout(()=>this.close(),600000);this.pending.set(id,{resolve,reject,timer});this.child.stdin.write(JSON.stringify({id,method,params})+'\n');});}
 close(){if(this.closed)return;this.closed=true;for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error('broker_closed'));}this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}
const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
const reasoning=a['--reasoning']||'none';if(!['none','low','medium'].includes(reasoning))throw new Error('Unregistered reasoning');
const b=new Broker(a['--python']);
try {
 const init=await b.call('init',{manifest:resolve(a['--manifest']),case_id:a['--case'],x2b_arm:a['--arm'],x2b_role:a['--role'],strategy:a['--strategy'],model:MODEL,delegate_reference:true,clock_anchor:'2026-11-05T00:00:00',judge_cache:resolve(a['--judge-cache']),policy_journal:resolve(a['--out'])+'.policy-journal.jsonl',policy_cache:resolve(a['--policy-cache'])});
 const wire=[],batchViolations=[];
 const stream=(model,context,options)=>{
  const r={reasoning_effort:reasoning};wire.push(r);
  const s=streamSimple(model,context,{...options,onPayload:payload=>{const q=options.onPayload?.(payload)||payload;q.reasoning={effort:reasoning};r.request_sha256=createHash('sha256').update(JSON.stringify(q)).digest('hex');return q;}});
  s.result().then(message=>{const n=message.content.filter(x=>x.type==='toolCall').length;if(n>1)batchViolations.push({draw:wire.indexOf(r),tool_calls:n});});
  return s;
 };
 const pi=await runPi(init,b,{maxRounds:16,maxOutputTokens:1400,episodeTimeoutMs:900000,streamFn:stream});
 if(wire.length!==pi.calls.length)throw new Error('Actor request accounting mismatch');
 for(let i=0;i<pi.calls.length;i++)Object.assign(pi.calls[i],wire[i]);
 pi.reasoning_effort=reasoning;
 const r=await b.call('finish',{final_text:pi.finalText});
 const row={...r.result,status:pi.status,pi:{...pi,finalText:undefined,events:undefined},initial_state_sha256:init.initial_state_sha256,batch_violations:batchViolations,reasoning_profile:reasoning};
 const out=resolve(a['--out']);await mkdir(dirname(out),{recursive:true});
 await writeFile(out+'.json.gz',gzipSync(JSON.stringify({result:row,...r.raw,actor_instructions:init.instructions,actor_prompt:init.prompt,pi_tool_events:pi.events})));
 await writeFile(out+'.json',JSON.stringify(row)+'\n');
 console.log(JSON.stringify({arm:row.x2b_arm,role:row.x2b_role,status:row.status,utility:row.native_utility,target:row.native_targeted_asr,partial_harm:row.partial_harm.any_declared_partial_harm}));
}catch(e){console.error('X2b episode failed: '+e.message);process.exitCode=1;}finally{b.close();}
