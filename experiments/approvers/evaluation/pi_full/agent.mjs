/** Reuse the measured Pi loop, with a multi-suite broker and atomic artifacts. */
import {runPi,MODEL} from '../pi/agent.mjs';
import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import {writeFile,mkdir,rename} from 'node:fs/promises';
import {dirname,join,resolve} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {gzipSync} from 'node:zlib';
const HERE=dirname(fileURLToPath(import.meta.url));
export class FullBrokerClient {
  constructor(python=process.env.PGA_PYTHON || 'python3') {
    this.child=spawn(python,['-B',join(HERE,'broker.py')],{stdio:['pipe','pipe','pipe']});
    this.pending=new Map();this.next=0;this.closed=false;this.child.stderr.on('data',()=>{});
    this.lines=createInterface({input:this.child.stdout});
    this.lines.on('line',line=>{
      let row;try{row=JSON.parse(line);}catch{this.close();return;}
      const wait=this.pending.get(row.id);if(!wait){this.close();return;}
      this.pending.delete(row.id);clearTimeout(wait.timer);
      if(row.ok)wait.resolve(row.result);else wait.reject(new Error('broker_'+row.error));
    });
    this.child.on('error',()=>this.close());this.child.on('exit',()=>{this.closed=true;this.fail();});
  }
  fail(){for(const p of this.pending.values()){clearTimeout(p.timer);p.reject(new Error('broker_closed'));}this.pending.clear();}
  call(method,params){
    if(this.closed)return Promise.reject(new Error('broker_closed'));
    const id=++this.next;return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>this.close(),120000);this.pending.set(id,{resolve,reject,timer});
      this.child.stdin.write(JSON.stringify({id,method,params})+'\n',e=>{if(e)this.close();});
    });
  }
  close(){if(this.closed)return;this.closed=true;this.fail();this.lines.close();this.child.stdin.end();this.child.kill('SIGTERM');}
}
export async function episode(o) {
  const b=new FullBrokerClient(o.python),start=performance.now();
  try {
    const init=await b.call('init',{manifest:resolve(o.manifest),case_id:o.caseId,arm:o.arm,model:MODEL,delegate_reference:o.delegateReference===true});
    const pi=await runPi(init,b,{maxRounds:16,maxOutputTokens:1400});
    const full=await b.call('finish',{final_text:pi.finalText});
    const row={...full.result,status:pi.status,pi:{...pi,finalText:undefined,events:undefined},elapsed_s:(performance.now()-start)/1000,new_closed_loop_episode:true};
    const raw={result:row,...full.raw,pi_tool_events:pi.events};await mkdir(dirname(o.out),{recursive:true});
    await writeFile(o.out+'.json.gz',gzipSync(JSON.stringify(raw)));
    await writeFile(o.out+'.json.tmp',JSON.stringify(row)+'\n');await rename(o.out+'.json.tmp',o.out+'.json');return row;
  }finally{b.close();}
}
if(process.argv[1] && import.meta.url===pathToFileURL(resolve(process.argv[1])).href) {
  const a={};for(let i=2;i<process.argv.length;i+=2)a[process.argv[i]]=process.argv[i+1];
  try {const r=await episode({manifest:a['--manifest'],caseId:a['--case'],arm:a['--arm'],python:a['--python'],out:resolve(a['--out']),delegateReference:a['--delegate-reference']==='true'});
    console.log(JSON.stringify({case_id:r.case_id,status:r.status,native_utility:r.native_utility,native_targeted_asr:r.native_targeted_asr}));
  }catch{console.error('Full benchmark episode failed; provider/credential details omitted.');process.exitCode=1;}
}
