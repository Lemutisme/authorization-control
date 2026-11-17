/** Exact-request response sharing for paired experiments; not a defense. */
import {AssistantMessageEventStream} from '@earendil-works/pi-ai';
import {streamSimple} from '@earendil-works/pi-ai/api/openai-responses';
import {readFile,writeFile,mkdir,rename} from 'node:fs/promises';
import {join} from 'node:path';
import {createHash} from 'node:crypto';

// Preserve array order, literal strings and object insertion order as serialized
// by the SDK. Do not erase history differences to manufacture a cache hit.
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');

async function frozenResponse(directory, payload) {
  let index;
  try { index = JSON.parse(await readFile(join(directory, 'frozen-index.json'), 'utf8')); }
  catch (error) { if (error.code === 'ENOENT') return null; throw error; }
  const selected = index.requests[hash(payload)];
  if (!selected) return null;
  if (!/^[0-9a-f]{64}$/.test(selected.cache_key)) throw new Error('invalid_frozen_source_key');
  const entry = JSON.parse(await readFile(join(directory, selected.cache_key + '.json'), 'utf8'));
  if (entry.request_sha256 !== selected.cache_key ||
      entry.response_sha256 !== selected.response_sha256 ||
      hash(entry.message) !== selected.response_sha256) throw new Error('frozen_source_integrity_mismatch');
  return entry;
}

export class CoupledStream {
  constructor(directory,{backend=streamSimple}={}){this.directory=directory;this.backend=backend;this.records=[];}
  stream=(model,context,options)=>{
    const out=new AssistantMessageEventStream();const record={cache_hit:false,network_requested:false};this.records.push(record);
    let cached=null,file=null;
    (async()=>{
      await mkdir(this.directory,{recursive:true});
      const inner=this.backend(model,context,{...options,onPayload:async payload=>{
        const replacement=await options.onPayload?.(payload,model);const actual=replacement===undefined?payload:replacement;
        const key=hash({api:model.api,provider:model.provider,endpoint_hash:createHash('sha256').update(model.baseUrl).digest('hex'),principal_hash:hash(options.apiKey??null),payload:actual});
        record.request_sha256=key;file=join(this.directory,key+'.json');
        try{const entry=JSON.parse(await readFile(file,'utf8'));if(entry.request_sha256!==key || hash(entry.message)!==entry.response_sha256)throw new Error('cache_identity_mismatch');cached=entry;}
        catch(error){if(error.code==='ENOENT')cached=null;else{record.cache_error=true;throw error;}}
        if (!cached) {
          cached = await frozenResponse(this.directory, actual);
          if (cached) {
            record.frozen_prefix_replay = true;
            record.source_request_sha256 = cached.request_sha256;
          }
        }
        if(cached){record.cache_hit=true;record.response_sha256=cached.response_sha256;throw new Error('COUPLED_RESPONSE_READY');}
        record.network_requested=true;return actual;
      }});
      let terminal=null;
      for await(const event of inner){
        if(cached)continue;
        if(event.type==='error' && event.error)event.error.errorMessage='provider_request_failed';
        if(event.type==='done'||event.type==='error')terminal=event;else out.push(event);
      }
      if(cached){
        const message=structuredClone(cached.message);
        out.push({type:'start',partial:message});
        out.push(message.stopReason==='error'||message.stopReason==='aborted'?{type:'error',reason:message.stopReason,error:message}:{type:'done',reason:message.stopReason,message});out.end();
      }else{
        const message=await inner.result();
        if(message.stopReason==='error'||message.stopReason==='aborted')message.errorMessage='provider_request_failed';
        const containsPrivateThinking=message.content.some(c=>c.type==='thinking' && c.thinking?.trim());
        record.response_sha256=hash(message);record.cacheable=!containsPrivateThinking;
        if(file && record.network_requested && !containsPrivateThinking){
          const saved={request_sha256:record.request_sha256,response_sha256:record.response_sha256,message};
          const temporary=file+'.tmp';await writeFile(temporary,JSON.stringify(saved)+'\n');await rename(temporary,file);
        }
        if(terminal)out.push(terminal);
        out.end(message);
      }
    })().catch(()=>{
      record.cache_error=true;const message={role:'assistant',api:model.api,provider:model.provider,model:model.id,
        content:[],stopReason:'error',errorMessage:'coupled_stream_failed',timestamp:Date.now(),
        usage:{input:0,output:0,cacheRead:0,cacheWrite:0,totalTokens:0,cost:{input:0,output:0,cacheRead:0,cacheWrite:0,total:0}}};
      out.push({type:'error',reason:'error',error:message});out.end();
    });
    return out;
  };
}
