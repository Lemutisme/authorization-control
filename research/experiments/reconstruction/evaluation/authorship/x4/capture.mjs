/** Capture the live Pi context and resample without the pending response. */
import {CoupledStream} from '../../pi/coupling.mjs';
import {RepairBank,clone,hash,textHash} from './pi_draw.mjs';

export class CapturedActor{
 constructor(prefixBank,repairBank,connection,{backend}={}){
  this.main=new CoupledStream(prefixBank,backend?{backend}:{});
  this.repair=new RepairBank(repairBank,backend?{backend}:{});
  this.connection=connection;this.pending=[];this.captures=[];this.batchViolations=[];
 }
 stream=(model,context,options)=>{
  // JSON cloning retains every serialized model-context field, not host tool
  // execute functions that the SDK does not send. Wire qualification checks it.
  const captured=clone(context),stream=this.main.stream(model,context,options);
  const contextJson=JSON.stringify(captured);
  const record={context:captured,context_json:contextJson,context_sha256:textHash(contextJson),stream,draw_index:this.pending.length};
  this.pending.push(record);
  stream.result().then(message=>{const count=(message.content||[]).filter(item=>item.type==='toolCall').length;if(count>1)this.batchViolations.push({draw_index:record.draw_index,tool_calls:count});});
  return stream;
 };
 async forCall(callId){
  for(let i=this.pending.length-1;i>=0;i--){const capture=this.pending[i];const message=await capture.stream.result();
   if((message.content||[]).some(x=>x.type==='toolCall'&&x.id===callId)){
    if(message.content.filter(item=>item.type==='toolCall').length!==1)throw new Error('Multiple-call source request cannot qualify one pre-proposal repair context');
    return {...capture,message};
   }
  }throw new Error('No live captured context for call');
 }
 async resample(callId,{reasoning='none',refusal=null}={}){
  const capture=await this.forCall(callId);const context=clone(capture.context);
  if(refusal!==null){const call=capture.message.content.find(x=>x.type==='toolCall'&&x.id===callId);
   context.messages.push(clone(capture.message),{role:'toolResult',toolCallId:callId,toolName:call.name,content:[{type:'text',text:refusal}],isError:true,timestamp:0});}
  const draw=await this.repair.draw({connection:this.connection,context,stage:'actor_resample',reasoning,maxTokens:1400});
  const one=draw.calls.length===1?draw.calls[0]:null;
  const snapshot={source_draw_index:capture.draw_index,pre_proposal_context_sha256:capture.context_sha256,resample_context_sha256:hash(context),feedback_disclosed:refusal!==null,...draw.meta};
  this.captures.push(snapshot);
  return {candidate:one?{function:one.name,args:one.arguments}:null,context_json:capture.context_json,meta:{...snapshot,context_hash_kind:'utf8_json_sha256'}};
 }
}
