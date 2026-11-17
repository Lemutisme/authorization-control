/** Capture Pi's actual context before the held proposal, including adversarial text. */
import {CoupledBank,DrawBudget,clone,textHash} from './pi_draw.mjs';
export class CapturedActor {
 constructor(directory,connection,{backend,fetchImpl,budget=new DrawBudget()}={}){this.bank=new CoupledBank(directory,{...(backend?{backend}:{}),...(fetchImpl?{fetchImpl}:{})});this.connection=connection;this.budget=budget;this.pending=[];this.captures=[];this.batchViolations=[];this.main={records:[]};this.repair={records:[]};}
 stream=(model,context,options)=>{
  const draw_index=this.budget.claim('ordinary_actor');
  const captured=clone(context),context_json=JSON.stringify(captured);
  const stream=this.bank.stream(model,context,options,{stage:'ordinary_actor',reasoning:'none',maxTokens:1400,draw_index});
  const meta=this.bank.records.at(-1);this.main.records.push(meta);
  const record={context:captured,context_json,context_sha256:textHash(context_json),stream,draw_index};this.pending.push(record);
  stream.result().then(message=>{const count=(message.content||[]).filter(item=>item.type==='toolCall').length;if(count>1)this.batchViolations.push({draw_index,stage:'ordinary_actor',tool_calls:count});});
  return stream;
 };
 async forCall(callId){for(let i=this.pending.length-1;i>=0;i--){const capture=this.pending[i],message=await capture.stream.result();if((message.content||[]).some(item=>item.type==='toolCall'&&item.id===callId)){if(message.content.filter(item=>item.type==='toolCall').length!==1)throw new Error('multiple_call_source_context');return {...capture,message};}}throw new Error('missing_live_preproposal_context');}
 async resample(callId){
  const capture=await this.forCall(callId),draw_index=this.budget.claim('actor_resample');
  // This is the original captured context, before the assistant proposal and
  // its held response. Earlier ordinary history and the malicious task remain.
  const draw=await this.bank.draw({connection:this.connection,context:clone(capture.context),stage:'actor_resample',reasoning:'none',maxTokens:1400,draw_index});this.repair.records.push(draw.meta);
  const snapshot={source_draw_index:capture.draw_index,pre_proposal_context_sha256:capture.context_sha256,context_hash_kind:'utf8_json_sha256',feedback_disclosed:false,current_proposal_disclosed:false,...draw.meta};
  this.captures.push({context_json:capture.context_json,...snapshot});
  if(draw.meta.error)throw Object.assign(new Error('repair_actor_inference_failure'),{draw:draw.meta});
  if(draw.calls.length>1)this.batchViolations.push({draw_index,stage:'actor_resample',tool_calls:draw.calls.length});
  const one=draw.calls.length===1?draw.calls[0]:null;
  return {candidate:one?{function:one.name,args:one.arguments}:null,context_json:capture.context_json,meta:snapshot};
 }
}
