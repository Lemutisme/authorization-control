import { resolve as researchPath } from "../../../../pipeline/paths.mjs";
/** Resume one retained Pi proposal; historical draws stay charged but are not sampled again. */
import {AssistantMessageEventStream} from '@earendil-works/pi-ai';
import {CapturedActor} from researchPath("experiments/sealed/evaluation/sealed_control/capture.mjs");
import {DrawBudget,clone,textHash} from researchPath("experiments/sealed/evaluation/sealed_control/pi_draw.mjs");
import {isDeepStrictEqual} from 'node:util';

export class NaturalActor extends CapturedActor {
 constructor(directory,connection,resume,options={}){
  const budget=new DrawBudget();
  if(!Number.isInteger(resume.historical_actor_calls)||resume.historical_actor_calls<1||resume.historical_actor_calls>16)throw new Error('Invalid historical actor budget');
  budget.used=resume.historical_actor_calls;
  budget.claims=Array.from({length:budget.used},(_,draw_index)=>({draw_index,stage:'historical_actor',historical_replayed:true}));
  super(directory,connection,{...options,budget});
  const ordinaryStream=this.stream;
  this.resume=resume;this.sourceReplayed=false;
  if(textHash(resume.actor_context_json)!==resume.actor_context_utf8_sha256)throw new Error('Source context byte hash mismatch');
  if(textHash(resume.actor_request_json)!==resume.actor_request_sha256)throw new Error('Source request byte hash mismatch');
  const context=JSON.parse(resume.actor_context_json);
  if(!Array.isArray(context.messages)||Object.keys(context).some(key=>key!=='messages'))throw new Error('Expected exact normalized source transcript');
  const message=clone(resume.source_proposal_message),calls=message.content.filter(item=>item.type==='toolCall');
  if(calls.length!==1||calls[0].id!==resume.original_proposal_call_id||calls[0].name!==resume.original_proposal.function||!isDeepStrictEqual(calls[0].arguments,resume.original_proposal.args))throw new Error('Source proposal identity changed');
  const retained=new AssistantMessageEventStream();retained.push({type:'start',partial:message});retained.push({type:'done',reason:message.stopReason,message});retained.end(message);
  this.pending.push({context,context_json:resume.actor_context_json,context_sha256:resume.actor_context_utf8_sha256,stream:retained,draw_index:resume.historical_actor_calls-1,historical_replayed:true});
  this.stream=(model,current,streamOptions)=>{
   if(!this.sourceReplayed){
    if(JSON.stringify(current)!==resume.actor_context_json)throw new Error('Resumed Pi preproposal context changed');
    this.sourceReplayed=true;
    this.sourceReplay={historical_draw_index:resume.historical_actor_calls-1,context_json:resume.actor_context_json,context_sha256:resume.actor_context_utf8_sha256,request_json:resume.actor_request_json,request_sha256:resume.actor_request_sha256,source_proposal_message:clone(resume.source_proposal_message),actual_network_call:false,new_actor_budget_slots:0,replayed_original_proposal:true};
    return retained;
   }
   return ordinaryStream(model,current,streamOptions);
  };
 }
 async resample(callId){
  const result=await super.resample(callId);
  if(callId===this.resume.original_proposal_call_id){
   if(result.context_json!==this.resume.actor_context_json)throw new Error('Original redraw context changed');
   if(result.meta.request_json!==this.resume.actor_request_json)throw new Error('Original redraw provider payload changed');
   result.meta.natural_original_context_exact=true;
   result.meta.natural_original_wire_exact=true;
  }
  return result;
 }
}
