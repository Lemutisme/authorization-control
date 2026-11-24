/** Qualification-only official Responses HTTP/SSE fixtures; never opens a socket. */
import {appendFileSync} from 'node:fs';
let serial=0;
export const fixtureArgs=(amount=0.01)=>({recipient:'AUTHORIZED',amount,subject:amount===0.02?'Distinct later operation':'qualification',date:'2022-01-01'});
export function installFakeFetch({journal=process.env.X6_QUALIFICATION_JOURNAL,profile=()=>process.env.X6_QUALIFICATION_PROFILE||'normal'}={}){
 if(!journal)throw new Error('Fixture journal required');
 const fake=async(url,options)=>{
  if(!String(url).startsWith('https://x6-qualification.invalid/'))throw new Error('Fixture forbids non-fixture endpoints');
  const body=JSON.parse(options.body),current=profile(),constructor=(body.tools||[]).some(tool=>tool.name==='submit_authorizations');
  const role=constructor?'constructor':body.tools?.length?'actor':'policy';
  appendFileSync(journal,JSON.stringify({role,profile:current,wire_json:options.body,body})+'\n');
  if(constructor&&current==='constructor_failure')throw new Error('Injected constructor HTTP failure');
  let name,args,finalText;
  const outputs=(body.input||[]).filter(item=>item.type==='function_call_output');
  if(constructor){name='submit_authorizations';args={status:'bind',authorizations:[0.01,0.02].map(amount=>({function:'send_money',selector:{},assignments:fixtureArgs(amount)}))};}
  else if(role==='policy'){finalText='[]';}
  else if(outputs.length===0){name='get_most_recent_transactions';args={n:100};}
  else if(outputs.length<=3||current==='budget'){
   name='send_money';args=fixtureArgs(current==='wrong_actor'?9:outputs.length===3?0.02:0.01);
  }else{finalText='The last tool returned: '+String(outputs.at(-1)?.output);}
  const id='fixture_'+process.pid+'_'+(++serial),argumentsText=JSON.stringify(args);
  const item=name?{id:'fc_'+id,type:'function_call',call_id:'call_'+id,name,arguments:argumentsText}:{id:'msg_'+id,type:'message',role:'assistant',content:[{type:'output_text',text:finalText,annotations:[]}]};
  const response={id:'resp_'+id,object:'response',created_at:1,status:'completed',model:'gpt-6-luna',output:[item],usage:{input_tokens:852,output_tokens:21,total_tokens:873}};
  const events=[{type:'response.created',response:{...response,status:'in_progress',output:[]}},
   {type:'response.output_item.added',output_index:0,item:name?{...item,arguments:''}:{...item,content:[]}},
   ...(name?[{type:'response.function_call_arguments.delta',item_id:item.id,output_index:0,delta:argumentsText},{type:'response.function_call_arguments.done',item_id:item.id,output_index:0,arguments:argumentsText}]:[{type:'response.content_part.added',item_id:item.id,output_index:0,content_index:0,part:{type:'output_text',text:'',annotations:[]}},{type:'response.output_text.delta',item_id:item.id,output_index:0,content_index:0,delta:finalText},{type:'response.output_text.done',item_id:item.id,output_index:0,content_index:0,text:finalText}]),
   {type:'response.output_item.done',output_index:0,item},{type:'response.completed',response}];
  return new Response(events.map(event=>`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('')+'data: [DONE]\n\n',{status:200,headers:{'content-type':'text/event-stream'}});
 };
 globalThis.fetch=fake;return fake;
}
if(process.env.X6_QUALIFICATION_JOURNAL)installFakeFetch();
