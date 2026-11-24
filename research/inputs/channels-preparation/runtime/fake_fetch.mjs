/** Model-free Responses/SSE qualification. Never opens a socket. */
import {readFileSync,appendFileSync} from 'node:fs';
let serial=0;
export function installFakeFetch(){
 const packet=JSON.parse(readFileSync(process.env.CHANNELS_QUALIFICATION_PACKET,'utf8'));
 const journal=process.env.CHANNELS_QUALIFICATION_JOURNAL;
 if(!journal)throw new Error('Qualification journal required');
 const oldOutputs=JSON.parse(packet.actor_context_json).messages.filter(m=>m.role==='toolResult').length;
 const fake=async(url,options)=>{
  if(!String(url).startsWith('https://channels-qualification.invalid/'))throw new Error('Qualification forbids nonfixture URL');
  const body=JSON.parse(options.body),role=body.tools?.length?'actor':'policy';
  appendFileSync(journal,JSON.stringify({role,wire_json:options.body})+'\n');
  const fault=process.env.CHANNELS_QUALIFICATION_FAILURE;
  if(fault===role+'_transport')throw new TypeError('qualification_transport_failure');
  let tool,args,text;
  if(role==='policy'){
   const user=(body.input||[]).filter(m=>m.role==='user').map(m=>typeof m.content==='string'?m.content:m.content.map(c=>c.text||'').join('')).join('\n');
   if(user.includes('\nCURRENT_RESTRICTIONS: ')){
    const params=JSON.parse(user.split('\nTOOL_CALL_PARAM: ')[1].split('\nTOOL_CALL_RESULT: ')[0]);
    const current=JSON.parse(user.split('\nCURRENT_RESTRICTIONS: ')[1]);
    const result=params.length?[{name:packet.original_proposal.function,args:{recipient:{const:params[0].args.recipient},amount:{const:params[0].args.amount}}}]:current;
    text='Yes\n'+JSON.stringify(result);
   }else{text='No';}
  }else{
   const outputs=(body.input||[]).filter(m=>m.type==='function_call_output');
   if(fault==='actor_budget'){tool=packet.original_proposal.function;args=structuredClone(packet.original_proposal.args);}
   else if(process.env.CHANNELS_QUALIFICATION_TERMINAL==='1'){text='Qualification complete.';}
   else if(outputs.length===oldOutputs+1){
    tool=packet.original_proposal.function;args=structuredClone(packet.original_proposal.args);
    const last=String(outputs.at(-1).output),match=last.match(/Policy constraint: (\{.*?\})\. Please try/);
    if(match){const c=JSON.parse(match[1]);args.amount=c.const??c.maximum??c.minimum??c.enum?.[0];}
   }else{text='Qualification complete.';}
  }
  const id='fixture_'+process.pid+'_'+(++serial),argText=JSON.stringify(args);
  const item=tool?{id:'fc_'+id,type:'function_call',call_id:'call_'+id,name:tool,arguments:argText}
   :{id:'msg_'+id,type:'message',role:'assistant',content:[{type:'output_text',text,annotations:[]}]};
  const limited=fault===role+'_length';
  const response={id:'resp_'+id,object:'response',created_at:1,status:limited?'incomplete':'completed',
   ...(limited?{incomplete_details:{reason:'max_output_tokens'}}:{}),model:'gpt-6-luna',output:[item],usage:{input_tokens:1024,output_tokens:32,total_tokens:1056}};
  const events=[{type:'response.created',response:{...response,status:'in_progress',output:[]}},
   {type:'response.output_item.added',output_index:0,item:tool?{...item,arguments:''}:{...item,content:[]}},
   ...(tool?[{type:'response.function_call_arguments.delta',item_id:item.id,output_index:0,delta:argText},{type:'response.function_call_arguments.done',item_id:item.id,output_index:0,arguments:argText}]
     :[{type:'response.content_part.added',item_id:item.id,output_index:0,content_index:0,part:{type:'output_text',text:'',annotations:[]}},{type:'response.output_text.delta',item_id:item.id,output_index:0,content_index:0,delta:text},{type:'response.output_text.done',item_id:item.id,output_index:0,content_index:0,text}]),
   {type:'response.output_item.done',output_index:0,item},{type:limited?'response.incomplete':'response.completed',response}];
  return new Response(events.map(e=>`event: ${e.type}\ndata: ${JSON.stringify(e)}\n\n`).join('')+'data: [DONE]\n\n',{status:200,headers:{'content-type':'text/event-stream'}});
 };
 globalThis.fetch=fake;return fake;
}
if(process.env.CHANNELS_QUALIFICATION_PACKET)installFakeFetch();
