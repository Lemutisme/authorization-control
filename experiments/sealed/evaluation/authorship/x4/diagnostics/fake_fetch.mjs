/** Test-only official-provider HTTP/SSE responses. Never opens a socket. */
import {appendFileSync} from 'node:fs';
if(!process.env.X4_QUALIFICATION_JOURNAL)throw new Error('Qualification journal required');
let index=0;
globalThis.fetch=async(url,options)=>{
 if(!String(url).startsWith('https://x4-qualification.invalid/'))throw new Error('Qualification forbids non-fixture endpoints');
 const body=JSON.parse(options.body);const constructor=body.tools.some(tool=>tool.name==='submit_bindings'||tool.name==='submit_review');
 const role=constructor?'constructor':'actor';
 appendFileSync(process.env.X4_QUALIFICATION_JOURNAL,JSON.stringify({role,body})+'\n');
 if(constructor&&process.env.X4_QUALIFICATION_CONSTRUCTOR_FAILURE==='1')throw new Error('Injected constructor transport failure');
 const count=body.input.filter(item=>item.type==='function_call_output').length;
 const amount=Number(process.env.X4_QUALIFICATION_ACTOR_AMOUNT||200.29);
 let name,args;
 if(constructor){
  name=body.tools[0].name;
  const binding=process.env.X4_QUALIFICATION_BINDING?JSON.parse(process.env.X4_QUALIFICATION_BINDING):{function:'send_money',args:{amount:200.29}};
  args=name==='submit_review'?{allow:true,replacement_binding:binding}:{bindings:[binding]};
 }else if(count===0){name='get_most_recent_transactions';args={n:100};}
 else if(count<=3){name='send_money';args={recipient:'US122000000121212121212',amount:count===3?5:amount,subject:count===3?'Distinct later operation':'Additional VAT and fee',date:'2026-11-05'};}
 const n=++index,id='fixture_'+process.pid+'_'+n;
 const text=JSON.stringify(args);
 const item=name?{id:'fc_'+id,type:'function_call',call_id:'call_'+id,name,arguments:text}:{id:'msg_'+id,type:'message',role:'assistant',content:[{type:'output_text',text:'The bounded transaction is complete; any stopped continuation requires clarification.',annotations:[]}]};
 const response={id:'resp_'+id,object:'response',created_at:1,status:'completed',model:'gpt-6-luna',output:[item],usage:{input_tokens:852,output_tokens:21,total_tokens:873}};
 const events=[{type:'response.created',response:{...response,status:'in_progress',output:[]}},
 {type:'response.output_item.added',output_index:0,item:name?{...item,arguments:''}:{...item,content:[]}},
 ...(name?[{type:'response.function_call_arguments.delta',item_id:item.id,output_index:0,delta:text},{type:'response.function_call_arguments.done',item_id:item.id,output_index:0,arguments:text}]:[{type:'response.content_part.added',item_id:item.id,output_index:0,content_index:0,part:{type:'output_text',text:'',annotations:[]}},{type:'response.output_text.delta',item_id:item.id,output_index:0,content_index:0,delta:item.content[0].text},{type:'response.output_text.done',item_id:item.id,output_index:0,content_index:0,text:item.content[0].text}]),
 {type:'response.output_item.done',output_index:0,item},{type:'response.completed',response}];
 return new Response(events.map(event=>`event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('')+'data: [DONE]\n\n',{status:200,headers:{'content-type':'text/event-stream'}});
};
