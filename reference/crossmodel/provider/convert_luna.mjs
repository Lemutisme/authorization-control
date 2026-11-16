/** Offline official Pi 1.5 Responses conversion; reads stdin, calls no model. */
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {convertResponsesMessages,convertResponsesTools} from '/artifact-source/d5d53baf1f75/openai-responses-shared.js';
import {normalizeContext} from '/artifact-source/61702529fbed/transcript.js';
const chunks=[];for await(const chunk of process.stdin)chunks.push(chunk);
const input=JSON.parse(Buffer.concat(chunks).toString('utf8'));
const model={id:'gpt-6-luna',name:'gpt-6-luna',api:'openai-responses',provider:'openai',reasoning:true,input:['text'],contextWindow:1050000,maxTokens:input.max_tokens??1400};
const providers=new Set(['openai','openai-codex','azure-openai-responses']);
const payload={model:model.id,input:convertResponsesMessages(model,normalizeContext(input.context),providers),
  tools:convertResponsesTools(input.context.tools??[]),parallel_tool_calls:false,
  max_output_tokens:input.max_tokens??1400,reasoning:{effort:'none'},store:false,stream:false};
if(input.temperature!==null&&input.temperature!==undefined)payload.temperature=input.temperature;
const source='/artifact-source/d5d53baf1f75/openai-responses-shared.js';
process.stdout.write(JSON.stringify({payload,conversion:{conversion:'official-pi-1.5-responses',converter_sha256:createHash('sha256').update(await readFile(source)).digest('hex'),streaming:false,automatic_retries:0}}));
