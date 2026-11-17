import { Agent } from '@earendil-works/pi-agent-core';
import { AssistantMessageEventStream } from '@earendil-works/pi-ai';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { AuthorizationController } from '../src/index.js';
import { guardTools } from '../src/pi-agent.js';

export async function runDemo() {
  const policy = JSON.parse(await readFile(new URL('./policy.json', import.meta.url), 'utf8'));
  const ledger = [], audit = [], successful = [];
  const control = new AuthorizationController({ policy, onAudit: e => audit.push(e), onSuccessfulResult: e => successful.push(e) });
  const tool = { name: 'demo_pay', label: 'Demo payment', description: 'Append to a local in-memory demo ledger.',
    parameters: { type: 'object', required: ['recipient', 'amount'], properties: { recipient: { type: 'string' }, amount: { type: 'number' } }, additionalProperties: false },
    execute: async (_id, input) => { ledger.push(input); return { content: [{ type: 'text', text: 'Recorded in the demo ledger.' }], details: { count: ledger.length } }; }
  };
  const model = { id: 'scripted-demo', name: 'Scripted, no inference', provider: 'demo', api: 'openai-responses', baseUrl: 'https://invalid.example', reasoning: false, input: ['text'], contextWindow: 4096, maxTokens: 1024, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } };
  let turn = 0;
  const agent = new Agent({ initialState: { model, tools: guardTools([tool], control), systemPrompt: 'Local scripted integration demonstration.' }, toolExecution: 'sequential',
    streamFn: async () => {
      const content = turn++ === 0 ? [100, 105].map(amount => ({ type: 'toolCall', id: `payment-${amount}`, name: 'demo_pay', arguments: { recipient: 'demo-merchant', amount } })) : [{ type: 'text', text: 'Demo finished.' }];
      const message = { role: 'assistant', content, api: model.api, provider: model.provider, model: model.id, timestamp: Date.now(),
        stopReason: content[0].type === 'toolCall' ? 'toolUse' : 'stop', usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0, cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
      const stream = new AssistantMessageEventStream(); stream.push({ type: 'start', partial: message }); stream.push({ type: 'done', reason: message.stopReason, message }); stream.end(); return stream;
    } });
  await agent.prompt('Run the local demo.');
  return { ledger, audit, successfulObservations: successful.length, toolResults: agent.state.messages.filter(m => m.role === 'toolResult'), modelCalls: 0, note: 'Scripted Pi loop; this is an integration check, not a research result.' };
}
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) console.log(JSON.stringify(await runDemo(), null, 2));
