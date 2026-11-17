/** Terminal Responses fixture used to qualify a fresh fork; no sockets or models. */
import { appendFileSync } from 'node:fs';
let ordinal = 0;
globalThis.fetch = async (url, options) => {
  if (!String(url).startsWith('https://prefix-fixture.invalid/')) throw new Error('Unexpected fixture endpoint');
  appendFileSync(process.env.AC_FIXTURE_JOURNAL, JSON.stringify({ payload: JSON.parse(options.body) }) + '\n');
  const id = 'fixture_' + (++ordinal);
  const text = 'The operation was refused. I will stop here.';
  const item = { id: 'msg_' + id, type: 'message', role: 'assistant', content: [{ type: 'output_text', text, annotations: [] }] };
  const response = { id: 'resp_' + id, object: 'response', created_at: 1, status: 'completed', model: 'gpt-6-luna', output: [item], usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } };
  const events = [
    { type: 'response.created', response: { ...response, status: 'in_progress', output: [] } },
    { type: 'response.output_item.added', output_index: 0, item: { ...item, content: [] } },
    { type: 'response.content_part.added', item_id: item.id, output_index: 0, content_index: 0, part: { type: 'output_text', text: '', annotations: [] } },
    { type: 'response.output_text.delta', item_id: item.id, output_index: 0, content_index: 0, delta: text },
    { type: 'response.output_text.done', item_id: item.id, output_index: 0, content_index: 0, text },
    { type: 'response.output_item.done', output_index: 0, item },
    { type: 'response.completed', response },
  ];
  return new Response(events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('') + 'data: [DONE]\n\n', { status: 200, headers: { 'content-type': 'text/event-stream' } });
};
