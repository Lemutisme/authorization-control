/** Model-free Pi wire qualification using a fake fetch and a minimal SSE reply. */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { draw, legacyPayload } from './pi_review_client.mjs';
import { MODEL } from '../pi/agent.mjs';

let fakeFetchCalls = 0;
let capturedHttpBody;
const history = [
  { role: 'developer', content: 'AUTHENTIC OWNER TASK:\nOnly use the requested task scope.' },
  { role: 'developer', content: 'TYPED ADAPTER FACTS:\n{"parameters_schema_validated":true}' },
  { role: 'user', content: '{"candidate":{"tool":{"name":"send_message"}}}' },
];
const schema = {
  type: 'object',
  properties: {
    reviewed_binding: { type: 'string' },
    basis: { type: 'string' },
    decision: { type: 'string', enum: ['allow', 'deny', 'needs_facts'] },
  },
  required: ['reviewed_binding', 'basis', 'decision'],
  additionalProperties: false,
};
const tools = [{
  type: 'function',
  name: 'authorize_effect',
  description: 'Review the exact candidate effect under the original owner task.',
  parameters: schema,
  strict: true,
}];
const instructions = 'Return reviewed_binding, basis, and decision for one proposed effect.';
const connection = { base_url: 'https://example.invalid/v1/responses', api_key: 'wire-check-sentinel' };
const args = JSON.stringify({
  reviewed_binding: JSON.stringify({ tool: 'send_message', parameters: {} }),
  basis: 'Model-free parser fixture.',
  decision: 'allow',
});
const item = {
  id: 'fc_wire_1',
  type: 'function_call',
  call_id: 'call_wire_1',
  name: 'authorize_effect',
  arguments: args,
};
const usage = { input_tokens: 13, output_tokens: 9, total_tokens: 22 };
const response = {
  id: 'resp_wire_1',
  object: 'response',
  created_at: 1,
  status: 'completed',
  model: MODEL,
  output: [item],
  usage,
};
const events = [
  { type: 'response.created', response: { ...response, status: 'in_progress', output: [] } },
  { type: 'response.output_item.added', output_index: 0, item: { ...item, arguments: '' } },
  { type: 'response.function_call_arguments.delta', item_id: item.id, output_index: 0, delta: args },
  { type: 'response.function_call_arguments.done', item_id: item.id, output_index: 0, arguments: args },
  { type: 'response.output_item.done', output_index: 0, item },
  { type: 'response.completed', response },
];
const sse = events.map(event => `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`).join('') + 'data: [DONE]\n\n';

const result = await draw({ history, tools, instructions, connection }, {
  fetchImpl: async (_input, init = {}) => {
    fakeFetchCalls += 1;
    capturedHttpBody = JSON.parse(init.body);
    return new Response(sse, {
      status: 200,
      headers: { 'content-type': 'text/event-stream', 'x-request-id': 'wire-fixture' },
    });
  },
});

const expectedBody = { ...legacyPayload(history, tools, instructions), stream: true };
assert.deepEqual(capturedHttpBody, expectedBody,
  'captured HTTP body must equal all legacy fields plus Pi SSE framing');
assert.deepEqual(Object.keys(capturedHttpBody).sort(), [
  'input', 'instructions', 'max_output_tokens', 'model', 'parallel_tool_calls',
  'reasoning', 'store', 'stream', 'tools',
].sort());
assert.deepEqual(capturedHttpBody.input.map(message => message.role), ['developer', 'developer', 'user']);
assert.equal(capturedHttpBody.tools[0].strict, true);
assert.equal(capturedHttpBody.model, 'gpt-6-luna');
assert.equal(capturedHttpBody.reasoning.effort, 'low');
assert.equal(capturedHttpBody.max_output_tokens, 1536);
assert.equal(capturedHttpBody.parallel_tool_calls, false);
assert.equal(capturedHttpBody.store, false);
assert.equal(capturedHttpBody.stream, true);
assert.equal(result.status, 'completed', 'Pi must parse the completed SSE function call');
assert.deepEqual(result.output, [{ type: 'function_call', name: 'authorize_effect', arguments: args }]);
assert.equal(fakeFetchCalls, 1);

const sha256 = createHash('sha256').update(JSON.stringify(capturedHttpBody)).digest('hex');
process.stdout.write(JSON.stringify({
  passed: true,
  model: MODEL,
  captured_http_body_sha256: sha256,
  fields: Object.keys(capturedHttpBody).sort(),
  developer_messages_preserved: 2,
  tools_strict: true,
  reasoning_effort: capturedHttpBody.reasoning.effort,
  max_output_tokens: capturedHttpBody.max_output_tokens,
  parallel_tool_calls: capturedHttpBody.parallel_tool_calls,
  store: capturedHttpBody.store,
  stream: capturedHttpBody.stream,
  parsed_function_call: result.output[0].name,
  provider_usage: result.meta.provider_usage,
  pi_usage: result.meta.pi_usage,
  model_requests: 0,
  network_requests: 0,
  fake_fetch_calls: fakeFetchCalls,
}) + '\n');
