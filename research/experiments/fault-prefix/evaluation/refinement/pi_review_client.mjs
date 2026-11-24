/** Single draw through the installed Pi Responses adapter, with exact legacy wire fields. */
import { makeModel, MODEL } from '../pi/agent.mjs';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Pi 1.5 exports this provider for ESM only; resolve its pinned sibling file.
const { streamSimple } = await import(pathToFileURL(
  fileURLToPath(new URL('../pi/node_modules/@earendil-works/pi-ai/dist/api/openai-responses.js', import.meta.url)),
).href);

const hash = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');

/**
 * Restore the AuthorizationTransport request body after Pi has prepared its
 * request. In particular, `input` is the original Responses history: Pi's
 * message conversion must not demote/drop the two developer owner messages.
 */
export function legacyPayload(history, tools, instructions) {
  return {
    model: MODEL,
    input: history,
    instructions,
    tools,
    parallel_tool_calls: false,
    max_output_tokens: 1536,
    reasoning: { effort: 'low' },
    store: false,
  };
}

function piOptions(connection, fetchImpl, onPayload, callbacks = {}) {
  return {
    apiKey: connection.api_key || 'unused-anonymous-endpoint-key',
    maxTokens: 1536,
    maxRetries: 0,
    timeoutMs: 90000,
    cacheRetention: 'none',
    fetch: fetchImpl,
    onPayload,
    ...callbacks,
  };
}

function modelFor(connection) {
  return {
    ...makeModel({
      base_url: String(connection.base_url).replace(/\/+$/, '').replace(/\/responses$/, ''),
      api_key: connection.api_key,
    }),
    maxTokens: 1536,
  };
}

function failedCall(message, meta) {
  const error = new Error(message);
  error.meta = meta;
  return error;
}

/**
 * Perform one model request. `fetchImpl` is injectable for model-free wire
 * qualification; production callers use the native fetch implementation.
 */
export async function draw({ history, tools, instructions, connection }, {
  streamFn = streamSimple,
  fetchImpl = globalThis.fetch,
} = {}) {
  const meta = {
    requested_model: MODEL,
    reasoning_effort: 'low',
    max_output_tokens: 1536,
    automatic_retries: 0,
    payload_prepared: false,
    actual_network_call: null,
  };
  const expected = legacyPayload(history, tools, instructions);
  const model = modelFor(connection);
  const started = performance.now();
  let providerStatus;
  let terminalError;
  try {
    const stream = await streamFn(model, {
      systemPrompt: '', messages: [{ role: 'user', content: 'authorization draw', timestamp: 0 }],
    }, piOptions(
      connection,
      fetchImpl,
      sdkPayload => {
        // The old eight semantic fields remain exact; stream:true is Pi's
        // documented transport framing required for its SSE response parser.
        const payload = { ...expected, stream: true };
        meta.callback_payload_sha256 = hash(payload);
        meta.payload_prepared = true;
        return payload;
      },
      {
        onResponse: response => {
          meta.http_status = response.status;
          meta.actual_network_call = true;
        },
        onProviderStreamEvent: event => {
          if (event?.response?.model) meta.returned_model = event.response.model;
          if (event?.response?.usage) meta.provider_usage = event.response.usage;
          if (event?.type === 'response.completed') providerStatus = event.response.status;
          if (event?.type === 'response.failed') providerStatus = event.response.status || 'failed';
          if (event?.type === 'error') terminalError = 'provider_stream_error';
        },
      },
    ));
    const message = await stream.result();
    meta.elapsed_s = (performance.now() - started) / 1000;
    meta.pi_usage = message?.usage;
    meta.stop_reason = message?.stopReason;
    meta.response_status = providerStatus;

    const functionCalls = (message?.content || []).filter(part => part?.type === 'toolCall');
    const validArguments = value => value !== null && typeof value === 'object' && !Array.isArray(value);
    if (providerStatus !== 'completed' || message?.stopReason !== 'toolUse' ||
        functionCalls.length !== 1 || typeof functionCalls[0].name !== 'string' ||
        !validArguments(functionCalls[0].arguments)) {
      throw failedCall('Authorization response was incomplete or malformed', meta);
    }
    return {
      status: 'completed',
      output: [{
        type: 'function_call',
        name: functionCalls[0].name,
        arguments: JSON.stringify(functionCalls[0].arguments),
      }],
      meta,
    };
  } catch (error) {
    meta.elapsed_s ??= (performance.now() - started) / 1000;
    meta.response_status ??= providerStatus;
    if (error?.meta === meta) throw error;
    const safe = error?.name === 'AbortError' ? 'TimeoutError' :
      (terminalError || error?.name || 'InferenceError');
    meta.error = safe;
    throw failedCall('Authorization inference failed (' + safe + ')', meta);
  }
}

// The Python adapter starts this file once per draw and exchanges one JSON line.
if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
  for await (const line of lines) {
    let request;
    try {
      request = JSON.parse(line);
      const result = await draw(request);
      process.stdout.write(JSON.stringify({ ok: true, response: result, meta: result.meta }) + '\n');
    } catch (error) {
      process.stdout.write(JSON.stringify({
        ok: false,
        error: 'Authorization inference failed',
        meta: error?.meta || {},
      }) + '\n');
    }
  }
}
