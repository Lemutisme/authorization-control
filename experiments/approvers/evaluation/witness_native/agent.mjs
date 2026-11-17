/** One fresh Pi/gpt-6-luna episode over the pinned native ToolSandbox scenario. */
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const MODEL = 'gpt-6-luna';
const NATIVE_DIR = dirname(fileURLToPath(import.meta.url));
const EVALUATION_DIR = dirname(NATIVE_DIR);
const REPOSITORY_ROOT = dirname(EVALUATION_DIR);
const SP27_ROOT = process.env.SP27_ROOT || REPOSITORY_ROOT;
const TOOL_SANDBOX_SOURCE = process.env.TOOL_SANDBOX_SOURCE;
if (!TOOL_SANDBOX_SOURCE) {
  throw new Error('TOOL_SANDBOX_SOURCE must point to the pinned ToolSandbox checkout');
}
const PI_AGENT_MODULE = process.env.PI_AGENT_MODULE || join(EVALUATION_DIR, 'pi', 'agent.mjs');
const PI_ENTRY = pathToFileURL(resolve(PI_AGENT_MODULE)).href;
const PI_PACKAGE_JSON = join(dirname(resolve(PI_AGENT_MODULE)), 'package.json');
const piPackage = JSON.parse(await readFile(PI_PACKAGE_JSON, 'utf8'));
if (piPackage.dependencies?.['@earendil-works/pi-agent-core'] !== '1.5.0' ||
    piPackage.dependencies?.['@earendil-works/pi-ai'] !== '1.5.0') {
  throw new Error('Expected the registered Pi 1.5.0 dependencies');
}
const { runPi } = await import(PI_ENTRY);
// Pi 1.5 exports this provider for ESM only; require.resolve would select the
// absent CJS export. Resolve its pinned dependency installation explicitly.
const { streamSimple } = await import(pathToFileURL(join(dirname(PI_PACKAGE_JSON), 'node_modules/@earendil-works/pi-ai/dist/api/openai-responses.js')).href);
const hash = (value) => createHash('sha256').update(value).digest('hex');
const piSource = {
  agent_module: resolve(PI_AGENT_MODULE),
  agent_module_sha256: hash(await readFile(resolve(PI_AGENT_MODULE))),
  package_json_sha256: hash(await readFile(PI_PACKAGE_JSON)),
  pi_agent_core: piPackage.dependencies['@earendil-works/pi-agent-core'],
  pi_ai: piPackage.dependencies['@earendil-works/pi-ai'],
};

class BrokerClient {
  constructor(python) {
    this.child = spawn(python, ['-B', join(NATIVE_DIR, 'broker.py')], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        PYTHONDONTWRITEBYTECODE: '1',
        SP27_ROOT,
        TOOL_SANDBOX_SOURCE: resolve(TOOL_SANDBOX_SOURCE),
      },
    });
    this.pending = new Map();
    this.next = 0;
    this.closed = false;
    this.stderrBytes = 0;
    this.child.stderr.on('data', (buffer) => { this.stderrBytes += buffer.length; });
    this.lines = createInterface({ input: this.child.stdout });
    this.lines.on('line', (line) => {
      let row;
      try { row = JSON.parse(line); } catch { this.fail('invalid_broker_protocol'); return; }
      const waiting = this.pending.get(row.id);
      if (!waiting) { this.fail('unexpected_broker_reply'); return; }
      this.pending.delete(row.id);
      clearTimeout(waiting.timer);
      if (row.ok) waiting.resolve(row.result);
      else waiting.reject(new Error(`broker_${row.error || 'error'}`));
    });
    this.child.on('error', () => this.fail('broker_process_error'));
    this.child.on('exit', () => { this.closed = true; this.fail('broker_exited'); });
  }

  fail(reason) {
    for (const waiting of this.pending.values()) {
      clearTimeout(waiting.timer);
      waiting.reject(new Error(reason));
    }
    this.pending.clear();
  }

  call(method, params) {
    if (this.closed) return Promise.reject(new Error('broker_closed'));
    const id = ++this.next;
    return new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('broker_timeout'));
        this.close();
      }, 120000);
      this.pending.set(id, { resolve: resolvePromise, reject, timer });
      this.child.stdin.write(JSON.stringify({ id, method, params }) + '\n', (error) => {
        if (error) this.fail('broker_write_failed');
      });
    });
  }

  close() {
    if (this.closed) return;
    this.closed = true;
    this.fail('broker_closed');
    this.lines.close();
    this.child.stdin.end();
    this.child.kill('SIGTERM');
  }
}

function parseArgs(argv) {
  const result = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!flag.startsWith('--')) throw new Error('invalid_argument');
    if (flag === '--help') { result.help = true; continue; }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`missing_${flag.slice(2)}`);
    result[flag.slice(2)] = value;
    i += 1;
  }
  return result;
}

function usage() {
  return 'node evaluation/witness_native/agent.mjs --arm none|gate --out PATH [--policy JSON_PATH] [--python VENV_PYTHON] [--max-rounds 1..16]';
}

export async function episode(options) {
  const broker = new BrokerClient(options.python);
  const started = performance.now();
  try {
    const init = await broker.call('init', {
      arm: options.arm,
      policy_path: options.policy ? resolve(options.policy) : null,
      model: MODEL,
    });
    const wireSchemas = [];
    const nativeStream = (model, context, options) => streamSimple(model, context, {
      ...options,
      onPayload: async payload => {
        // Preserve native optional search filters. The Responses API's implicit
        // strict normalization can otherwise make every property mandatory.
        for (const tool of payload.tools || []) if (tool.type === 'function') tool.strict = false;
        wireSchemas.push((payload.tools || []).map(t => ({name:t.name, strict:t.strict, parameters:t.parameters})));
        return options.onPayload ? await options.onPayload(payload) : payload;
      },
    });
    const pi = await runPi(init, broker, {
      maxRounds: options.maxRounds,
      maxOutputTokens: 1400,
      episodeTimeoutMs: 240000,
      streamFn: nativeStream,
    });
    const finished = await broker.call('finish', { final_text: pi.finalText || '' });
    const row = {
      ...finished.result,
      pi: {
        status: pi.status,
        calls: pi.calls.map(call => ({
          ...call,
          actual_network_call: call.http_status != null || call.provider_usage != null ? true : null,
          request_prepared: typeof call.request_sha256 === 'string',
          network_evidence: call.http_status != null || call.provider_usage != null
            ? 'HTTP response or provider usage observed; no response cache in this adapter.'
            : 'Network completion unknown; a prepared payload alone is insufficient.',
        })),
        tool_events: pi.events,
        registered_tools: pi.registered_tools,
        runtime: pi.runtime,
        reasoning_effort: pi.reasoning_effort,
        max_rounds: pi.max_rounds,
        max_output_tokens: pi.max_output_tokens,
      },
      transport_metadata: init.transport_metadata,
      pi_source: piSource,
      adapter_sha256: {
        broker_py: hash(await readFile(join(NATIVE_DIR, 'broker.py'))),
        agent_mjs: hash(await readFile(fileURLToPath(import.meta.url))),
      },
      wire_tool_schemas: wireSchemas,
      elapsed_s: (performance.now() - started) / 1000,
    };
    const report = {
      result: row,
      public_preparation: init.public_view,
      raw: {
        ...finished.raw,
        final_text: pi.finalText || '',
        pi_events: pi.events,
      },
    };
    await mkdir(dirname(options.out), { recursive: true });
    await writeFile(options.out, JSON.stringify(report, null, 2) + '\n');
    return row;
  } finally {
    broker.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let args;
  try { args = parseArgs(process.argv.slice(2)); }
  catch { process.stderr.write(usage() + '\n'); process.exitCode = 2; }
  if (args?.help) process.stdout.write(usage() + '\n');
  else if (args) {
    if (!['none', 'gate'].includes(args.arm) || !args.out) {
      process.stderr.write(usage() + '\n');
      process.exitCode = 2;
    } else if (args.arm === 'none' && args.policy) {
      process.stderr.write('Baseline arm cannot receive --policy.\n');
      process.exitCode = 2;
    } else {
      const python = args.python || process.env.WITNESS_PYTHON || 'python3';
      try {
        const row = await episode({
          arm: args.arm,
          policy: args.policy,
          out: resolve(args.out),
          python,
          maxRounds: Number(args['max-rounds'] || 16),
        });
        const summary = {
          scenario: row.scenario,
          arm: row.arm,
          policy_status: row.policy.status,
          pi_status: row.pi.status,
          native_scorer: row.native_utility.status,
          native_similarity: row.native_utility.similarity ?? null,
          owner_effect_complete: row.owner_effect_oracle.owner_effect_complete,
          output: resolve(args.out),
        };
        process.stdout.write(JSON.stringify(summary) + '\n');
      } catch (error) {
        process.stderr.write(`Native Pi lifecycle failed (${error?.message || 'unknown error'}).\n`);
        process.exitCode = 1;
      }
    }
  }
}
