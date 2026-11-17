import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { AuthorizationController, OPAQUE_REFUSAL } from '../src/index.js';

/** Pi 1.5 extension. No model calls, automatic policy regeneration or repair. */
export default function authorizationExtension(pi) {
  pi.registerFlag('auth-policy', { type: 'string', description: 'Trusted authorization-policy JSON file; unset means inactive.' });
  let controller = null;
  let configured = false;
  let state = 'inactive';
  let policyPath = null;
  const pending = new Map();
  const append = data => pi.appendEntry('authorization-control', data);
  const statusText = () => JSON.stringify({ state, ...(controller?.status ?? {}) });

  async function load(ctx) {
    controller?.abandonAll();
    pending.clear();
    controller = null;
    const flag = pi.getFlag('auth-policy');
    configured = typeof flag === 'string' && flag.length > 0;
    if (!configured) { state = 'inactive'; ctx.ui.setStatus('authorization', 'Auth: inactive'); return; }
    policyPath = resolve(ctx.cwd, flag);
    try {
      const document = JSON.parse(await readFile(policyPath, 'utf8'));
      controller = new AuthorizationController({ policy: document, onAudit: append });
      state = 'active';
      ctx.ui.setStatus('authorization', `Auth: ${controller.status.policyId}`);
      append({ version: 1, type: 'configured', policyId: controller.status.policyId, policyFingerprint: controller.status.policyFingerprint });
    } catch {
      // A supplied but invalid configuration must not silently disable enforcement.
      state = 'configuration_error';
      ctx.ui.setStatus('authorization', 'Auth: configuration error');
      ctx.ui.notify('Authorization policy could not be loaded. Tool calls are blocked until /auth reload succeeds.', 'error');
      append({ version: 1, type: 'configuration_error' });
    }
  }

  pi.on('session_start', (_event, ctx) => load(ctx));
  pi.on('session_switch', (_event, ctx) => load(ctx));
  pi.on('session_shutdown', () => { controller?.abandonAll(); pending.clear(); });
  pi.on('tool_call', event => {
    if (!configured) return;
    if (!controller) return { block: true, reason: OPAQUE_REFUSAL };
    const decision = controller.begin({ toolCallId: event.toolCallId, toolName: event.toolName, input: event.input });
    if (!decision.allowed) return { block: true, reason: decision.message };
    pending.set(event.toolCallId, { ticket: decision.ticket, input: event.input, owner: controller });
  });
  // Unlike tool_result, this also runs when another handler blocks or a call aborts.
  pi.on('tool_execution_end', async event => {
    const entry = pending.get(event.toolCallId);
    if (!entry) return; // Our denied/unknown calls have no admitted ticket.
    pending.delete(event.toolCallId);
    await entry.owner.finish(entry.ticket, { input: entry.input, result: event.result, isError: event.isError });
  });
  pi.registerCommand('auth', {
    description: 'Show authorization status; /auth reload explicitly reloads the trusted policy file.',
    handler: async (args, ctx) => {
      if (args.trim() === 'reload') {
        if (!ctx.isIdle()) { ctx.ui.notify('Wait for the current turn before reloading authorization policy.', 'warning'); return; }
        await load(ctx);
      } else if (args.trim() && args.trim() !== 'status') {
        ctx.ui.notify('Usage: /auth [status|reload]', 'warning');
        return;
      }
      ctx.ui.notify(statusText(), state === 'configuration_error' ? 'error' : 'info');
    }
  });
}
