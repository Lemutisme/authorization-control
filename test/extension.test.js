import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { discoverAndLoadExtensions, ExtensionRunner, SessionManager } from '@earendil-works/pi-coding-agent';

const policy = JSON.parse(await readFile(new URL('../examples/policy.json', import.meta.url), 'utf8'));
const extension = fileURLToPath(new URL('../extensions/authorization.js', import.meta.url));
async function harness(t, { configured = true, broken = false } = {}) {
  const cwd = await mkdtemp(join(tmpdir(), 'authorization-extension-'));
  t.after(() => rm(cwd, { recursive: true, force: true }));
  const path = join(cwd, 'policy.json');
  await writeFile(path, broken ? 'invalid json' : JSON.stringify(policy));
  const loaded = await discoverAndLoadExtensions([extension], cwd, join(cwd, 'pi-agent'));
  assert.deepEqual(loaded.errors, []);
  assert.equal(loaded.extensions.length, 1);
  const entries = [], notices = [];
  loaded.runtime.appendEntry = (type, data) => entries.push({ type, data });
  const runner = new ExtensionRunner(loaded.extensions, loaded.runtime, cwd, SessionManager.inMemory(cwd), {});
  const errors = [];
  runner.onError(error => errors.push(error));
  runner.setUIContext({ ...runner.getUIContext(), setStatus() {}, notify: (text, level) => notices.push({ text, level }) });
  if (configured) runner.setFlagValue('auth-policy', 'policy.json');
  await runner.emit({ type: 'session_start' });
  assert.deepEqual(errors, []);
  return { runner, entries, notices, path, errors };
}
const event = (id, amount = 105) => ({ type: 'tool_call', toolCallId: id, toolName: 'demo_pay', input: { recipient: 'demo-merchant', amount } });

test('real Pi loader/runner blocks with opaque feedback and records only completed admitted results', async t => {
  const { runner, entries } = await harness(t);
  const blocked = await runner.emitToolCall(event('denied', 100));
  assert.equal(blocked.block, true); assert.ok(!blocked.reason.includes('105'));
  await runner.emit({ type: 'tool_execution_end', toolCallId: 'denied', toolName: 'demo_pay', result: { content: [] }, isError: true });
  assert.equal(await runner.emitToolCall(event('ok')), undefined);
  await runner.emit({ type: 'tool_execution_end', toolCallId: 'ok', toolName: 'demo_pay', result: { content: [] }, isError: false });
  assert.equal(entries.filter(e => e.data.type === 'outcome' && e.data.status === 'success').length, 1);
  assert.equal(entries.filter(e => e.data.updateEligible).length, 1);
  assert.ok(!JSON.stringify(entries).includes('demo-merchant'));
});

test('invalid configured policy blocks; missing configuration is explicitly inactive', async t => {
  const bad = await harness(t, { broken: true });
  assert.equal((await bad.runner.emitToolCall(event('x'))).block, true);
  assert.ok(bad.notices.some(x => x.level === 'error'));
  const inactive = await harness(t, { configured: false });
  assert.equal(await inactive.runner.emitToolCall(event('x')), undefined);
});

test('pending calls blocked elsewhere are finalized without success evidence; shutdown abandons pending calls', async t => {
  const { runner, entries } = await harness(t);
  await runner.emitToolCall(event('blocked-elsewhere'));
  await runner.emit({ type: 'tool_execution_end', toolCallId: 'blocked-elsewhere', toolName: 'demo_pay', result: { content: [] }, isError: true });
  await runner.emitToolCall(event('pending'));
  await runner.emit({ type: 'session_shutdown' });
  assert.equal(entries.filter(e => e.data.updateEligible).length, 0);
  assert.ok(entries.some(e => e.data.status === 'tool_error'));
  assert.ok(entries.some(e => e.data.status === 'aborted'));
});

test('file edits do not automatically change a loaded policy', async t => {
  const { runner, path } = await harness(t);
  const changed = structuredClone(policy); changed.rules[0].arguments.properties.amount.const = 100;
  await writeFile(path, JSON.stringify(changed));
  assert.equal((await runner.emitToolCall(event('still-denied', 100))).block, true);
  await runner.emit({ type: 'session_switch', reason: 'resume' });
  assert.equal(await runner.emitToolCall(event('new-policy', 100)), undefined);
  await runner.emit({ type: 'session_shutdown' });
});

test('explicit reload waits for idle and audit distinguishes changed policy contents under the same ID', async t => {
  const { runner, entries, path, notices } = await harness(t);
  const before = entries.find(x => x.data.type === 'configured').data.policyFingerprint;
  const changed = structuredClone(policy); changed.rules[0].arguments.properties.amount.const = 100;
  await writeFile(path, JSON.stringify(changed));
  const command = runner.getCommand('auth');
  const context = { cwd: runner.createContext().cwd, ui: runner.getUIContext() };
  await command.handler('reload', { ...context, isIdle: () => false });
  assert.ok(notices.some(n => n.level === 'warning'));
  assert.equal((await runner.emitToolCall(event('busy', 100))).block, true);
  await command.handler('reload', { ...context, isIdle: () => true });
  const after = entries.filter(x => x.data.type === 'configured').at(-1).data.policyFingerprint;
  assert.notEqual(before, after);
  assert.equal(await runner.emitToolCall(event('reloaded', 100)), undefined);
  await runner.emit({ type: 'session_shutdown' });
});
