import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { AuthorizationController, OPAQUE_REFUSAL, compilePolicy } from '../src/index.js';
import { guardTool } from '../src/pi-agent.js';

const policy = JSON.parse(await readFile(new URL('../examples/policy.json', import.meta.url), 'utf8'));
const call = (amount = 105) => ({ toolCallId: 'call-1', toolName: 'demo_pay', input: { recipient: 'demo-merchant', amount } });

test('denial prevents the effect and does not disclose the permitted amount', async () => {
  const audit = [], observations = [], ledger = [];
  const control = new AuthorizationController({ policy, onAudit: e => audit.push(e), onSuccessfulResult: e => observations.push(e) });
  const tool = guardTool({ name: 'demo_pay', execute: async (_id, input) => { ledger.push(input); return { content: [] }; } }, control);
  const rejected = await tool.execute('no', call(100).input);
  assert.equal(rejected.isError, true);
  assert.equal(rejected.content[0].text, OPAQUE_REFUSAL);
  assert.ok(!JSON.stringify(rejected).includes('105'));
  assert.equal(ledger.length, 0); assert.equal(observations.length, 0);
  const accepted = await tool.execute('yes', call().input);
  assert.deepEqual(accepted.content, []);
  assert.equal(ledger.length, 1); assert.equal(observations.length, 1);
  assert.equal(audit.filter(e => e.type === 'admission' && e.allowed === false).length, 1);
  assert.ok(!JSON.stringify(audit).includes('demo-merchant'));
  assert.equal(control.status.pending, 0);
});

test('the native effect uses the checked copy despite caller mutation', async () => {
  let release;
  const ready = new Promise(resolve => { release = resolve; });
  const control = new AuthorizationController({ policy });
  const ledger = [];
  const tool = guardTool({ name: 'demo_pay', execute: async (_id, args) => { await ready; ledger.push(args.amount); return { content: [] }; } }, control);
  const original = call().input;
  const running = tool.execute('p', original);
  original.amount = 10000;
  assert.throws(() => control.replacePolicy(policy), /pending/);
  release(); await running;
  assert.deepEqual(ledger, [105]);
});

test('denial rules take precedence; unknown and inherited tool names are denied', () => {
  const compiled = compilePolicy({ ...policy, rules: [...policy.rules, { tool: 'demo_pay', effect: 'deny', arguments: { type: 'object', properties: { amount: { const: 105 } } } }] });
  assert.equal(compiled.evaluate('demo_pay', call().input), false);
  assert.equal(compiled.evaluate('toString', {}), false);
  const c = new AuthorizationController({ policy });
  assert.equal(c.begin({ ...call(), toolName: '__proto__' }).allowed, false);
  assert.equal(c.begin(call('105')).allowed, false); // No schema coercion.
  assert.equal(c.begin({ ...call(), input: { ...call().input, extra: 'x' } }).allowed, false);
});

test('native failures, explicit error results, cancellation and changed arguments never become update evidence', async () => {
  const seen = [];
  const c = new AuthorizationController({ policy, onSuccessfulResult: r => seen.push(r) });
  const throwing = guardTool({ name: 'demo_pay', execute: async () => { throw new Error('native failure'); } }, c);
  await assert.rejects(throwing.execute('throw', call().input), /native failure/);
  const errorTool = guardTool({ name: 'demo_pay', execute: async () => ({ content: [], isError: true }) }, c);
  await errorTool.execute('error', call().input);
  let ran = false;
  const aborted = guardTool({ name: 'demo_pay', execute: async () => { ran = true; return { content: [] }; } }, c);
  const abort = new AbortController(); abort.abort();
  await assert.rejects(aborted.execute('abort', call().input, abort.signal)); assert.equal(ran, false);
  const ticket = c.begin(call()).ticket;
  assert.equal(await c.finish(ticket, { input: call(999).input, result: { content: [] } }), 'input_changed');
  assert.deepEqual(seen, []); assert.equal(c.status.pending, 0);
});

test('tickets are one-use and cannot be forged or transferred between controllers', async () => {
  const one = new AuthorizationController({ policy }), two = new AuthorizationController({ policy });
  const ticket = one.begin(call()).ticket;
  await assert.rejects(two.finish(ticket, { input: call().input, result: {} }), /Unknown/);
  assert.equal(one.begin(call()).allowed, false); // Concurrent ID collision.
  await one.finish(ticket, { input: call().input, result: {} });
  await assert.rejects(one.finish(ticket, { input: call().input, result: {} }), /completed/);
  const retry = one.begin(call()); assert.equal(retry.allowed, true); // Sequential ID reuse is permitted.
  one.abandonAll(); assert.equal(one.status.pending, 0);
});

test('policy and observation snapshots are immutable and optional result fields are supported', async () => {
  const original = structuredClone(policy), seen = [];
  const c = new AuthorizationController({ policy: original, onSuccessfulResult: r => seen.push(r) });
  original.rules[0].arguments.properties.amount.const = 100;
  assert.equal(c.begin(call(100)).allowed, false);
  const granted = c.begin(call());
  await c.finish(granted.ticket, { input: call().input, result: { content: [], details: undefined } });
  assert.deepEqual(seen[0].result, { content: [] });
  assert.throws(() => { seen[0].input.amount = 7; }, TypeError);
});

test('invalid inputs and policies fail before effects; audit failures remain observable', () => {
  assert.throws(() => new AuthorizationController({ policy: { version: 1, id: 'bad', rules: [{ tool: 'x', effect: 'allow', arguments: { $ref: 'https://example.invalid/schema' } }] } }));
  const c = new AuthorizationController({ policy, onAudit: () => { throw new Error('sink offline'); } });
  for (const amount of [NaN, Infinity, undefined, () => 105]) assert.equal(c.begin({ ...call(), input: { recipient: 'demo-merchant', amount } }).allowed, false);
  const input = call().input; Object.defineProperty(input, 'amount', { get() { throw new Error('getter invoked'); }, enumerable: true });
  assert.equal(c.begin({ ...call(), input }).allowed, false);
  assert.ok(c.status.auditErrors > 0);
});
