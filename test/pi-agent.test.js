import test from 'node:test';
import assert from 'node:assert/strict';
import { runDemo } from '../examples/sdk-demo.js';
test('official Pi Agent loop observes an error for denial and invokes only the permitted effect', async () => {
  const result = await runDemo();
  assert.deepEqual(result.ledger, [{ recipient: 'demo-merchant', amount: 105 }]);
  assert.equal(result.toolResults.length, 2);
  assert.equal(result.toolResults[0].isError, true);
  assert.equal(result.toolResults[1].isError, false);
  assert.ok(!JSON.stringify(result.toolResults[0]).includes('105'));
  assert.equal(result.successfulObservations, 1);
  assert.equal(result.modelCalls, 0);
});
