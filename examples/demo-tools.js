/** Optional CLI demo tool; it only appends to an in-memory ledger. */
export default function demoTools(pi) {
  const ledger = [];
  pi.registerTool({
    name: 'demo_pay', label: 'Demo payment', description: 'Record a synthetic payment in memory. No network or financial service is contacted.',
    parameters: { type: 'object', required: ['recipient', 'amount'], properties: { recipient: { type: 'string' }, amount: { type: 'number' } }, additionalProperties: false },
    execute: async (_id, input) => { ledger.push(input); return { content: [{ type: 'text', text: 'Demo payment recorded.' }], details: { count: ledger.length } }; }
  });
}
