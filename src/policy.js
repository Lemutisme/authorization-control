import Ajv from 'ajv';
import { createHash } from 'node:crypto';
import { canonicalJson, copyJson, freezeJson } from './json.js';

const schema = {
  type: 'object', additionalProperties: false, required: ['version', 'id', 'rules'],
  properties: {
    version: { const: 1 }, id: { type: 'string', minLength: 1, maxLength: 200 },
    rules: { type: 'array', maxItems: 1000, items: {
      type: 'object', additionalProperties: false, required: ['tool', 'effect', 'arguments'],
      properties: {
        tool: { type: 'string', minLength: 1, maxLength: 200 },
        effect: { enum: ['allow', 'deny'] },
        arguments: { anyOf: [{ type: 'object' }, { type: 'boolean' }] }
      }
    } }
  }
};

/** Compile a trusted policy; no remote references, coercion, defaults or input edits. */
export function compilePolicy(document) {
  const policy = copyJson(document);
  const ajv = new Ajv({ strict: true, allErrors: false, coerceTypes: false, useDefaults: false, removeAdditional: false, ownProperties: true });
  if (!ajv.compile(schema)(policy)) throw new TypeError('Invalid authorization policy document');
  const rules = policy.rules.map(rule => ({ tool: rule.tool, effect: rule.effect, check: ajv.compile(rule.arguments) }));
  return Object.freeze({
    id: policy.id,
    fingerprint: createHash('sha256').update(canonicalJson(policy)).digest('hex'),
    document: freezeJson(policy),
    evaluate(tool, input) {
      if (typeof tool !== 'string' || input === null || typeof input !== 'object' || Array.isArray(input)) return false;
      let allowed = false;
      for (const rule of rules) {
        if (rule.tool !== tool || !rule.check(input)) continue;
        if (rule.effect === 'deny') return false;
        allowed = true;
      }
      return allowed;
    }
  });
}
