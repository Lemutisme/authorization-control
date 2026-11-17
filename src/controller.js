import { compilePolicy } from './policy.js';
import { canonicalJson, copyJson, freezeJson, observationSnapshot } from './json.js';

export const OPAQUE_REFUSAL = 'This call is not permitted by the current runtime policy.';

/** A policy check is not a proof that the policy expresses the user's authorization. */
export class AuthorizationController {
  #policy;
  #pending = new Map();
  #ids = new Set();
  #sequence = 0;
  #audit;
  #success;
  #revision = 0;
  #auditErrors = 0;

  constructor({ policy, onAudit = () => {}, onSuccessfulResult = null }) {
    this.#policy = compilePolicy(policy);
    this.#audit = onAudit;
    this.#success = onSuccessfulResult;
  }

  #emit(event) {
    // Audit sinks are trusted application code. A logging failure does not re-run a tool.
    try { this.#audit(freezeJson(copyJson({ version: 1, ...event }))); } catch { this.#auditErrors++; }
  }

  get status() { return { policyId: this.#policy.id, policyFingerprint: this.#policy.fingerprint, revision: this.#revision, pending: this.#pending.size, auditErrors: this.#auditErrors }; }

  /** Trusted application entry point, never registered as an agent-callable tool. */
  replacePolicy(document) {
    if (this.#pending.size) throw new Error('Cannot replace policy while calls are pending');
    const next = compilePolicy(document);
    this.#policy = next;
    this.#revision++;
    this.#emit({ type: 'policy_replaced', policyId: next.id, policyFingerprint: next.fingerprint, revision: this.#revision });
  }

  begin({ toolCallId, toolName, input }) {
    const sequence = ++this.#sequence;
    const base = { sequence, toolCallId: typeof toolCallId === 'string' ? toolCallId : null, toolName: typeof toolName === 'string' ? toolName : null, policyId: this.#policy.id, policyFingerprint: this.#policy.fingerprint, revision: this.#revision };
    let args;
    let reason = 'not_permitted';
    try {
      if (typeof toolCallId !== 'string' || !toolCallId || typeof toolName !== 'string' || !toolName) throw new TypeError('Invalid call identity');
      if (this.#ids.has(toolCallId)) {
        reason = 'duplicate_pending_id';
      } else {
        args = copyJson(input);
        if (this.#policy.evaluate(toolName, args)) {
          const ticket = Object.freeze({ sequence });
          this.#pending.set(ticket, { ...base, args: freezeJson(args), fingerprint: canonicalJson(args) });
          this.#ids.add(toolCallId);
          this.#emit({ ...base, type: 'admission', allowed: true });
          return { allowed: true, ticket, input: copyJson(args) };
        }
      }
    } catch { reason = 'invalid_call'; }
    this.#emit({ ...base, type: 'admission', allowed: false, reason });
    return { allowed: false, message: OPAQUE_REFUSAL };
  }

  /** Only a private ticket from an admitted call can produce update-eligible evidence. */
  async finish(ticket, { input, result, isError = false, aborted = false }) {
    const call = this.#pending.get(ticket);
    if (!call) throw new Error('Unknown or completed admission ticket');
    this.#pending.delete(ticket);
    this.#ids.delete(call.toolCallId);
    let unchanged = false;
    try { unchanged = canonicalJson(input) === call.fingerprint; } catch { /* invalid input */ }
    const status = aborted ? 'aborted' : !unchanged ? 'input_changed' : isError ? 'tool_error' : 'success';
    this.#emit({ type: 'outcome', sequence: call.sequence, toolCallId: call.toolCallId, toolName: call.toolName,
      policyId: call.policyId, policyFingerprint: call.policyFingerprint, revision: call.revision, status, updateEligible: status === 'success' });
    if (status === 'success' && this.#success) {
      // No rejected proposal or its refusal can reach this callback.
      try {
        await this.#success(freezeJson({ toolCallId: call.toolCallId, toolName: call.toolName,
          input: copyJson(call.args), result: observationSnapshot(result), policyId: call.policyId, policyFingerprint: call.policyFingerprint, revision: call.revision }));
      } catch {
        this.#emit({ type: 'observer_error', sequence: call.sequence, toolCallId: call.toolCallId, toolName: call.toolName });
      }
    }
    return status;
  }

  abandonAll() {
    for (const [ticket, call] of this.#pending) {
      this.#emit({ type: 'outcome', sequence: call.sequence, toolCallId: call.toolCallId, toolName: call.toolName,
        policyId: call.policyId, policyFingerprint: call.policyFingerprint, revision: call.revision, status: 'aborted', updateEligible: false });
      this.#pending.delete(ticket);
    }
    this.#ids.clear();
  }
}
