export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface PolicyRule { tool: string; effect: 'allow' | 'deny'; arguments: boolean | Record<string, Json> }
export interface Policy { version: 1; id: string; rules: PolicyRule[] }
export interface Call { toolCallId: string; toolName: string; input: Record<string, Json> }
declare const ticketBrand: unique symbol;
export interface AdmissionTicket { readonly [ticketBrand]: true; readonly sequence: number }
export type Admission = { allowed: false; message: string } | { allowed: true; ticket: AdmissionTicket; input: Record<string, Json> };
export interface AuditEvent { readonly version: 1; readonly type: string; readonly [key: string]: Json }
export interface SuccessfulResult { readonly toolCallId: string; readonly toolName: string; readonly input: Record<string, Json>; readonly result: Json; readonly policyId: string; readonly policyFingerprint: string; readonly revision: number }
export interface ControllerOptions { policy: Policy; onAudit?: (event: AuditEvent) => void; onSuccessfulResult?: ((result: SuccessfulResult) => void | Promise<void>) | null }
export declare const OPAQUE_REFUSAL: string;
export declare function compilePolicy(policy: Policy): Readonly<{ id: string; fingerprint: string; document: Policy; evaluate(tool: string, input: unknown): boolean }>;
export declare class AuthorizationController {
  constructor(options: ControllerOptions);
  readonly status: { policyId: string; policyFingerprint: string; revision: number; pending: number; auditErrors: number };
  begin(call: Call): Admission;
  finish(ticket: AdmissionTicket, outcome: { input: unknown; result: unknown; isError?: boolean; aborted?: boolean }): Promise<'success' | 'aborted' | 'input_changed' | 'tool_error'>;
  replacePolicy(policy: Policy): void;
  abandonAll(): void;
}
