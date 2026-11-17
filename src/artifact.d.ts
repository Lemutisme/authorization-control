export type MatchedArm = 'all_tools_complete' | 'known_function_complete' | 'known_function_protected';
export declare const MATCHED_ARMS: MatchedArm[];
export interface ContextCounts { n: number; known: number; validFirstTuple: number; abstain: number; malformed: number; otherValid: number; rate: number | null }
export interface MatchedSummary {
  schema: 'matched-reconstruction-readback-v1'; logicalRows: number; freshResponses: number; semanticContexts: number; unknownRows: number;
  findings: string[];
  arms: Record<MatchedArm, { tax: ContextCounts; refund: ContextCounts; macro: number | null }>;
  primary: { delta: number | null; threshold: number; verdict: 'supported' | 'refuted' | 'indeterminate' };
  malformedNestedContent: { context: string; arm: MatchedArm; replicate: number; validPacket: boolean; nestedTupleMatches: boolean; primaryCredit: false }[];
  scope: string;
}
export declare function readArtifact(path: string | URL, options?: { expectedSha256?: string; maxBytes?: number }): Promise<{ data: unknown; sha256: string }>;
export declare function summarizeMatched(data: unknown): MatchedSummary;
export declare function referenceTuple(packet: unknown): { context: 'tax' | 'refund'; recipient: string; amount: [bigint, bigint] };
