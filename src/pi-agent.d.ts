import type { AgentTool } from '@earendil-works/pi-agent-core';
import type { AuthorizationController } from './index.js';
export declare function guardTool<T extends AgentTool>(tool: T, controller: AuthorizationController): T;
export declare function guardTools<T extends AgentTool>(tools: readonly T[], controller: AuthorizationController): T[];
