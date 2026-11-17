import { copyJson } from './json.js';

/** Decorate an official Pi AgentTool; execute only the checked copy of its arguments. */
export function guardTool(tool, controller) {
  if (!tool || typeof tool.name !== 'string' || typeof tool.execute !== 'function') throw new TypeError('Expected a Pi tool');
  return {
    ...tool,
    async execute(toolCallId, input, signal, onUpdate, ...rest) {
      const admission = controller.begin({ toolCallId, toolName: tool.name, input });
      if (!admission.allowed) return { content: [{ type: 'text', text: admission.message }], details: { authorizationDenied: true }, isError: true };
      const checked = copyJson(admission.input);
      if (signal?.aborted) {
        await controller.finish(admission.ticket, { input: checked, result: null, aborted: true });
        throw signal.reason ?? new Error('Tool call aborted');
      }
      let result;
      try { result = await tool.execute.call(tool, toolCallId, checked, signal, onUpdate, ...rest); }
      catch (error) {
        await controller.finish(admission.ticket, { input: checked, result: null, isError: true, aborted: Boolean(signal?.aborted) });
        throw error;
      }
      await controller.finish(admission.ticket, { input: checked, result, isError: result?.isError === true, aborted: Boolean(signal?.aborted) });
      return result;
    }
  };
}

export function guardTools(tools, controller) { return tools.map(tool => guardTool(tool, controller)); }
