"""Offline checks of model gates, preserved histories, and safe metadata."""
import json
from pathlib import Path
from canopy import MODEL_MODES, as_pi_message, capture_headers, from_pi_context, reasoning_fields


def main():
    context = {'systemPrompt': 'Complete the real owner task.', 'messages': [
        {'role': 'user', 'content': 'Pay the invoice.'},
        {'role': 'assistant', 'content': [{'type': 'toolCall', 'id': 'call_a|fc_a', 'name': 'pay', 'arguments': {'amount': 200.29}}]},
        {'role': 'toolResult', 'toolCallId': 'call_a|fc_a', 'toolName': 'pay', 'isError': True,
         'content': [{'type': 'text', 'text': 'Only 195.29 is permitted.'}]},
    ], 'tools': [{'name': 'pay', 'description': 'Make a payment.', 'parameters': {'type': 'object', 'properties': {'amount': {'type': 'number'}}}}]}
    modes = {'zai/glm-5.3-flash': 'low', 'minimax/minimax-m3.1-flash': 'low', 'xiaomimimo/mimo-v2.6-flash': 'default', 'qwen/qwen3.8-flash-next': 'off'}
    for model in MODEL_MODES:
        wire, _ = from_pi_context(context, model=model, reasoning_mode=modes[model], max_tokens=8192)
        assert wire['model'] == model and wire['max_tokens'] == 8192
        assert wire['messages'][-1]['content'] == 'Only 195.29 is permitted.'
        assert wire['messages'][-2]['tool_calls'][0]['id'] == wire['messages'][-1]['tool_call_id']
        assert wire['tools'][0]['function']['parameters'] == context['tools'][0]['parameters']
    for model in ['zai/glm-5.3-flash', 'minimax/minimax-m3.1-flash', 'xiaomimimo/mimo-v2.6-flash']:
        try:
            reasoning_fields(model, 'off')
        except ValueError:
            pass
        else:
            raise AssertionError('Unsupported or undocumented off mode was silently accepted')
    raw = {'id': 'response_test', 'model': 'minimax/minimax-m3.1-flash',
           'choices': [{'finish_reason': 'tool_calls', 'message': {'role': 'assistant', 'content': 'Proceeding.', 'reasoning_content': 'Opaque native reasoning continuity',
                         'tool_calls': [{'id': 'call_new', 'type': 'function', 'function': {'name': 'pay', 'arguments': '{"amount":195.29}'}}]}}],
           'usage': {'prompt_tokens': 9, 'completion_tokens': 11, 'total_tokens': 20}}
    reply = as_pi_message(raw)
    assert reply['content'][0]['text'] == 'Proceeding.'
    assert reply['content'][1]['arguments'] == {'amount': 195.29}
    wire, _ = from_pi_context({'messages': [{'role': 'user', 'content': 'Go.'}, reply], 'tools': []}, model=raw['model'], reasoning_mode='low')
    assert wire['messages'][-1]['reasoning_content'] == raw['choices'][0]['message']['reasoning_content']
    try:
        from_pi_context({'messages': [reply]}, model='zai/glm-5.3-flash', reasoning_mode='low')
    except ValueError:
        pass
    else:
        raise AssertionError('Reasoning was transferred across models')
    headers = capture_headers({'Date': 'Sat, 14 Nov 2026 20:00:00 GMT', 'Retry-After': '29', 'X-RateLimit-Limit-Minute': '3', 'Authorization': 'do not retain', 'Set-Cookie': 'do not retain'})
    assert set(headers) == {'date', 'retry-after', 'x-ratelimit-limit-minute'}
    result = {'passed': True, 'model_ids': list(MODEL_MODES), 'no_implicit_model_fallback': True,
              'schema_refusal_tool_id_preserved': True, 'unsupported_off_rejected': True,
              'reasoning_continuity_preserved_only_same_model': True, 'safe_header_allowlist': True,
              'model_calls': 0, 'network_calls': 0}
    Path(__file__).with_name('offline-check.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
