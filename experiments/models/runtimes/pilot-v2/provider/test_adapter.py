"""Consequential offline protocol checks; no credentials or network needed."""
import json
from pathlib import Path
from haiku import as_pi_message, from_pi_context

context = {
    'systemPrompt': 'Complete the user task faithfully.',
    'messages': [
        {'role': 'user', 'content': 'Pay the bill.'},
        {'role': 'assistant', 'content': [{'type': 'toolCall', 'id': 'call_X|fc_X', 'name': 'pay', 'arguments': {'amount': 200.29}}]},
        {'role': 'toolResult', 'toolCallId': 'call_X|fc_X', 'content': [{'type': 'text', 'text': 'Only 195.29 is allowed.'}], 'isError': True},
    ],
    'tools': [{'name': 'pay', 'description': 'Transfer money.', 'parameters': {'type': 'object', 'properties': {'amount': {'type': 'number'}}, 'required': ['amount']}}],
}
payload, conversion = from_pi_context(context)
assert payload['system'] == context['systemPrompt']
assert payload['tools'][0]['input_schema'] == context['tools'][0]['parameters']
assert payload['messages'][1]['content'][0]['input'] == {'amount': 200.29}
assert payload['messages'][2]['content'][0]['content'][0]['text'] == 'Only 195.29 is allowed.'
assert payload['messages'][1]['content'][0]['id'] == payload['messages'][2]['content'][0]['tool_use_id']
assert payload['messages'][2]['content'][0]['is_error'] is True
assert len(conversion['tool_call_id_map']) == 1
reply = {'id': 'msg_test', 'type': 'message', 'role': 'assistant', 'model': payload['model'],
         'content': [{'type': 'tool_use', 'id': 'toolu_native', 'name': 'pay', 'input': {'amount': 195.29}}],
         'stop_reason': 'tool_use', 'usage': {'input_tokens': 10, 'output_tokens': 12}}
normalized = as_pi_message(reply)
assert normalized['content'][0]['arguments'] == {'amount': 195.29}
assert normalized['stopReason'] == 'toolUse'
assert normalized['usage']['totalTokens'] == 22
context['messages'].extend([normalized, {'role': 'toolResult', 'toolCallId': 'toolu_native', 'content': [{'type': 'text', 'text': 'Paid.'}], 'isError': False}])
continuation, _ = from_pi_context(context)
assert continuation['messages'][-1]['content'][0]['tool_use_id'] == 'toolu_native'
assert continuation['messages'][-1]['content'][0]['is_error'] is False
try:
    from_pi_context({'messages': [{'role': 'assistant', 'content': [{'type': 'thinking', 'thinking': 'not silently dropped'}]}]})
except ValueError:
    pass
else:
    raise AssertionError('Unsupported reasoning silently discarded')
out = Path(__file__).with_name('offline-check.json')
out.write_text(json.dumps({'passed': True, 'model_calls': 0, 'network_calls': 0,
                           'checks': ['tool schema preserved', 'refusal preserved', 'call IDs consistently mapped', 'error bit preserved', 'response usage parsed', 'continuation IDs preserved', 'unsupported reasoning rejected']}, indent=2) + '\n')
print(out.read_text())
