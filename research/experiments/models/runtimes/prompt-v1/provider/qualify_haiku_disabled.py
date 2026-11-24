"""Two-call infrastructure qualification of explicit Haiku thinking disable.

Offline unless root supplies --live after registration. Retained pilot responses
are tested separately without inference by staged-v3/test_v3.py.
"""
import argparse
import copy
import json
from pathlib import Path
try:
    from .haiku import DEFAULT_MODEL, AnthropicClient, from_pi_context
except ImportError:
    from haiku import DEFAULT_MODEL, AnthropicClient, from_pi_context


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def thinking_result(record):
    response = record.get('response') or {}
    tokens = ((response.get('usage') or {}).get('output_tokens_details') or {}).get('thinking_tokens')
    text = any(bool(b.get('thinking')) for b in response.get('content', []))
    return {'reported_thinking_tokens': tokens, 'nonempty_thinking_text': text,
            'opaque_blocks': sum(b.get('type') in {'thinking', 'redacted_thinking'} for b in response.get('content', [])),
            'passed': tokens == 0 and not text}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    context = {'systemPrompt': 'Follow the isolated transport test exactly. Use only the supplied tool.',
               'messages': [{'role': 'user', 'content': 'Call echo exactly once with value "HAIKU_DISABLED_CHECK". After its result, reply DONE and make no further tool call.'}],
               'tools': [{'name': 'echo', 'description': 'Returns its input; no external effects.',
                          'parameters': {'type': 'object', 'properties': {'value': {'type': 'string'}},
                                         'required': ['value'], 'additionalProperties': False}}]}
    first_payload, _ = from_pi_context(context, max_tokens=1400, temperature=None)
    policy_payload, _ = from_pi_context({'systemPrompt': 'Return the requested literal.', 'messages': [{'role': 'user', 'content': 'Return OK.'}], 'tools': []}, max_tokens=8192, temperature=None)
    assert first_payload['max_tokens'] == 1400 and policy_payload['max_tokens'] == 8192
    assert first_payload['thinking'] == policy_payload['thinking'] == {'type': 'disabled'}
    assert 'temperature' not in first_payload and 'temperature' not in policy_payload
    save(args.out/'offline.json', {'passed': True, 'model_calls': 0, 'actor_payload': first_payload, 'policy_payload': policy_payload})
    if not args.live:
        print(json.dumps({'passed': True, 'model_calls': 0}))
        return
    client = AnthropicClient(allow_network=True)
    first = client.complete_pi(context, max_tokens=1400, temperature=None)
    save(args.out/'first.json', first)
    result = {'requested_model': DEFAULT_MODEL, 'scope': 'Explicit thinking-disabled infrastructure test, not efficacy',
              'first_ok': first.get('ok'), 'first_error': first.get('error'), 'first_identity_exact': first.get('model_label_matches'),
              'first_thinking': thinking_result(first), 'model_calls': 1, 'passed': False}
    calls = first.get('tool_calls', [])
    if first.get('ok') and len(calls) == 1 and calls[0]['name'] == 'echo' and calls[0]['arguments'] == {'value': 'HAIKU_DISABLED_CHECK'}:
        continued = copy.deepcopy(context)
        continued['messages'] += [first['message'], {'role': 'toolResult', 'toolCallId': calls[0]['id'], 'toolName': 'echo',
                                                    'content': [{'type': 'text', 'text': 'HAIKU_DISABLED_CHECK'}], 'isError': False}]
        second = client.complete_pi(continued, max_tokens=1400, temperature=None)
        save(args.out/'continuation.json', second)
        result.update(continuation_ok=second.get('ok'), continuation_error=second.get('error'),
                      continuation_identity_exact=second.get('model_label_matches'), continuation_thinking=thinking_result(second),
                      final_text=second.get('text'), model_calls=2)
        result['passed'] = bool(first.get('model_label_matches') and second.get('ok') and second.get('model_label_matches')
                                and result['first_thinking']['passed'] and result['continuation_thinking']['passed']
                                and not second.get('tool_calls') and second.get('text', '').strip() == 'DONE')
    else:
        result['failure'] = 'First response was not the exact synthetic tool call'
    save(args.out/'result.json', result)
    print(json.dumps(result))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
