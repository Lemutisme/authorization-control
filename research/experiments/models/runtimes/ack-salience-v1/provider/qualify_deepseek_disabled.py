"""Infrastructure-only flag qualification, offline unless root passes --live.

At most two model calls. Exact request flags/budgets/identity and measured
reasoning counters are retained. This is not an efficacy experiment.
"""
import argparse
import copy
import json
from pathlib import Path
try:
    from .deepseek import MODEL, DeepSeekClient, from_pi_context
except ImportError:
    from deepseek import MODEL, DeepSeekClient, from_pi_context


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def no_observed_reasoning(result):
    raw = result.get('response') or {}
    message = ((raw.get('choices') or [{}])[0]).get('message') or {}
    tokens = ((raw.get('usage') or {}).get('completion_tokens_details') or {}).get('reasoning_tokens')
    return {'nonempty_reasoning_content': bool(message.get('reasoning_content')),
            'reported_reasoning_tokens': tokens,
            'explicit_reported_zero': tokens == 0,
            'passed': not message.get('reasoning_content') and tokens == 0}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    context = {'systemPrompt': 'Follow this isolated transport test exactly. Use only the supplied tool.',
               'messages': [{'role': 'user', 'content': 'Call echo exactly once with value "DISABLED_FLAG_CHECK". After its tool result, reply DONE with no further tool calls.'}],
               'tools': [{'name': 'echo', 'description': 'Returns its input; no external effects.',
                          'parameters': {'type': 'object', 'properties': {'value': {'type': 'string'}},
                                         'required': ['value'], 'additionalProperties': False}}]}
    actor_payload, _ = from_pi_context(context, max_tokens=1400, temperature=None)
    policy_payload, _ = from_pi_context({'systemPrompt': 'Output the requested literal.', 'messages': [{'role': 'user', 'content': 'Return OK.'}], 'tools': []}, max_tokens=8192, temperature=None)
    assert actor_payload['max_tokens'] == 1400 and policy_payload['max_tokens'] == 8192
    assert actor_payload['thinking'] == policy_payload['thinking'] == {'type': 'disabled'}
    assert actor_payload['temperature'] == policy_payload['temperature'] == 0.7
    save(args.out / 'offline.json', {'passed': True, 'model_calls': 0,
                                    'actor_payload': actor_payload, 'policy_payload': policy_payload})
    if not args.live:
        print(json.dumps({'passed': True, 'live': False, 'model_calls': 0}))
        return
    client = DeepSeekClient(allow_network=True)
    first = client.complete_pi(context, max_tokens=1400, temperature=None)
    save(args.out / 'first.json', first)
    result = {'scope': 'Explicit thinking-disabled tool lifecycle qualification; no efficacy estimate',
              'requested_model': MODEL, 'first_identity_exact': first.get('model_label_matches'),
              'first_ok': first.get('ok'), 'first_error': first.get('error'),
              'first_reasoning': no_observed_reasoning(first), 'model_calls': 1, 'passed': False}
    calls = first.get('tool_calls', [])
    if first.get('ok') and len(calls) == 1 and calls[0]['name'] == 'echo' and calls[0]['arguments'] == {'value': 'DISABLED_FLAG_CHECK'}:
        continued = copy.deepcopy(context)
        continued['messages'] += [first['message'], {'role': 'toolResult', 'toolName': 'echo', 'toolCallId': calls[0]['id'],
                                                    'content': [{'type': 'text', 'text': 'DISABLED_FLAG_CHECK'}], 'isError': False}]
        second = client.complete_pi(continued, max_tokens=1400, temperature=None)
        save(args.out / 'continuation.json', second)
        result.update(continuation_identity_exact=second.get('model_label_matches'), continuation_ok=second.get('ok'),
                      continuation_error=second.get('error'), continuation_reasoning=no_observed_reasoning(second),
                      final_text=second.get('text'), model_calls=2)
        result['passed'] = bool(first.get('model_label_matches') and second.get('ok') and second.get('model_label_matches')
                                and result['first_reasoning']['passed'] and result['continuation_reasoning']['passed']
                                and not second.get('tool_calls') and second.get('text', '').strip() == 'DONE')
    else:
        result['failure'] = 'First response was not the exact one-call synthetic request'
    save(args.out / 'result.json', result)
    print(json.dumps(result))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
