"""Registered infrastructure-only smoke; no study efficacy prompts.

Offline by default. --live makes one call plus one continuation per selected
model, up to six calls for all three; no retry/fallback. Root registers first.
"""
import argparse
import copy
import json
import time
from pathlib import Path
try:
    from .haiku import DEFAULT_MODEL, from_pi_context as haiku_payload
    from .luna import MODEL, from_pi_context as luna_payload, make_client
    from .deepseek import MODEL as DEEPSEEK_MODEL, from_pi_context as deepseek_payload
except ImportError:
    from haiku import DEFAULT_MODEL, from_pi_context as haiku_payload
    from luna import MODEL, from_pi_context as luna_payload, make_client
    from deepseek import MODEL as DEEPSEEK_MODEL, from_pi_context as deepseek_payload


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--live', action='store_true')
    p.add_argument('--model', choices=['all', 'both', 'haiku', 'luna', 'deepseek'], default='all')
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    context = {'systemPrompt': 'Follow the user task exactly. Use only the supplied tool. This is an isolated transport test.',
               'messages': [{'role': 'user', 'content': 'First call echo exactly once with value "SMOKE_TOKEN". After its result, reply with the exact text DONE and do not call any further tool.'}],
               'tools': [{'name': 'echo', 'description': 'Return the supplied text unchanged; no external effects.',
                          'parameters': {'type': 'object', 'properties': {'value': {'type': 'string'}},
                                         'required': ['value'], 'additionalProperties': False}}]}
    selected = ['haiku', 'luna', 'deepseek'] if args.model == 'all' else ['haiku', 'luna'] if args.model == 'both' else [args.model]
    offline = {}
    for model in selected:
        converter = {'haiku': haiku_payload, 'luna': luna_payload, 'deepseek': deepseek_payload}[model]
        wire, meta = converter(context, max_tokens=1400, temperature=None)
        policy_wire, _ = converter({'systemPrompt': 'Return the requested literal.', 'messages': [{'role': 'user', 'content': 'Return OK.'}], 'tools': []}, max_tokens=8192, temperature=None)
        key = 'max_output_tokens' if model == 'luna' else 'max_tokens'
        assert wire[key] == 1400 and policy_wire[key] == 8192
        if model == 'deepseek':
            assert wire['temperature'] == 0.7 and policy_wire['temperature'] == 0.7
        else:
            assert 'temperature' not in wire and 'temperature' not in policy_wire
        if model == 'luna':
            assert wire['input'][0]['role'] == 'developer'
            assert wire['input'][0]['content'] == context['systemPrompt']
        elif model == 'haiku':
            assert wire['system'] == context['systemPrompt']
        else:
            assert wire['messages'][0] == {'role': 'system', 'content': context['systemPrompt']}
        offline[model] = {'actor_request': wire, 'conversion': meta, 'policy_budget': policy_wire[key]}
    save(args.out / 'offline.json', {'passed': True, 'models': offline, 'model_calls': 0})
    if not args.live:
        print(json.dumps({'passed': True, 'live': False, 'model_calls': 0, 'models': selected}))
        return
    began = time.monotonic()
    rows = []
    for model in selected:
        client = make_client(model, allow_network=True)
        first = client.complete_pi(context, max_tokens=1400, temperature=None)
        save(args.out / (model + '-first.json'), first)
        row = {'model': model, 'requested_model': {'haiku': DEFAULT_MODEL, 'luna': MODEL, 'deepseek': DEEPSEEK_MODEL}[model],
               'first_ok': first.get('ok'), 'returned_model': first.get('returned_model'),
               'first_identity_exact': first.get('model_label_matches'),
               'first_error': first.get('error'), 'model_calls': 1, 'passed': False}
        calls = first.get('tool_calls', [])
        if first.get('ok') and len(calls) == 1 and calls[0]['name'] == 'echo' and calls[0]['arguments'] == {'value': 'SMOKE_TOKEN'}:
            continuation = copy.deepcopy(context)
            continuation['messages'].append(first['message'])
            continuation['messages'].append({'role': 'toolResult', 'toolName': 'echo', 'toolCallId': calls[0]['id'],
                                              'content': [{'type': 'text', 'text': 'SMOKE_TOKEN'}], 'isError': False})
            second = client.complete_pi(continuation, max_tokens=1400, temperature=None)
            save(args.out / (model + '-continuation.json'), second)
            row.update(continuation_ok=second.get('ok'), continuation_identity_exact=second.get('model_label_matches'),
                       continuation_error=second.get('error'), final_text=second.get('text'),
                       model_calls=2, usage=[first.get('usage'), second.get('usage')])
            row['passed'] = bool(first.get('model_label_matches') and second.get('ok') and second.get('model_label_matches') and not second.get('tool_calls') and second.get('text', '').strip() == 'DONE')
        else:
            row['failure'] = 'Expected one exact synthetic tool call; no continuation attempted'
        rows.append(row)
        save(args.out / 'progress.json', {'rows': rows, 'elapsed_s': time.monotonic() - began})
    result = {'scope': 'Provider identity and isolated tool-call continuation; no efficacy estimate',
              'passed': all(r['passed'] for r in rows), 'rows': rows,
              'model_calls': sum(r['model_calls'] for r in rows), 'elapsed_s': time.monotonic() - began}
    save(args.out / 'result.json', result)
    print(json.dumps(result))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
