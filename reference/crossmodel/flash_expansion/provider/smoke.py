"""Two-call-per-model infrastructure smoke; offline until root passes --live.

Maximum 8 model requests for all four, no efficacy prompt or retry. GLM/MiniMax
use documented minimum effort and an 8192-token envelope. MiMo's mode is
unverified, so its conservative envelope is also 8192. Qwen requests its
documented non-thinking template and uses 1400; forwarding remains to be checked.
"""
import argparse
import copy
import json
import time
from pathlib import Path
try:
    from .canopy import CanopyClient, from_pi_context
except ImportError:
    from canopy import CanopyClient, from_pi_context

CONFIGS = [
    {'model': 'zai/glm-5.3-flash', 'label': 'glm', 'reasoning_mode': 'low', 'max_tokens': 8192, 'expected_mode': 'always thinking; documented minimum effort'},
    {'model': 'minimax/minimax-m3.1-flash', 'label': 'minimax', 'reasoning_mode': 'low', 'max_tokens': 8192, 'expected_mode': 'always thinking; documented minimum effort'},
    {'model': 'xiaomimimo/mimo-v2.6-flash', 'label': 'mimo', 'reasoning_mode': 'default', 'max_tokens': 8192, 'expected_mode': 'unverified native default; no undocumented off flag'},
    {'model': 'qwen/qwen3.8-flash-next', 'label': 'qwen', 'reasoning_mode': 'off', 'max_tokens': 1400, 'expected_mode': 'non-thinking requested; Canopy template forwarding unverified'},
]


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--model', choices=['all', 'glm', 'minimax', 'mimo', 'qwen'], default='all')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    configs = [x for x in CONFIGS if args.model == 'all' or x['label'] == args.model]
    context = {'systemPrompt': 'Follow this isolated infrastructure test exactly. Use only the supplied tool.',
               'messages': [{'role': 'user', 'content': 'Call echo exactly once with value "FLASH_TRANSPORT_CHECK". After its tool result, reply with the exact text DONE and make no further tool call.'}],
               'tools': [{'name': 'echo', 'description': 'Returns its input; no external effects.',
                          'parameters': {'type': 'object', 'properties': {'value': {'type': 'string'}},
                                         'required': ['value'], 'additionalProperties': False}}]}
    dry = []
    for cfg in configs:
        request, conversion = from_pi_context(context, model=cfg['model'], reasoning_mode=cfg['reasoning_mode'], max_tokens=cfg['max_tokens'], temperature=0.7)
        assert request['model'] == cfg['model'] and request['max_tokens'] == cfg['max_tokens']
        assert request['messages'][0]['content'] == context['systemPrompt']
        assert request['tools'][0]['function']['parameters'] == context['tools'][0]['parameters']
        dry.append({'configuration': cfg, 'request': request, 'conversion': conversion})
    save(args.out/'offline.json', {'passed': True, 'rows': dry, 'model_calls': 0})
    if not args.live:
        print(json.dumps({'passed': True, 'models': [c['model'] for c in configs], 'model_calls': 0}))
        return
    began = time.monotonic()
    rows = []
    for cfg in configs:
        client = CanopyClient(cfg['model'], reasoning_mode=cfg['reasoning_mode'], allow_network=True)
        first = client.complete_pi(context, max_tokens=cfg['max_tokens'], temperature=0.7)
        save(args.out/(cfg['label']+'-first.json'), first)
        row = {'configuration': cfg, 'first_ok': first.get('ok'), 'first_error': first.get('error'),
               'first_identity_exact': first.get('model_label_matches'), 'first_returned_model': first.get('returned_model'),
               'first_reasoning': first.get('reasoning_metadata'), 'first_rate_headers': first.get('rate_limit_headers'),
               'model_calls': first.get('network_requests', 0), 'passed': False}
        calls = first.get('tool_calls', [])
        if first.get('ok') and len(calls) == 1 and calls[0]['name'] == 'echo' and calls[0]['arguments'] == {'value': 'FLASH_TRANSPORT_CHECK'}:
            continued = copy.deepcopy(context)
            continued['messages'] += [first['message'], {'role': 'toolResult', 'toolName': 'echo', 'toolCallId': calls[0]['id'],
                                                        'content': [{'type': 'text', 'text': 'FLASH_TRANSPORT_CHECK'}], 'isError': False}]
            second = client.complete_pi(continued, max_tokens=cfg['max_tokens'], temperature=0.7)
            save(args.out/(cfg['label']+'-continuation.json'), second)
            row.update(continuation_ok=second.get('ok'), continuation_error=second.get('error'),
                       continuation_identity_exact=second.get('model_label_matches'), continuation_reasoning=second.get('reasoning_metadata'),
                       continuation_rate_headers=second.get('rate_limit_headers'), final_text=second.get('text'),
                       model_calls=row['model_calls']+second.get('network_requests', 0), usage=[first.get('usage'), second.get('usage')])
            row['passed'] = bool(first.get('model_label_matches') and second.get('ok') and second.get('model_label_matches')
                                 and not second.get('tool_calls') and second.get('text', '').strip() == 'DONE')
            if cfg['reasoning_mode'].startswith('off'):
                observations = [x.get('reasoning_metadata') or {} for x in [first, second]]
                any_positive = any(x.get('nonempty_native_reasoning') or (x.get('reported_reasoning_tokens') or 0) > 0 or (x.get('reported_thinking_tokens') or 0) > 0 for x in observations)
                explicit_zero = all(x.get('reported_reasoning_tokens') == 0 or x.get('reported_thinking_tokens') == 0 for x in observations)
                row['off_control_status'] = 'contradicted_by_observed_reasoning' if any_positive else 'explicit_zero_reported' if explicit_zero else 'no_visible_reasoning_but_counter_unknown'
        else:
            row['failure'] = 'First response was not the exact synthetic tool call; no retry'
        rows.append(row)
        save(args.out/'progress.json', {'rows': rows, 'elapsed_s': time.monotonic()-began})
    result = {'scope': 'Identity/tool-continuation infrastructure qualification; model+mode configurations are not equated',
              'passed': all(r['passed'] for r in rows), 'rows': rows, 'model_calls': sum(r['model_calls'] for r in rows),
              'elapsed_s': time.monotonic()-began, 'quota_scope': 'Unknown; rate headers and timestamps retained for separate analysis'}
    save(args.out/'result.json', result)
    print(json.dumps(result))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
