"""Offline replay of all four retained Lumen smoke-v1 responses."""
import ast
import copy
import hashlib
import json
from pathlib import Path
from lumen import as_pi_message, reasoning_observation


def main():
    here = Path(__file__).resolve().parent
    source = here.parent/'qualification/provider-smoke-v1'
    rows = []
    for name in ['qwen-first', 'qwen-continuation', 'glm-first', 'glm-continuation']:
        path = source/(name+'.json')
        saved = json.loads(path.read_text())
        raw = saved['response']
        message = as_pi_message(raw)
        calls = [x for x in message['content'] if x['type'] == 'toolCall']
        text = ''.join(x['text'] for x in message['content'] if x['type'] == 'text')
        assert raw['model'] == saved['request']['model']
        if name.endswith('first'):
            assert len(calls) == 1 and calls[0]['name'] == 'echo'
            assert calls[0]['arguments'] == {'value': 'LUMEN_TRANSPORT_CHECK'}
        else:
            assert calls == [] and text.strip() == 'DONE'
        observation = reasoning_observation(raw)
        expected = 0 if name.startswith('qwen') else 1
        assert observation['reported_reasoning_tokens'] == expected
        assert observation['reasoning_token_sources'] == {'usage.reasoning_tokens': expected}
        rows.append({'artifact': str(path), 'artifact_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                     'previous_ok': saved['ok'], 'previous_error': saved.get('error'),
                     'normalized_success': True, 'returned_model': raw['model'],
                     'tool_call_count': len(calls), 'final_text': text if name.endswith('continuation') else None,
                     'reasoning': observation})
    assert reasoning_observation({'usage': {}})['reported_reasoning_tokens'] is None
    conflict = reasoning_observation({'usage': {'reasoning_tokens': 1, 'completion_tokens_details': {'reasoning_tokens': 0}}})
    assert conflict['reasoning_token_conflict'] and conflict['reported_reasoning_tokens'] is None
    for invalid in ['not a list', {}, 7, [None], [{'function': None}]]:
        raw = {'choices': [{'message': {'content': 'DONE', 'tool_calls': invalid}, 'finish_reason': 'stop'}]}
        try:
            as_pi_message(raw)
        except ValueError:
            pass
        else:
            raise AssertionError('Invalid tool_calls shape accepted')
    # The request construction and all pacing/credential code are unchanged.
    def function_source(path, name):
        text = path.read_text()
        node = next(x for x in ast.parse(text).body if isinstance(x, ast.FunctionDef) and x.name == name)
        return ast.get_source_segment(text, node)
    original = here.parent/'provider'
    for name in ['reasoning_fields', 'text_content', 'from_pi_context']:
        assert function_source(original/'lumen.py', name) == function_source(here/'lumen.py', name)
    for name in ['common.py', 'throttle.py']:
        assert (original/name).read_bytes() == (here/name).read_bytes()
    result = {'passed': True, 'responses_replayed': len(rows), 'rows': rows,
              'request_construction_unchanged': True, 'credential_and_throttle_code_unchanged': True,
              'null_tool_calls_is_empty_list': True, 'invalid_tool_call_shapes_rejected': True,
              'absent_counter_is_unknown': True, 'conflicting_counters_preserved': conflict,
              'model_calls': 0, 'network_calls': 0}
    (here/'replay-v1.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({'passed': True, 'responses_replayed': 4, 'qwen_reasoning': [0, 0],
                      'glm_reasoning': [1, 1], 'model_calls': 0, 'network_calls': 0}))


if __name__ == '__main__':
    main()
