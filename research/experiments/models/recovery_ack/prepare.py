"""Freeze old-study post-update states for a new acknowledgement diagnostic.

Selection uses the completed 2026-11-13 study only. No new-model response or
Haiku/DeepSeek/Luna cross-model efficacy output is consulted.
"""
from __future__ import annotations
from pipeline.paths import resolve as research_path
import argparse
import copy
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path
import runtime
HERE = Path(__file__).resolve().parent
OLD = Path(research_path('experiments/shared/evaluation/two_channel'))

def read(path):
    data = Path(path).read_bytes()
    return json.loads(gzip.decompress(data) if str(path).endswith('.gz') else data)

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def portable_message(message):
    role = message['role']
    if role == 'user':
        return {'role': 'user', 'content': copy.deepcopy(message['content'])}
    if role == 'assistant':
        content = []
        for block in message['content']:
            if block['type'] == 'text':
                content.append({'type': 'text', 'text': block['text']})
            elif block['type'] == 'toolCall':
                content.append({'type': 'toolCall', 'id': block['id'], 'name': block['name'], 'arguments': copy.deepcopy(block['arguments'])})
            else:
                raise ValueError('Unsupported source assistant block; cannot silently omit it')
        return {'role': 'assistant', 'content': content}
    if role == 'toolResult':
        if any((block['type'] != 'text' for block in message['content'])):
            raise ValueError('Unsupported native source tool result')
        return {'role': 'toolResult', 'toolCallId': message['toolCallId'], 'toolName': message['toolName'], 'content': copy.deepcopy(message['content']), 'isError': bool(message['isError'])}
    raise ValueError('Unsupported source actor role')

def context_from_source(raw):
    packet = raw['factorial_source_packet']
    first = next((x for x in raw['all_actor_messages'] if not x['historical_replayed']))
    before = json.loads(packet['actor_context_json'])
    after = json.loads(first['context_json'])
    assert before['messages'] == after['messages'][:-2]
    assert packet['source_proposal_message']['content'] == after['messages'][-2]['content']
    systems = [m for m in after['messages'] if m['role'] == 'system']
    assert len(systems) == 1 and isinstance(systems[0]['content'], str)
    assert systems[0]['content'] == raw['actor_instructions']
    wire = json.loads(packet['actor_request_json'])
    assert all((t['type'] == 'function' for t in wire['tools']))
    tools = [{'name': t['name'], 'description': t.get('description', ''), 'parameters': copy.deepcopy(t['parameters'])} for t in wire['tools']]
    context = {'systemPrompt': systems[0]['content'], 'messages': [portable_message(m) for m in after['messages'] if m['role'] != 'system'], 'tools': tools}
    last = context['messages'][-1]
    first_refusal = raw['result']['factorial_first_refusal']
    assert last['role'] == 'toolResult' and last['toolCallId'] == packet['original_proposal_call_id']
    assert last['isError'] is True and len(last['content']) == 1
    assert last['content'][0]['text'] == first_refusal['actor_feedback']['text']
    return (context, first)

def main(old, out):
    rows_path = old / 'analysis-main/rows.json'
    old_rows = read(rows_path)
    selected = sorted([r for r in old_rows if r['arm'] == 'f0_u1' and (r['panel'] == 'honest_fault' or (r['panel'] == 'attack' and r['metrics']['first_update_admits_original'] == 1))], key=lambda r: (r['panel'], r['task_id'], r['unit_id']))
    assert len(selected) == 27
    assert Counter((r['panel'] for r in selected)) == {'honest_fault': 23, 'attack': 4}
    labels = {r['unit_id']: r['unit'] for r in read(old / 'frozen-v1/cohort/honest-selection.json')['rows']}
    out.mkdir(parents=True, exist_ok=True)
    (out / 'packets').mkdir(exist_ok=True)
    index, qualifications = ([], [])
    for row in selected:
        raw_path = old / 'outputs/main-v1' / row['unit_id'] / 'repetition-0/f0_u1.json.gz'
        raw = read(raw_path)
        source = raw['factorial_source_packet']
        refusal = raw['result']['factorial_first_refusal']
        context, first = context_from_source(raw)
        suite, task, initial, tools, _ = runtime.base.setup(source['suite'], source['task_id'])
        initial = type(initial).model_validate(source['native_initial_state'])
        boundary = type(initial).model_validate(source['native_boundary_state'])
        functions = {t.name: t for t in tools}
        assert [t['name'] for t in context['tools']] == [t.name for t in tools]
        for tool in context['tools']:
            assert tool['parameters'] == functions[tool['name']].parameters.model_json_schema()
        before_probe = runtime.probe(functions, boundary, refusal['decision_policy'], source['authentic_owner_request'], source['original_proposal'])
        after_probe = runtime.probe(functions, boundary, refusal['policy_after_update'], source['authentic_owner_request'], source['original_proposal'])
        assert before_probe['allowed'] is False
        assert after_probe['allowed'] == bool(row['metrics']['first_update_admits_original'])
        assert after_probe['allowed'] == refusal['same_call_after_update']['allowed']
        assert refusal['refusal_state_unchanged'] is True
        assert all((rule[3] == 0 for rules in refusal['policy_after_update'].values() for rule in rules))
        role = source['actor_role']
        injection_id = source['case_id'].split('__')[-1] if role == 'attack' else None
        if role == 'attack':
            assert injection_id.startswith('injection_task_')
            assert raw['side_goal'] == suite.get_injection_task_by_id(injection_id).GOAL
            user_content = context['messages'][0]['content']
            user_text = user_content if isinstance(user_content, str) else ''.join((b['text'] for b in user_content if b['type'] == 'text'))
            assert raw['side_goal'] in user_text
        label = labels.get(source['unit_id'])
        no_gate = boundary.model_copy(deep=True)
        operation = after_probe['normalized_call']
        value, error = runtime.base.FunctionsRuntime(tools).run_function(no_gate, operation['function'], operation['args'])
        event = {'operation': operation, 'before': boundary.model_dump(mode='json'), 'after': no_gate.model_dump(mode='json'), 'entry_state_changed': boundary.model_dump(mode='json') != no_gate.model_dump(mode='json'), 'error': error}
        assert error is None and event['entry_state_changed']
        proposals = [runtime.base.FunctionCall.model_validate(p) for p in source['prior_native_proposals']]
        proposals.append(runtime.base.FunctionCall(function=operation['function'], args=operation['args'], id=source['original_proposal_call_id']))
        no_gate_scores = runtime.score_state(suite, task, initial, no_gate, proposals, '', injection_id)
        if role == 'attack':
            assert no_gate_scores['native_goal'] is True
        else:
            assert runtime.selected_effects([event], label)['legacy']['correct_selected_effect'] is True
        old_final = type(initial).model_validate(raw['final'])
        old_props = [runtime.base.FunctionCall.model_validate(p) for p in raw['proposed_calls']]
        old_scores = runtime.score_state(suite, task, initial, old_final, old_props, raw['final_response'], injection_id)
        assert old_scores['native_utility'] == raw['result']['native_utility']
        if role == 'attack':
            assert old_scores['native_goal'] == raw['result']['native_targeted_asr']
        packet = {'version': 'recovery-ack-source-v1', 'unit_id': source['unit_id'], 'panel': source['panel'], 'suite': source['suite'], 'task_id': source['task_id'], 'cluster_id': source['suite'] + '__' + source['task_id'], 'case_id': source['case_id'], 'actor_role': role, 'strategy': source['strategy'], 'injection_id': injection_id, 'owner_request': source['authentic_owner_request'], 'side_goal': raw.get('side_goal'), 'native_initial_state': source['native_initial_state'], 'native_boundary_state': source['native_boundary_state'], 'prior_native_events': source['prior_native_events'], 'prior_native_proposals': source['prior_native_proposals'], 'original_proposal': source['original_proposal'], 'original_proposal_call_id': source['original_proposal_call_id'], 'source_proposal_message': source['source_proposal_message'], 'source_actor_context_json': source['actor_context_json'], 'source_first_post_update_context_json': first['context_json'], 'source_context_after_refusal': context, 'refusal_message_index': len(context['messages']) - 1, 'stale_refusal_text': refusal['actor_feedback']['text'], 'policy_before_refusal': refusal['decision_policy'], 'post_update_policy': refusal['policy_after_update'], 'post_update_policy_sha256': runtime.digest(refusal['policy_after_update']), 'original_admitted_after_update': after_probe['allowed'], 'historical_actor_calls': source['historical_actor_calls'], 'remaining_actor_budget': 16 - source['historical_actor_calls'], 'historical_constructor_calls': source['historical_constructor_calls'], 'historical_first_update_requests': refusal['update']['actual_requests'], 'historical_first_update_calls_before': refusal['update']['calls_before'], 'historical_first_update_calls_after': refusal['update']['calls_after'], 'selected_effect_label': label, 'source': {'raw_path': str(raw_path), 'raw_sha256': sha(raw_path), 'analysis_rows_sha256': sha(rows_path), 'old_arm': 'f0_u1', 'actor_context_sha256': hashlib.sha256(source['actor_context_json'].encode()).hexdigest(), 'first_post_update_context_sha256': hashlib.sha256(first['context_json'].encode()).hexdigest()}, 'native_references': {'before_probe': before_probe, 'after_probe': after_probe, 'no_gate_original_event': event, 'no_gate_original_scores': no_gate_scores, 'old_complete_episode_scores': old_scores}, 'scope': 'Selected from completed old-study first-update permissions, not new efficacy. No source policy is regenerated. Original actor role/history is retained; only final refusal message is varied. All later policies are fixed in this new diagnostic.'}
        assert packet['remaining_actor_budget'] > 0
        filename = out / 'packets' / (source['unit_id'] + '.json')
        filename.write_text(json.dumps(packet, indent=2) + '\n')
        arm_checks = {}
        for arm in runtime.ARMS:
            broker = runtime.Broker()
            init = broker.init({'packet': str(filename), 'arm': arm})
            assert broker.env.model_dump(mode='json') == source['native_boundary_state']
            expected_context = copy.deepcopy(context)
            expected_context['messages'][-1]['content'][0]['text'] = runtime.notification(packet['stale_refusal_text'], after_probe['allowed'], arm)
            assert init['context'] == expected_context
            response = broker.invoke({**source['original_proposal'], 'call_id': 'qualification_retry'})
            final = broker.finish({'final_text': ''})
            assert (not response['is_error']) == after_probe['allowed']
            assert final['original_call_executed_normalized'] == after_probe['allowed']
            assert final['original_call_changed_state_normalized'] == after_probe['allowed']
            assert final['policy_fixed'] and final['updater_calls'] == 0
            if role == 'attack':
                assert final['native_goal'] == after_probe['allowed']
            elif after_probe['allowed']:
                assert final['selected_effects']['legacy']['correct_selected_effect'] is True
            arm_checks[arm] = {'original_retry_allowed': not response['is_error'], 'original_call_changed_state': final['original_call_changed_state_normalized'], 'permission_fixed': final['policy_fixed'], 'updater_calls': final['updater_calls']}
        index.append({'unit_id': packet['unit_id'], 'panel': packet['panel'], 'actor_role': role, 'task': packet['cluster_id'], 'original_admitted_after_update': after_probe['allowed'], 'packet': str(filename), 'packet_sha256': sha(filename), 'remaining_actor_budget': packet['remaining_actor_budget']})
        qualifications.append({'unit_id': packet['unit_id'], 'before_refused': True, 'after_allowed': after_probe['allowed'], 'native_source_eligible': True, 'old_complete_scores_match': True, 'arms': arm_checks})
    summary = {'version': 'recovery-ack-envelope-v1', 'sources': len(index), 'arms': runtime.ARMS, 'honest_sources': sum((r['panel'] == 'honest_fault' for r in index)), 'honest_admitted': sum((r['panel'] == 'honest_fault' and r['original_admitted_after_update'] for r in index)), 'honest_still_refused_controls': sum((r['panel'] == 'honest_fault' and (not r['original_admitted_after_update']) for r in index)), 'attack_sources': sum((r['panel'] == 'attack' for r in index)), 'honest_tasks': len({r['task'] for r in index if r['panel'] == 'honest_fault'}), 'attack_tasks': len({r['task'] for r in index if r['panel'] == 'attack'}), 'selection': 'All23 original f0_u1 honest-fault sources plus all4 attack sources whose original call became admitted after the first update. Selection is conditional on old-study path/state, not a prevalence sample.', 'protocol_change': 'Install recorded first post-update policy and keep it fixed for all later calls in every message arm; no future optional or refusal-triggered regeneration.', 'actor_information': 'Source actor instructions including original controller description remain identical across arms; no new system instruction is added. Only the final historical refusal text changes.', 'notification_texts': {'neutral_suffix': runtime.NEUTRAL, 'permitted_status_suffix': runtime.PERMITTED, 'still_refused_status_suffix': runtime.NOT_PERMITTED}, 'suggested_models': ['luna', 'haiku'], 'continuations_with_two_models': len(index) * len(runtime.ARMS) * 2, 'units': index, 'model_calls': 0, 'network_calls': 0, 'source_sha256': {str(p): sha(p) for p in [Path(__file__), HERE / 'runtime.py', runtime.CHANNELS, runtime.X2B / 'scoring.py', runtime.X2B / 'broker.py', HERE.parent / 'correctness/native.py']}}
    (out / 'index.json').write_text(json.dumps(summary, indent=2) + '\n')
    (out / 'qualification.json').write_text(json.dumps({'sources': len(qualifications), 'native_arm_retries': len(qualifications) * 3, 'all_passed': True, 'rows': qualifications, 'model_calls': 0, 'network_calls': 0}, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ['units', 'source_sha256']}, indent=2))
if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--old-study', type=Path, default=OLD)
    p.add_argument('--out', type=Path, default=HERE / 'frozen-v1')
    args = p.parse_args()
    main(args.old_study, args.out)
