"""Freeze symmetric correctness cells from the pre-existing X1 M1/M2 envelope."""
from __future__ import annotations
import argparse
import copy
import gzip
import hashlib
import json
from collections import Counter
from pathlib import Path
from native import setup, native_call, check, effects, normalization, digest, PanelBroker, FunctionsRuntime


def read(p):
    data = p.read_bytes()
    return json.loads(gzip.decompress(data) if p.suffix == '.gz' else data)


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def portable_assistant(message):
    content = []
    for part in message['content']:
        if part['type'] == 'text':
            content.append({'type': 'text', 'text': part['text']})
        elif part['type'] == 'toolCall':
            content.append({'type': 'toolCall', 'id': part['id'], 'name': part['name'], 'arguments': part['arguments']})
        else:
            raise ValueError('Unexpected original assistant content: ' + part['type'])
    return {'role': 'assistant', 'content': content}


def history(raw, folder, anchor):
    messages = [{'role': 'user', 'content': raw['prompt']}]
    seen = 0
    sources = []
    for draw, info in enumerate(raw['result']['pi']['calls']):
        p = folder / 'actor-cache' / (info['coupling']['request_sha256'] + '.json')
        cached = read(p)
        sources.append({'path': str(p), 'sha256': sha(p), 'response_sha256': cached['response_sha256']})
        message = portable_assistant(cached['message'])
        calls = [b for b in message['content'] if b['type'] == 'toolCall']
        if len(calls) > 1:
            raise ValueError('Batch source proposal requires an explicit protocol')
        if calls and seen == anchor['proposed_index']:
            call = calls[0]
            assert call['name'] == anchor['function'] and call['arguments'] == anchor['args']
            return messages, message, draw, sources
        messages.append(message)
        for call in calls:
            original = raw['proposed_calls'][seen]
            observation = raw['observations'][seen]
            assert call['id'] == original['id'] and call['name'] == original['function']
            assert call['arguments'] == original['args'] == observation['args']
            messages.append({'role': 'toolResult', 'toolCallId': call['id'], 'toolName': call['name'],
                             'content': [{'type': 'text', 'text': observation['text']}], 'isError': observation['is_error']})
            seen += 1
    raise ValueError('Pending source proposal not found')


def replay_prefix(raw, anchor, initial, tools):
    state = type(initial).model_validate(raw['initial'])
    runtime = FunctionsRuntime(tools)
    checks = []
    for i, call in enumerate(raw['proposed_calls'][:anchor['proposed_index']]):
        source_event = raw['events'][i]
        assert state.model_dump(mode='json') == source_event['before']
        _, error = runtime.run_function(state, call['function'], call['args'])
        assert state.model_dump(mode='json') == source_event['after']
        assert error == source_event['error']
        checks.append({'index': i, 'function': call['function'], 'state_matches': True, 'error_matches': True})
    assert state.model_dump(mode='json') == anchor['before']
    return {'prior_events': len(checks), 'boundary_matches': True, 'checks': checks}


def prepare(jobs, source, out):
    out.mkdir(parents=True, exist_ok=True)
    packet_dir = out / 'packets'
    packet_dir.mkdir(exist_ok=True)
    cohort_path = source / 'cohort.json'
    manifest_path = jobs / 'authorship-x1-prepare-v2/artifacts/branches/manifest.json'
    cohort, manifest = read(cohort_path), read(manifest_path)
    units = {u['unit_id']: u for u in cohort['units']}
    selected = sorted([c for c in manifest['condition_rows'] if c['fault_class'] in ['M1', 'M2'] and c['feedback'] == 'F0'],
                      key=lambda c: (c['cluster_id'], c['unit_id'], c['fault_class']))
    assert len(selected) == 83
    rows, contexts, references = [], {}, []
    for condition in selected:
        unit = units[condition['unit_id']]
        folder = jobs / 'authorship-x1-prefix-main-v1/artifacts' / unit['case_id']
        rawpath = folder / 'prefix.json.gz'
        raw = read(rawpath)
        anchor = raw['result']['x1_prefix_anchors'][unit['function']]
        messages, pending_message, historical_draws, caches = history(raw, folder, anchor)
        suite, task, initial, tools, instructions = setup(unit['suite'], unit['task_id'])
        tool_specs = [{'name': f.name, 'description': f.description, 'parameters': f.parameters.model_json_schema()} for f in tools]
        context = {'system': instructions, 'messages': messages, 'tools': tool_specs}
        # Main symmetric manipulation standardizes the pending call to a single
        # tool block. It adds any implicit correct companion projection explicitly
        # to ensure only the selected value differs between c and w.
        correct_args = copy.deepcopy(anchor['args'])
        correct_args.update(unit['correct_projection'])
        fn = next(f for f in tools if f.name == unit['function'])
        correct = {'function': unit['function'], 'args': fn.parameters.model_validate(correct_args).model_dump()}
        faulty = copy.deepcopy(correct)
        faulty['args'][unit['argument']] = condition['fault_value']
        faulty['args'] = fn.parameters.model_validate(faulty['args']).model_dump()
        context_id = digest({'context': context, 'boundary': anchor['before']})[:24]
        replay = replay_prefix(raw, anchor, initial, tools)
        packet = {'version': 'correctness-symmetric-panel-v1', 'packet_id': condition['unit_id'] + '__' + condition['fault_class'],
                  'unit_id': unit['unit_id'], 'cluster_id': unit['cluster_id'], 'case_id': unit['case_id'],
                  'suite': unit['suite'], 'task_id': unit['task_id'], 'fault_class': condition['fault_class'],
                  'fault_value': condition['fault_value'], 'unit': unit, 'owner_request': raw['prompt'],
                  'source_context_before_pending': context, 'context_id': context_id,
                  'source_pending_assistant_message': pending_message,
                  'source_original_proposal': {'function': anchor['function'], 'args': anchor['args']},
                  'correct_proposal': correct, 'faulty_proposal': faulty,
                  'native_initial_state': raw['initial'], 'native_boundary_state': anchor['before'],
                  'native_prefix_replay': replay,
                  'prior_native_proposals': raw['proposed_calls'][:anchor['proposed_index']],
                  'prior_native_events': raw['events'][:anchor['proposed_index']],
                  'historical_actor_draws_before_pending': historical_draws,
                  'historical_actor_draws_including_pending': historical_draws + 1,
                  'remaining_actor_budget': 16 - historical_draws - 1,
                  'source': {'prefix': str(rawpath), 'prefix_sha256': sha(rawpath), 'cohort_sha256': sha(cohort_path),
                             'branch_manifest_sha256': sha(manifest_path), 'actor_cache_records': caches},
                  'scope': 'Frozen Luna-generated prefix; c/w pending proposals are supplied interventions, never sampled Haiku choices. Portable source text/tool history is retained; provider metadata is omitted. The main pending message is tool-only, and companion projection/defaults are explicit.'}
        assert packet['remaining_actor_budget'] > 0
        refs = {}
        for label, call in [('correct', correct), ('faulty', faulty)]:
            event, _ = native_call(unit['suite'], unit['task_id'], anchor['before'], call)
            values = effects.effect_values(event, unit)
            target = unit['correct_value'] if label == 'correct' else condition['fault_value']
            assert event['error'] is None and event['entry_state_changed']
            matches = any(normalization(unit['argument'], v, unit.get('calendar_owner')) == normalization(unit['argument'], target, unit.get('calendar_owner')) for v in values)
            # Original X1 feasibility required any state change. A sibling value
            # can already occupy the selected field while a companion field changes.
            # Retain such pre-existing units and report the selected-field no-op.
            assert not values or matches
            refs[label] = {'native_event': event, 'selected_values': values, 'selected_effect_observed': matches,
                           'selected_field_noop': not values}
        cells = {}
        for ac in [True, False]:
            for gc in [True, False]:
                key = ('actor_correct' if ac else 'actor_wrong') + '__' + ('gate_correct' if gc else 'gate_wrong')
                call = correct if ac else faulty
                decisions = {f: check(packet, call, gc, feedback=f) for f in ['value_stating', 'value_free', 'original_F0', 'original_F3']}
                assert all(d['allowed'] == (ac == gc) for d in decisions.values())
                if ac != gc:
                    assert decisions['value_stating']['failed_argument'] == unit['argument']
                    assert decisions['value_free']['feedback'] != decisions['value_stating']['feedback']
                cells[key] = {'actor_correct': ac, 'gate_correct': gc, 'decision': decisions,
                              'native_reference': None if ac != gc else refs['correct' if ac else 'faulty']}
        packet['cells'] = cells
        filename = packet_dir / (packet['packet_id'] + '.json')
        filename.write_text(json.dumps(packet, indent=2) + '\n')
        rows.append({'packet_id': packet['packet_id'], 'unit_id': unit['unit_id'], 'context_id': context_id,
                     'cluster_id': unit['cluster_id'], 'suite': unit['suite'], 'fault_class': condition['fault_class'],
                     'path': str(filename), 'sha256': sha(filename), 'remaining_actor_budget': packet['remaining_actor_budget']})
        contexts.setdefault(context_id, {'context_id': context_id, 'cluster_id': unit['cluster_id'], 'suite': unit['suite'],
                                        'packet_path': str(filename), 'context': context, 'native_boundary_state': anchor['before'],
                                        'native_initial_state': raw['initial'], 'prior_native_proposals': packet['prior_native_proposals'],
                                        'historical_actor_draws': historical_draws, 'remaining_actor_budget': 16-historical_draws,
                                        'meaning': 'Unforced next decision before any controlled pending call/refusal; sample once per context and replicate independently of main outcomes.'})
        contexts[context_id].setdefault('covered_packet_ids', []).append(packet['packet_id'])
        references.append({'packet_id': packet['packet_id'], 'cell_allowed': {k: c['decision']['value_free']['allowed'] for k, c in cells.items()},
                           'correct_native_values': refs['correct']['selected_values'], 'faulty_native_values': refs['faulty']['selected_values'],
                           'correct_selected_field_noop': refs['correct']['selected_field_noop'],
                           'faulty_selected_field_noop': refs['faulty']['selected_field_noop'],
                           'native_prefix_replay': replay})
    summary = {'version': 'correctness-symmetric-panel-v1', 'packets': len(rows), 'unique_argument_units': len({r['unit_id'] for r in rows}),
               'task_clusters': len({r['cluster_id'] for r in rows}), 'unique_pre_pending_contexts': len(contexts),
               'by_suite': dict(Counter(r['suite'] for r in rows)), 'by_fault_class': dict(Counter(r['fault_class'] for r in rows)),
               'correct_selected_field_noops': sum(r['correct_selected_field_noop'] for r in references),
               'faulty_selected_field_noops': sum(r['faulty_selected_field_noop'] for r in references),
               'selection': 'All prior source-selected X1 M1+M2 actor-right faults, without new model draws or outcome filtering.',
               'independent_unit': 'owner task; fault units, correctness cells and feedback arms are paired clustered observations',
               'rows': rows, 'model_calls': 0, 'network_calls': 0,
               'source_code_sha256': {str(p): sha(p) for p in [Path(__file__), Path(__file__).with_name('native.py'), source/'cohort.py', source/'analyze.py']}}
    (out/'manifest.json').write_text(json.dumps(summary, indent=2) + '\n')
    (out/'spontaneous-contexts.json').write_text(json.dumps({'contexts': list(contexts.values()), 'selection_independent_of_new_model_outcomes': True}, indent=2) + '\n')
    (out/'native-qualification.json').write_text(json.dumps({'passed_packets': len(references), 'native_executions': len(references)*2,
        'gate_decisions': len(references)*16, 'references': references, 'model_calls': 0, 'network_calls': 0}, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ['rows', 'source_code_sha256']}, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--jobs', type=Path, default=Path('/artifact-source/80d38c89da1c/jobs'))
    p.add_argument('--source', type=Path, default=Path('/artifact-source/9efadf13d615/x1'))
    p.add_argument('--out', type=Path, default=Path(__file__).resolve().parent/'frozen-v1')
    args = p.parse_args()
    prepare(args.jobs, args.source, args.out)
