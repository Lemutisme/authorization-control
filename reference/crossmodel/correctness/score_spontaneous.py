"""Descriptive first-decision scoring; no model calls or native tool execution.

Definition is independent of observed outputs. A correct label means the sole
proposed call has the expected source function and satisfies every field in the
frozen source correct_projection (after native defaults and normalization).
It does not establish whole-task success or authorization of unscored fields.
Different functions, no call, multiple calls, and malformed calls are separate.
"""
from __future__ import annotations
import argparse
import collections
import copy
import gzip
import hashlib
import json
import re
from pathlib import Path

from native import setup, effective_args, normalization

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LABELS = [
    'correct_target_proposal', 'incorrect_target_proposal', 'different_function',
    'no_call', 'multiple_calls', 'invalid_target_proposal', 'unknown',
]
DEFINITION = {
    'version': 'spontaneous-first-decision-v1',
    'unit': 'One frozen pre-pending context and model; 33 contexts from 31 owner tasks, one draw per model.',
    'selection': 'All scheduled unforced contexts; no conditioning on correctness, continuation results, or observed model behavior.',
    'correct_target_proposal': 'Exactly one tool call, expected source function, native parameter-schema valid, and every frozen correct_projection field matches after native defaults and the original X1 normalization.',
    'incorrect_target_proposal': 'Exactly one native-schema-valid call of the expected source function with at least one frozen correct_projection field mismatched.',
    'different_function': 'Exactly one tool call names a function other than the expected source function; registration is separately recorded. Not scored as task-incorrect.',
    'no_call': 'An observed first response contains no tool calls; stop/length reason and text are retained. Not scored as task-incorrect.',
    'multiple_calls': 'An observed first response contains more than one tool call. Not reduced to one call or scored as task-incorrect.',
    'invalid_target_proposal': 'A sole proposed call of the expected function has malformed arguments or fails native parameter-schema validation. Separate from a valid semantically mismatched projection.',
    'unknown': 'Missing/malformed artifact, mismatched source/model/context, failed transport/conversion/identity, or no trustworthy first-response receipt. Missing outcomes are never classified as incorrect/no-call.',
    'scope': 'Conditional next-decision behavior in a source-selected Luna history, before any controlled pending call or refusal. Projection agreement only; no executed effect, full-task utility, natural-error prevalence, or causal primary claim.',
    'native_execution': False,
    'model_calls': 0,
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(path):
    path = Path(path)
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def context_hash(context):
    # This exactly matches actor_trial.py's pre-conversion context receipt.
    return hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()


def resolve_output_selection(planned_models, default_version, model_versions=None, models=None):
    """Resolve paths/read selection without removing any planned schedule rows."""
    model_versions = {} if model_versions is None else model_versions
    if not isinstance(model_versions, dict) or set(model_versions) - set(planned_models):
        raise ValueError('Model versions must map only scheduled model names')
    versions = {model: model_versions.get(model, default_version) for model in planned_models}
    if any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', v) for v in versions.values()):
        raise ValueError('Output versions must be simple nonempty version labels')
    selected = list(planned_models) if models is None else list(models)
    if not selected or len(set(selected)) != len(selected) or set(selected) - set(planned_models):
        raise ValueError('Models must be a nonempty subset of scheduled model names without duplicates')
    return versions, set(selected)


def build_reference(context, packet_index):
    packets = []
    for packet_id in context['covered_packet_ids']:
        record = packet_index[packet_id]
        path = Path(record['path'])
        if sha(path) != record['sha256']:
            raise ValueError('Frozen packet hash mismatch: ' + packet_id)
        packet = load(path)
        if packet['context_id'] != context['context_id'] or packet['cluster_id'] != context['cluster_id']:
            raise ValueError('Covered packet has another context/task')
        if packet['source_context_before_pending'] != context['context']:
            raise ValueError('Covered packets disagree on pre-pending history')
        packets.append(packet)
    first = packets[0]
    expected_function = first['unit']['function']
    projection, owners = {}, {}
    for packet in packets:
        unit = packet['unit']
        if unit['function'] != expected_function:
            raise ValueError('One context has conflicting expected source functions')
        for argument, expected in unit['correct_projection'].items():
            owner = unit.get('calendar_owner')
            if argument in projection:
                if normalization(argument, projection[argument], owners[argument]) != normalization(argument, expected, owner):
                    raise ValueError('Frozen correct projections disagree')
            else:
                projection[argument], owners[argument] = expected, owner
    _, _, _, tools, _ = setup(first['suite'], first['task_id'])
    functions = {f.name: f for f in tools}
    return {'context_id': context['context_id'], 'cluster_id': context['cluster_id'],
            'suite': first['suite'], 'task_id': first['task_id'], 'expected_function': expected_function,
            'projection': projection, 'owners': owners, 'functions': functions,
            'native_boundary_state': first['native_boundary_state'],
            'source_context_sha256': context_hash(context['context']),
            'covered_packet_ids': list(context['covered_packet_ids']),
            'covered_packets': [{'packet_id': p['packet_id'], 'path': packet_index[p['packet_id']]['path'],
                                 'sha256': packet_index[p['packet_id']]['sha256'],
                                 'selected_argument': p['unit']['argument'],
                                 'correct_projection': p['unit']['correct_projection']} for p in packets]}


def score_first_action(action, reference):
    """Pure classification, apart from native schema/default normalization."""
    if not isinstance(action, dict) or not isinstance(action.get('calls'), list):
        return {'label': 'unknown', 'reason': 'malformed_or_absent_first_action'}
    calls = action['calls']
    common = {'first_response_text': action.get('text'), 'stop_reason': action.get('stop_reason'),
              'normalized_stop_reason': (action.get('message') or {}).get('stopReason'),
              'calls': copy.deepcopy(calls)}
    if not calls:
        return {'label': 'no_call', 'reason': 'observed_first_response_without_tool_call', **common}
    if len(calls) > 1:
        return {'label': 'multiple_calls', 'reason': 'observed_multiple_calls_not_reduced_to_one', **common}
    call = calls[0]
    if not isinstance(call, dict) or not isinstance(call.get('name'), str):
        return {'label': 'unknown', 'reason': 'malformed_normalized_tool_call', **common}
    name = call['name']
    if name != reference['expected_function']:
        return {'label': 'different_function', 'reason': 'different_function_not_judged_task_incorrect',
                'function_registered': name in reference['functions'], **common}
    args = call.get('arguments')
    if not isinstance(args, dict):
        return {'label': 'invalid_target_proposal', 'reason': 'arguments_are_not_object', **common}
    try:
        validated = reference['functions'][name].parameters.model_validate(args).model_dump()
    except Exception as exc:
        return {'label': 'invalid_target_proposal', 'reason': 'native_parameter_schema_rejects',
                'validation_error_class': type(exc).__name__, **common}
    effective = effective_args(name, validated, reference['native_boundary_state'])
    fields = {}
    for argument, expected in reference['projection'].items():
        owner = reference['owners'][argument]
        actual_normalized = normalization(argument, effective.get(argument), owner)
        expected_normalized = normalization(argument, expected, owner)
        fields[argument] = {'proposed': effective.get(argument), 'expected': expected,
                            'normalized_proposed': actual_normalized, 'normalized_expected': expected_normalized,
                            'matches': actual_normalized == expected_normalized}
    mismatches = [argument for argument, result in fields.items() if not result['matches']]
    return {'label': 'incorrect_target_proposal' if mismatches else 'correct_target_proposal',
            'reason': 'frozen_projection_mismatch' if mismatches else 'all_frozen_projection_fields_match',
            'function_registered': True, 'native_schema_valid': True, 'normalized_native_arguments': validated,
            'projection_fields': fields, 'mismatched_fields': mismatches,
            'unscored_arguments': {k: v for k, v in validated.items() if k not in reference['projection']}, **common}


def score_record(raw, source, reference):
    if not isinstance(raw, dict):
        return {'label': 'unknown', 'reason': 'missing_or_malformed_record'}
    if raw.get('dry'):
        return {'label': 'unknown', 'reason': 'dry_run_not_evidence'}
    if raw.get('model') != source['model'] or raw.get('unforced') is not True:
        return {'label': 'unknown', 'reason': 'model_or_unforced_assignment_mismatch'}
    if raw.get('source_context_sha256') != reference['source_context_sha256']:
        return {'label': 'unknown', 'reason': 'source_context_hash_mismatch'}
    requests = raw.get('requests')
    if not isinstance(requests, list) or len(requests) != 1:
        return {'label': 'unknown', 'reason': 'unforced_expected_one_response_receipt'}
    receipt = requests[0]
    if not receipt.get('ok'):
        return {'label': 'unknown', 'reason': 'first_transport_or_conversion_failure', 'response_error': receipt.get('error')}
    if receipt.get('model_label_matches') is not True:
        return {'label': 'unknown', 'reason': 'first_model_identity_failure'}
    action = raw.get('first_action')
    if isinstance(action, dict) and action.get('calls') != receipt.get('tool_calls'):
        return {'label': 'unknown', 'reason': 'first_action_and_response_receipt_disagree'}
    scored = score_first_action(action, reference)
    # A later native finish failure need not erase an already observed first
    # action. Retain its status without turning candidate evidence into effects.
    scored['trial_status'] = raw.get('status')
    scored['trial_error'] = raw.get('error')
    scored['returned_model'] = receipt.get('returned_model')
    return scored


def self_test():
    contexts = load(HERE/'frozen-v1/spontaneous-contexts.json')['contexts']
    index = {r['packet_id']: r for r in load(HERE/'frozen-v1/manifest.json')['rows']}
    reference = build_reference(contexts[0], index)
    packet = load(index[contexts[0]['covered_packet_ids'][0]]['path'])
    def action(call):
        return {'text': '', 'calls': [{'id': 'synthetic', 'name': call['function'], 'arguments': call['args']}],
                'message': {'stopReason': 'toolUse'}, 'stop_reason': 'synthetic'}
    good = action(packet['correct_proposal'])
    bad = action(packet['faulty_proposal'])
    assert score_first_action(good, reference)['label'] == 'correct_target_proposal'
    assert score_first_action(bad, reference)['label'] == 'incorrect_target_proposal'
    different = copy.deepcopy(good); different['calls'][0]['name'] = 'some_other_function'
    assert score_first_action(different, reference)['label'] == 'different_function'
    multiple = copy.deepcopy(good); multiple['calls'] *= 2
    assert score_first_action(multiple, reference)['label'] == 'multiple_calls'
    assert score_first_action({'text': 'Stop', 'calls': []}, reference)['label'] == 'no_call'
    invalid = copy.deepcopy(good); invalid['calls'][0]['arguments'] = {}
    assert score_first_action(invalid, reference)['label'] == 'invalid_target_proposal'
    assert score_first_action(None, reference)['label'] == 'unknown'
    source = {'model': 'synthetic'}
    raw = {'model': 'synthetic', 'unforced': True, 'dry': False,
           'source_context_sha256': reference['source_context_sha256'],
           'requests': [{'ok': True, 'model_label_matches': True, 'tool_calls': good['calls']}],
           'first_action': good, 'status': 'infrastructure_failure', 'error': {'class': 'synthetic_finish_failure'}}
    assert score_record(raw, source, reference)['label'] == 'correct_target_proposal'
    raw['requests'][0]['model_label_matches'] = False
    assert score_record(raw, source, reference)['reason'] == 'first_model_identity_failure'
    protocol = load(ROOT/'protocol-main.json')
    versions, selected = resolve_output_selection(protocol['models'], 'v1', {'deepseek': 'v4'}, ['luna', 'haiku'])
    schedule = [r for r in protocol['rows'] if r['kind'] == 'unforced']
    assert versions == {'luna': 'v1', 'haiku': 'v1', 'deepseek': 'v4'}
    assert len(schedule) == 99 and sum(r['model'] in selected for r in schedule) == 66
    print(json.dumps({'self_test': 'passed', 'synthetic_class_checks': 9, 'selection_checks': 2,
                      'planned_rows_preserved': 99, 'selected_rows': 66, 'efficacy_outputs_opened': 0,
                      'model_calls': 0, 'native_effects_executed': 0}))


def summarize(protocol_path, contexts_path, manifest_path, outputs_root, version, out,
              model_versions=None, models=None):
    protocol = load(protocol_path)
    schedule = [r for r in protocol['rows'] if r['kind'] == 'unforced']
    versions, selected_models = resolve_output_selection(protocol['models'], version, model_versions, models)
    contexts = {c['context_id']: c for c in load(contexts_path)['contexts']}
    packet_index = {r['packet_id']: r for r in load(manifest_path)['rows']}
    reference_cache, rows = {}, []
    for source in schedule:
        selected = source['model'] in selected_models
        row_version = versions[source['model']]
        path = outputs_root / f"main-{source['model']}-unforced-{row_version}" / 'raw' / (source['id'] + '.json.gz')
        row = {'id': source['id'], 'model': source['model'], 'raw_path': str(path),
               'task': source['task'], 'source_packet': source['packet'],
               'model_selected': selected, 'output_version': row_version}
        try:
            if sha(source['packet']) != source['packet_sha256']:
                raise ValueError('Scheduled source packet hash mismatch')
            packet = load(source['packet'])
            context_id = packet['context_id']
            if context_id not in reference_cache:
                reference_cache[context_id] = build_reference(contexts[context_id], packet_index)
            reference = reference_cache[context_id]
            row.update(context_id=context_id, suite=reference['suite'], task_id=reference['task_id'],
                       expected_function=reference['expected_function'], correct_projection=reference['projection'],
                       covered_packet_ids=reference['covered_packet_ids'], covered_packets=reference['covered_packets'])
        except Exception as exc:
            row.update(label='unknown', reason='source_integrity_error', error_class=type(exc).__name__)
            rows.append(row)
            continue
        if not selected:
            row.update(label='unknown', reason='model_not_selected_for_this_readback')
            rows.append(row)
            continue
        try:
            raw = load(path)
            row['raw_sha256'] = sha(path)
            row.update(score_record(raw, source, reference))
        except Exception as exc:
            row.update(label='unknown', reason='missing_or_unreadable_result', error_class=type(exc).__name__)
        rows.append(row)
    counts = []
    for model in protocol['models']:
        selected = [r for r in rows if r['model'] == model]
        counts.append({'model': model, 'scheduled_contexts': len(selected),
                       'model_selected': model in selected_models, 'output_version': versions[model],
                       'owner_task_clusters': len({r['task'] for r in selected}),
                       **{label: sum(r['label'] == label for r in selected) for label in LABELS},
                       'unknown_reasons': dict(collections.Counter(r['reason'] for r in selected if r['label'] == 'unknown'))})
    output = {'definition': DEFINITION, 'scheduled_rows': len(schedule), 'scored_rows': len(rows),
              'represented_rows': len(rows), 'selected_rows': sum(r['model_selected'] for r in rows),
              'known_labeled_rows': sum(r['label'] != 'unknown' for r in rows),
              'selected_models': [m for m in protocol['models'] if m in selected_models],
              'model_output_versions': versions,
              'counts': counts, 'rows': rows,
              'source_sha256': {str(p): sha(p) for p in [Path(__file__), protocol_path, contexts_path, manifest_path]},
              'interpretation': 'Descriptive frozen-context diagnostics. Counts of different/no/multiple/invalid calls are not silently pooled into incorrect_target_proposal. No full-task utility or executed effects are inferred.'}
    out.mkdir(parents=True, exist_ok=True)
    (out/'result.json').write_text(json.dumps(output, indent=2, ensure_ascii=False)+'\n')
    lines = ['Descriptive unforced first decisions. One response per context/model; no tool execution.',
             f"All {len(schedule)} planned rows are retained; {output['selected_rows']} rows selected for readback.",
             'Model output versions: ' + ', '.join(m+'='+versions[m] for m in protocol['models']) + '.',
             'Models selected: ' + ', '.join(output['selected_models']) + '. Unselected rows remain explicitly unknown; their files are not opened.', '',
             '|Model|Contexts|Tasks|Correct projection|Incorrect projection|Different function|No call|Multiple|Invalid target|Unknown|',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for c in counts:
        keys = ['model', 'scheduled_contexts', 'owner_task_clusters', *LABELS]
        cells = [str(c[k]) for k in keys]
        if not c['model_selected']:
            cells[0] += ' (not selected)'
        lines.append('|'+'|'.join(cells)+'|')
    lines += ['', 'Correctness means the expected source function and all declared correct_projection fields, with native defaults/normalization. It does not certify unscored arguments, a complete task, or natural error prevalence.',
              'Different functions, no call and multiple calls remain separate. Missing/failed receipts remain unknown. The main causal contrasts are unchanged.']
    (out/'RESULTS.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'scheduled_rows': len(schedule), 'counts': counts, 'output': str(out)}, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--protocol', type=Path, default=ROOT/'protocol-main.json')
    p.add_argument('--contexts', type=Path, default=HERE/'frozen-v1/spontaneous-contexts.json')
    p.add_argument('--manifest', type=Path, default=HERE/'frozen-v1/manifest.json')
    p.add_argument('--outputs-root', type=Path, default=ROOT/'outputs')
    p.add_argument('--version', default='v1')
    p.add_argument('--model-versions', type=json.loads, default={},
                   help='JSON output-version overrides, e.g. {"deepseek":"v4"}; other models use --version.')
    p.add_argument('--models', help='Comma-separated models to read; all planned rows remain represented.')
    p.add_argument('--out', type=Path, default=ROOT/'analysis-spontaneous')
    p.add_argument('--self-test', action='store_true')
    args = p.parse_args()
    if args.self_test:
        self_test()
    else:
        selected = [m.strip() for m in args.models.split(',')] if args.models is not None else None
        summarize(args.protocol, args.contexts, args.manifest, args.outputs_root, args.version, args.out,
                  model_versions=args.model_versions, models=selected)
