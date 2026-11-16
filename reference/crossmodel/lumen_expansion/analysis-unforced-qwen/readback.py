"""Read only the completed Lumen-Qwen unforced first-decision panel.

Uses the existing score_spontaneous definition unchanged. No model calls, no
native effects, no reading other models or actor-feedback efficacy outcomes.
"""
from __future__ import annotations
import copy
import gzip
import hashlib
import inspect
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
LUMEN = HERE.parent
STUDY = LUMEN.parent
SCORER = STUDY/'correctness/score_spontaneous.py'
sys.path.insert(0, str(SCORER.parent))
import score_spontaneous as scorer


def read(path):
    path = Path(path); data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def transport_digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


def main():
    protocol_path = LUMEN/'protocol-main.json'
    contexts_path = STUDY/'correctness/frozen-v1/spontaneous-contexts.json'
    manifest_path = STUDY/'correctness/frozen-v1/manifest.json'
    protocol = read(protocol_path)
    schedule = [r for r in protocol['rows'] if r['model'] == 'lumen_qwen' and r['kind'] == 'unforced']
    assert len(schedule) == 33
    expected_model = protocol['requested_models']['lumen_qwen']
    assert expected_model == 'qwen3.8-flash'
    contexts = {c['context_id']: c for c in read(contexts_path)['contexts']}
    packets = {r['packet_id']: r for r in read(manifest_path)['rows']}
    rows, issues = [], []
    checks = Counter()
    for source in schedule:
        path = LUMEN/'outputs/main-lumen_qwen-all-v1/raw'/(source['id']+'.json.gz')
        row = {'id': source['id'], 'raw_path': str(path), 'model_alias': 'lumen_qwen', 'expected_model_id': expected_model,
               'source_packet': source['packet'], 'task': source['task']}
        try:
            assert sha(source['packet']) == source['packet_sha256'], 'source_packet_hash'
            packet = read(source['packet'])
            context = contexts[packet['context_id']]
            reference = scorer.build_reference(context, packets)
            raw = read(path)
            row.update(raw_sha256=sha(path), context_id=context['context_id'], suite=packet['suite'], task_id=packet['task_id'],
                       expected_function=reference['expected_function'], correct_projection=reference['projection'],
                       covered_packet_ids=reference['covered_packet_ids'], covered_packets=reference['covered_packets'])
            assert raw['source_context_sha256'] == reference['source_context_sha256'], 'stored_source_context_hash'
            assert raw['model'] == 'lumen_qwen' and raw['unforced'] is True and raw['repetition'] == 0, 'assignment'
            assert raw.get('system_addendum') in [None, ''], 'unexpected_system_addendum'
            assert len(raw['requests']) == 1, 'unforced_request_count'
            request = raw['requests'][0]
            assert request.get('ok') is True and request.get('model_label_matches') is True, 'response_success_and_identity_flag'
            assert request['returned_model'] == expected_model, 'returned_model_id'
            assert request['request']['model'] == expected_model, 'wire_requested_model_id'
            assert request['message']['model'] == expected_model, 'normalized_reply_model_id'
            assert request['request_sha256'] == transport_digest(request['request']), 'wire_request_hash'
            portable = copy.deepcopy(context['context'])
            portable['systemPrompt'] = portable.pop('system')
            assert request['conversion']['source_context_sha256'] == transport_digest(portable), 'converted_source_context_hash'
            wire = request['request']
            assert wire['messages'][0] == {'role': 'system', 'content': portable['systemPrompt']}, 'wire_system_unchanged'
            expected_tools = {t['name']: t for t in portable['tools']}
            wire_tools = {t['function']['name']: t['function'] for t in wire['tools']}
            assert set(wire_tools) == set(expected_tools), 'wire_tool_names'
            assert all(wire_tools[name]['parameters'] == expected_tools[name]['parameters'] for name in expected_tools), 'wire_tool_schemas'
            assert all(wire_tools[name].get('description', '') == expected_tools[name].get('description', '') for name in expected_tools), 'wire_tool_descriptions'
            assert raw['native']['events'] == [] and raw['native_results'] == [], 'unforced_must_not_execute'
            scored = scorer.score_record(raw, source, reference)
            row.update(scored)
            row['source_context_hash_verified'] = True
            row['wire_source_hash_verified'] = True
            row['exact_model_identity_verified'] = True
            row['native_effects_executed'] = 0
            row['requested_mode'] = raw.get('model_configuration', {}).get('reasoning_mode')
            row['requested_output_cap'] = wire.get('max_tokens', wire.get('max_completion_tokens'))
            row['observed_reasoning_metadata'] = request.get('reasoning_metadata')
            if scored['label'] == 'different_function':
                call = raw['first_action']['calls'][0]
                if call['name'] in reference['functions']:
                    try:
                        reference['functions'][call['name']].parameters.model_validate(call['arguments'])
                        row['different_function_native_schema_valid'] = True
                    except Exception:
                        row['different_function_native_schema_valid'] = False
                else:
                    row['different_function_native_schema_valid'] = False
            checks['source_packet_and_covered_packet_hashes'] += 1
            checks['source_and_converted_context_hashes'] += 1
            checks['requested_returned_and_normalized_model_ids'] += 1
            checks['unchanged_system_and_tool_schemas'] += 1
            checks['single_response_without_native_execution'] += 1
        except Exception as exc:
            row.update(label='unknown', reason='audit_failure', error_class=type(exc).__name__, error_detail=str(exc))
            issues.append({'id': source['id'], 'class': type(exc).__name__, 'detail': str(exc)})
        rows.append(row)
    counts = {label: sum(r['label'] == label for r in rows) for label in scorer.LABELS}
    by_suite = {suite: {label: sum(r.get('suite') == suite and r['label'] == label for r in rows) for label in scorer.LABELS}
                for suite in sorted({r.get('suite') for r in rows if r.get('suite')})}
    different = [r for r in rows if r['label'] == 'different_function']
    deviations = [r for r in rows if r['label'] in {'incorrect_target_proposal', 'invalid_target_proposal'}]
    unique_witness = None
    if len(deviations) == 1 and deviations[0].get('expected_function') == 'delete_file':
        deviation = deviations[0]
        packet = read(deviation['source_packet'])
        reference = scorer.build_reference(contexts[deviation['context_id']], packets)
        function = reference['functions']['delete_file'].run
        implementation = function.__globals__['CloudDrive'].delete_file
        function_lines, function_line = inspect.getsourcelines(function)
        implementation_lines, implementation_line = inspect.getsourcelines(implementation)
        source_file = Path(inspect.getsourcefile(function))
        retained_file = Path('/artifact-source/9e9cfc3ab463/cloud_drive_client.py')
        assert sha(source_file) == sha(retained_file)
        files = packet['native_boundary_state']['cloud_drive']['files']
        expected_id = deviation['correct_projection']['file_id']
        target = files[expected_id]
        supplied = deviation['calls'][0]['arguments']['file_id']
        tool = next(t for t in packet['source_context_before_pending']['tools'] if t['name'] == 'delete_file')
        assert function.__globals__['CloudDriveFileID'] is str
        unique_witness = {'task': deviation['task'], 'context_id': deviation['context_id'],
            'raw_path': deviation['raw_path'], 'raw_sha256': deviation['raw_sha256'],
            'owner_request': packet['owner_request'], 'first_response_text': deviation['first_response_text'],
            'proposed_call': deviation['calls'][0], 'expected_projection': deviation['correct_projection'],
            'target_record': {k: target[k] for k in ['id_', 'filename', 'size']},
            'target_is_largest': target['size'] == max(f['size'] for f in files.values()),
            'supplied_filename_matches_target_filename': supplied == target['filename'],
            'supplied_value_is_a_native_file_id': supplied in files,
            'visible_tool_description': tool['description'],
            'visible_parameter_description': tool['parameters']['properties']['file_id']['description'],
            'native_source_file': str(source_file), 'native_source_sha256': sha(source_file),
            'retained_pinned_source_file': str(retained_file), 'retained_pinned_source_sha256': sha(retained_file),
            'runtime_and_retained_source_byte_identical': True,
            'public_function_line': function_line, 'public_function_source': ''.join(function_lines),
            'native_method_line': implementation_line, 'native_method_source': ''.join(implementation_lines),
            'identifier_conversion': 'CloudDriveFileID is str; the filename is not resolved to an ID by this cast.',
            'scoring_label_unchanged': deviation['label'],
            'semantic_interpretation': 'The model identifies the largest file and its correct ID in text, then supplies its filename, consistent with the visible tool/parameter descriptions but inconsistent with the implementation and frozen ID projection. This is an API documentation/implementation conflict, not evidence that the model failed to identify the target. No deletion was executed.',
            'native_tool_calls': 0}
        (HERE/'unique-api-contract-witness.json').write_text(json.dumps(unique_witness, indent=2, ensure_ascii=False)+'\n')
    result = {'model_alias': 'lumen_qwen', 'requested_model_id': expected_model,
              'planned_contexts': 33, 'owner_task_clusters': len({r['task'] for r in rows}),
              'counts': counts, 'by_suite': by_suite, 'checks': dict(checks), 'audit_issues': issues,
              'different_function_calls': [{'task': r['task'], 'context_id': r['context_id'], 'expected_function': r['expected_function'],
                                            'calls': r['calls'], 'native_schema_valid': r.get('different_function_native_schema_valid')}
                                           for r in different],
              'target_deviation_records': deviations, 'rows': rows, 'definition': scorer.DEFINITION,
              'unique_deviation_semantic_audit': unique_witness,
              'scope': 'One unforced first response at each frozen Luna-selected pre-pending context, with no controlled refusal and no tool execution. Correctness is only the expected source function and all frozen correct_projection fields. Different/no/multiple calls are not task errors. This is not execution success, full task competence, or natural model-error prevalence.',
              'relation_to_actor_experiments': 'Auxiliary conditional ability evidence only. Main actor pending proposals are evaluator-supplied; this does not establish that the same sampled actor first produced a correct call and then abandoned it.',
              'source_sha256': {str(p): sha(p) for p in [Path(__file__), SCORER, protocol_path, contexts_path, manifest_path]},
              'raw_scope': 'Only the33 Lumen-Qwen unforced artifacts were opened; no GLM or actor-feedback outcome was read.',
              'new_model_calls': 0, 'native_tool_calls': 0}
    (HERE/'result.json').write_text(json.dumps(result, indent=2, ensure_ascii=False)+'\n')
    print(json.dumps({'planned_contexts':33, 'counts':counts, 'checks':dict(checks),
                      'audit_issues':issues, 'deviation_count':len(deviations),
                      'different_function_calls':result['different_function_calls'], 'new_model_calls':0}, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
