"""Source/schema-derived X4 hash audit plus actual native operation replay.

Never changes study rows or guesses numeric types from target hashes. One
condition/arm qualifies the implementation; root registers full-panel execution.
"""
import argparse
from collections import Counter
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback

FORBIDDEN_CALLS = []


def forbidden(*args, **kwargs):
    FORBIDDEN_CALLS.append('network_or_model_attempt')
    raise RuntimeError('Native audit forbids network and model calls')


socket.create_connection = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.socket.sendto = forbidden


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def load(path):
    path = Path(path)
    data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


class NodeNormalizer:
    def __init__(self):
        script = "const r=require('node:readline').createInterface({input:process.stdin});r.on('line',s=>{try{process.stdout.write(JSON.stringify({ok:true,value:JSON.parse(JSON.stringify(JSON.parse(s)))})+'\\n')}catch(e){process.stdout.write(JSON.stringify({ok:false,error:e.name})+'\\n')}})"
        self.child = subprocess.Popen(['node', '-e', script], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)

    def normalize(self, value):
        self.child.stdin.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + '\n')
        self.child.stdin.flush()
        result = json.loads(self.child.stdout.readline())
        assert result['ok'], result
        return result['value']

    def close(self):
        self.child.stdin.close()
        assert self.child.wait(timeout=10) == 0


def differences(typed, stored, path='$'):
    rows = []
    if isinstance(typed, dict) and isinstance(stored, dict):
        for key in typed.keys() & stored.keys():
            rows += differences(typed[key], stored[key], path + '.' + str(key))
    elif isinstance(typed, (list, tuple)) and isinstance(stored, list):
        for index, (first, second) in enumerate(zip(typed, stored)):
            rows += differences(first, second, path + f'[{index}]')
    elif type(typed) in {int, float} and type(stored) in {int, float} and (type(typed) != type(stored) or typed != stored):
        rows.append({'path': path, 'native_type': type(typed).__name__, 'stored_type': type(stored).__name__,
                     'native_repr': repr(typed), 'stored_repr': repr(stored)})
    return rows


def load_source(frozen):
    evaluation = frozen / 'evaluation'
    sys.path[:0] = [str(evaluation / 'authorship/x4'), str(evaluation / 'authorship/x1'),
                    str(evaluation), str(evaluation / 'intent_guard'), str(evaluation / 'pi'),
                    os.environ['BASELINE_VENDOR'], os.environ['PROGENT_SOURCE']]
    from native import NativeGrantAdapter
    from cohort import instantiate, effective_args, normalization
    from native_clock import install
    from pga_runtime import AuditedRuntime
    from agentdojo.functions_runtime import make_function
    from agentdojo.default_suites.v1.tools.calendar_client import get_current_day
    os.environ['SECAGENT_POLICY_MODEL'] = 'gpt-6-luna'
    from secagent import tool as progent
    progent.api_request = forbidden
    assert Path(inspect.getfile(NativeGrantAdapter)).resolve() == (evaluation / 'authorship/x4/native.py').resolve()
    assert Path(inspect.getfile(instantiate)).resolve() == (evaluation / 'authorship/x1/cohort.py').resolve()
    return dict(adapter=NativeGrantAdapter, instantiate=instantiate, effective_args=effective_args,
                normalization=normalization, install_clock=install, runtime=AuditedRuntime,
                make_function=make_function, get_current_day=get_current_day, progent=progent)


def restore_model(model_type, saved):
    """Restore saved fields using declared Pydantic field schemas only.

    Native collection models have initialization validators that rebuild mutable
    maps from initial arrays. Validate each retained field against its original
    annotation, then retain that field's typed saved value. Computed fields are
    recomputed by the native model. Exact Node readback is required afterward.
    No target hash participates in this reconstruction; ambiguous numeric unions
    keep Pydantic's declared interpretation and fail if the exact hash differs.
    """
    from pydantic import BaseModel, TypeAdapter

    def retained(typed, raw):
        if isinstance(typed, BaseModel):
            return restore_model(type(typed), raw)
        if isinstance(typed, list):
            assert len(typed) == len(raw)
            return [retained(value, original) for value, original in zip(typed, raw)]
        if isinstance(typed, dict):
            assert len(typed) == len(raw)
            return {key: retained(value, raw[str(key)] if str(key) in raw else raw[key]) for key, value in typed.items()}
        if isinstance(typed, tuple):
            return tuple(retained(value, original) for value, original in zip(typed, raw))
        return typed

    instance = model_type.model_validate(saved)
    fields = {}
    for name, field in model_type.model_fields.items():
        if name in saved:
            typed = TypeAdapter(field.rebuild_annotation()).validate_python(saved[name])
            fields[name] = retained(typed, saved[name])
    return instance.model_copy(update=fields)


def readback(typed, stored, node, label, hashes=None):
    actual = digest(typed)
    for expected in hashes or []:
        assert actual == expected, f'{label}: exact original Python hash not recovered'
    assert digest(node.normalize(typed)) == digest(stored), f'{label}: actual Node serialization does not match stored raw'
    return {'location': label, 'typed_sha256': actual, 'stored_sha256': digest(stored),
            'numeric_changes': differences(typed, stored), 'exact_hashes_checked': len(hashes or [])}


def audit_raw(raw, condition, source, node):
    result = raw['result']
    clock = result['clock_profile']
    assert clock['kind'] == 'controlled_native_writer_clock'
    assert clock['anchor'] == '2026-11-05T00:00:00'
    source['install_clock'](clock['anchor'])
    suite, task, source_initial = source['instantiate'](result['suite'], result['task_id'])
    Env = type(source_initial)
    changes = []
    sources = {}
    for function in suite.tools:
        module = inspect.getmodule(function.run)
        if module and getattr(module, '__file__', None):
            sources[str(Path(module.__file__).resolve())] = sha(module.__file__)
    for method in [task.utility, suite._check_task_result]:
        path = Path(inspect.getfile(method)).resolve()
        sources[str(path)] = sha(path)
    expected_catalog = result.get('effect_catalog', {})
    for name, entry in expected_catalog.items():
        module = importlib.import_module(entry['source_module'])
        assert sha(module.__file__) == entry['source_sha256'], f'{name}: native source differs from study'
    initial = restore_model(Env, raw['initial'])
    changes.append(readback(initial.model_dump(mode='json'), raw['initial'], node, 'initial', [result['initial_state_sha256']]))
    assert digest(source_initial.model_dump(mode='json')) == digest(initial.model_dump(mode='json')), 'Source initial state does not reproduce stored typed initial state'
    typed_events = []
    previous = initial.model_dump(mode='json')
    for index, event in enumerate(raw['events']):
        before = restore_model(Env, event['before']).model_dump(mode='json')
        after = restore_model(Env, event['after']).model_dump(mode='json')
        changes.append(readback(before, event['before'], node, f'event{index}.before'))
        changes.append(readback(after, event['after'], node, f'event{index}.after'))
        assert digest(before) == digest(previous), f'event{index}: native state chain discontinuity'
        if event.get('controller_denied'):
            assert digest(before) == digest(after) and event.get('error'), 'Recorded denial changed native state'
        typed_events.append({'before': before, 'after': after})
        previous = after
    final = restore_model(Env, raw['final']).model_dump(mode='json')
    changes.append(readback(final, raw['final'], node, 'final'))
    assert digest(previous) == digest(final), 'Final state differs from final event'
    records = result.get('x4_records', [])
    assert len(records) <= 1
    executed = [record for record in records if record['status'] == 'executed']
    repair_events = [(index, event) for index, event in enumerate(raw['events']) if event.get('x4_repaired_effect')]
    assert len(repair_events) == len(raw.get('x4_repair_effects', [])) == result.get('x4_repaired_effects', 0)
    assert len(repair_events) == len(executed), 'Repair record/event count mismatch'
    repairs, resolutions = [], []
    for record, (index, event), duplicate in zip(executed, repair_events, raw['x4_repair_effects']):
        assert digest(event) == digest(duplicate), 'Two saved views of repaired native event differ'
        env = restore_model(Env, event['before'])
        adapter = source['adapter'](suite=suite, environment=env, owner_request=raw['prompt'], progent=source['progent'],
                                    policy=record['original_fault_policy'],
                                    protected_fields={raw['x1_unit']['function']: [raw['x1_unit']['argument']]},
                                    effective_arguments=source['effective_args'],
                                    normalize_field=lambda field, value: source['normalization'](field, value, raw['x1_unit'].get('calendar_owner')))
        call = adapter.normalize(record['proposed_repair'])
        effect = record['native_effect']
        grant = record['grant']
        changes.append(readback(call, record['proposed_repair'], node, 'proposed_repair', [grant['complete_call_sha256']]))
        native_call = adapter.normalize(event['operation'])
        assert digest(native_call) == digest(call)
        changes.append(readback(native_call, event['operation'], node, 'repaired_event.operation', [grant['complete_call_sha256']]))
        changes.append(readback(adapter.normalize(effect['operation']), effect['operation'], node, 'native_effect.operation', [grant['complete_call_sha256']]))
        changes.append(readback(typed_events[index]['before'], event['before'], node, 'repair.before',
                               [record['native_state_revision'], grant['native_state_revision'], effect['before_sha256']]))
        changes.append(readback(typed_events[index]['after'], event['after'], node, 'repair.after', [effect['after_sha256']]))
        assert grant['owner_request_sha256'] == digest(raw['prompt'])
        assert grant['repair_id'] == digest([raw['x4_audit_plan']['scope'], record['unit_id'], record['native_state_revision'], record['pre_refusal_actor_context_sha256']])
        assert effect['state_changed'] == event['entry_state_changed'] == (typed_events[index]['before'] != typed_events[index]['after'])
        assert effect['native_error'] == event['error']
        assert record['residual_authorization']['allow'] is True
        contexts = raw.get('x4_contexts', [])
        assert len(contexts) == 1
        assert hashlib.sha256(contexts[0]['context_json'].encode('utf-8')).hexdigest() == record['pre_refusal_actor_context_sha256'] == record['actor_transport']['pre_proposal_context_sha256']
        keys = []
        if grant['complete_call_sha256'] != digest(record['proposed_repair']):
            keys.append('effect_call_binding')
        original_match = any(e.get('x4_repaired_effect') and digest(e['operation']) == digest(record['proposed_repair'])
                             and digest(e['after']) == effect['after_sha256'] for e in raw['events'])
        if effect['state_changed'] and not original_match:
            keys.append('missing_repaired_effect_event')
        resolutions += [[condition['condition_id'], result['x4_arm'], key] for key in keys]
        repairs.append({'event_index': index, 'exact_call_hash': grant['complete_call_sha256'],
                        'exact_before_hash': effect['before_sha256'], 'exact_after_hash': effect['after_sha256'],
                        'schema': adapter.functions[call['function']].parameters.model_json_schema(),
                        'typed_call': call, 'resolved_types': differences(call, record['proposed_repair'])})

    evidence = {'passed': False, 'record_consistency_verified': True, 'native_execution_replayed': False,
                'recorded_denials_reauthorized': False, 'repairs': repairs,
                'serialization_changes': [row for row in changes if row['numeric_changes']],
                'readback_locations': len(changes), 'resolved_prior_finding_keys': resolutions,
                'native_source_sha256': sources, 'original_status': result.get('status'),
                'native_environment_schema_sha256': digest(Env.model_json_schema()),
                'original_actor_status': result.get('actor_status'), 'original_native_utility': result.get('native_utility'),
                'original_unknown_reasons': result.get('x4_unknown_reasons', []),
                'original_errors': result.get('errors', []),
                'original_transport_failures': result.get('x4_transport_failures', []),
                'original_repair_statuses': [{'status': r['status'], 'reason': r['reason'], 'events': r['events']} for r in records],
                'original_rpc_errors': result.get('x4_rpc_errors', []), 'study_records_modified': False}
    try:
        evidence.update(replay_native(raw, source, node, suite, initial.model_dump(mode='json'), typed_events, final, clock))
        evidence.update(passed=True, native_execution_replayed=True)
    except Exception as error:
        evidence.update(error=type(error).__name__, failure_stage='native_execution_replay', traceback=traceback.format_exc())
    return evidence


def replay_native(raw, source, node, suite, initial, typed_events, final, clock):
    # This independent execution starts from the original source initial state.
    # Clock ticks arise only through native writer now(), never fitted timestamps.
    result = raw['result']
    replay_clock = source['install_clock'](clock['anchor'])
    _, task, replay_env = source['instantiate'](result['suite'], result['task_id'])
    assert digest(replay_env.model_dump(mode='json')) == digest(initial)
    replay_initial = replay_env.model_copy(deep=True)
    tools = list(suite.tools)
    if hasattr(replay_env, 'calendar') and 'get_current_day' not in {f.name for f in tools}:
        tools.append(source['make_function'](source['get_current_day']))
    runtime = source['runtime'](tools, max_calls=64)
    replays = []
    for index, event in enumerate(raw['events']):
        assert event.get('depth') == 0, 'Nested native events need a separately qualified replay'
        assert digest(replay_env.model_dump(mode='json')) == digest(typed_events[index]['before']), f'event{index}: replay pre-state mismatch'
        if event.get('controller_denied'):
            replays.append({'index': index, 'status': 'recorded_controller_denial_skipped_no_authorization_claim'})
            continue
        call = copy.deepcopy(event['operation'])
        if event.get('x4_repaired_effect'):
            function = next(f for f in suite.tools if f.name == call['function'])
            call['args'] = function.parameters.model_validate(call['args']).model_dump(mode='json')
        count = len(runtime.events)
        value, error = runtime.run_function(replay_env, call['function'], call['args'])
        assert len(runtime.events) == count + 1, f'event{index}: native event multiplicity differs'
        assert error == event['error'], f'event{index}: native error differs'
        actual = replay_env.model_dump(mode='json')
        assert digest(actual) == digest(typed_events[index]['after']), f'event{index}: native replay after-state differs'
        assert digest(node.normalize(actual)) == digest(event['after'])
        replays.append({'index': index, 'status': 'native_operation_replayed', 'native_error': error,
                        'after_sha256': digest(actual)})
    assert digest(replay_env.model_dump(mode='json')) == digest(final)
    # Exact original pi_full.Broker.finish scoring path, with restored typed
    # repaired proposals and untouched ordinary JSON-RPC proposal arguments.
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.types import text_content_block_from_string
    proposals = []
    for saved in raw['proposed_calls']:
        call = copy.deepcopy(saved)
        if str(call.get('id', '')).startswith('x4-repair-'):
            function = next(f for f in suite.tools if f.name == call['function'])
            call['args'] = function.parameters.model_validate(call['args']).model_dump(mode='json')
        proposals.append(FunctionCall.model_validate(call))
    utility, utility_error = None, None
    try:
        utility = suite._check_task_result(task, [text_content_block_from_string(raw['final_response'])],
                                          replay_initial, replay_env.model_copy(deep=True), proposals)
    except Exception as error:
        utility_error = type(error).__name__
    assert utility == result['native_utility'] and utility_error == result.get('utility_error'), 'Native utility or scorer error differs'
    assert replay_clock == clock, 'Native writer-clock ticks differ; no timestamp fitting permitted'
    return {'native_replay': replays, 'clock_reproduced': replay_clock,
            'native_utility_recomputed': utility, 'utility_error_recomputed': utility_error}


def interpretation(analysis, audited):
    audited_keys = {(r['condition_id'], r['arm']): r['passed'] for r in audited}
    rows = [dict(row, audit_passed=audited_keys.get((row['condition_id'], row['arm']), False))
            for row in analysis['rows'] if (row['condition_id'], row['arm']) in audited_keys]
    groups = {}
    for arm in sorted({row['arm'] for row in rows}):
        group = [row for row in rows if row['arm'] == arm]
        known = [row for row in group if row['audit_passed'] and row['episode_known']]
        groups[arm] = {'selected_records': len(group), 'source_episodes_known': sum(row['episode_known'] for row in group),
                       'audit_and_source_known': len(known), 'audit_or_source_unknown': len(group) - len(known),
                       **{key: sum(row.get(key, 0) for row in known) for key in ['wrong_effect', 'correct_effect', 'no_effect', 'repair_stops', 'expert_audits']},
                       'native_utility': sum(row['native_utility'] is True for row in known),
                       'correct_selected_effect_but_native_utility_false': sum(row['correct_effect'] and row['native_utility'] is False for row in known)}
    paired = []
    for cid in sorted({row['condition_id'] for row in rows}):
        by_arm = {row['arm']: row for row in rows if row['condition_id'] == cid}
        if not {'x4_projection_H0', 'extra_review_H0'}.issubset(by_arm):
            continue
        primary, editing = by_arm['x4_projection_H0'], by_arm['extra_review_H0']
        known = all(row['audit_passed'] and row['episode_known'] for row in [primary, editing])
        paired.append({'condition_id': cid, 'known': known,
                       'primary_utility_gain': known and primary['native_utility'] is True and editing['native_utility'] is False,
                       'primary_utility_loss': known and primary['native_utility'] is False and editing['native_utility'] is True,
                       'primary_correct_effect': primary.get('correct_effect'), 'editing_correct_effect': editing.get('correct_effect')})
    return {'groups': groups, 'paired_primary_vs_strong_editing': {
        'pairs': len(paired), 'known_pairs': sum(row['known'] for row in paired),
        'primary_utility_gains': sum(row['primary_utility_gain'] for row in paired),
        'primary_utility_losses': sum(row['primary_utility_loss'] for row in paired), 'rows': paired},
        'limits': ['Audit status is additional integrity evidence; no original scientific status is changed.',
                   'Native task utility and correctness of the selected effect are distinct endpoints.',
                   'Conditions share 59 units / 32 task clusters; they are not independent task samples.',
                   'An independently sampled H10 run cannot estimate incremental audit benefit from unpaired H0 differences.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--frozen', type=Path, default=Path('/artifact-source/a42f1d53d42c/frozen-x4-v2'))
    parser.add_argument('--analysis', type=Path, required=True)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--condition')
    parser.add_argument('--arm')
    args = parser.parse_args()
    args.out = args.out or Path(os.environ['AROS_ARTIFACTS'])
    args.out.mkdir(parents=True, exist_ok=True)
    assert not (args.out / 'result.json').exists(), 'Fresh audit output required'
    assert bool(args.condition) == bool(args.arm), 'Qualification requires one explicit condition/arm'
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    assert os.environ.get('PYTHONHASHSEED') == '20261106'
    run_config = load(args.run / 'config.json')
    analysis = load(args.analysis)
    assert all(finding[-1] in {'effect_call_binding', 'missing_repaired_effect_event'} for finding in analysis['audit_findings']), 'Audit finding scope changed'
    x4 = args.frozen / 'evaluation/authorship/x4'
    release = load(x4 / 'recovery-v2/release.json')
    assert sha(x4 / 'recovery-v2/release.json') == run_config['release']['release_sha256']
    for relative, expected in release['source_sha256'].items():
        assert sha(x4 / relative) == expected, 'Frozen X4 source changed: ' + relative
    for name, expected in release['x1_core_sha256'].items():
        assert sha(x4.parent / 'x1' / name) == expected, 'Frozen X1 core changed: ' + name
    manifest_path = x4 / 'dataset-v1/manifest.json'
    assert sha(manifest_path) == run_config['manifest_sha256']
    manifest = load(manifest_path)
    conditions = {row['condition_id']: row for row in manifest['rows']}
    scheduled = [(cid, arm) for cid in run_config['conditions'] for arm in run_config['arms']]
    if args.condition:
        assert (args.condition, args.arm) in scheduled
        scheduled = [(args.condition, args.arm)]
    else:
        assert (run_config['phase'], len(scheduled)) in {('main', 756), ('audit_diagnostic', 84)}, 'Declared full panel changed'
    source = load_source(args.frozen)
    progent_path = Path(os.environ['PROGENT_SOURCE'])
    assert subprocess.check_output(['git', '-C', str(progent_path), 'rev-parse', 'HEAD'], text=True).strip() == 'b02783b896d4bf01a2adf24738015e258db8d35b'
    assert not subprocess.check_output(['git', '-C', str(progent_path), 'status', '--short'], text=True).strip()
    script_sha256 = sha(__file__)
    save(args.out / 'config.json', {'audit': 'x4-native-audit-v1', 'script_sha256': script_sha256,
         'qualification_only': bool(args.condition), 'selected_records': len(scheduled),
         'frozen_release_sha256': sha(x4 / 'recovery-v2/release.json'), 'run_config_sha256': sha(args.run / 'config.json'),
         'analysis_sha256': sha(args.analysis), 'manifest_sha256': sha(manifest_path),
         'python': sys.version, 'sources': {str(path): sha(path) for path in [x4 / 'native.py', x4 / 'kernel.py', x4.parent / 'x1/cohort.py',
             args.frozen / 'evaluation/intent_guard/native_clock.py', args.frozen / 'evaluation/pga_runtime.py', progent_path / 'secagent/tool.py']},
         'scope': 'Schema-derived exact Python call/state hashes, real Node JSON readback and separate native replay; no type search, hash waiver, model inference or study-row change.'})
    rows = []
    node = NodeNormalizer()
    started = time.monotonic()
    try:
        for cid, arm in scheduled:
            path = args.run / cid / (arm + '.json.gz')
            row = {'condition_id': cid, 'arm': arm, 'raw_sha256': sha(path)}
            try:
                raw = load(path)
                assert raw['result']['x4_arm'] == arm
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    row.update(audit_raw(raw, conditions[cid], source, node))
            except Exception as error:
                row.update(passed=False, record_consistency_verified=False, native_execution_replayed=False,
                           failure_stage='typed_record_consistency', error=type(error).__name__, traceback=traceback.format_exc())
            assert sha(path) == row['raw_sha256'], 'Study raw file changed during audit'
            rows.append(row)
            save(args.out / 'records' / (cid + '__' + arm + '.json'), row)
            (args.out / 'status.md').write_text(f"X4 native audit: {len(rows)}/{len(scheduled)} arm records; {sum(not r['passed'] for r in rows)} unresolved; elapsed {time.monotonic()-started:.1f}s.\n")
    finally:
        node.close()
    selected = {(row['condition_id'], row['arm']) for row in rows}
    expected = Counter(tuple(finding) for finding in analysis['audit_findings'] if tuple(finding[:2]) in selected)
    observed = Counter(tuple(finding) for row in rows if row['passed'] for finding in row['resolved_prior_finding_keys'])
    assert sha(__file__) == script_sha256, 'Audit source changed during execution'
    result = {'audit_only': True, 'qualification_only': bool(args.condition), 'arm_records_checked': len(rows),
              'arm_records_passed': sum(row['passed'] for row in rows), 'failed_records': [row for row in rows if not row['passed']],
              'prior_findings_selected': sum(expected.values()), 'prior_findings_reconciled': sum((expected & observed).values()),
              'unresolved_findings': [list(key) + [n] for key, n in (expected - observed).items()],
              'additional_findings': [list(key) + [n] for key, n in (observed - expected).items()],
              'network_or_model_attempts': len(FORBIDDEN_CALLS), 'model_requests': 0,
              'study_records_modified': False, 'elapsed_s': time.monotonic() - started,
              'scope': 'Typed-record hash consistency and separately replayed native operations. Recorded denials are skipped, not newly authorized. Original statuses/errors are retained. No H10 incremental-benefit inference.'}
    result['passed'] = all(row['passed'] for row in rows) and expected == observed and not FORBIDDEN_CALLS
    save(args.out / 'result.json', result)
    save(args.out / 'interpretation.json', interpretation(analysis, rows))
    print(json.dumps(result, indent=2))
    if result['failed_records'] or result['unresolved_findings'] or result['additional_findings'] or FORBIDDEN_CALLS:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
