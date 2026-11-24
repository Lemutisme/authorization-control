"""Independent, model-free continuation replay and native rescoring.

Imports pinned native tools/checker/scorers, not the experimental runner or
primary endpoint analysis. Every recorded continuation transition is executed,
including refusal, native-error and no-op branches. Historical prefixes are
checked for preservation but are not rerun here.
"""
from __future__ import annotations
from pipeline.paths import resolve as research_path
import argparse
import contextlib
import copy
import gzip
import hashlib
import importlib.metadata
import inspect
import io
import json
import math
import os
from pathlib import Path
import socket
import sys
import time
import traceback
from collections import Counter
from recovery import recover_policy
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PROGENT = Path(research_path('progent'))
VENDOR = Path(research_path('dependencies'))
MANIFEST = Path(research_path('experiments/sealed/evaluation/authorship/x2b/manifest-v1.json'))
EXPECTED_PROGENT_COMMIT = 'b02783b896d4bf01a2adf24738015e258db8d35b'
NETWORK_ATTEMPTS = []

def forbid_network(*args, **kwargs):
    NETWORK_ATTEMPTS.append('network_attempt')
    raise RuntimeError('Model-free native audit forbids network access')
socket.create_connection = forbid_network
socket.socket.connect = forbid_network
socket.socket.connect_ex = forbid_network
sys.path[:0] = [str(VENDOR), str(PROGENT)]
os.environ.update(ENABLE_SECAGENT='True', SECAGENT_GENERATE='False', SECAGENT_UPDATE='False')
with contextlib.redirect_stderr(io.StringIO()):
    from secagent import tool as progent
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime, FunctionCall
from agentdojo.types import text_content_block_from_string
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()).hexdigest()

def same(a, b):
    """JSON structural equality, numeric int/float equivalence, strict booleans.

    Gzip outputs were serialized through JS, which erases integral float spelling.
    Native numeric state semantics are preserved; strings remain exact.
    """
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isfinite(a) and math.isfinite(b) and (a == b)
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        return a.keys() == b.keys() and all((same(a[k], b[k]) for k in a))
    if isinstance(a, list):
        return len(a) == len(b) and all((same(x, y) for x, y in zip(a, b)))
    return a == b

def differences(expected, actual, path='$'):
    """Return all exact divergent leaves; do not truncate mismatches."""
    if same(expected, actual):
        return []
    if isinstance(expected, dict) and isinstance(actual, dict):
        rows = []
        for key in sorted(set(expected) | set(actual)):
            p = path + '[' + json.dumps(key) + ']'
            if key not in expected:
                rows.append({'path': p, 'kind': 'unexpected_key', 'actual': actual[key]})
            elif key not in actual:
                rows.append({'path': p, 'kind': 'missing_key', 'expected': expected[key]})
            else:
                rows.extend(differences(expected[key], actual[key], p))
        return rows
    if isinstance(expected, list) and isinstance(actual, list):
        rows = []
        if len(expected) != len(actual):
            rows.append({'path': path, 'kind': 'length', 'expected': len(expected), 'actual': len(actual)})
        for index, (a, b) in enumerate(zip(expected, actual)):
            rows.extend(differences(a, b, f'{path}[{index}]'))
        for index in range(min(len(expected), len(actual)), max(len(expected), len(actual))):
            rows.append({'path': f'{path}[{index}]', **({'expected': expected[index]} if index < len(expected) else {'actual': actual[index]})})
        return rows
    return [{'path': path, 'kind': 'value', 'expected': expected, 'actual': actual}]

def check(issues, code, expected, actual, **where):
    if not same(expected, actual):
        issues.append({'code': code, **where, 'differences': differences(expected, actual)})

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2, ensure_ascii=False, allow_nan=False) + '\n')
    temporary.replace(path)

def replay_operation(suite, state, policy, owner_request, operation):
    """Run the original policy wrapper and native tool, with all errors retained."""
    env = type(suite.load_and_inject_default_environment({})).model_validate(copy.deepcopy(state))
    native_check = progent.check_tool_call
    decisions = []
    fields = {f.name: set(f.parameters.model_fields) for f in suite.tools}

    def checked(name, kwargs):
        item = {'operation': {'function': name, 'args': {k: copy.deepcopy(v) for k, v in kwargs.items() if k in fields[name]}}}
        try:
            result = native_check(name, kwargs)
        except Exception as exc:
            decisions.append({**item, 'allowed': False, 'reason': str(exc)})
            raise
        decisions.append({**item, 'allowed': True})
        return result
    progent.security_policy = copy.deepcopy(policy)
    progent.init_user_query = owner_request
    progent.available_tools = []
    progent.check_tool_call = checked
    unexpected = None
    try:
        tools = [f.model_copy(update={'run': progent.apply_secure_tool_wrapper(f.run)}) for f in suite.tools]
        runtime = FunctionsRuntime(tools)
        try:
            value, error = runtime.run_function(env, operation['function'], copy.deepcopy(operation['args']))
        except Exception as exc:
            value, error = (None, type(exc).__name__)
            unexpected = {'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}
        after = env.model_dump(mode='json')
        return {'after': after, 'error': error, 'entry_state_changed': not same(state, after), 'decisions': decisions, 'result': {'text': tool_result_to_str(value) if error is None else 'Error: ' + error, 'is_error': error is not None}, 'unexpected_exception': unexpected}
    finally:
        progent.check_tool_call = native_check

def scores(suite, case, initial, final, final_response, proposed_calls):
    env_type = type(suite.load_and_inject_default_environment({}))
    before = env_type.model_validate(copy.deepcopy(initial))
    after = env_type.model_validate(copy.deepcopy(final))
    calls = [FunctionCall.model_validate(call) for call in proposed_calls]
    output = [text_content_block_from_string(final_response)]
    result = {'native_utility': None, 'native_targeted_asr': None, 'utility_error': None, 'asr_error': None, 'error_details': {}}
    task = suite.get_user_task_by_id(case['task_id'])
    try:
        result['native_utility'] = suite._check_task_result(task, output, before.model_copy(deep=True), after.model_copy(deep=True), calls)
    except Exception as exc:
        result['utility_error'] = type(exc).__name__
        result['error_details']['utility'] = str(exc)
    if case['condition'] == 'attack':
        try:
            injection = suite.get_injection_task_by_id(case['injection_id'])
            result['native_targeted_asr'] = suite._check_injection_task_security(injection, output, before.model_copy(deep=True), after.model_copy(deep=True), calls)
        except Exception as exc:
            result['asr_error'] = type(exc).__name__
            result['error_details']['target'] = str(exc)
    return result

def audit_raw(raw, case, version, source_packet=None):
    issues, event_reports = ([], [])
    row, packet = (raw['result'], raw['factorial_source_packet'])
    authoritative_source_policy = source_packet['policy_at_boundary'] if source_packet is not None else None
    suite = get_suite(version, case['suite'])
    if case['suite'] != 'banking':
        raise ValueError('This pinned audit supports the banking two-channel cohort only')
    check(issues, 'case_id', case['case_id'], row['case_id'])
    check(issues, 'task_id', case['task_id'], row['task_id'])
    check(issues, 'condition', case['condition'], row['condition'])
    for function in suite.tools:
        source_text = Path(inspect.getsourcefile(function.run)).read_bytes()
        catalog = row['effect_catalog'][function.name]
        check(issues, 'tool_source_module', catalog['source_module'], function.run.__module__, tool=function.name)
        check(issues, 'tool_source_hash', catalog['source_sha256'], hashlib.sha256(source_text).hexdigest(), tool=function.name)
    if source_packet is not None:
        check(issues, 'embedded_source_packet', source_packet, packet)
    task = suite.get_user_task_by_id(case['task_id'])
    initial = task.init_environment(suite.load_and_inject_default_environment(case['injections'])).model_dump(mode='json')
    check(issues, 'native_initial_state', initial, raw['initial'])
    check(issues, 'retained_initial_state', packet['native_initial_state'], raw['initial'])
    check(issues, 'owner_request', task.PROMPT, raw['authentic_owner_request'])
    check(issues, 'source_state', packet['native_boundary_state'], raw['factorial_source_state'])
    check(issues, 'source_policy', packet['policy_at_boundary'], raw['factorial_source_policy'])
    prior = packet['prior_native_events']
    proposals = raw['proposed_calls']
    events, records = (raw['events'], row['factorial_records'])
    n = len(prior)
    check(issues, 'retained_event_prefix', prior, events[:n])
    check(issues, 'retained_proposal_prefix', packet['prior_native_proposals'], proposals[:len(packet['prior_native_proposals'])])
    check(issues, 'event_proposal_count', len(events), len(proposals))
    check(issues, 'continuation_record_count', len(events) - n, len(records))
    check(issues, 'historical_event_proposal_count', n, len(packet['prior_native_proposals']))
    for index, event in enumerate(events):
        check(issues, 'event_index', index, event.get('index'), event=index)
        expected_before = raw['initial'] if index == 0 else events[index - 1]['after']
        check(issues, 'recorded_state_chain', expected_before, event['before'], event=index)
        check(issues, 'recorded_change_flag', not same(event['before'], event['after']), event.get('entry_state_changed'), event=index)
        if index < len(proposals):
            proposal = proposals[index]
            check(issues, 'proposal_event_operation', {'function': proposal['function'], 'args': proposal['args']}, event['operation'], event=index)
    if n:
        check(issues, 'retained_boundary_state', prior[-1]['after'], packet['native_boundary_state'])
    else:
        check(issues, 'empty_prefix_boundary', raw['initial'], packet['native_boundary_state'])
    cumulative = copy.deepcopy(packet['native_boundary_state'])
    cumulative_known = True
    for offset, event in enumerate(events[n:]):
        index = n + offset
        per_event = []
        check(per_event, 'recorded_event_kind', 'agent', event.get('kind'), event=index)
        check(per_event, 'recorded_event_depth', 0, event.get('depth'), event=index)
        if offset >= len(records):
            issue = {'code': 'missing_decision_policy', 'event': index, 'operation': event['operation'], 'recorded_error': event.get('error')}
            issues.append(issue)
            event_reports.append({'event': index, 'status': 'not_replayable', 'issues': [issue]})
            cumulative_known = False
            continue
        record = records[offset]
        op = record['proposal']
        expected_policy = packet['policy_at_boundary'] if offset == 0 else records[offset - 1]['policy_after_update']
        check(per_event, 'decision_policy_chain', expected_policy, record['decision_policy'], event=index)
        check(per_event, 'record_operation', {'function': op['name'], 'args': op['args']}, event['operation'], event=index)
        if index < len(proposals):
            check(per_event, 'record_call_id', proposals[index]['id'], record['call_id'], event=index)
        before_matches = cumulative_known and same(cumulative, event['before'])
        check(per_event, 'cumulative_before', event['before'], cumulative if cumulative_known else None, event=index)
        if record['decisions']:
            expected_hash = record['decisions'][0].get('policy_before_sha256')
            replay_policy, representation = recover_policy(record['decision_policy'], expected_hash, authoritative_source_policy)
            if replay_policy is None:
                per_event.append({'code': 'policy_representation_uncertain', 'event': index, 'recovery': representation})
                replay_policy = record['decision_policy']
        else:
            replay_policy = record['decision_policy']
            representation = {'status': 'not_exercised', 'reason': 'no_policy_checker_decision'}
        local = replay_operation(suite, event['before'], replay_policy, raw['authentic_owner_request'], event['operation'])
        check(per_event, 'native_after', event['after'], local['after'], event=index)
        check(per_event, 'native_error', event['error'], local['error'], event=index)
        check(per_event, 'native_change_flag', event['entry_state_changed'], local['entry_state_changed'], event=index)
        check(per_event, 'native_result', record['native_result_before_feedback'], local['result'], event=index)
        expected_decisions = [{k: v for k, v in d.items() if k not in ['policy_before_sha256', 'policy_after_sha256']} for d in record['decisions']]
        check(per_event, 'native_policy_decisions', expected_decisions, local['decisions'], event=index)
        refused = any((d['allowed'] is False for d in local['decisions']))
        check(per_event, 'policy_refusal_flag', record['policy_refused'], refused, event=index)
        check(per_event, 'record_native_error', None if refused else local['error'], record['native_error'], event=index)
        if local['unexpected_exception']:
            per_event.append({'code': 'unexpected_replay_exception', 'event': index, **local['unexpected_exception']})
        if cumulative_known:
            chain = local if before_matches else replay_operation(suite, cumulative, replay_policy, raw['authentic_owner_request'], event['operation'])
            cumulative = chain['after']
        event_reports.append({'event': index, 'continuation_index': offset, 'operation': event['operation'], 'status': 'pass' if not per_event else 'mismatch', 'branch': 'policy_refusal' if refused else 'native_error' if local['error'] else 'native_effect' if local['entry_state_changed'] else 'native_noop', 'recorded_error': event['error'], 'replayed_error': local['error'], 'policy_representation': representation, 'recorded_before_sha256': digest(event['before']), 'recorded_after_sha256': digest(event['after']), 'replayed_after_sha256': digest(local['after']), 'issues': per_event})
        issues.extend(per_event)
    check(issues, 'recorded_final_chain', events[-1]['after'] if events else raw['initial'], raw['final'])
    check(issues, 'replayed_final', raw['final'], cumulative if cumulative_known else None)
    recorded_scores = scores(suite, case, raw['initial'], raw['final'], raw['final_response'], proposals)
    replayed_scores = scores(suite, case, raw['initial'], cumulative, raw['final_response'], proposals) if cumulative_known else None
    for key in ['native_utility', 'native_targeted_asr', 'utility_error', 'asr_error']:
        check(issues, 'recorded_final_score', row.get(key), recorded_scores[key], field=key)
        if replayed_scores is not None:
            check(issues, 'replayed_final_score', row.get(key), replayed_scores[key], field=key)
    return {'status': 'pass' if not issues else 'mismatch', 'unit_id': row['factorial_unit_id'], 'arm': row['factorial_arm'], 'case_id': row['case_id'], 'source_events_preserved': n, 'continuation_events': len(events) - n, 'all_event_count': len(events), 'proposed_call_count': len(proposals), 'branch_counts': dict(Counter((e.get('branch', 'not_replayable') for e in event_reports))), 'policy_representation_counts': dict(Counter((e.get('policy_representation', {}).get('method', e.get('policy_representation', {}).get('status', 'unavailable')) for e in event_reports))), 'policy_spelling_restored': sum((bool(e.get('policy_representation', {}).get('changed')) for e in event_reports)), 'recorded_scores': {k: row.get(k) for k in ['native_utility', 'native_targeted_asr', 'utility_error', 'asr_error']}, 'rescored_recorded_final': recorded_scores, 'rescored_replayed_final': replayed_scores, 'issues': issues, 'event_reports': event_reports}

def provenance(suites):
    files = {Path(__file__), Path(inspect.getfile(recover_policy)), Path(inspect.getfile(FunctionsRuntime)), Path(inspect.getfile(FunctionCall)), Path(inspect.getfile(progent)), Path(inspect.getfile(tool_result_to_str)), MANIFEST}
    for suite in suites:
        files.add(Path(inspect.getfile(type(suite))))
        files.add(Path(inspect.getfile(type(suite.load_and_inject_default_environment({})))))
        for function in suite.tools:
            files.add(Path(inspect.getfile(function.run)))
        for task in [*suite.user_tasks.values(), *suite.injection_tasks.values()]:
            files.add(Path(inspect.getfile(type(task))))
    for name, module in list(sys.modules.items()):
        if name.startswith(('agentdojo.', 'secagent.')) and getattr(module, '__file__', None):
            path = Path(module.__file__)
            if path.is_file() and path.suffix == '.py':
                files.add(path)
    return {'python': sys.version, 'progent_pinned_commit': EXPECTED_PROGENT_COMMIT, 'packages': {name: importlib.metadata.version(name) for name in ['agentdojo', 'pydantic', 'jsonschema']}, 'files': {str(p): sha(p) for p in sorted(files)}, 'model_calls': 0, 'network_attempts': len(NETWORK_ATTEMPTS), 'scope': 'Independent native continuation replay and native scorers; no primary endpoint analysis or model calls. Historical prefixes are preserved, not re-executed.'}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input-root', type=Path, required=True)
    parser.add_argument('--protocol', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--source-lock', type=Path, default=HERE / 'pinned-sources.json')
    args = parser.parse_args()
    source_lock = json.loads(args.source_lock.read_text())
    drift = [{'path': path, 'expected': expected, 'actual': sha(path)} for path, expected in source_lock['files'].items() if sha(path) != expected]
    if drift:
        raise ValueError('Native audit source lock mismatch: ' + json.dumps(drift))
    if args.out.resolve() == args.input_root.resolve() or args.input_root.resolve() in args.out.resolve().parents:
        raise ValueError('Audit output must be separate from experiment output')
    args.out.mkdir(parents=True, exist_ok=False)
    protocol = json.loads(args.protocol.read_text())
    manifest = json.loads(MANIFEST.read_text())
    cases = {c['case_id']: c for c in manifest['cases']}
    planned = [(unit, repetition, arm) for unit in protocol['units'] for repetition in range(protocol.get('repeats', 1)) for arm in protocol['arms']]
    rows, started = ([], time.monotonic())
    for unit, repetition, arm in planned:
        path = args.input_root / unit['unit_id'] / f'repetition-{repetition}' / (arm + '.json.gz')
        audit_path = args.out / 'episodes' / unit['unit_id'] / f'repetition-{repetition}' / (arm + '.json')
        try:
            if not path.is_file():
                raise FileNotFoundError(str(path))
            source_path = Path(unit['packet'])
            if sha(source_path) != unit['packet_sha256']:
                raise ValueError('Frozen source packet hash changed')
            raw = json.loads(gzip.decompress(path.read_bytes()))
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                report = audit_raw(raw, cases[raw['result']['case_id']], manifest['version'], json.loads(source_path.read_text()))
            check(report['issues'], 'scheduled_unit', unit['unit_id'], report['unit_id'])
            check(report['issues'], 'scheduled_arm', arm, report['arm'])
            report['status'] = 'pass' if not report['issues'] else 'mismatch'
            report.update(raw_path=str(path.resolve()), raw_sha256=sha(path), repetition=repetition)
        except Exception as exc:
            report = {'status': 'error', 'unit_id': unit['unit_id'], 'arm': arm, 'repetition': repetition, 'raw_path': str(path.resolve()), 'issues': [{'code': 'audit_exception', 'type': type(exc).__name__, 'message': str(exc), 'traceback': traceback.format_exc()}], 'event_reports': []}
        save(audit_path, report)
        rows.append({k: v for k, v in report.items() if k != 'event_reports'})
        if len(rows) % 50 == 0:
            print(json.dumps({'audited': len(rows), 'scheduled': len(planned), 'status': dict(Counter((r['status'] for r in rows)))}), flush=True)
    expected_paths = {str(args.input_root / u['unit_id'] / f'repetition-{rep}' / (arm + '.json.gz')) for u, rep, arm in planned}
    extra = sorted((str(p) for p in args.input_root.rglob('*.json.gz') if str(p) not in expected_paths))
    result = {'scheduled': len(planned), 'audited': len(rows), 'counts': dict(Counter((r['status'] for r in rows))), 'extra_raw_files': extra, 'declared_expected_episodes': protocol.get('expected_episodes'), 'continuation_events': sum((r.get('continuation_events', 0) for r in rows)), 'branches': dict(sum((Counter(r.get('branch_counts', {})) for r in rows), Counter())), 'policy_representation_counts': dict(sum((Counter(r.get('policy_representation_counts', {})) for r in rows), Counter())), 'policy_spelling_restored': sum((r.get('policy_spelling_restored', 0) for r in rows)), 'protocol_sha256': sha(args.protocol), 'input_root': str(args.input_root.resolve()), 'source_lock_sha256': sha(args.source_lock), 'elapsed_s': time.monotonic() - started, 'provenance': provenance([get_suite(manifest['version'], 'banking')]), 'rows': rows}
    result['passed'] = all((r['status'] == 'pass' for r in rows)) and (not extra) and (not NETWORK_ATTEMPTS) and (protocol.get('expected_episodes', len(planned)) == len(planned))
    save(args.out / 'result.json', result)
    print(json.dumps({k: v for k, v in result.items() if k not in ['rows', 'provenance']}), flush=True)
    raise SystemExit(0 if result['passed'] else 1)
if __name__ == '__main__':
    main()
