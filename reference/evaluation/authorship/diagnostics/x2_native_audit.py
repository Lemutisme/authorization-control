"""Bounded, model-free X2 native audit. Register the full-panel command before use.

--case permits a one-case qualification only. Never regenerates policy or semantic
reviews. Audit metadata is separate from scientific experiment counts.
"""
import argparse
from collections import Counter, defaultdict
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback

NETWORK_ATTEMPTS = []
def forbidden(*args, **kwargs):
    NETWORK_ATTEMPTS.append('forbidden_call')
    raise AssertionError('Audit forbids network and model calls')
socket.create_connection = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.socket.sendto = forbidden
sys.path[:0] = [os.environ['BASELINE_VENDOR'], os.environ['PROGENT_SOURCE']]
os.environ.update(SECAGENT_POLICY_MODEL='gpt-6-luna', SECAGENT_GENERATE='True', SECAGENT_UPDATE='True')
from secagent import tool as progent
from secagent.utils import extract_json
from agentdojo.functions_runtime import FunctionsRuntime, FunctionCall
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import text_content_block_from_string
progent.api_request = forbidden
EXECUTOR_PATH = Path(os.environ['PROGENT_SOURCE']) / 'agentdojo/src/agentdojo/agent_pipeline/tool_execution.py'
spec = importlib.util.spec_from_file_location('audit_original_executor', EXECUTOR_PATH)
executor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(executor)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode()).hexdigest()

def normal(value):
    return json.loads(json.dumps(value, default=str))

def effect(call):
    return {key: copy.deepcopy(call[key]) for key in ['function', 'args']}

def base(policy):
    return {tool: [rule for rule in rules if rule[0] < 100]
            for tool, rules in (policy or {}).items() if any(rule[0] < 100 for rule in rules)}

def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def native_submit(suite, anchor, owner, candidate, policy=None, stage=0):
    """Original executor, function runtime and (when given) secure wrapper; no updater."""
    env = anchor.model_copy(deep=True)
    calls, inputs = [], []
    old_check = progent.check_tool_call
    old_update = executor.generate_update_security_policy
    original_policy = copy.deepcopy(policy)
    progent.available_tools = []
    progent.security_policy = None
    progent.init_user_query = owner
    if policy is not None:
        functions = [f.model_copy(update={'run': progent.apply_secure_tool_wrapper(f.run)}) for f in suite.tools]
        progent.update_always_allowed_tools(['get_most_recent_transactions'], allow_all_no_arg_tools=True)
        progent.security_policy = copy.deepcopy(policy)
        fields = {f.name: set(f.parameters.model_fields) for f in suite.tools}
        def checked(name, kwargs):
            decision = {'operation': {'function': name, 'args': {k: copy.deepcopy(v) for k, v in kwargs.items() if k in fields[name]}},
                        'policy_before_sha256': digest(progent.security_policy)}
            try:
                result = old_check(name, kwargs)
                decision['allowed'] = True
                return result
            except Exception as exc:
                decision.update(allowed=False, reason=str(exc))
                raise
            finally:
                decision['policy_after_sha256'] = digest(progent.security_policy)
                calls.append(decision)
        progent.check_tool_call = checked
    else:
        functions = suite.tools
    def captured(params, result, manual_check=True):
        inputs.append({'tool_call_param': copy.deepcopy(params), 'tool_call_result': result, 'manual_check': manual_check})
    executor.generate_update_security_policy = captured
    try:
        call = FunctionCall.model_validate(candidate)
        call.id = f'x2_stage_{stage}'
        output = executor.ToolsExecutor().query(owner, FunctionsRuntime(functions), env,
                   [{'role': 'assistant', 'content': '', 'tool_calls': [call]}], {})
        response = output[3][-1]
        assert len(inputs) == 1
        if policy is not None:
            assert len(calls) == 1
            assert normal(progent.security_policy) == normal(original_policy), 'Native checker mutated saved policy'
        return {'env': env, 'response': response, 'decision': calls[0] if calls else None,
                'update_input': inputs[0], 'tool_definitions': normal(progent.get_available_tools())}
    finally:
        progent.check_tool_call = old_check
        executor.generate_update_security_policy = old_update


def coupled_responses(run, config, row, cache_root):
    cid, arm = row['case_id'], row['arm']
    path = run / cid / (arm + '.policy-journal.jsonl')
    journal = [json.loads(line) for line in path.read_text().splitlines() if line.strip()] if path.exists() else []
    responses = [j for j in journal if j.get('stage') == 'policy_response']
    assert len(responses) == len(row['policy_calls'])
    counts = Counter()
    records = []
    for index, (j, meta) in enumerate(zip(responses, row['policy_calls'])):
        assert j['response']['meta'] == meta
        expected_request = hashlib.sha256(json.dumps(j['request'], sort_keys=True).encode()).hexdigest()
        assert j['request_sha256'] == expected_request
        coupling = meta['coupling']
        identity, occurrence = coupling['input_identity'], coupling['occurrence']
        counts[identity] += 1
        assert occurrence == counts[identity]
        assert coupling['stage'] == j['logical_stage']
        assert coupling['sample_key'] == digest([identity, occurrence])
        cache = cache_root / config['campaign'] / config['phase'] / config['panel'] / cid / (coupling['sample_key'] + '.json')
        saved = json.loads(cache.read_text())
        assert saved['key'] == coupling['sample_key']
        assert saved['response_sha256'] == digest(saved['response'])
        assert j['response']['ok'] == saved['response']['ok']
        for key in ['text', 'error']:
            assert j['response'].get(key) == saved['response'].get(key)
        for key in ['request_sha256', 'policy_instruction_sha256', 'requested_model', 'reasoning_effort', 'requested_upstream_temperature']:
            assert meta.get(key) == saved['response']['meta'].get(key)
        if coupling['cache_hit']:
            assert meta['actual_network_call'] is False
            assert meta.get('cached_sample_usage') == saved['response']['meta'].get('usage')
        else:
            assert meta.get('actual_network_call') == saved['response']['meta'].get('actual_network_call')
        records.append({'panel': config['panel'], 'case_id': cid, 'arm': arm,
                        'request_sha256': expected_request, 'logical_stage': j['logical_stage'],
                        'input_identity': identity, 'occurrence': occurrence,
                        'sample_key': coupling['sample_key'], 'response_sha256': saved['response_sha256'],
                        'cache_file_sha256': sha(cache), 'cache_hit': coupling['cache_hit'],
                        'call_index': index})
    return responses, records


def subset_replay(row, responses):
    verified = []
    for update in row['update_records']:
        before = update['policy_before']
        assert digest(before) == update['before_sha256']
        assert digest(update['policy_after']) == update['after_sha256']
        assert normal(base(before)) == normal(base(update['policy_after']))
        expected_checks = update.get('subset_checks', [])
        reconstructed = []
        candidates = []
        for j in responses[update['calls_before']:update['calls_after']]:
            if j['logical_stage'] != 'regeneration' or not j['response']['ok']:
                continue
            generated = extract_json(j['response']['text'])
            if generated is None:
                continue
            candidate = copy.deepcopy(base(before))
            try:
                for tool in generated:
                    candidate.setdefault(tool['name'], []).append((100, 0, tool['args'], 0))
            except (KeyError, TypeError):
                # Native updater would reject/retry malformed response before the subset check.
                continue
            candidates.append(candidate)
            if row['arm'] != 'narrow_only':
                continue
            check = {'before_sha256': digest(before), 'candidate_sha256': digest(candidate)}
            try:
                check['result'] = bool(progent.security_policy_subset_check(copy.deepcopy(before), copy.deepcopy(candidate)))
            except Exception as exc:
                check.update(result=None, error=type(exc).__name__)
            reconstructed.append(check)
        assert reconstructed == expected_checks, 'Recorded subset checks differ from native checker on regenerated candidates'
        if update.get('applied'):
            assert candidates and digest(candidates[-1]) == update['after_sha256']
            if row['arm'] == 'narrow_only':
                assert reconstructed and reconstructed[-1]['result'] is True
        else:
            assert update['before_sha256'] == update['after_sha256']
        verified.append({'stage': update['stage'], 'recorded_checks_reproduced': len(reconstructed),
                         'applied': update.get('applied', False), 'policy_changed': update['policy_changed']})
    return verified


def audit_record(run, config, fixture, cache_root):
    cid, arm = fixture['case_id'], config['arm']
    path = run / cid / (arm + '.json.gz')
    raw = json.loads(gzip.decompress(path.read_bytes()))
    row = raw['result']
    assert row['case_id'] == cid and row['arm'] == arm and row['panel'] == fixture['panel']
    assert raw['fresh_actor'] is False and row['fresh_actor'] is False
    assert raw['prompt'] == fixture['owner_request']
    assert raw['initial'] == fixture['state'] and raw['retained_original_initial'] == fixture['initial_state']
    assert row['initial_state_sha256'] == digest(fixture['state'])
    assert row['initial_policy_sha256'] == digest(fixture['policy'])
    assert all(effect(c) == effect(fixture['candidate']) for c in raw['proposed_calls'])
    assert len(raw['proposed_calls']) == len(row['steps'])
    assert 1 <= len(row['steps']) <= 4
    assert not any(s['allowed'] for s in row['steps'][:-1]), 'Submissions continued after admission'
    suite = get_suite('v1.2.2', 'banking')
    Env = type(suite.load_and_inject_default_environment({}))
    anchor, initial = Env.model_validate(fixture['state']), Env.model_validate(fixture['initial_state'])
    target = FunctionCall.model_validate(fixture['candidate'])
    goal = suite.get_injection_task_by_id(fixture['injection_id'])
    def score(env):
        return bool(suite._check_injection_task_security(goal, [text_content_block_from_string('')],
                     initial.model_copy(deep=True), env.model_copy(deep=True), [target]))
    step_audits = []
    event_index = 0
    final = anchor
    for i, stage in enumerate(row['steps']):
        assert stage['stage'] == i
        assert stage['state_before_sha256'] == digest(fixture['state'])
        candidate = copy.deepcopy(fixture['candidate'])
        if arm != 'pga_minimal':
            policy = stage['policy_before']
            assert normal(base(policy)) == normal(base(fixture['policy']))
            assert normal(base(stage['policy_after'])) == normal(base(fixture['policy']))
            if i == 0:
                assert normal(policy) == normal(fixture['policy'])
            else:
                assert normal(policy) == normal(row['steps'][i-1]['policy_after'])
            replay = native_submit(suite, anchor, fixture['owner_request'], candidate, policy, i)
            assert replay['decision'] == stage['decision']
            assert replay['decision'] == row['progent_decisions'][i]
            assert replay['decision']['allowed'] == stage['allowed']
            assert replay['response']['error'] == stage['native_error']
            assert replay['response']['content'] == stage['formatted_result']
            for key, value in replay['update_input'].items():
                assert value == stage['native_updater_input'][key]
            if fixture.get('tool_definitions') is not None:
                assert replay['tool_definitions'] == fixture['tool_definitions']
            final = replay['env']
        elif stage['allowed']:
            # Replay the observed native invocation, not the semantic authorization.
            replay = native_submit(suite, anchor, fixture['owner_request'], candidate, None, i)
            final = replay['env']
            assert replay['response']['error'] == stage['native_error']
            assert replay['response']['content'] == stage['formatted_result']
        else:
            final = anchor.model_copy(deep=True)
            assert stage['decision']['decision'] != 'allow'
            assert stage['decision'] == row['gate_decisions'][i]
            assert stage['operational_unavailable'] == bool(stage['decision'].get('operational_unavailable'))
        state = final.model_dump(mode='json')
        assert digest(state) == stage['state_after_sha256']
        assert (state != fixture['state']) == stage['state_changed']
        assert score(final) == stage['native_goal']
        if arm != 'pga_minimal' or stage['allowed']:
            event = raw['events'][event_index]
            event_index += 1
            assert event['before'] == fixture['state'] and event['after'] == state
            assert event['entry_state_changed'] == stage['state_changed']
            assert event['error'] == stage['native_error']
            # PGA stores normalized defaults; validate through the native schema before comparing.
            parameters = {f.name: f.parameters for f in suite.tools}[candidate['function']]
            assert parameters.model_validate(event['operation']['args']).model_dump() == parameters.model_validate(candidate['args']).model_dump()
            assert event['operation']['function'] == candidate['function']
        step_audits.append({'stage': i, 'native_admission_replayed': arm != 'pga_minimal',
                           'observed_native_effect_replayed': arm != 'pga_minimal' or stage['allowed'],
                           'saved_state_and_native_goal_verified': True,
                           'review_unavailable_retained': bool(stage.get('operational_unavailable'))})
    assert event_index == len(raw['events'])
    assert raw['final'] == final.model_dump(mode='json')
    assert row['observed_final_native_goal'] == score(final)
    if row.get('native_targeted_asr') is not None:
        assert row['native_targeted_asr'] == score(final)
    coupling, checks = [], []
    if arm != 'pga_minimal':
        responses, coupling = coupled_responses(run, config, row, cache_root)
        checks = subset_replay(row, responses)
        assert len(raw['policy_history']) == len(row['steps']) + 1
        assert normal(raw['policy_history'][0]['policy']) == normal(fixture['policy'])
        for stage, history in zip(row['steps'], raw['policy_history'][1:]):
            assert normal(stage['policy_after']) == normal(history['policy'])
    else:
        unavailable = sum(s.get('operational_unavailable', False) for s in row['steps'])
        assert row['pga_operational_unavailable'] == unavailable
        if unavailable:
            assert row['scientific_status'] == 'review_unavailable'
            assert row['status'] == 'completed_with_review_unavailable'
    return {'case_id': cid, 'panel': config['panel'], 'arm': arm, 'passed': True,
            'raw_sha256': sha(path), 'step_audits': step_audits,
            'subset_checks': checks, 'coupling': coupling,
            'stage0': {'allowed': row['steps'][0]['allowed'], 'error': row['steps'][0]['native_error'],
                       'state_sha256': row['steps'][0]['state_before_sha256'],
                       'policy_sha256': row['initial_policy_sha256'], 'candidate_sha256': digest(effect(fixture['candidate']))},
            'original_scientific_status': row.get('scientific_status'),
            'pga_semantic_model_replayed': False,
            'pga_unavailable_episode_retained': arm == 'pga_minimal' and bool(row['pga_operational_unavailable'])}


def cross_record_checks(rows, qualification=False):
    groups = defaultdict(dict)
    coupling = defaultdict(list)
    for row in rows:
        if not row['passed']:
            continue
        groups[(row['panel'], row['case_id'])][row['arm']] = row
        for call in row['coupling']:
            coupling[(row['panel'], row['case_id'], call['sample_key'])].append(call)
    pairs = []
    for (panel, cid), arms in groups.items():
        if 'auto_approve' in arms and 'narrow_only' in arms:
            assert arms['auto_approve']['stage0'] == arms['narrow_only']['stage0']
            pairs.append({'panel': panel, 'case_id': cid, 'same_initial_control': True})
        elif not qualification:
            assert not ({'auto_approve', 'narrow_only'} & set(arms)), 'Missing paired Progent audit'
    shared = 0
    for records in coupling.values():
        if len(records) < 2:
            continue
        assert len(records) == 2 and {r['arm'] for r in records} == {'auto_approve', 'narrow_only'}
        for field in ['request_sha256', 'logical_stage', 'input_identity', 'occurrence', 'response_sha256', 'cache_file_sha256']:
            assert len({r[field] for r in records}) == 1
        assert sum(not r['cache_hit'] for r in records) <= 1
        shared += 1
    # Also detect identical requests that wrongly received different cross-arm identities.
    inputs = defaultdict(list)
    for row in rows:
        if not row['passed']:
            continue
        for call in row['coupling']:
            inputs[(row['panel'], row['case_id'], call['logical_stage'], call['request_sha256'], call['occurrence'])].append(call)
    for calls in inputs.values():
        if {r['arm'] for r in calls} == {'auto_approve', 'narrow_only'}:
            assert len({r['sample_key'] for r in calls}) == 1
    return {'paired_initial_controls_verified': len(pairs), 'paired_controls': pairs,
            'shared_policy_response_records_verified': shared,
            'provider_scope_limit': 'Credential-derived scope hash is opaque; credential material is not read. Exact request hash, stage, occurrence, recorded identity-to-key hash and saved response checksum are verified.'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', type=Path, nargs='+', required=True)
    ap.add_argument('--fixtures', type=Path, required=True, help='Frozen fixtures directory or manifest.json')
    ap.add_argument('--coupling-root', type=Path, default=Path('/artifact-source/5b0515137436/x2-coupling'))
    ap.add_argument('--out', type=Path)
    ap.add_argument('--case', help='One-case model-free qualification; never a full-panel audit')
    a = ap.parse_args()
    a.out = a.out or Path(os.environ['AROS_ARTIFACTS'])
    a.out.mkdir(parents=True, exist_ok=True)
    assert not (a.out / 'result.json').exists(), 'Use a fresh audit output'
    manifest_path = a.fixtures / 'manifest.json' if a.fixtures.is_dir() else a.fixtures
    manifest = json.loads(manifest_path.read_text())
    fixtures = {(r['panel'], r['case_id']): r for r in manifest['cases']}
    jobs = []
    for run in a.runs:
        config = json.loads((run / 'config.json').read_text())
        assert config['phase'] == 'main' and not config['model_free_scripted']
        assert config['manifest_sha256'] == sha(manifest_path)
        assert len(config['cases']) == len(set(config['cases']))
        assert set(config['cases']) == {cid for panel, cid in fixtures if panel == config['panel']}
        jobs.append((run, config))
    if not a.case:
        assert {(c['panel'], c['arm']) for _, c in jobs} == {(p, arm) for p in ['post_exposure', 'initial'] for arm in ['auto_approve', 'narrow_only', 'pga_minimal']}
        assert len(jobs) == 6
    provenance = {'audit': 'x2-native-v1', 'qualification_only': bool(a.case),
                  'script_sha256': sha(__file__), 'fixture_manifest_sha256': sha(manifest_path),
                  'source_pins': {'progent': subprocess.check_output(['git','-C',os.environ['PROGENT_SOURCE'],'rev-parse','HEAD'], text=True).strip()},
                  'source_sha256': {str(p): sha(p) for p in [EXECUTOR_PATH, Path(progent.__file__),
                       Path(os.environ['PROGENT_SOURCE']) / 'secagent/policy_analysis.py']},
                  'runs': [{'path':str(run),'config_sha256':sha(run/'config.json')} for run,_ in jobs],
                  'coupling_root': str(a.coupling_root),
                  'scope': 'Native/code-and-record consistency only; no fresh inference, semantic-review correctness or population independence claim. Arm records and overlapping panel units are not independent cases.'}
    assert provenance['source_pins']['progent'] == 'b02783b896d4bf01a2adf24738015e258db8d35b'
    provenance['progent_worktree_status'] = subprocess.check_output(['git','-C',os.environ['PROGENT_SOURCE'],'status','--short'], text=True).strip()
    assert provenance['progent_worktree_status'] == '', 'Pinned Progent source changed'
    suite = get_suite('v1.2.2', 'banking')
    native_files = {Path(inspect.getfile(FunctionsRuntime))}
    native_files.update(Path(inspect.getfile(f.run)) for f in suite.tools)
    native_files.update(Path(inspect.getfile(type(suite.get_injection_task_by_id(f'injection_task_{i}')))) for i in range(9))
    provenance['native_source_sha256'] = {str(path): sha(path) for path in sorted(native_files)}
    save(a.out / 'config.json', provenance)
    rows = []
    start = time.monotonic()
    for run, config in jobs:
        for cid in config['cases']:
            if a.case and cid != a.case:
                continue
            indexed = fixtures[(config['panel'], cid)]
            path = manifest_path.parent / indexed['path']
            assert sha(path) == indexed['sha256']
            fixture = json.loads(path.read_text())
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    result = audit_record(run, config, fixture, a.coupling_root)
            except Exception as exc:
                result = {'case_id':cid,'panel':config['panel'],'arm':config['arm'],'passed':False,
                          'error':type(exc).__name__,'traceback':traceback.format_exc()}
            rows.append(result)
            save(a.out / 'records' / config['panel'] / (cid + '__' + config['arm'] + '.json'), result)
            (a.out / 'status.md').write_text(f"X2 native audit: {len(rows)} arm records checked; failures {sum(not r['passed'] for r in rows)}; elapsed {time.monotonic()-start:.1f}s.\n")
    assert rows, 'No records selected'
    cross = {}
    cross_failure = None
    try:
        cross = cross_record_checks(rows, bool(a.case))
    except Exception:
        cross_failure = traceback.format_exc()
    summary = {'audit_only':True, 'qualification_only':bool(a.case), 'arm_records_checked':len(rows),
               'arm_records_passed':sum(r['passed'] for r in rows), 'failed_records':[r for r in rows if not r['passed']],
               'distinct_panel_units_checked':len({(r['panel'],r['case_id']) for r in rows}),
               'distinct_case_ids_checked':len({r['case_id'] for r in rows}),
               'pga_unavailable_episodes_preserved':sum(r.get('pga_unavailable_episode_retained',False) for r in rows),
               'pga_semantic_model_replayed':False, 'cross_record_checks':cross,'cross_record_failure':cross_failure,
               'model_calls':0,'network_calls':0,'forbidden_attempts':len(NETWORK_ATTEMPTS),
               'elapsed_s':time.monotonic()-start,'scientific_counts_replaced':False}
    summary['passed'] = all(r['passed'] for r in rows) and cross_failure is None and not NETWORK_ATTEMPTS
    if not a.case:
        summary['passed'] &= len(rows) == 630 and len({(r['panel'],r['case_id']) for r in rows}) == 210 and summary['pga_unavailable_episodes_preserved'] == 1
    save(a.out / 'result.json', summary)
    print(json.dumps(summary, indent=2))
    if not summary['passed']:
        raise SystemExit(1)

if __name__ == '__main__':
    main()
