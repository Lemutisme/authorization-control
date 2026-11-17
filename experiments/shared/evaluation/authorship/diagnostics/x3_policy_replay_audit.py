"""Recover original Python X3 policies from retained model text, never from hashes.

Native parser/updater replay follows X2 audit-v2: exact retained requests and
responses, original retry/partial-mutation behavior, no model transport.
Full 740-record execution requires root registration; --case/--arm qualify one.
"""
from pipeline.paths import resolve as research_path
import argparse
from collections import Counter
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import gzip
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback
ATTEMPTS = []

def forbidden(*args, **kwargs):
    ATTEMPTS.append('forbidden_call')
    raise AssertionError('No model or network calls in policy replay audit')
socket.create_connection = forbidden
socket.socket.connect = forbidden
socket.socket.connect_ex = forbidden
socket.socket.sendto = forbidden
sys.path[:0] = [os.environ['BASELINE_VENDOR'], os.environ['PROGENT_SOURCE']]
os.environ.update(SECAGENT_POLICY_MODEL='gpt-6-luna', SECAGENT_GENERATE='True', SECAGENT_UPDATE='True', SECAGENT_IGNORE_UPDATE_ERROR='True', SECAGENT_ONLY_ALLOW_NARROW='False')
from secagent import tool as progent
from agentdojo.task_suite.load_suites import get_suite
progent.api_request = forbidden

def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode()).hexdigest()

def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.replace(path)

class NodeNormalizer:
    """Use the actual Node parse/stringify boundary; no hand-edited numeric types."""

    def __init__(self):
        script = "const r=require('node:readline').createInterface({input:process.stdin});r.on('line',s=>{try{process.stdout.write(JSON.stringify({ok:true,value:JSON.parse(JSON.stringify(JSON.parse(s)))})+'\\n')}catch(e){process.stdout.write(JSON.stringify({ok:false,error:e.name})+'\\n')}})"
        self.child = subprocess.Popen(['node', '-e', script], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def normalize(self, value):
        self.child.stdin.write(json.dumps(value, ensure_ascii=False, default=str) + '\n')
        self.child.stdin.flush()
        response = json.loads(self.child.stdout.readline())
        assert response['ok'], response
        return response['value']

    def close(self):
        self.child.stdin.close()
        assert self.child.wait(timeout=10) == 0

def numeric_changes(before, after, path='$'):
    rows = []
    if isinstance(before, dict) and isinstance(after, dict):
        for key in before:
            rows += numeric_changes(before[key], after[key], path + '.' + str(key))
    elif isinstance(before, (tuple, list)) and isinstance(after, list):
        for index, (a, b) in enumerate(zip(before, after)):
            rows += numeric_changes(a, b, path + f'[{index}]')
    elif type(before) in {int, float} and type(after) in {int, float} and (type(before) != type(after) or before != after):
        rows.append({'path': path, 'python_type': type(before).__name__, 'stored_type': type(after).__name__, 'python_repr': repr(before), 'stored_repr': repr(after), 'kind': 'integral_float_to_integer' if type(before) is float and type(after) is int and (before == after) else 'other_numeric_boundary_change'})
    return rows

class RetainedClient:

    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.stage = 'initial'
        self.errors = []
        self.cap_attempts = 0

    def request(self, system, user, temperature=0):
        if len(self.calls) >= 64:
            self.cap_attempts += 1
            raise RuntimeError('Policy request cap reached')
        index = len(self.calls)
        actual = {'system': system, 'user': user, 'temperature': temperature}
        if index >= len(self.responses):
            self.errors.append({'index': index, 'error': 'unexpected_extra_request'})
            raise AssertionError('Replay requested an unrecorded response')
        expected = self.responses[index]
        if actual != expected['request'] or self.stage != expected['logical_stage']:
            self.errors.append({'index': index, 'error': 'request_or_stage_mismatch', 'actual_sha256': digest(actual), 'expected_sha256': digest(expected['request']), 'actual_stage': self.stage, 'expected_stage': expected['logical_stage']})
            raise AssertionError('Exact original policy request did not reproduce')
        self.calls.append(copy.deepcopy(expected['response']['meta']))
        if not expected['response']['ok']:
            raise RuntimeError(expected['response']['error'])
        return expected['response']['text']

def load_controller(frozen):
    evaluation = frozen / 'evaluation'
    sys.path.insert(0, str(evaluation / 'intent_guard'))
    spec = importlib.util.spec_from_file_location('audited_frozen_x3_controller', evaluation / 'authorship/x3/controller.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    from catalog import PURE_READS
    return (module, PURE_READS)

def audit_episode(run, phase, cid, arm, controller, pure_reads, node):
    rawpath = run / cid / (arm + '.json.gz')
    raw = json.loads(gzip.decompress(rawpath.read_bytes()))
    row = raw['result']
    journalpath = run / cid / (arm + '.policy-journal.jsonl')
    responses = [j for j in (json.loads(s) for s in journalpath.read_text().splitlines() if s.strip()) if j.get('stage') == 'policy_response']
    assert len(responses) == len(row['policy_calls'])
    for j in responses:
        assert j['request_sha256'] == hashlib.sha256(json.dumps(j['request'], sort_keys=True).encode()).hexdigest()
    assert row['x3_arm'] == arm
    assert len(row['update_records']) == len(raw['proposed_calls'])
    assert len(raw['policy_history']) == len(row['update_records']) + 1
    suite = get_suite('v1.2.2', 'banking')
    progent.available_tools = []
    progent.security_policy = None
    progent.init_user_query = None
    for f in suite.tools:
        progent.apply_secure_tool_wrapper(f.run)
    progent.update_always_allowed_tools(['get_most_recent_transactions'], allow_all_no_arg_tools=True)
    client = RetainedClient(responses)
    progent.api_request = client.request
    changes = []
    locations = []

    def policy_readback(actual, stored, location, expected_hash=None):
        actual_hash = digest(actual)
        if expected_hash is not None:
            assert actual_hash == expected_hash, f'{location}: original Python hash mismatch'
        normalized = node.normalize(actual)
        assert digest(normalized) == digest(stored), f'{location}: Node-normalized stored policy mismatch'
        if actual_hash != digest(stored):
            difference = numeric_changes(actual, stored)
            assert difference, f'{location}: unexplained nonnumeric serialization difference'
            changes.append({'location': location, 'python_hash': actual_hash, 'stored_hash': digest(stored), 'changes': difference})
        locations.append(location)
    progent.generate_security_policy(raw['prompt'])
    assert not client.errors, client.errors
    policy_readback(progent.security_policy, raw['policy_history'][0]['policy'], 'initial_policy')
    if row['update_records']:
        assert len(client.calls) == row['update_records'][0]['calls_before']
    updates = []
    finding_resolutions = []
    for index, (saved, proposal) in enumerate(zip(row['update_records'], raw['proposed_calls'])):
        policy_readback(progent.security_policy, saved['policy_before'], f'update{index}.before', saved['before_sha256'])
        assert len(client.calls) == saved['calls_before']
        params = [{'name': proposal['function'], 'args': copy.deepcopy(proposal['args'])}]
        eligible = saved['native_error'] is None and proposal['function'] in pure_reads
        assert eligible == saved['eligible_boundary']
        function = next((f for f in suite.tools if f.name == proposal['function']))
        candidate = None
        probe_error = None
        try:
            candidate = {'function': proposal['function'], 'args': function.parameters.model_validate(proposal['args']).model_dump()}
        except Exception as exc:
            probe_error = type(exc).__name__
        assert probe_error == saved['current_call_probe_unavailable']
        replayed = controller.update_with_approval(progent, client, arm, params, saved['tool_result_for_update'], eligible=eligible, candidate=candidate, admission_checker=progent.check_tool_call)
        assert not client.errors, client.errors
        for key in ['before_sha256', 'after_sha256', 'selected', 'calls_before', 'calls_after', 'applications', 'status', 'policy_changed', 'applied', 'failed_responses', 'regeneration_requests', 'narrow_flag', 'approver_accepts', 'approver_rejects', 'approver_errors', 'non_generated_unchanged']:
            assert replayed.get(key) == saved.get(key), f'update{index}.{key}'
        policy_readback(progent.security_policy, saved['policy_after'], f'update{index}.after', saved['after_sha256'])
        policy_readback(progent.security_policy, raw['policy_history'][index + 1]['policy'], f'history{index + 1}')
        assert len(replayed['approver_checks']) == len(saved['approver_checks'])
        for check_index, (actual, stored) in enumerate(zip(replayed['approver_checks'], saved['approver_checks'])):
            for key in ['before_sha256', 'candidate_sha256', 'is_subset', 'error', 'message']:
                assert actual.get(key) == stored.get(key), f'update{index}.check{check_index}.{key}'
            policy_readback(actual['before'], stored['before'], f'update{index}.check{check_index}.before', stored['before_sha256'])
            policy_readback(actual['candidate'], stored['candidate'], f'update{index}.check{check_index}.candidate', stored['candidate_sha256'])
        assert node.normalize(replayed['final_subset_diagnostic']) == saved['final_subset_diagnostic']
        if candidate is not None:
            assert node.normalize(replayed['current_call_probe']) == saved['current_call_probe']
        before_mismatch = digest(saved['policy_before']) != saved['before_sha256']
        after_mismatch = digest(saved['policy_after']) != saved['after_sha256']
        if before_mismatch or after_mismatch:
            finding_resolutions.append([phase, cid, arm, index, 'policy_hash'])
        for check in saved['approver_checks']:
            if digest(check['before']) != check['before_sha256'] or digest(check['candidate']) != check['candidate_sha256']:
                finding_resolutions.append([phase, cid, arm, index, 'actual_smt_input_hash'])
        updates.append({'index': index, 'exact_before_after_hashes_reproduced': True, 'recorded_smt_checks_reproduced': len(saved['approver_checks']), 'eligible': eligible, 'selector': saved['selector'], 'responses_after': len(client.calls)})
    assert not client.errors and len(client.calls) == len(responses), 'Not all retained responses consumed exactly'
    return {'phase': phase, 'case_id': cid, 'arm': arm, 'passed': True, 'raw_sha256': sha(rawpath), 'journal_sha256': sha(journalpath), 'updates': updates, 'retained_policy_responses_consumed': len(client.calls), 'logical_cap_attempts_reproduced': client.cap_attempts, 'policy_readback_locations_checked': len(locations), 'serialization_changes': changes, 'resolved_prior_finding_keys': finding_resolutions, 'original_scientific_status': row.get('status'), 'models_called': 0, 'study_records_modified': False}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--runs', type=Path, nargs='+', required=True)
    ap.add_argument('--frozen', type=Path, default=Path(research_path('experiments/approvers')))
    ap.add_argument('--analysis', type=Path, default=Path(research_path('runs/authorship-x3-analysis-v1/analysis.json')))
    ap.add_argument('--out', type=Path)
    ap.add_argument('--case')
    ap.add_argument('--arm', choices=['optional_auto', 'optional_narrow', 'forced_auto', 'forced_narrow'])
    a = ap.parse_args()
    a.out = a.out or Path(os.environ['AROS_ARTIFACTS'])
    a.out.mkdir(parents=True, exist_ok=True)
    assert not (a.out / 'result.json').exists(), 'Fresh audit output required'
    assert not a.arm or a.case, 'Arm filter only for one-case qualification'
    controller, pure_reads = load_controller(a.frozen)
    analysis = json.loads(a.analysis.read_text())
    prior = analysis['audit_findings']
    assert all((f[-1] in {'policy_hash', 'actual_smt_input_hash'} for f in prior)), 'Named audit scope changed'
    run_configs = [(run, json.loads((run / 'config.json').read_text())) for run in a.runs]
    if not a.case:
        assert len(run_configs) == 2 and {c['phase'] for _, c in run_configs} == {'main', 'clean_repeat'}
        assert sum((len(c['cases']) * len(c['arms']) for _, c in run_configs)) == 740
    source = Path(os.environ['PROGENT_SOURCE'])
    assert subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip() == 'b02783b896d4bf01a2adf24738015e258db8d35b'
    assert not subprocess.check_output(['git', '-C', str(source), 'status', '--short'], text=True).strip()
    config = {'audit': 'x3-policy-replay-v1', 'qualification_only': bool(a.case), 'script_sha256': sha(__file__), 'analysis_path': str(a.analysis), 'analysis_sha256': sha(a.analysis), 'prior_finding_count': len(prior), 'frozen': str(a.frozen), 'sources': {str(p): sha(p) for p in [source / 'secagent/tool.py', source / 'secagent/policy_analysis.py', a.frozen / 'evaluation/authorship/x3/controller.py', a.frozen / 'evaluation/refinement/controllers.py']}, 'runs': [{'path': str(run), 'config_sha256': sha(run / 'config.json')} for run, _ in run_configs], 'scope': 'Exact response-defined Python policy reconstruction followed by real Node parse/stringify readback; no numeric-type guessing from hashes or relaxed hash matches.'}
    save(a.out / 'config.json', config)
    node = NodeNormalizer()
    rows = []
    started = time.monotonic()
    try:
        for run, c in run_configs:
            for cid in c['cases']:
                if a.case and cid != a.case:
                    continue
                for arm in c['arms']:
                    if a.arm and arm != a.arm:
                        continue
                    try:
                        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                            r = audit_episode(run, c['phase'], cid, arm, controller, pure_reads, node)
                    except Exception as exc:
                        r = {'phase': c['phase'], 'case_id': cid, 'arm': arm, 'passed': False, 'error': type(exc).__name__, 'traceback': traceback.format_exc()}
                    rows.append(r)
                    save(a.out / 'records' / c['phase'] / (cid + '__' + arm + '.json'), r)
                    (a.out / 'status.md').write_text(f'X3 policy replay: {len(rows)} arm records; {sum((not r['passed'] for r in rows))} failures; elapsed {time.monotonic() - started:.1f}s.\n')
    finally:
        node.close()
    assert rows
    selected = {(r['phase'], r['case_id'], r['arm']) for r in rows}
    expected = [f for f in prior if tuple(f[:3]) in selected]
    observed = [f for r in rows if r['passed'] for f in r['resolved_prior_finding_keys']]
    expected_counts = Counter((tuple(f) for f in expected))
    observed_counts = Counter((tuple(f) for f in observed))
    result = {'audit_only': True, 'qualification_only': bool(a.case), 'arm_records_checked': len(rows), 'arm_records_passed': sum((r['passed'] for r in rows)), 'failed_records': [r for r in rows if not r['passed']], 'prior_findings_selected': len(expected), 'prior_findings_reconciled': sum((expected_counts & observed_counts).values()), 'unresolved_findings': [list(k) + [v] for k, v in (expected_counts - observed_counts).items()], 'additional_hash_findings': [list(k) + [v] for k, v in (observed_counts - expected_counts).items()], 'serialization_change_kinds': dict(Counter((change['kind'] for r in rows if r['passed'] for location in r['serialization_changes'] for change in location['changes']))), 'model_calls': 0, 'network_calls': 0, 'forbidden_attempts': len(ATTEMPTS), 'elapsed_s': time.monotonic() - started, 'study_records_modified': False, 'scientific_counts_or_unknown_classifications_replaced': False, 'scope': 'Verification metadata, not 740 independent cases or replacement scientific outcomes.'}
    result['passed'] = all((r['passed'] for r in rows)) and expected_counts == observed_counts and (not ATTEMPTS)
    save(a.out / 'result.json', result)
    print(json.dumps(result, indent=2))
    if not result['passed']:
        raise SystemExit(1)
if __name__ == '__main__':
    main()
