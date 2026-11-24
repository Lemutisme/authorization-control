"""Native score, approval instrumentation and paired-outcome audit for X3."""
import argparse
import collections
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys

EVALUATION = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(EVALUATION / 'intent_guard'), str(EVALUATION / 'pi'), str(EVALUATION), str(Path(__file__).parent)]


def blocked(*args, **kwargs):
    raise RuntimeError('Analysis network disabled')


socket.create_connection = blocked
socket.socket.connect = blocked
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import text_content_block_from_string
from controller import ARMS, digest, non_generated, generated_tools

spec = importlib.util.spec_from_file_location('x3_refinement_analysis', EVALUATION / 'refinement/analyze.py')
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--main', type=Path, required=True)
    parser.add_argument('--repeat', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    suite = get_suite('v1.2.2', 'banking')
    Env = type(suite.load_and_inject_default_environment({}))
    findings, missing, panels = [], [], {}
    for label, folder in [('main', args.main), ('clean_repeat', args.repeat)]:
        if folder is None:
            continue
        source = json.loads((folder / 'summary.json').read_text())
        costs = {arm: {'actor': [], 'control': []} for arm in ARMS}
        counters = {arm: collections.Counter() for arm in ARMS}
        updates, rows = [], []
        for row in source['rows']:
            case = folder / row['case_id']
            reference.journal_audit(case, ARMS, findings)
            initial_hashes, provider_hashes, actor_samples = [], [], {}
            for arm in ARMS:
                episode = row['arms'][arm]
                raw_path = case / (arm + '.json.gz')
                if not raw_path.exists():
                    missing.append([label, row['case_id'], arm, 'raw_episode_unavailable'])
                    continue
                raw = json.loads(gzip.decompress(raw_path.read_bytes()))
                pre, post = Env.model_validate(raw['initial']), Env.model_validate(raw['final'])
                trace = [FunctionCall.model_validate(call) for call in raw['proposed_calls']]
                task = suite.get_injection_task_by_id(row['task_id']) if row['condition'] == 'goal_control' else suite.get_user_task_by_id(row['task_id'])
                messages = [text_content_block_from_string(raw['final_response'])]
                utility = suite._check_task_result(task, messages, pre.model_copy(deep=True), post.model_copy(deep=True), trace)
                if bool(utility) != episode.get('native_utility'):
                    findings.append([label, row['case_id'], arm, 'native_utility_mismatch'])
                if row['condition'] == 'attack':
                    goal = suite.get_injection_task_by_id(row['case_id'].split('__')[-1])
                    target = suite._check_injection_task_security(goal, messages, pre.model_copy(deep=True), post.model_copy(deep=True), trace)
                    if bool(target) != episode.get('native_targeted_asr'):
                        findings.append([label, row['case_id'], arm, 'native_target_mismatch'])
                initial_hashes.append(digest(pre.model_dump(mode='json')))
                provider_hashes.append(episode.get('provider_scope_sha256'))
                for call in episode.get('pi', {}).get('calls', []):
                    coupling = call.get('coupling', {})
                    key, response = coupling.get('request_sha256'), coupling.get('response_sha256')
                    if key in actor_samples and actor_samples[key] != response:
                        findings.append([label, row['case_id'], arm, 'actor_coupling_mismatch'])
                    actor_samples[key] = response
                costs[arm]['actor'] += episode.get('pi', {}).get('calls', [])
                costs[arm]['control'] += episode.get('policy_calls', [])
                history = raw.get('policy_history', [])
                recorded_updates = episode.get('update_records', [])
                if len(history) != len(recorded_updates) + 1:
                    findings.append([label, row['case_id'], arm, 'policy_history_update_count'])
                for index, update in enumerate(recorded_updates):
                    counters[arm]['updates'] += 1
                    before, after = update['policy_before'], update['policy_after']
                    if update['before_sha256'] != digest(before) or update['after_sha256'] != digest(after):
                        findings.append([label, row['case_id'], arm, index, 'policy_hash'])
                    if index + 1 < len(history) and digest(history[index + 1]['policy']) != digest(after):
                        findings.append([label, row['case_id'], arm, index, 'installed_policy_history'])
                    base_unchanged = non_generated(before) == non_generated(after)
                    if base_unchanged != update['non_generated_unchanged']:
                        findings.append([label, row['case_id'], arm, index, 'base_policy_change_flag'])
                    added = sorted(set(generated_tools(after)) - set(generated_tools(before)))
                    if added != update['generated_tools_added']:
                        findings.append([label, row['case_id'], arm, index, 'added_generated_tools'])
                    counters[arm]['base_changes'] += not base_unchanged
                    counters[arm]['added_generated_tools'] += bool(added)
                    checks = update['approver_checks']
                    counters[arm]['actual_smt_calls'] += len(checks)
                    counters[arm]['smt_rejects'] += sum(check.get('is_subset') is False for check in checks)
                    counters[arm]['smt_errors'] += sum(check.get('is_subset') is None for check in checks)
                    for check in checks:
                        if check['before_sha256'] != digest(check['before']) or check['candidate_sha256'] != digest(check['candidate']):
                            findings.append([label, row['case_id'], arm, index, 'actual_smt_input_hash'])
                    if arm.endswith('_auto') and checks:
                        findings.append([label, row['case_id'], arm, index, 'unexpected_auto_subset_decision'])
                    changed = digest(before) != digest(after)
                    subset = update['final_subset_diagnostic']['is_subset']
                    probe = update.get('current_call_probe')
                    counters[arm]['changed_updates'] += changed
                    counters[arm]['final_subset_unknown'] += subset is None
                    counters[arm]['current_call_probe_missing'] += probe is None
                    counters[arm]['current_call_new_admissions'] += bool(probe and probe['new_admission'])
                    if arm.endswith('_narrow') and changed:
                        counters[arm]['narrow_changed_non_subset'] += subset is False
                        counters[arm]['narrow_changed_subset_unknown'] += subset is None
                        counters[arm]['narrow_changed_without_accepted_check'] += not any(check.get('is_subset') is True for check in checks)
                    updates.append({
                        'panel': label, 'case_id': row['case_id'], 'arm': arm, 'index': index,
                        'selected': update.get('selected'), 'changed': changed,
                        'non_generated_unchanged': base_unchanged, 'generated_tools_added': added,
                        'final_subset': subset, 'new_current_call_admission': None if probe is None else probe['new_admission'],
                        'actual_smt_results': [check.get('is_subset') for check in checks],
                    })
            if len(initial_hashes) == len(ARMS) and len(set(initial_hashes)) != 1:
                findings.append([label, row['case_id'], 'initial_state_mismatch'])
            if len(provider_hashes) == len(ARMS) and (None in provider_hashes or len(set(provider_hashes)) != 1):
                findings.append([label, row['case_id'], 'provider_scope_mismatch'])
            rows.append({
                'case_id': row['case_id'], 'task_id': row['task_id'], 'condition': row['condition'],
                'arms': {arm: {key: row['arms'][arm].get(key) for key in ['status', 'native_utility', 'native_targeted_asr']} for arm in ARMS},
            })
        contrasts = []
        for condition in ['clean', 'attack', 'goal_control']:
            selected = [row for row in rows if row['condition'] == condition]
            if not selected:
                continue
            for control, intervention in [('optional_auto', 'optional_narrow'), ('forced_auto', 'forced_narrow'),
                                          ('optional_auto', 'forced_auto'), ('optional_narrow', 'forced_narrow')]:
                contrasts.append({'condition': condition, **reference.contrast(selected, control, intervention, 'native_utility')})
        panels[label] = {
            'scheduled': source['scheduled'], 'observed': len(rows), 'complete': source['complete'],
            'groups': source['groups'], 'contrasts': contrasts,
            'instrumentation': {arm: dict(counts) for arm, counts in counters.items()},
            'costs': {arm: {kind: reference.cost(calls) for kind, calls in groups.items()} for arm, groups in costs.items()},
            'updates': updates, 'rows': rows,
        }
    result = {
        'kind': 'Fresh original-approver ablation; no no-gate utility comparison',
        'panels': panels, 'audit_findings': findings, 'missing_records': missing,
        'model_requests': 0, 'network_requests': 0,
        'scope': 'Native score and retained-input audit. Post-update SMT diagnostic uses the same implementation as approval, not an independent proof of its semantic completeness. Fixed current-call probes are complementary finite witnesses.',
        'source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    (args.out / 'analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'panels': {label: panel['instrumentation'] for label, panel in panels.items()},
                      'audit_findings': findings, 'missing_records': missing}, indent=2))
    if findings:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
