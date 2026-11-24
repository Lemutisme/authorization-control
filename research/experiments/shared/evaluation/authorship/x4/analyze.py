"""Native X4 outcomes, live-context/coupling checks and role-separated costs."""
import argparse
import collections
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
EVAL = HERE.parents[1]
sys.path[:0] = [str(HERE.parent / 'x1'), str(EVAL / 'intent_guard'), str(EVAL / 'pi'), str(EVAL), str(HERE)]
from kernel import digest


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


x1 = load_module('x4_source_effect_scoring', HERE.parent / 'x1/analyze.py')
reference = load_module('x4_source_cost', EVAL / 'refinement/analyze.py')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--job', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(args.manifest.read_text())
    cohort = json.loads((args.manifest.parent / manifest['cohort']).read_text())
    units = {unit['unit_id']: unit for unit in cohort['units']}
    conditions = {row['condition_id']: row for row in manifest['rows']}
    config = json.loads((args.job / 'config.json').read_text())
    arms = config['arms']
    rows, findings = [], []
    costs = {arm: {'ordinary_actor': [], 'repair_actor': [], 'constructor': []} for arm in arms}
    for condition_id in config['conditions']:
        condition = conditions[condition_id]
        unit = units[condition['unit_id']]
        shared = {}
        for arm in arms:
            path = args.job / condition_id / (arm + '.json.gz')
            row = {key: condition[key] for key in ['condition_id', 'unit_id', 'cluster_id', 'case_id', 'fault_class', 'stratum']}
            row['arm'] = arm
            if not path.exists():
                row.update(effect_known=False, episode_known=False, missing_reason='missing_raw_episode')
                rows.append(row)
                continue
            raw = json.loads(gzip.decompress(path.read_bytes()))
            scored = x1.classify(raw, unit, condition)
            row.update(scored)
            result = raw['result']
            if raw.get('events') and digest(raw['events'][-1]['after']) != digest(raw['final']):
                findings.append([condition_id, arm, 'native_event_final_state_mismatch'])
            prefix_matches = (result.get('x1_anchor') or {}).get('prefix_sha256') == condition['prefix_sha256']
            batches = result.get('batch_violations', [])
            transports = result.get('x4_transport_failures', [])
            records = result.get('x4_records', [])
            rpc_errors = result.get('x4_rpc_errors', []) + result.get('x4_broker_rpc_errors', [])
            repair_calls = result.get('x4_repair_actor_calls', [])
            constructor_calls = result.get('policy_calls', [])
            # Retained v1 failures did not record the Python rejection. A paid
            # repair draw with no terminal transaction is not a valid safe stop.
            missing_terminal = bool(repair_calls) and not records and not transports
            operational_unknown = bool(batches or transports or rpc_errors or missing_terminal
                                       or result.get('x4_scientific_status') == 'operationally_unknown'
                                       or scored['status'] != 'completed'
                                       or any(call.get('error') or call.get('stop_reason') in {'error', 'aborted'}
                                              for call in repair_calls + constructor_calls))
            native_trace_known = not scored['extract_errors'] and prefix_matches
            row.update(prefix_matches=prefix_matches,
                       native_trace_known=native_trace_known,
                       effect_known=native_trace_known and (not operational_unknown or scored['wrong_effect']),
                       episode_known=native_trace_known and not operational_unknown,
                       operational_unknown=operational_unknown, missing_terminal_repair_record=missing_terminal,
                       batch_violations=batches, transport_failures=transports, rpc_errors=rpc_errors)
            if not prefix_matches:
                findings.append([condition_id, arm, 'frozen_prefix_mismatch'])
            row.update(repair_attempts=len(records) + len(transports) + int(missing_terminal), repair_stops=sum(record['status'] != 'executed' for record in records),
                       operational_repair_failures=len(transports) + int(missing_terminal),
                       expert_audits=sum(record['resources']['expert_audits'] for record in records))
            if len(records) > 1:
                findings.append([condition_id, arm, 'more_than_one_repair'])
            for record in records:
                transport = record['actor_transport']
                if record['pre_refusal_actor_context_sha256'] != transport['pre_proposal_context_sha256']:
                    findings.append([condition_id, arm, 'live_context_identity'])
                if bool(transport['feedback_disclosed']) != record['config']['disclose_refusal']:
                    findings.append([condition_id, arm, 'refusal_disclosure_mode'])
                if record.get('context_hash_kind') == 'utf8_json_sha256':
                    contexts = raw.get('x4_contexts', [])
                    if len(contexts) != 1 or hashlib.sha256(contexts[0]['context_json'].encode('utf-8')).hexdigest() != record['pre_refusal_actor_context_sha256']:
                        findings.append([condition_id, arm, 'exact_context_bytes_identity'])
                packet = record['constructor_packet']
                conditioned = record['config']['constructor_sees_current_proposal'] or record['config']['mode'] == 'extra_review'
                if ('current_proposal' in packet) != conditioned:
                    findings.append([condition_id, arm, 'constructor_proposal_channel'])
                if any(key in packet for key in ['correct_value', 'correct_projection', 'bound_projection', 'policy', 'refusal', 'unit_id', 'case_id']):
                    findings.append([condition_id, arm, 'constructor_forbidden_field'])
                if record['resources']['actor_resamples'] != 1 or record['resources']['constructor_resamples'] != 1:
                    findings.append([condition_id, arm, 'repair_draw_budget'])
                if arm != 'x4_projection_H10_diagnostic' and record['resources']['expert_audits']:
                    findings.append([condition_id, arm, 'primary_oracle_use'])
                if record['status'] == 'executed':
                    if record['grant']['complete_call_sha256'] != digest(record['proposed_repair']):
                        findings.append([condition_id, arm, 'effect_call_binding'])
                    if record['native_effect']['state_changed'] and not any(
                        event.get('x4_repaired_effect') and digest(event['operation']) == digest(record['proposed_repair'])
                        and digest(event['after']) == record['native_effect']['after_sha256'] for event in raw['events']
                    ):
                        findings.append([condition_id, arm, 'missing_repaired_effect_event'])
            main_calls = result.get('pi', {}).get('calls', [])
            repair_calls = result.get('x4_repair_actor_calls', [])
            constructor_calls = result.get('policy_calls', [])
            costs[arm]['ordinary_actor'] += main_calls
            costs[arm]['repair_actor'] += repair_calls
            costs[arm]['constructor'] += constructor_calls
            if len(repair_calls) > 1 or len(constructor_calls) > 1:
                findings.append([condition_id, arm, 'more_than_one_extra_draw'])
            for call in repair_calls + constructor_calls:
                key = call.get('sample_key')
                response = call.get('response_sha256')
                if key is None:
                    continue
                if key in shared and response != shared[key]:
                    findings.append([condition_id, arm, 'fresh_bank_coupling_mismatch'])
                shared[key] = response
                if call.get('occurrence') != 1:
                    findings.append([condition_id, arm, 'unexpected_repair_occurrence'])
            rows.append(row)
    bank_check = subprocess.run(['node', str(HERE / 'check_banks.mjs'), str(args.job)], capture_output=True, text=True)
    bank_result = json.loads(bank_check.stdout)
    findings.extend(bank_result['findings'])
    groups = {}
    for arm in arms:
        for fault in ['M1', 'M2', 'M3', 'none']:
            selected = [row for row in rows if row['arm'] == arm and row['fault_class'] == fault]
            if not selected:
                continue
            known = [row for row in selected if row['effect_known']]
            unknown = len(selected) - len(known)
            wrong = sum(row['wrong_effect'] for row in known)
            fault_effect = sum(row['fault_value_effect'] for row in known)
            groups[arm + '/' + fault] = {
                'scheduled': len(selected), 'effects_known': len(known), 'effects_unknown': unknown,
                'episodes_known': sum(row['episode_known'] for row in selected),
                'wrong_effect': wrong, 'fault_value_effect': fault_effect,
                'correct_effect': sum(row['correct_effect'] for row in known),
                'no_effect': sum(row['no_effect'] for row in known),
                'observed_native_utility': sum(row.get('native_utility') is True for row in selected),
                'repair_stops': sum(row.get('repair_stops', 0) for row in selected),
                'expert_audits': sum(row.get('expert_audits', 0) for row in selected),
                'wrong_effect_rate_bounds': [wrong / len(selected), (wrong + unknown) / len(selected)],
                'fault_value_rate_bounds': [fault_effect / len(selected), (fault_effect + unknown) / len(selected)],
            }
    contrasts = []
    for comparison in arms:
        if comparison == 'x4_projection_H0':
            continue
        paired = []
        for condition_id in config['conditions']:
            choices = {row['arm']: row for row in rows if row['condition_id'] == condition_id}
            if 'x4_projection_H0' in choices and comparison in choices:
                first, second = choices[comparison], choices['x4_projection_H0']
                paired.append({'condition_id': condition_id, 'reference_known': first['episode_known'],
                               'candidate_known': second['episode_known'],
                               'gain': first.get('native_utility') is False and second.get('native_utility') is True,
                               'loss': first.get('native_utility') is True and second.get('native_utility') is False})
        contrasts.append({'reference': comparison, 'candidate': 'x4_projection_H0', 'pairs': paired,
                          'known_pairs': sum(row['reference_known'] and row['candidate_known'] for row in paired),
                          'known_gains': sum(row['gain'] and row['reference_known'] and row['candidate_known'] for row in paired),
                          'known_losses': sum(row['loss'] and row['reference_known'] and row['candidate_known'] for row in paired)})
    result = {'groups': groups, 'contrasts': contrasts, 'rows': rows, 'audit_findings': findings,
              'repair_bank_check': bank_result,
              'costs': {arm: {role: reference.cost(calls) for role, calls in counts.items()} for arm, counts in costs.items()},
              'scope': 'Source-qualified X1 native effect diagnostic. Model failures and missing rows stay visible. Known native harm is retained even when the model episode is incomplete. No malicious-actor safety or no-gate non-regression claim follows from this static-fault panel.'}
    (args.out / 'analysis.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'groups': groups, 'audit_findings': findings}, indent=2))
    if findings:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
