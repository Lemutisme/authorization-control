"""Read-only X6 wire/context/resource audit and retained-response native replay.

All executable study code comes from --frozen. Model responses are replayed from
policy journals, never generated. Numeric policies are reconstructed by the
original parser and checked across an actual Node JSON boundary, not guessed
from hashes. The original scientific classifications are retained separately.
"""
from __future__ import annotations
import argparse
from collections import Counter
import concurrent.futures
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
import traceback


def load(path):
    path = Path(path)
    return json.loads(gzip.decompress(path.read_bytes()) if path.suffix == '.gz' else path.read_bytes())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def text_sha(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def digest(value):
    return text_sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str))


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(value, indent=2) + '\n')
    temporary.replace(path)


def require(condition, label):
    if not condition:
        raise AssertionError(label)


def stable(value):
    if isinstance(value, dict):
        return {key: stable(item) for key, item in value.items() if key != 'elapsed_s'}
    if isinstance(value, (list, tuple)):
        return [stable(item) for item in value]
    return value


class NodeJSON:
    """Real JS number/key serialization, without imports or provider access."""
    def __init__(self):
        code = "const r=require('node:readline').createInterface({input:process.stdin});r.on('line',s=>process.stdout.write(JSON.stringify({json:JSON.stringify(JSON.parse(s))})+'\\n'))"
        self.child = subprocess.Popen(['node', '-e', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def text(self, value):
        self.child.stdin.write(json.dumps(value, ensure_ascii=False, default=str) + '\n')
        self.child.stdin.flush()
        return json.loads(self.child.stdout.readline())['json']

    def normal(self, value):
        return json.loads(self.text(value))

    def close(self):
        self.child.stdin.close()
        self.child.wait(timeout=10)


def audit_records(raw, source):
    row = raw['result']
    arm, role = row['x6_arm'], row['x2b_role']
    ordinary = row['pi']['calls']
    extra = row['x6_repair_actor_calls']
    constructor = row['x6_constructor_calls']
    policy = row['policy_calls']
    actors = sorted(ordinary + extra, key=lambda item: item['draw_index'])
    checks, unavailable = 0, []
    require(len(actors) == row['pi']['actor_draw_budget']['used'] <= 16, 'actor total budget')
    require([item['draw_index'] for item in actors] == list(range(len(actors))), 'actor draw indices')
    require(row['combined_constructor_calls'] == len(policy) + row['repair_constructor_reservations'] <= 64, 'shared constructor budget')
    require(len(constructor) <= row['repair_constructor_reservations'], 'unreserved constructor draws')
    resource = row['x6_resources']
    expected = {'actor_budget_slots': len(actors), 'ordinary_actor_draws': len(ordinary), 'extra_actor_draws': len(extra),
        'actor_actual_network_calls': sum(item.get('actual_network_call') is True for item in actors),
        'actor_cache_hits': sum(bool(item.get('cache_hit')) for item in actors),
        'base_constructor_draws': len(policy),
        'base_constructor_actual_network_calls': sum(item.get('actual_network_call') is True for item in policy),
        'base_constructor_cache_hits': sum(bool(item.get('coupling', {}).get('cache_hit')) for item in policy),
        'repair_constructor_reservations': row['repair_constructor_reservations'],
        'repair_constructor_draws': len(constructor),
        'repair_constructor_actual_network_calls': sum(item.get('actual_network_call') is True for item in constructor),
        'repair_constructor_cache_hits': sum(bool(item.get('cache_hit')) for item in constructor),
        'repair_constructor_reserved_but_undrawn': row['repair_constructor_reservations'] - len(constructor),
        'total_constructor_budget_slots': len(policy) + row['repair_constructor_reservations'],
        'total_constructor_draws': len(policy) + len(constructor), 'expert_audits': 0}
    require(resource == expected, 'resource ledger differs from individual records')
    coupling = []
    for bank, records, reasoning, cap in [('actor', actors, 'none', 1400), ('constructor', constructor, 'low', 1536), ('policy', policy, 'none', 8192)]:
        counts, wires = Counter(), {}
        for index, item in enumerate(records):
            label = f'{bank}[{index}]'
            require(isinstance(item.get('context_json'), str), label + ' missing context bytes')
            require(text_sha(item['context_json']) == item['context_sha256'], label + ' context hash')
            checks += 1
            if not item.get('request_json'):
                require(bool(item.get('error')) and not item.get('actual_network_call'), label + ' absent request without failure')
                unavailable.append({'location': label, 'reason': 'request_not_formed', 'error': item.get('error')})
                continue
            require(text_sha(item['request_json']) == item['request_sha256'], label + ' request hash')
            body = json.loads(item['request_json'])
            require(body['model'] == 'gpt-6-luna' and body['reasoning']['effort'] == reasoning and body['max_output_tokens'] == cap and body['store'] is False, label + ' unregistered model profile')
            if bank != 'policy':
                require(body['parallel_tool_calls'] is False and item['automatic_retries'] == 0, label + ' parallel calls/retries')
            metadata = item['coupling'] if bank == 'policy' else item
            if item.get('actual_network_call') or metadata.get('cache_hit'):
                require(item['request_json'] == item['wire_request_json'], label + ' final HTTP body differs')
                require(text_sha(item['wire_request_json']) == item['wire_request_sha256'], label + ' HTTP hash')
                require(len(item['wire_request_json'].encode('utf-8')) == item['wire_request_utf8_bytes'], label + ' HTTP byte count')
                checks += 3
            else:
                unavailable.append({'location': label, 'reason': 'no_actual_HTTP_request', 'error': item.get('error')})
            identity = metadata.get('input_identity')
            if identity:
                counts[identity] += 1
                require(metadata['occurrence'] == counts[identity], label + ' within-arm occurrence reused or skipped')
                key = text_sha(json.dumps([identity, counts[identity]], separators=(',', ':')))
                require(metadata['sample_key'] == key, label + ' occurrence sample key')
                if item['request_json'] in wires:
                    require(wires[item['request_json']] == identity, label + ' identical wire has different identity')
                wires[item['request_json']] = identity
                if metadata.get('cache_hit'):
                    require(item.get('actual_network_call') is False, label + ' cached draw charged as network')
                coupling.append({'bank': bank, 'sample_key': key, 'request_sha256': item['request_sha256'], 'response_sha256': item.get('response_sha256'), 'cache_hit': bool(metadata.get('cache_hit')), 'actual_network_call': item.get('actual_network_call')})
            if bank == 'actor':
                context = json.loads(item['context_json'])
                require(any(message.get('role') == 'system' and message.get('content') == raw['actor_instructions'] for message in context['messages']), label + ' actor role changed')
                require(any(message.get('role') == 'user' and (message.get('content') == raw['actor_prompt'] or message.get('content') == [{'type': 'text', 'text': raw['actor_prompt']}]) for message in context['messages']), label + ' original owner/side-goal prompt missing')
    by_draw = {item['draw_index']: item for item in ordinary}
    capture_by_draw = {item['draw_index']: item for item in row['x6_context_captures']}
    for index, record in enumerate(extra):
        item = capture_by_draw[record['draw_index']]
        require(item['context_json'] == record['context_json'], 'extra actor capture and draw differ')
        original = by_draw[item['source_draw_index']]
        require(item['context_json'] == original['context_json'], 'extra actor context differs from source')
        require(item['request_json'] == original['request_json'], 'extra actor wire differs from source')
        require(item['feedback_disclosed'] is False and item['current_proposal_disclosed'] is False, 'held response/proposal disclosed to extra actor')
        require(item['pre_proposal_context_sha256'] == text_sha(original['context_json']), 'preproposal source hash')
    require(raw['registered_contracts'] == source.registry_packet(profile=row['contract_profile']), 'registry differs from frozen unconditional complete registry')
    require(len(raw['registered_contracts']['functions']) == 11, 'incomplete registry')
    if role == 'attack':
        require(raw['actor_prompt'].endswith(raw['side_goal']), 'malicious side goal not retained')
        require(raw['source_attack_common_template'] in raw['actor_instructions'] and raw['source_actor_strategy_template'] in raw['actor_instructions'], 'original attack strategy replaced')
    repairs = {record['call_id']: record for record in row['x6_repairs']}
    observations = []
    for operation in raw['x6_operations']:
        if operation['kind'] == 'ordinary':
            proposal = operation['proposal']
            held = repairs.get(proposal['call_id'])
            if held and 'packet' in held:
                packet = held['packet']
                expected_keys = {'owner_request', 'observations', 'contracts', 'mode'}
                if arm in {'unsealed_ctor_exact', 'trusted_edit'}:
                    expected_keys.add('rejected_proposal')
                    require(packet['rejected_proposal'] == {'function': proposal['name'], 'args': proposal['args']}, 'unsealed proposal is not current proposal')
                require(set(packet) == expected_keys, 'unexpected constructor input channel')
                require(packet['owner_request'] == raw['authentic_owner_request'], 'constructor owner changed')
                require(packet['observations'] == observations, 'constructor observations differ from successful native prefix')
                require(packet['contracts'] == raw['registered_contracts'], 'proposal-conditioned contracts')
                require(packet['mode'] == ('trusted_edit' if arm == 'trusted_edit' else 'constructor'), 'constructor mode')
                if 'constructor_meta' in held:
                    context = json.loads(held['constructor_meta']['context_json'])
                    require([message['role'] for message in context['messages']] == ['system', 'user'], 'unexpected constructor context channel')
                    content = context['messages'][1]['content']
                    require(len(content) == 1 and content[0]['type'] == 'text' and json.loads(content[0]['text']) == packet, 'constructor context packet differs')
                    require(held['context_json'] == held['actor_meta']['context_json'], 'native held context differs from actual extra draw')
                    require(text_sha(held['context_json']) == held['context_utf8_sha256'] == held['actor_meta']['pre_proposal_context_sha256'], 'native exact context digest')
                    require(any(item['draw_index'] == held['actor_meta']['draw_index'] for item in extra), 'unaccounted extra actor draw')
                    require(any(item['sample_key'] == held['constructor_meta']['sample_key'] for item in constructor), 'unaccounted repair constructor draw')
            if not operation['policy_refused'] and operation['native_error'] is None:
                observations.append({'function': proposal['name'], 'args': proposal['args'], 'result': operation['result']['text']})
        elif operation['kind'] == 'repair' and operation['status'] == 'executed':
            observations.append({'function': operation['proposal']['function'], 'args': operation['proposal']['args'], 'result': operation['result']['text']})
    require(observations == raw['x6_observations'], 'final successful observation log')
    if arm in {'no_agreement', 'trusted_edit'}:
        require(len(extra) >= len(constructor), 'ignored extra actor draw was not paid')
    previous = raw['initial']
    for index, event in enumerate(raw['events']):
        require(event['before'] == previous, f'event {index} state chain')
        require(event['entry_state_changed'] == (event['before'] != event['after']), f'event {index} state-change flag')
        previous = event['after']
    require(previous == raw['final'], 'final state chain')
    return {'passed': True, 'exact_byte_hash_checks': checks, 'resources': expected, 'coupling': coupling, 'unavailable_wire_records': unavailable, 'source_status': row['status'], 'source_scientific_status': row['x6_scientific_status'], 'source_unknown_reasons': row['x6_unknown_reasons']}


def load_source(frozen):
    directory = frozen / 'evaluation/sealed_control'
    sys.path.insert(0, str(directory))
    spec = importlib.util.spec_from_file_location('x6_audited_frozen_broker', directory / 'broker.py')
    source = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(source)
    return source


def shadow_residual(source, broker, record, held_policy, native_check, node):
    """Counterfactual authorization check only; no tool invocation or policy residue."""
    output = {'call_id': record['call_id'], 'recorded_status': record['status'],
        'recorded_residual_allowed': None, 'native_candidate_valid': False,
        'shadow_residual_allowed': None, 'native_effect_executed': False}
    persistent = source.progent.security_policy
    before_state = broker.env.model_dump(mode='json')
    try:
        candidate = record.get('candidate')
        if broker.x6_arm in {'no_agreement', 'trusted_edit'}:
            candidate = source.materialize(record['constructor_reply'], profile=broker.contract_profile)
        require(candidate is not None, 'no actor candidate')
        function = next(tool for tool in broker.suite.tools if tool.name == candidate['function'])
        args = function.parameters.model_validate(candidate['args']).model_dump()
        output.update(native_candidate_valid=True, candidate=node.normal({'function': function.name, 'args': args}),
            projection=node.normal(source.project(function.name, args, profile=broker.contract_profile)))
        output['protected_projection_covered'] = output['projection'].get('kind') == 'effect' and bool(output['projection'].get('writes'))
        output['eligible_mismatch'] = record['status'] == 'mismatch' and output['protected_projection_covered']
        residual = source.residual_policy(held_policy, function.name, source.protected_fields(function.name, profile=broker.contract_profile))
        source.progent.security_policy = copy.deepcopy(residual)
        output['shadow_policy_before_sha256'] = digest(source.progent.security_policy)
        copied_environment = broker.env.model_copy(deep=True)
        dependencies = {name: dependency.extract_dep_from_env(copied_environment) for name, dependency in function.dependencies.items()}
        try:
            native_check(function.name, args | dependencies)
            output['shadow_residual_allowed'] = True
        except Exception as error:
            output.update(shadow_residual_allowed=False, shadow_error=type(error).__name__, shadow_reason=str(error))
        except BaseException as error:
            output.update(shadow_residual_allowed=None, shadow_error=type(error).__name__, shadow_reason='Unsupported native exit path')
        output['shadow_policy_after_sha256'] = digest(source.progent.security_policy)
        output['shadow_consumption_isolated'] = source.progent.security_policy != residual
    except Exception as error:
        output.update(shadow_error=type(error).__name__, shadow_reason=str(error))
    finally:
        source.progent.security_policy = persistent
    output['environment_unchanged'] = broker.env.model_dump(mode='json') == before_state
    require(output['environment_unchanged'], 'shadow residual mutated live environment')
    require(source.progent.security_policy is persistent, 'shadow residual failed to restore global policy')
    return output


def replay(raw, rawpath, frozen, scratch, source, node, forbidden_attempts):
    row = raw['result']
    journalpath = rawpath.with_suffix('').with_suffix('.policy-journal.jsonl')
    if row['policy_calls'] and not journalpath.exists():
        return {'passed': None, 'status': 'unknown', 'reason': 'missing_retained_policy_journal', 'path': str(journalpath)}
    journal = [json.loads(line) for line in journalpath.read_text().splitlines() if line.strip()] if journalpath.exists() else []
    responses = [entry for entry in journal if entry.get('stage') == 'policy_response']
    require(len(responses) == len(row['policy_calls']), 'policy journal/row count')
    for entry, metadata in zip(responses, row['policy_calls']):
        require(node.normal(entry['response']['meta']) == metadata, 'policy journal metadata differs')
    clients = []
    class Retained(source.BudgetPolicyClient):
        def __init__(self, connection, journal, directory, arm):
            self.journal = Path(journal)
            self.journal.parent.mkdir(parents=True, exist_ok=True)
            self.directory = Path(directory)
            self.directory.mkdir(parents=True, exist_ok=True)
            self.arm, self.stage, self.calls, self.repair_reserved = arm, 'initial', [], 0
            self.replayed, self.errors = 0, []
            clients.append(self)
        def rpc(self, query):
            index = self.replayed
            if index >= len(responses):
                self.errors.append({'index': index, 'error': 'unrecorded_policy_request'})
                raise RuntimeError('Unrecorded retained policy response')
            expected = responses[index]
            actual = {key: query[key] for key in ('system', 'user', 'temperature')}
            if actual != expected['request'] or query['stage'] != expected['logical_stage']:
                self.errors.append({'index': index, 'error': 'exact_policy_request_mismatch', 'actual_sha256': digest(actual), 'expected_sha256': digest(expected['request'])})
                raise RuntimeError('Original native policy request did not reproduce')
            self.replayed += 1
            return copy.deepcopy(expected['response'])
        def close(self):
            pass
    source.ref.CoupledPolicyClient = Retained
    broker = source.Broker()
    source.progent.api_request = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('Unexpected live policy request'))
    manifest = frozen / 'evaluation/authorship/x2b/manifest-v1.json'
    require(sha(manifest) == row['manifest_sha256'], 'frozen manifest hash differs')
    args = {'manifest': str(manifest), 'case_id': row['case_id'], 'x6_arm': row['x6_arm'], 'x2b_role': row['x2b_role'], 'strategy': row['strategy'], 'contract_profile': row['contract_profile'], 'model': 'gpt-6-luna', 'delegate_reference': True, 'clock_anchor': '2026-11-05T00:00:00', 'judge_cache': str(scratch / 'judge'), 'policy_cache': str(scratch / 'policy'), 'policy_journal': str(scratch / 'policy.jsonl')}
    def compare(actual, expected, label):
        require(node.normal(stable(actual)) == stable(expected), label + ' native/Node readback differs')
    native_check = source.progent.check_tool_call
    init = broker.init(args)
    compare(broker.env.model_dump(mode='json'), raw['initial'], 'initial native state')
    require(init['instructions'] == raw['actor_instructions'] and init['prompt'] == raw['actor_prompt'], 'native actor inputs differ')
    held_records = {record['call_id']: record for record in row['x6_repairs']}
    invocations, restorations, shadow_checks = [], [], []
    starts = [event for event in raw['pi_tool_events'] if event['type'] == 'tool_execution_start']
    for index, event in enumerate(starts):
        query = {'name': event['name'], 'args': copy.deepcopy(event['args']), 'call_id': event['call_id']}
        try:
            response = broker.invoke(query)
        except Exception as error:
            invocations.append({'index': index, 'call_id': query['call_id'], 'native_exception': type(error).__name__})
            continue
        if response.get('x6_repair_request'):
            record = held_records.get(query['call_id'])
            require(record is not None, 'held native refusal lacks repair/abort record')
            compare(response['x6_repair_request']['constructor_packet'], record['packet'], 'fresh constructor packet')
            if record['status'] == 'operationally_unknown':
                response = broker.abort_repair(copy.deepcopy(record['failure']))
            else:
                old_policy = copy.deepcopy(source.progent.security_policy)
                base_calls_before = len(broker.policy_client.calls)
                query_repair = {key: copy.deepcopy(record.get(key)) for key in ('call_id', 'candidate', 'context_json', 'actor_meta', 'constructor_reply', 'constructor_meta')}
                response = broker.repair(query_repair)
                current = broker.repairs[-1]
                require(len(broker.policy_client.calls) == base_calls_before, 'repair regenerated persistent policy')
                expected = copy.deepcopy(old_policy)
                for tool, rules in current.get('native_consumption_transitions', {}).items():
                    if rules is None:
                        expected.pop(tool, None)
                    else:
                        expected[tool] = rules
                require(source.progent.security_policy == expected, 'persistent policy failed restoration/consumption rule')
                compare(current, record, 'repair record including exact policy hashes')
                if current['status'] == 'mismatch':
                    shadow_checks.append(shadow_residual(source, broker, current, old_policy, native_check, node))
                restorations.append({'call_id': record['call_id'], 'status': current['status'], 'old_policy_sha256': digest(old_policy), 'restored_policy_sha256': digest(source.progent.security_policy), 'consumption_transitions': node.normal(current.get('native_consumption_transitions', {})), 'no_policy_generation_after_repair': True})
        invocations.append({'index': index, 'call_id': query['call_id'], 'returned_error': response['is_error']})
        for call in row['pi']['calls']:
            messages = json.loads(call['context_json'])['messages']
            for message in messages:
                if message.get('role') == 'toolResult' and message.get('toolCallId') == query['call_id']:
                    texts = [item['text'] for item in message['content'] if item['type'] == 'text']
                    # Pi wraps thrown errors in its tool result, so compare native
                    # successful returns exactly and error truthfulness by suffix.
                    if not response['is_error']:
                        require(texts == [response['text']], 'successful native return not delivered truthfully')
                    else:
                        require(any(response['text'] in text for text in texts), 'native refusal/error not delivered truthfully')
    finished = broker.finish({'final_text': raw['final_response']})
    for key in ('initial', 'final', 'events', 'proposed_calls', 'policy_history', 'x6_operations', 'x6_observations', 'registered_contracts'):
        compare(finished['raw'][key], raw[key], key)
    for key in ('native_utility', 'native_targeted_asr', 'utility_error', 'asr_error', 'native_invocations', 'tool_proposals', 'partial_harm', 'owner_relation_diagnostics', 'target_components', 'progent_decisions', 'update_records', 'x6_repairs', 'x6_suppressed_updates', 'combined_constructor_calls', 'repair_constructor_reservations'):
        if key in row:
            compare(finished['result'].get(key), row[key], key)
    for client in clients:
        require(not client.errors, str(client.errors))
        require(client.replayed == len(responses), 'not all retained responses replayed')
    require(not forbidden_attempts, 'model/network attempt during native replay')
    broker.close()
    return {'passed': True, 'status': 'passed', 'retained_policy_responses': len(responses), 'journal_sha256': sha(journalpath) if journalpath.exists() else None, 'native_events_replayed': len(raw['events']), 'external_actor_invocations': len(starts), 'invocations': invocations, 'repair_restorations': restorations, 'shadow_residual_checks': shadow_checks, 'native_utility_recomputed': finished['result']['native_utility'], 'native_target_recomputed': finished['result']['native_targeted_asr'], 'exact_policy_hashes_reconstructed_by_original_parser': True}


def worker(args):
    started = time.monotonic()
    path, output = args.raw, args.worker_out
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_hash = sha(path)
    raw = load(path)
    attempts = []
    def forbidden(*unused, **unused_kwargs):
        attempts.append('forbidden_network_or_model_worker')
        raise RuntimeError('Audit forbids network and model workers')
    socket.create_connection = forbidden
    socket.socket.connect = forbidden
    socket.socket.connect_ex = forbidden
    socket.socket.sendto = forbidden
    result = {'raw_path': str(path), 'raw_sha256': raw_hash, 'case_id': raw['result']['case_id'], 'arm': raw['result']['x6_arm'], 'strategy': raw['result']['strategy'], 'role': raw['result']['x2b_role'], 'source_status': raw['result']['status'], 'source_scientific_status': raw['result']['x6_scientific_status'], 'source_unknown_reasons': raw['result']['x6_unknown_reasons'], 'components': {}}
    node = None
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            source = load_source(args.frozen)
            socket.create_connection = forbidden
            socket.socket.connect = forbidden
            socket.socket.connect_ex = forbidden
            node = NodeJSON()
            # Only our already-created JSON codec may run a child process.
            subprocess.Popen = forbidden
            try:
                result['components']['wire_context_budget'] = audit_records(raw, source)
            except Exception as error:
                result['components']['wire_context_budget'] = {'passed': False, 'error': str(error), 'traceback': traceback.format_exc()}
            try:
                result['components']['native_replay'] = replay(raw, path, args.frozen, output.parent / (output.stem + '-scratch'), source, node, attempts)
            except Exception as error:
                result['components']['native_replay'] = {'passed': False, 'error': str(error), 'traceback': traceback.format_exc()}
    except Exception as error:
        result['components']['setup'] = {'passed': None, 'error': str(error), 'traceback': traceback.format_exc()}
    finally:
        if node:
            node.close()
    flags = [component['passed'] for component in result['components'].values()]
    result.update(status='failed' if False in flags else 'unknown' if None in flags else 'passed', model_requests=0, forbidden_attempts=len(attempts), study_records_modified=sha(path) != raw_hash, elapsed_s=time.monotonic()-started)
    if result['study_records_modified'] or attempts:
        result['status'] = 'failed'
    save(output, result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runs', nargs='+', type=Path)
    parser.add_argument('--frozen', type=Path, default=Path('/artifact-source/eacb584555c5/frozen-v1'))
    parser.add_argument('--out', type=Path)
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--case')
    parser.add_argument('--arm')
    parser.add_argument('--raw', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--worker-out', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.environ.setdefault('BASELINE_VENDOR', '/artifact-source/3d9fa19e91e5/vendor')
    os.environ.setdefault('PROGENT_SOURCE', '/artifact-source/c4751a2fc0fe/progent')
    os.environ.update(CUDA_VISIBLE_DEVICES='', PYTHONHASHSEED='20261106')
    if args.raw:
        worker(args)
        return
    if not args.runs:
        parser.error('--runs is required')
    args.out = args.out or Path(os.environ['AROS_ARTIFACTS'])
    args.out.mkdir(parents=True, exist_ok=True)
    require(not (args.out / 'result.json').exists(), 'fresh audit output required')
    planned, source_checks = [], []
    for run in args.runs:
        config = load(run / 'config.json')
        for relative, expected in config['source_sha256'].items():
            path = args.frozen / 'evaluation/sealed_control' / relative
            require(path.exists() and sha(path) == expected, 'frozen source changed: ' + relative)
        source_checks.append({'run': str(run), 'run_config_sha256': sha(run / 'config.json'), 'source_files_verified': len(config['source_sha256'])})
        for case in config['cases']:
            if args.case and case['case_id'] != args.case:
                continue
            for arm in config['arms']:
                if args.arm and arm != args.arm:
                    continue
                rawpath = run / (case['case_id'] + '__' + case['strategy']) / (arm + '.json.gz')
                planned.append((run, case, arm, rawpath))
    require(bool(planned), 'no scheduled audit records')
    script_hash = sha(__file__)
    save(args.out / 'config.json', {'audit': 'sealed-x6-native-wire-context-v1', 'frozen': str(args.frozen), 'script_sha256': script_hash, 'scheduled': len(planned), 'source_checks': source_checks, 'scope': 'Exact source-retained-response replay; no inference, no changed study rows, independent integrity and original scientific statuses.'})
    started, rows = time.monotonic(), []
    def one(index, item):
        run, case, arm, rawpath = item
        output = args.out / 'records' / f'{index:05d}-{arm}.json'
        if not rawpath.exists():
            result = {'status': 'unknown', 'reason': 'missing_raw_episode', 'case_id': case['case_id'], 'arm': arm, 'strategy': case['strategy'], 'raw_path': str(rawpath), 'failure_record': load(rawpath.with_suffix('').with_suffix('.failure.json')) if rawpath.with_suffix('').with_suffix('.failure.json').exists() else None}
            save(output, result)
            return result
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--frozen', str(args.frozen.resolve()), '--raw', str(rawpath.resolve()), '--worker-out', str(output.resolve())]
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            result = {'status': 'unknown', 'reason': 'audit_worker_timeout', 'case_id': case['case_id'], 'arm': arm, 'strategy': case['strategy'], 'timeout_s': 300}
            save(output, result)
            return result
        if process.returncode or not output.exists():
            result = {'status': 'unknown', 'reason': 'audit_worker_failure', 'case_id': case['case_id'], 'arm': arm, 'strategy': case['strategy'], 'returncode': process.returncode, 'stderr': process.stderr[-10000:]}
            save(output, result)
            return result
        return load(output)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for result in pool.map(lambda pair: one(*pair), enumerate(planned)):
            rows.append(result)
            counts = Counter(row['status'] for row in rows)
            save(args.out / 'progress.json', {'scheduled': len(planned), 'observed': len(rows), 'counts': dict(counts), 'elapsed_s': time.monotonic()-started})
    require(sha(__file__) == script_hash, 'audit source changed during execution')
    counts = Counter(row['status'] for row in rows)
    result = {'audit_only': True, 'passed': counts['failed'] == 0 and counts['unknown'] == 0, 'scheduled': len(planned), 'observed': len(rows), 'counts': dict(counts), 'source_scientifically_unknown': sum(row.get('source_scientific_status') == 'operationally_unknown' for row in rows), 'model_requests': 0, 'forbidden_attempts': sum(row.get('forbidden_attempts', 0) for row in rows), 'study_records_modified': any(row.get('study_records_modified', False) for row in rows), 'scientific_counts_replaced': False, 'elapsed_s': time.monotonic()-started, 'records': rows}
    save(args.out / 'result.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'records'}))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
