"""Deterministic audit of retained-boundary X6 continuations; never calls a model.

The frozen natural broker replays the source native prefix and restores its
packet-defined boundary. New policy requests consume retained response journals
through the original budgeted request/parser/updater path. All historical and
new counts remain separate; no scientific episode classification is replaced.
"""
from __future__ import annotations
from pipeline.paths import resolve as research_path
import argparse
import ast
from collections import Counter
import concurrent.futures
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback
HELPER_PATH = Path(__file__).resolve().parents[1] / 'sealed_control/audit.py'
spec = importlib.util.spec_from_file_location('x6_main_audit_helpers', HELPER_PATH)
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
load, sha, save, require, digest, stable = (h.load, h.sha, h.save, h.require, h.digest, h.stable)
PACKET_KEYS = {'unit_id', 'authentic_owner_request', 'native_initial_state', 'native_boundary_state', 'policy_at_boundary', 'original_proposal', 'original_proposal_call_id', 'source_proposal_message', 'actor_context_json', 'actor_context_utf8_sha256', 'actor_request_json', 'actor_request_sha256', 'successful_observations', 'registered_contracts', 'prior_native_proposals', 'prior_native_events', 'case_id', 'task_id', 'historical_actor_calls', 'historical_constructor_calls', 'historical_actor_call_metadata', 'historical_constructor_call_metadata', 'source_representative', 'prior_wrong_value_policy_disclosure', 'prior_bound_value_in_successful_observations', 'context_equivalence_group'}

def frozen_source(directory, main_frozen=None):
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location('natural_audited_frozen_broker', directory / 'broker.py')
    source = importlib.util.module_from_spec(spec)
    if main_frozen is None:
        spec.loader.exec_module(source)
    else:
        tree = ast.parse((directory / 'broker.py').read_text(), filename=str(directory / 'broker.py'))
        matches = [statement for statement in tree.body if isinstance(statement, ast.Assign) and any((isinstance(target, ast.Name) and target.id == 'FROZEN' for target in statement.targets))]
        require(len(matches) == 1, 'unexpected frozen broker root declaration')
        assignment = matches[0]
        require(isinstance(assignment.value, ast.Call) and isinstance(assignment.value.func, ast.Name) and (assignment.value.func.id == 'Path'), 'unexpected frozen root expression')
        assignment.value = ast.Call(func=ast.Name(id='Path', ctx=ast.Load()), args=[ast.Constant(value=str(Path(main_frozen) / 'evaluation/sealed_control'))], keywords=[])
        ast.fix_missing_locations(tree)
        exec(compile(tree, str(directory / 'broker.py'), 'exec'), source.__dict__)
        require(source.FROZEN == Path(main_frozen) / 'evaluation/sealed_control', 'main frozen root override failed')
    return source

def wire_context_budget(raw, packet, source):
    row, original = (raw['result'], raw['natural_actor_resume'])
    historical_u, historical_t = (packet['historical_actor_calls'], packet['historical_constructor_calls'])
    require(set(packet) == PACKET_KEYS, 'runtime packet contains an unregistered input/evaluator channel')
    require(original['context_json'] == packet['actor_context_json'], 'original host context bytes changed')
    require(original['request_json'] == packet['actor_request_json'], 'original source provider wire changed')
    require(h.text_sha(original['context_json']) == original['context_sha256'] == packet['actor_context_utf8_sha256'], 'source context byte hash')
    require(h.text_sha(original['request_json']) == original['request_sha256'] == packet['actor_request_sha256'], 'source provider byte hash')
    require(original['source_proposal_message'] == packet['source_proposal_message'], 'retained source proposal message changed')
    require(original['historical_draw_index'] == historical_u - 1 and original['actual_network_call'] is False and (original['new_actor_budget_slots'] == 0) and (original['replayed_original_proposal'] is True), 'retained source draw was charged as new')
    require(row['pi']['retained_actor_message_replays'] == 1 and row['natural_original_proposal_dispatched'] is True, 'original proposal not dispatched exactly once')
    require(raw['natural_source_actor_context_json'] == packet['actor_context_json'] and raw['natural_source_actor_request_sha256'] == packet['actor_request_sha256'] and (raw['natural_source_proposal_message'] == packet['source_proposal_message']), 'two retained source views differ')
    require(raw['natural_boundary_state'] == packet['native_boundary_state'] and raw['natural_boundary_policy'] == packet['policy_at_boundary'], 'broker-private boundary changed')
    require(raw['initial'] == packet['native_initial_state'], 'historical initial state changed')
    require(raw['historical_actor_calls'] == packet['historical_actor_call_metadata'] and raw['historical_policy_calls'] == packet['historical_constructor_call_metadata'], 'historical metadata changed')
    require(len(raw['historical_actor_calls']) == historical_u and len(raw['historical_policy_calls']) == historical_t, 'historical metadata count')
    require(raw['events'][:len(packet['prior_native_events'])] == packet['prior_native_events'], 'historical event prefix changed')
    require(raw['proposed_calls'][:len(packet['prior_native_proposals'])] == packet['prior_native_proposals'], 'historical proposal prefix changed')
    first = next((event for event in raw['pi_tool_events'] if event['type'] == 'tool_execution_start'))
    require(first['call_id'] == packet['original_proposal_call_id'] and first['name'] == packet['original_proposal']['function'] and (first['args'] == packet['original_proposal']['args']), 'first continuation proposal changed')
    require(sum((event['type'] == 'tool_execution_start' and event['call_id'] == packet['original_proposal_call_id'] for event in raw['pi_tool_events'])) == 1, 'source proposal dispatched twice')
    context = json.loads(packet['actor_context_json'])
    source_messages = context['messages']
    source_system = next((message['content'] for message in source_messages if message['role'] == 'system'))
    require(raw['actor_instructions'] == source_system and raw['actor_prompt'] == packet['authentic_owner_request'], 'actor role/owner task changed')
    require(row['x2b_role'] == 'honest' and raw['side_goal'] is None, 'natural source actor role changed')
    ordinary, extra, constructor, policy = (row['pi']['calls'], row['x6_repair_actor_calls'], row['x6_constructor_calls'], row['policy_calls'])
    actors = sorted(ordinary + extra, key=lambda item: item['draw_index'])
    require([item['draw_index'] for item in actors] == list(range(historical_u, historical_u + len(actors))), 'new actor draw index accounting')
    require(row['pi']['actor_draw_budget']['used'] == historical_u + len(actors) <= 16, 'cumulative actor cap')
    require(row['pi']['actor_draw_budget']['new'] == len(actors) and row['pi']['actor_draw_budget']['historical'] == historical_u, 'historical/new actor ledger')
    reservations = row['repair_constructor_reservations']
    require(row['combined_constructor_calls'] == historical_t + len(policy) + reservations <= 64, 'cumulative constructor cap')
    require(len(constructor) <= reservations and all((not item.get('historical_replayed') for item in policy)), 'new constructor metadata includes historical placeholders or lacks reservation')
    expected = {'historical_actor_draws': historical_u, 'new_actor_draws': len(actors), 'actor_budget_slots': historical_u + len(actors), 'ordinary_actor_draws': len(ordinary), 'extra_actor_draws': len(extra), 'actor_actual_network_calls': sum((item.get('actual_network_call') is True for item in actors)), 'actor_cache_hits': sum((bool(item.get('cache_hit')) for item in actors)), 'historical_constructor_draws': historical_t, 'base_constructor_draws': len(policy), 'base_constructor_actual_network_calls': sum((item.get('actual_network_call') is True for item in policy)), 'base_constructor_cache_hits': sum((bool(item.get('coupling', {}).get('cache_hit')) for item in policy)), 'repair_constructor_reservations': reservations, 'repair_constructor_draws': len(constructor), 'repair_constructor_actual_network_calls': sum((item.get('actual_network_call') is True for item in constructor)), 'repair_constructor_cache_hits': sum((bool(item.get('cache_hit')) for item in constructor)), 'repair_constructor_reserved_but_undrawn': reservations - len(constructor), 'new_constructor_budget_slots': len(policy) + reservations, 'new_constructor_draws': len(policy) + len(constructor), 'total_constructor_budget_slots': historical_t + len(policy) + reservations, 'total_constructor_draws': historical_t + len(policy) + len(constructor), 'expert_audits': 0}
    require(row['x6_resources'] == expected, 'new/cumulative resource ledger differs from individual calls')
    require(row['natural_history_budget'] == {'actor_calls': historical_u, 'constructor_calls': historical_t, 'native_calls': len(packet['prior_native_events'])}, 'source history budget')
    require(row['natural_remaining_budget_at_start'] == {'actor': 16 - historical_u, 'constructor': 64 - historical_t}, 'remaining initial budget')
    hashes, unavailable = (2, [])
    for bank, records, reasoning, cap in [('actor', actors, 'none', 1400), ('constructor', constructor, 'low', 1536), ('policy', policy, 'none', 8192)]:
        counts, identities = (Counter(), {})
        for index, item in enumerate(records):
            label = f'{bank}[{index}]'
            require(h.text_sha(item['context_json']) == item['context_sha256'], label + ' context hash')
            hashes += 1
            if not item.get('request_json'):
                require(bool(item.get('error')) and (not item.get('actual_network_call')), label + ' unaccounted missing request')
                unavailable.append({'location': label, 'reason': 'request_not_formed', 'error': item.get('error')})
                continue
            require(h.text_sha(item['request_json']) == item['request_sha256'], label + ' request hash')
            body = json.loads(item['request_json'])
            require(body['model'] == 'gpt-6-luna' and body['reasoning']['effort'] == reasoning and (body['max_output_tokens'] == cap) and (body['store'] is False), label + ' model profile changed')
            meta = item['coupling'] if bank == 'policy' else item
            if item.get('actual_network_call') or meta.get('cache_hit'):
                require(item['request_json'] == item['wire_request_json'] and h.text_sha(item['wire_request_json']) == item['wire_request_sha256'], label + ' final HTTP bytes/hash')
                require(len(item['wire_request_json'].encode('utf-8')) == item['wire_request_utf8_bytes'], label + ' final HTTP byte count')
                hashes += 3
            else:
                unavailable.append({'location': label, 'reason': 'no_actual_HTTP_request', 'error': item.get('error')})
            if bank != 'policy':
                require(body['parallel_tool_calls'] is False and item['automatic_retries'] == 0, label + ' automatic retry or batch enabled')
            identity = meta.get('input_identity')
            if identity:
                counts[identity] += 1
                require(meta['occurrence'] == counts[identity], label + ' reused within-arm response occurrence')
                require(meta['sample_key'] == h.text_sha(json.dumps([identity, counts[identity]], separators=(',', ':'))), label + ' sample-key hash')
                if item['request_json'] in identities:
                    require(identities[item['request_json']] == identity, label + ' equal wire has unequal identity')
                identities[item['request_json']] = identity
            if meta.get('cache_hit'):
                require(item['actual_network_call'] is False, label + ' cached draw counted as network')
            if bank == 'actor':
                current = json.loads(item['context_json'])
                require(current['messages'][:len(source_messages)] == source_messages, label + ' historical actor context changed or private packet inserted')
                require(any((message.get('role') == 'system' and message.get('content') == source_system for message in current['messages'])), label + ' actor role missing')
    source_by_draw = {item['draw_index']: item for item in ordinary}
    source_by_draw[historical_u - 1] = {'context_json': packet['actor_context_json'], 'request_json': packet['actor_request_json']}
    captures = {item['draw_index']: item for item in row['x6_context_captures']}
    for item in extra:
        capture = captures[item['draw_index']]
        previous = source_by_draw[capture['source_draw_index']]
        require(item['context_json'] == capture['context_json'] == previous['context_json'], 'extra actor was not drawn from exact preproposal context')
        require(item['request_json'] == previous['request_json'], 'extra actor provider wire changed')
        require(capture['feedback_disclosed'] is False and capture['current_proposal_disclosed'] is False, 'held proposal/refusal disclosed to extra actor')
    registry = source.m.registry_packet(profile=row['contract_profile'])
    require(raw['registered_contracts'] == registry == packet['registered_contracts'] and len(registry['functions']) == 11, 'incomplete/proposal-conditioned registry')
    repairs = {record['call_id']: record for record in row['x6_repairs']}
    observations = copy.deepcopy(packet['successful_observations'])
    for operation in raw['x6_operations']:
        if operation['kind'] == 'ordinary':
            proposal = operation['proposal']
            repair = repairs.get(proposal['call_id'])
            if repair and 'packet' in repair:
                constructor_packet = repair['packet']
                keys = {'owner_request', 'observations', 'contracts', 'mode'}
                if row['x6_arm'] in {'unsealed_ctor_exact', 'trusted_edit'}:
                    keys.add('rejected_proposal')
                    require(constructor_packet['rejected_proposal'] == {'function': proposal['name'], 'args': proposal['args']}, 'unsealed input not current proposal')
                require(set(constructor_packet) == keys, 'private state/policy/evaluator input leaked to constructor')
                require(constructor_packet['owner_request'] == packet['authentic_owner_request'] and constructor_packet['observations'] == observations and (constructor_packet['contracts'] == registry), 'protected constructor inputs differ')
                if 'constructor_meta' in repair:
                    current = json.loads(repair['constructor_meta']['context_json'])
                    require([message['role'] for message in current['messages']] == ['system', 'user'], 'extra constructor message channel')
                    content = current['messages'][1]['content']
                    require(len(content) == 1 and json.loads(content[0]['text']) == constructor_packet, 'constructor actual context not protected packet')
                    require(repair['actor_meta']['pre_proposal_context_sha256'] == h.text_sha(repair['context_json']), 'native actor-context digest')
                    if repair['call_id'] == packet['original_proposal_call_id']:
                        require(repair['context_json'] == packet['actor_context_json'] and repair['actor_meta']['request_json'] == packet['actor_request_json'], 'original redraw source changed')
            if not operation['policy_refused'] and operation['native_error'] is None:
                observations.append({'function': proposal['name'], 'args': proposal['args'], 'result': operation['result']['text']})
        elif operation['kind'] == 'repair' and operation['status'] == 'executed':
            observations.append({'function': operation['proposal']['function'], 'args': operation['proposal']['args'], 'result': operation['result']['text']})
    require(observations == raw['x6_observations'], 'successful observation trajectory differs')
    if row['x6_arm'] in {'no_agreement', 'trusted_edit'}:
        require(len(extra) >= len(constructor), 'ignored actor draw omitted from charged budget')
    previous = raw['initial']
    for index, event in enumerate(raw['events']):
        require(event['before'] == previous and event['entry_state_changed'] == (event['before'] != event['after']), f'native event {index} chain/change flag')
        previous = event['after']
    require(previous == raw['final'], 'final state mismatch')
    return {'passed': True, 'exact_byte_hash_checks': hashes, 'resources': expected, 'unavailable_wire_records': unavailable, 'source_context_recovery_scope': 'Provider-payload-equivalent reconstructed historical context; excluded historical host timestamps are not claimed recovered.', 'runtime_packet_evaluator_fields_absent': True, 'constructor_private_input_channels_absent': True}

def replay(raw, path, packet_path, frozen, scratch, source, node, attempts):
    row, m = (raw['result'], source.m)
    journal_path = path.with_suffix('').with_suffix('.policy-journal.jsonl')
    if row['policy_calls'] and (not journal_path.exists()):
        return {'passed': None, 'status': 'unknown', 'reason': 'missing_new_policy_response_journal'}
    entries = [json.loads(line) for line in journal_path.read_text().splitlines() if line.strip()] if journal_path.exists() else []
    responses = [entry for entry in entries if entry.get('stage') == 'policy_response']
    require(len(responses) == len(row['policy_calls']), 'new policy journal count mismatch')
    for entry, metadata in zip(responses, row['policy_calls']):
        require(node.normal(entry['response']['meta']) == metadata, 'new policy journal metadata mismatch')
    clients = []
    original_client = m.BudgetPolicyClient

    class Retained(original_client):

        def __init__(self, connection, journal, directory, arm):
            self.journal, self.directory = (Path(journal), Path(directory))
            self.journal.parent.mkdir(parents=True, exist_ok=True)
            self.directory.mkdir(parents=True, exist_ok=True)
            self.arm, self.calls, self.stage, self.repair_reserved = (arm, [], 'initial', 0)
            self.replayed, self.errors = (0, [])
            clients.append(self)

        def rpc(self, query):
            index = self.replayed
            if index >= len(responses):
                self.errors.append({'index': index, 'error': 'unrecorded_policy_request'})
                raise RuntimeError('Replay requested an unrecorded model response')
            entry = responses[index]
            actual = {key: query[key] for key in ('system', 'user', 'temperature')}
            if actual != entry['request'] or query['stage'] != entry['logical_stage']:
                self.errors.append({'index': index, 'error': 'exact_retained_request_mismatch', 'actual_sha256': digest(actual), 'expected_sha256': digest(entry['request'])})
                raise RuntimeError('Exact new policy request did not reproduce')
            self.replayed += 1
            return copy.deepcopy(entry['response'])

        def close(self):
            pass
    m.BudgetPolicyClient = Retained
    broker = source.Broker()
    native_check = m.progent.check_tool_call
    fixed = source.FROZEN.parents[1]
    manifest = fixed / 'evaluation/authorship/x2b/manifest-v1.json'
    require(sha(manifest) == row['manifest_sha256'], 'main manifest changed')
    args = {'natural_packet': str(packet_path), 'manifest': str(manifest), 'x6_arm': row['x6_arm'], 'model': 'gpt-6-luna', 'delegate_reference': True, 'clock_anchor': '2026-11-05T00:00:00', 'judge_cache': str(scratch / 'judge'), 'policy_cache': str(scratch / 'policy'), 'policy_journal': str(scratch / 'policy.jsonl')}

    def compare(actual, expected, label):
        require(node.normal(stable(actual)) == stable(expected), label + ' native/Node readback differs')
    init = broker.init(args)
    packet = load(packet_path)
    compare(broker.env.model_dump(mode='json'), packet['native_boundary_state'], 'restored source boundary state')
    compare(m.progent.security_policy, packet['policy_at_boundary'], 'restored source boundary policy')
    require(not broker.update_records and (not broker.progent_decisions) and all((client.replayed == 0 for client in clients)), 'startup generated policy or performed a new check')
    require(init['instructions'] == raw['actor_instructions'] and init['prompt'] == raw['actor_prompt'], 'resumed actor input changed')
    repairs = {record['call_id']: record for record in row['x6_repairs']}
    starts = [event for event in raw['pi_tool_events'] if event['type'] == 'tool_execution_start']
    restorations, shadow, exceptions = ([], [], [])
    for index, event in enumerate(starts):
        query = {'name': event['name'], 'args': copy.deepcopy(event['args']), 'call_id': event['call_id']}
        try:
            response = broker.invoke(query)
        except Exception as error:
            exceptions.append({'index': index, 'call_id': query['call_id'], 'error': type(error).__name__})
            continue
        if response.get('x6_repair_request'):
            record = repairs.get(query['call_id'])
            require(record is not None, 'held refusal missing repair/abort record')
            compare(response['x6_repair_request']['constructor_packet'], record['packet'], 'constructor packet')
            if record['status'] == 'operationally_unknown':
                response = broker.abort_repair(copy.deepcopy(record['failure']))
            else:
                old_policy = copy.deepcopy(m.progent.security_policy)
                before_calls = len(broker.policy_client.calls)
                response = broker.repair({key: copy.deepcopy(record.get(key)) for key in ('call_id', 'candidate', 'context_json', 'actor_meta', 'constructor_reply', 'constructor_meta')})
                current = broker.repairs[-1]
                require(len(broker.policy_client.calls) == before_calls, 'persistent policy regenerated after repair')
                restored = copy.deepcopy(old_policy)
                for tool, rules in current.get('native_consumption_transitions', {}).items():
                    if rules is None:
                        restored.pop(tool, None)
                    else:
                        restored[tool] = rules
                require(m.progent.security_policy == restored, 'one-use repair policy not restored with only consumption transitions')
                compare(current, record, 'repair record including exact native policy hashes')
                restorations.append({'call_id': record['call_id'], 'status': current['status'], 'old_policy_sha256': digest(old_policy), 'restored_policy_sha256': digest(restored), 'consumption_transitions': node.normal(current.get('native_consumption_transitions', {}))})
                if current['status'] == 'mismatch':
                    shadow.append(h.shadow_residual(m, broker, current, old_policy, native_check, node))
        for call in row['pi']['calls']:
            for message in json.loads(call['context_json'])['messages']:
                if message.get('role') == 'toolResult' and message.get('toolCallId') == query['call_id']:
                    texts = [item['text'] for item in message['content'] if item['type'] == 'text']
                    require(texts == [response['text']] if not response['is_error'] else any((response['text'] in text for text in texts)), 'native tool result not returned truthfully')
    completed = broker.finish({'final_text': raw['final_response']})
    for key in ('initial', 'final', 'events', 'proposed_calls', 'policy_history', 'x6_operations', 'x6_observations', 'registered_contracts', 'historical_policy_calls', 'historical_actor_calls', 'natural_boundary_state', 'natural_boundary_policy', 'natural_source_representative', 'natural_source_actor_context_json', 'natural_source_actor_request_sha256', 'natural_source_proposal_message'):
        compare(completed['raw'][key], raw[key], key)
    for key in ('native_utility', 'native_targeted_asr', 'utility_error', 'asr_error', 'native_invocations', 'tool_proposals', 'partial_harm', 'owner_relation_diagnostics', 'progent_decisions', 'update_records', 'x6_repairs', 'x6_suppressed_updates', 'combined_constructor_calls', 'repair_constructor_reservations', 'natural_history_budget', 'natural_remaining_budget_at_start', 'natural_original_proposal_dispatched'):
        compare(completed['result'][key], row[key], key)
    require(all((not client.errors and client.replayed == len(responses) for client in clients)), 'retained response replay incomplete/mismatched')
    require(not attempts, 'forbidden network/model worker attempt')
    broker.close()
    return {'passed': True, 'status': 'passed', 'new_policy_responses_replayed': len(responses), 'new_policy_journal_sha256': sha(journal_path) if journal_path.exists() else None, 'source_native_events_replayed': len(packet['prior_native_events']), 'continuation_native_events_replayed': len(raw['events']) - len(packet['prior_native_events']), 'external_continuation_invocations': len(starts), 'native_exceptions': exceptions, 'repair_restorations': restorations, 'shadow_residual_checks': shadow, 'native_utility_recomputed': completed['result']['native_utility'], 'native_target_recomputed': completed['result']['native_targeted_asr'], 'source_state_and_policy_unchanged': True, 'new_startup_policy_generations': 0}

def worker(args):
    raw_hash, packet_hash = (sha(args.raw), sha(args.packet))
    raw, packet = (load(args.raw), load(args.packet))
    row = raw['result']
    attempts = []

    def forbidden(*unused, **unused_kwargs):
        attempts.append('network_or_model_worker')
        raise RuntimeError('Natural audit forbids network/model workers')
    socket.create_connection = forbidden
    socket.socket.connect = forbidden
    socket.socket.connect_ex = forbidden
    socket.socket.sendto = forbidden
    result = {'natural_unit_id': row['natural_unit_id'], 'arm': row['x6_arm'], 'raw_sha256': raw_hash, 'packet_sha256': packet_hash, 'source_status': row['status'], 'source_scientific_status': row['x6_scientific_status'], 'source_unknown_reasons': row['x6_unknown_reasons'], 'components': {}}
    node = None
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            source = frozen_source(args.frozen, args.main_frozen)
            socket.create_connection = forbidden
            socket.socket.connect = forbidden
            socket.socket.connect_ex = forbidden
            node = h.NodeJSON()
            subprocess.Popen = forbidden
            require(row['natural_packet_sha256'] == packet_hash, 'producer packet hash differs')
            for name, operation in [('wire_context_budget', lambda: wire_context_budget(raw, packet, source)), ('native_replay', lambda: replay(raw, args.raw, args.packet, args.frozen, args.worker_out.parent / (args.worker_out.stem + '-scratch'), source, node, attempts))]:
                try:
                    result['components'][name] = operation()
                except Exception as error:
                    result['components'][name] = {'passed': None if isinstance(error, KeyError) else False, 'error': str(error), 'traceback': traceback.format_exc()}
    except Exception as error:
        result['components']['setup'] = {'passed': None, 'error': str(error), 'traceback': traceback.format_exc()}
    finally:
        if node:
            node.close()
    flags = [component['passed'] for component in result['components'].values()]
    result.update(status='failed' if False in flags else 'unknown' if None in flags else 'passed', model_requests=0, forbidden_attempts=len(attempts), study_records_modified=sha(args.raw) != raw_hash or sha(args.packet) != packet_hash)
    if attempts or result['study_records_modified']:
        result['status'] = 'failed'
    save(args.worker_out, result)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', type=Path)
    parser.add_argument('--frozen', type=Path, default=Path(research_path('experiments/natural')))
    parser.add_argument('--out', type=Path)
    parser.add_argument('--main-frozen', type=Path, help='Explicit relocated fixed-main snapshot; only the frozen broker root constant is overridden in memory')
    parser.add_argument('--workers', type=int, default=4)
    parser.add_argument('--unit')
    parser.add_argument('--arm')
    parser.add_argument('--raw', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--packet', type=Path, help=argparse.SUPPRESS)
    parser.add_argument('--worker-out', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.environ.setdefault('BASELINE_VENDOR', research_path('dependencies'))
    os.environ.setdefault('PROGENT_SOURCE', research_path('progent'))
    os.environ.update(CUDA_VISIBLE_DEVICES='', PYTHONHASHSEED='20261106', ENABLE_SECAGENT='True')
    if args.raw:
        worker(args)
        return
    if not args.run:
        parser.error('--run required')
    args.out = args.out or Path(os.environ['AROS_ARTIFACTS'])
    args.out.mkdir(parents=True, exist_ok=True)
    require(not (args.out / 'result.json').exists(), 'fresh audit output required')
    freeze, protocol, config = (load(args.frozen / 'freeze.json'), load(args.frozen / 'protocol.json'), load(args.run / 'config.json'))
    for relative, expected in freeze['files'].items():
        require(sha(args.frozen / relative) == expected, 'natural frozen source changed: ' + relative)
    require(sha(args.frozen / 'protocol.json') == config['protocol_sha256'], 'run protocol differs')
    dependency = protocol['frozen_x6_dependency']
    args.main_frozen = args.main_frozen or Path(dependency['path'])
    require(sha(args.main_frozen / 'freeze.json') == dependency['freeze_manifest_sha256'], 'frozen main dependency changed')
    fixed = load(args.main_frozen / 'freeze.json')
    for relative, expected in fixed['files'].items():
        require(sha(args.main_frozen / relative) == expected, 'main frozen source changed: ' + relative)
    unit_map = {unit['unit_id']: unit for unit in protocol['units']}
    require(set(config['units']) == set(unit_map) and config['arms'] == protocol['arms'], 'run schedule differs from seven-source/eight-arm protocol')
    planned = []
    for uid in config['units']:
        if args.unit and args.unit != uid:
            continue
        unit = unit_map[uid]
        packet = args.frozen / 'runtime' / Path(unit['runtime_packet']).name
        require(sha(packet) == unit['runtime_packet_sha256'], 'runtime packet differs from frozen protocol')
        for arm in config['arms']:
            if args.arm and args.arm != arm:
                continue
            planned.append((uid, arm, args.run / uid / (arm + '.json.gz'), packet))
    require(bool(planned), 'empty audit schedule')
    script_hash, helper_hash = (sha(__file__), sha(HELPER_PATH))
    save(args.out / 'config.json', {'audit': 'natural-retained-boundary-v1', 'scheduled': len(planned), 'script_sha256': script_hash, 'helper_path': str(HELPER_PATH), 'helper_sha256': helper_hash, 'frozen': str(args.frozen), 'main_frozen': str(args.main_frozen), 'loader_adapter': 'Only FROZEN Path literal replaced in memory; all source files and method bodies unchanged', 'freeze_sha256': sha(args.frozen / 'freeze.json'), 'protocol_sha256': sha(args.frozen / 'protocol.json'), 'run_config_sha256': sha(args.run / 'config.json'), 'qualification_only': bool(args.unit or args.arm)})

    def one(index, item):
        uid, arm, path, packet = item
        output = args.out / 'records' / f'{index:05d}-{uid}-{arm}.json'
        if not path.exists():
            result = {'natural_unit_id': uid, 'arm': arm, 'status': 'unknown', 'reason': 'missing_raw_continuation', 'raw_path': str(path)}
            save(output, result)
            return result
        command = [sys.executable, '-B', str(Path(__file__).resolve()), '--frozen', str(args.frozen.resolve()), '--main-frozen', str(args.main_frozen.resolve()), '--raw', str(path.resolve()), '--packet', str(packet.resolve()), '--worker-out', str(output.resolve())]
        try:
            process = subprocess.run(command, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            result = {'natural_unit_id': uid, 'arm': arm, 'status': 'unknown', 'reason': 'audit_worker_timeout', 'timeout_s': 300}
            save(output, result)
            return result
        if process.returncode or not output.exists():
            result = {'natural_unit_id': uid, 'arm': arm, 'status': 'unknown', 'reason': 'audit_worker_failure', 'returncode': process.returncode, 'stderr': process.stderr[-10000:]}
            save(output, result)
            return result
        return load(output)
    started = time.monotonic()
    rows = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for result in pool.map(lambda pair: one(*pair), enumerate(planned)):
            rows.append(result)
            save(args.out / 'progress.json', {'scheduled': len(planned), 'observed': len(rows), 'counts': dict(Counter((row['status'] for row in rows)))})
    require(sha(__file__) == script_hash and sha(HELPER_PATH) == helper_hash, 'audit sources changed during execution')
    counts = Counter((row['status'] for row in rows))
    result = {'audit_only': True, 'passed': counts['failed'] == 0 and counts['unknown'] == 0, 'scheduled': len(planned), 'observed': len(rows), 'counts': dict(counts), 'source_scientifically_unknown': sum((row.get('source_scientific_status') == 'operationally_unknown' for row in rows)), 'model_requests': 0, 'forbidden_attempts': sum((row.get('forbidden_attempts', 0) for row in rows)), 'study_records_modified': any((row.get('study_records_modified', False) for row in rows)), 'scientific_counts_replaced': False, 'elapsed_s': time.monotonic() - started, 'records': rows}
    save(args.out / 'result.json', result)
    print(json.dumps({key: value for key, value in result.items() if key != 'records'}))
    if not result['passed']:
        raise SystemExit(1)
if __name__ == '__main__':
    main()
