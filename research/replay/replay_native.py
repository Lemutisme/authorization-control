#!/usr/bin/env python3
"""Replay matched artifact native effects and pinned policy checks; no model access.

Inputs are explicit files; no research workspace, private broker, API key or
model endpoint is discovered. Policies and parser decisions are retained data.
This checks those decisions/effects against the installed pinned simulators,
not a general authorization proof or a replay of fresh model generation.
"""
from __future__ import annotations
import argparse
import contextlib
import copy
import gzip
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import socket
import sys


def residual_policy(policy, function, protected):
    """Exact one-use transformation from the retained X6 kernel, not enabled by the extension."""
    result = copy.deepcopy(policy or {})
    rules = result.get(function, [])
    generated = False
    for index, rule in enumerate(rules):
        if rule[0] >= 100 and rule[1] == 0:
            generated = True
            replacement = list(rule)
            replacement[2] = {k: v for k, v in rule[2].items() if k not in protected}
            rules[index] = replacement
    if not generated:
        rules.append([100, 0, {}, 0])
    result[function] = sorted(rules, key=lambda r: (r[0], -r[1]))
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', type=Path, required=True)
    p.add_argument('--output', type=Path)
    p.add_argument('--sha256', help='Expected SHA-256 of decompressed result bytes')
    p.add_argument('--progent-source', type=Path, help='Optional pinned source checkout instead of installed secagent')
    a = p.parse_args()
    raw = a.input.read_bytes()
    if raw[:2] == b'\x1f\x8b':
        raw = gzip.decompress(raw)
    digest = hashlib.sha256(raw).hexdigest()
    if a.sha256 and digest != a.sha256.lower():
        raise ValueError('Artifact SHA-256 mismatch')
    data = json.loads(raw)
    if not isinstance(data.get('rows'), list) or not data['rows']:
        raise ValueError('Missing matched result rows')
    if a.progent_source:
        sys.path.insert(0, str(a.progent_source.resolve()))
    # Import and execution both run without network. Installation is a separate step.
    attempts = []
    def deny_network(*args, **kwargs):
        attempts.append('network_attempt')
        raise RuntimeError('Native replay has no network access')
    socket.create_connection = deny_network
    socket.socket.connect = deny_network
    socket.socket.connect_ex = deny_network
    os.environ['ENABLE_SECAGENT'] = 'True'
    os.environ['SECAGENT_GENERATE'] = 'False'
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        from agentdojo.task_suite import get_suite
        from agentdojo.functions_runtime import FunctionsRuntime
        from secagent import tool as progent
    progent.api_request = deny_network
    suite = get_suite('v1.2.2', 'banking')
    env_type = type(suite.load_and_inject_default_environment({}))
    tools = {tool.name: tool for tool in suite.tools}
    progent.available_tools = []
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        wrapped = [tool.model_copy(update={'run': progent.apply_secure_tool_wrapper(tool.run)}) for tool in suite.tools]
    original_check = progent.check_tool_call
    decisions = []
    def checked(name, kwargs):
        try:
            result = original_check(name, kwargs)
        except Exception:
            decisions.append(False)
            raise
        decisions.append(True)
        return result
    progent.check_tool_call = checked
    def invoke(boundary, call, policy=None):
        env = env_type.model_validate(copy.deepcopy(boundary))
        decisions.clear()
        if policy is not None:
            progent.security_policy = copy.deepcopy(policy)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            _, error = FunctionsRuntime(wrapped if policy is not None else suite.tools).run_function(env, call['function'], call['args'])
        return env.model_dump(mode='json'), error, list(decisions)
    rows_checked = candidates_checked = policy_forks = 0
    findings = []
    prefixes = {}
    for row in data['rows']:
        unit = row.get('source', {}).get('unit_id')
        try:
            if row.get('version') != 'matched-natural-repair-v1':
                raise ValueError('Unsupported row schema')
            if row.get('scientific_status') != 'known':
                raise ValueError('Unknown outcome retained; cannot certify it')
            packet = row['source_packet']
            task = suite.get_user_task_by_id(packet['task_id'])
            if task.PROMPT != packet['authentic_owner_request']:
                raise ValueError('Pinned owner request differs')
            source = Path(inspect.getfile(type(task)))
            expected_source = row['endpoint_evaluation']['reference']['native_source']['sha256']
            if hashlib.sha256(source.read_bytes()).hexdigest() != expected_source:
                raise ValueError('Native task source hash differs from record')
            boundary = packet['native_boundary_state']
            prefixes.setdefault(unit, packet)
            progent.init_user_query = packet['authentic_owner_request']
            for candidate in row['candidate_results']:
                if candidate['before'] != boundary:
                    raise ValueError('Candidate did not start at the source boundary')
                if row['parse_status'] != 'valid_bind':
                    if candidate['after'] != boundary or candidate.get('executed'):
                        raise ValueError('Malformed binding changed native state')
                    continue
                call = candidate['normalized_call']
                tool = tools[call['function']]
                normalized = tool.parameters.model_validate(call['args']).model_dump()
                if normalized != call['args']:
                    raise ValueError('Recorded call is not normalized')
                contract = packet['registered_contracts']['functions'][call['function']]
                protected = list(contract['selector_fields']) + list(contract['protected_write_fields'])
                residual = residual_policy(packet['policy_at_boundary'], call['function'], protected)
                if residual != candidate['residual_policy']:
                    raise ValueError('Residual transformation changed')
                after, error, checks = invoke(boundary, call, residual)
                policy_forks += 1
                if checks != [candidate['residual_allowed']] or after != candidate['after']:
                    raise ValueError('Residual decision or native effect changed')
                if candidate['executed'] != (checks == [True] and error is None):
                    raise ValueError('Execution status changed')
                original_after, _, checks = invoke(boundary, call, packet['policy_at_boundary'])
                policy_forks += 1
                if checks != [candidate['original_policy_allowed']] or original_after != candidate['original_policy_check']['after']:
                    raise ValueError('Original policy fork changed')
                utility = bool(task.utility('', env_type.model_validate(packet['native_initial_state']), env_type.model_validate(after)))
                if utility != candidate['native_utility']:
                    raise ValueError('Native utility changed')
                candidates_checked += 1
            rows_checked += 1
        except Exception as exc:
            findings.append({'unit': unit, 'arm': row.get('arm'), 'replicate': row.get('replicate'), 'error': str(exc)})
    source_checks = []
    for unit, packet in prefixes.items():
        try:
            current = packet['native_initial_state']
            for event in packet['prior_native_events']:
                if current != event['before']:
                    raise ValueError('Source prefix before-state differs')
                if not event.get('error'):
                    current, error, _ = invoke(current, event['operation'])
                    if error:
                        raise ValueError('Retained source operation now fails')
                if current != event['after']:
                    raise ValueError('Source prefix after-state differs')
            if current != packet['native_boundary_state']:
                raise ValueError('Source boundary differs')
            source_checks.append({'unit': unit, 'passed': True})
        except Exception as exc:
            source_checks.append({'unit': unit, 'passed': False, 'error': str(exc)})
    passed = not findings and all(c['passed'] for c in source_checks) and not attempts and rows_checked == len(data['rows'])
    result = {'passed': passed, 'input_sha256': digest, 'rows': len(data['rows']), 'rows_checked': rows_checked,
              'candidate_effects_checked': candidates_checked, 'policy_forks': policy_forks,
              'source_prefixes': source_checks, 'findings': findings, 'network_attempts': len(attempts),
              'new_model_calls': 0, 'checker_source_sha256': hashlib.sha256(Path(progent.__file__).read_bytes()).hexdigest(),
              'scope': 'Pinned native transitions, retained original/residual decisions and utility. Parser decisions retained; no model-generation replay or authorization completeness proof.'}
    encoded = json.dumps(result, indent=2) + '\n'
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(encoded)
    print(encoded)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
