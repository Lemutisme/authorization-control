"""Check generic native rebinding with explicit oracle fixtures, never model claims."""
import argparse
import contextlib
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'x1'), os.environ['BASELINE_VENDOR'], os.environ['PROGENT_SOURCE']]


def blocked(*args, **kwargs):
    raise RuntimeError('Native qualification network disabled')


socket.create_connection = blocked
socket.socket.connect = blocked
os.environ['SECAGENT_POLICY_MODEL'] = 'gpt-6-luna'
from secagent import tool as progent
from cohort import instantiate, install, normalization, effective_args
from kernel import AuditPlan, AuditLedger, Config, Hooks, RebindingController
from native import NativeGrantAdapter

spec = importlib.util.spec_from_file_location('x4_qualified_effects', HERE.parent / 'x1/analyze.py')
effects = importlib.util.module_from_spec(spec)
spec.loader.exec_module(effects)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    assert os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    install('2026-11-05T00:00:00')
    manifest = json.loads(args.manifest.read_text())
    cohort = json.loads((args.manifest.parent / manifest['cohort']).read_text())
    units = {unit['unit_id']: unit for unit in cohort['units']}
    rows = []
    for condition in manifest['rows']:
        unit = units[condition['unit_id']]
        raw = json.loads(gzip.decompress((args.prefix / condition['case_id'] / 'prefix.json.gz').read_bytes()))
        anchor = raw['result']['x1_prefix_anchors'][unit['function']]
        suite, task, initial = instantiate(unit['suite'], unit['task_id'])
        environment = type(initial).model_validate(anchor['before'])
        policy = {unit['function']: [(100, 0, {key: {'enum': [normalization(key, value, unit.get('calendar_owner'))]}
                                                for key, value in condition['bound_projection'].items()}, 0)]}
        adapter = NativeGrantAdapter(suite=suite, environment=environment, owner_request=task.PROMPT,
                                    progent=progent, policy=policy,
                                    protected_fields={unit['function']: [unit['argument']]},
                                    effective_arguments=effective_args,
                                    normalize_field=lambda key, value: normalization(key, value, unit.get('calendar_owner')))
        controller = RebindingController(list(adapter.contracts.values()), Config(),
                                         AuditLedger(AuditPlan.create([unit['unit_id']], scope='model-free-cohort')),
                                         projection_hook=adapter.projection, binding_normalizer=adapter.normalize_binding)
        intended = {'function': unit['function'], 'args': {**anchor['args'], **unit['correct_projection']}}
        binding = {'bindings': [{'function': unit['function'], 'args': {unit['argument']: unit['correct_value']}}]}
        hooks = Hooks(adapter.normalize, lambda packet: copy.deepcopy(intended), lambda packet: copy.deepcopy(binding),
                      adapter.residual_authorize, adapter.revision, adapter.execute)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            record = controller.repair(unit_id=unit['unit_id'], owner_request=task.PROMPT,
                                       original_call={'function': unit['function'], 'args': anchor['args']},
                                       refusal='Model-free native fixture', observations=anchor['observations'],
                                       pre_refusal_actor_context={'qualification_fixture': True}, hooks=hooks)
        values = []
        for event in adapter.runtime.events:
            values.extend(effects.effect_values(event, unit))
        correct = normalization(unit['argument'], unit['correct_value'], unit.get('calendar_owner'))
        correct_effect = any(normalization(unit['argument'], value, unit.get('calendar_owner')) == correct for value in values)
        passed = record['status'] == 'executed' and record['native_effect']['native_error'] is None and correct_effect
        rows.append({'condition_id': condition['condition_id'], 'unit_id': unit['unit_id'], 'suite': unit['suite'],
                     'passed': passed, 'status': record['status'], 'reason': record['reason'],
                     'residual_authorization': record.get('residual_authorization'),
                     'native_effect_values': values, 'native_error': (record.get('native_effect') or {}).get('native_error')})
    result = {'n': len(rows), 'passed': sum(row['passed'] for row in rows), 'rows': rows,
              'model_requests': 0, 'network_requests': 0,
              'manifest_sha256': hashlib.sha256(args.manifest.read_bytes()).hexdigest(),
              'prefix_summary_sha256': hashlib.sha256((args.prefix / 'summary.json').read_bytes()).hexdigest(),
              'source_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                for path in HERE.iterdir() if path.suffix in {'.py', '.mjs', '.json'}},
              'scope': 'Explicit evaluator-supplied intended tuples qualify native schema/equivalence/rebinding mechanics only. They are not constructor or actor predictions and never enter real H0 model packets.'}
    (args.out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'n': result['n'], 'passed': result['passed'], 'failures': [row for row in rows if not row['passed']]}, indent=2))
    if result['passed'] != result['n']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
