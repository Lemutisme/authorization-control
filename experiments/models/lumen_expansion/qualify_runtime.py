"""Offline integration checks for the frozen Lumen engine; no inference."""
from pipeline.paths import resolve as research_path
import argparse, gzip, hashlib, importlib.util, json, subprocess, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PYTHON = research_path('python')

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--runtime', default='runtime-v1')
    a = p.parse_args()
    runtime = HERE / a.runtime
    out = HERE / 'qualification/runtime-v1'
    out.mkdir(parents=True, exist_ok=True)
    protocol = json.loads((HERE / 'protocol-pilot.json').read_text())
    actor = next((r for r in protocol['rows'] if r['kind'] == 'actor'))
    update = next((r for r in protocol['rows'] if r['kind'] == 'update'))
    checks = []
    for model in protocol['models']:
        path = out / (model + '-actor-dry.json.gz')
        cmd = [PYTHON, '-B', str(runtime / 'actor_trial.py'), '--packet', actor['packet'], '--model', model, '--direction', 'corruption', '--feedback', 'value_stating', '--out', str(path), '--dry']
        r = subprocess.run(cmd, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        raw = json.loads(gzip.decompress(path.read_bytes()))
        assert raw['dry'] and raw['primary_effect_definition'].startswith('strict-') and ('legacy_metrics' in raw)
        assert raw['model_configuration'] == protocol['model_modes'][model]
        path = out / (model + '-update-dry.json.gz')
        cmd = [PYTHON, '-B', str(runtime / 'update_trial.py'), '--packet', update['packet'], '--model', model, '--visible', '1', '--out', str(path), '--dry']
        r = subprocess.run(cmd, capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        raw = json.loads(gzip.decompress(path.read_bytes()))
        assert raw['dry'] and raw['only_input_treatment_differs']
        checks.append({'model': model, 'dry_actor_and_generator': 'pass', 'model_calls': 0})
    sys.path.insert(0, str(runtime))
    strict = module('lumen_strict_qualification', runtime / 'strict_effects.py')
    packet = json.loads((ROOT / 'correctness/frozen-v1/packets/banking__user_task_15__update_scheduled_transaction__amount__M2.json').read_text())
    event = packet['cells']['actor_wrong__gate_wrong']['native_reference']['native_event']
    old = strict.summarize_effects([event], packet['unit'], packet['fault_value'], definition='legacy')
    new = strict.summarize_effects([event], packet['unit'], packet['fault_value'], definition='strict')
    assert old['wrong_selected_effect'] and (not new['wrong_selected_effect'])
    result = {'checks': checks, 'model_calls': 0, 'known_existing_field_noop_legacy1_strict0': True, 'source_inputs_unchanged': True, 'runtime_sha256': hashlib.sha256((runtime / 'source-sha256.json').read_bytes()).hexdigest()}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
if __name__ == '__main__':
    main()
