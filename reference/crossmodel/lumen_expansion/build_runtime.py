"""Freeze a Lumen-only copy of the already qualified native Flash engine."""
import argparse, hashlib, json, shutil
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parent/'flash_expansion/runtime-v1'

def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError('Unexpected source shape: '+old[:70])
    return text.replace(old, new)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', default='runtime-v1')
    parser.add_argument('--configs', default='model-configs.json')
    parser.add_argument('--provider', default='provider-v2')
    args = parser.parse_args()
    dest = HERE/args.out
    if dest.exists():
        raise ValueError('Use a fresh immutable runtime namespace')
    configs = json.loads((HERE/args.configs).read_text())
    if set(configs) != {'lumen_qwen', 'lumen_glm'}:
        raise ValueError('Only the two user-requested deployments are authorized here')
    dest.mkdir(parents=True)
    sources = {}
    for name in ['actor_trial.py', 'update_trial.py', 'campaign.py', 'correctness/native.py', 'strict_effects.py']:
        src = SOURCE/name
        target = dest/name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, target)
        sources[str(src)] = hashlib.sha256(src.read_bytes()).hexdigest()
    (dest/'provider').mkdir()
    for name in ['lumen.py', 'common.py', 'throttle.py']:
        src = HERE/args.provider/name
        shutil.copy2(src, dest/'provider'/name)
        sources[str(src)] = hashlib.sha256(src.read_bytes()).hexdigest()
    (dest/'provider/model_config.json').write_text(json.dumps(configs, indent=2)+'\n')
    (dest/'provider/luna.py').write_text('''"""Factory bridge keeps the native engine import surface unchanged."""
import json
from pathlib import Path
from lumen import LumenClient
CONFIGS=json.loads(Path(__file__).with_name('model_config.json').read_text())
def make_client(model, *, allow_network=False, timeout=180.0):
    if model not in CONFIGS: raise ValueError('Unknown Lumen configuration')
    config=CONFIGS[model]
    client=LumenClient(config['model_id'], reasoning_mode=config['reasoning_mode'], allow_network=allow_network, timeout=timeout)
    client.actor_output_tokens=config['actor_output_tokens']
    client.policy_output_tokens=config['policy_output_tokens']
    client.experiment_profile=config
    return client
''')
    for name in ['actor_trial.py', 'update_trial.py']:
        path=dest/name
        path.write_text(replace_once(path.read_text(), "choices=['glm', 'minimax', 'mimo', 'qwen']", 'choices='+repr(list(configs))))
    path=dest/'campaign.py'
    text=path.read_text()
    text=replace_once(text,"            record['transport_failed']=d.get('transport_failed')", "            record['transport_failed']=d.get('transport_failed')\n            record['terminal_provider_halt']=any(r.get('terminal_provider_halt') for r in d.get('requests',[]))")
    text=replace_once(text,"p.add_argument('--workers',type=int,default=4)","p.add_argument('--workers',type=int,default=1)")
    start=text.index('    with concurrent.futures.ThreadPoolExecutor(')
    end=text.index("    summary={'scheduled'",start)
    text=text[:start]+'''    if a.workers!=1:raise ValueError('This Lumen schedule uses one serial worker')
    terminal_halt=False
    for row in rows:
        try:r=task(row,out)
        except Exception as exc:r={'id':row['id'],'ok':False,'error':type(exc).__name__}
        results.append(r);status()
        if r.get('terminal_provider_halt'):
            terminal_halt=True
            break
'''+text[end:]
    text=replace_once(text,"'rows':results,'efficacy_scored_separately':True}","'rows':results,'efficacy_scored_separately':True,'terminal_provider_halt':terminal_halt}")
    text=replace_once(text,"    print(json.dumps({k:v for k,v in summary.items() if k!='rows'}))", "    print(json.dumps({k:v for k,v in summary.items() if k!='rows'}))\n    if terminal_halt:raise SystemExit(3)")
    path.write_text(text)
    assert (dest/'correctness/native.py').read_bytes() == (SOURCE/'correctness/native.py').read_bytes()
    assert (dest/'strict_effects.py').read_bytes() == (HERE/'strict_effects.py').read_bytes()
    receipt={'source_files':sources,
             'changes':['Only exact Lumen provider factory and aliases; explicit model/mode/budget metadata',
                        'Serial scheduling stops on explicit provider quota exhaustion; unfinished cases remain scheduled',
                        'Native gate, tools, source states, pending proposals, strict/legacy endpoints and logical budgets unchanged'],
             'files':{str(p.relative_to(dest)):hashlib.sha256(p.read_bytes()).hexdigest() for p in dest.rglob('*') if p.is_file()}}
    (dest/'source-sha256.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'runtime':str(dest),'models':list(configs),'native_gate_unchanged':True}))

if __name__=='__main__': main()
