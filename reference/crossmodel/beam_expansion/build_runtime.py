"""Freeze the qualified Lumen engine for the single newly authorized Beam route."""
import hashlib,json,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=HERE.parent/'lumen_expansion/runtime-v1'
def main():
    dest=HERE/'runtime-v1'
    if dest.exists():raise ValueError('Use a fresh runtime namespace')
    configs=json.loads((HERE/'model-configs.json').read_text())
    assert list(configs)==['lumen_beam'] and configs['lumen_beam']['model_id']=='beam-1.0'
    dest.mkdir(parents=True)
    sources={}
    for name in ['actor_trial.py','update_trial.py','campaign.py','correctness/native.py','strict_effects.py','provider/luna.py']:
        source=SOURCE/name;target=dest/name;target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copy2(source,target);sources[str(source)]=hashlib.sha256(source.read_bytes()).hexdigest()
    for name in ['lumen.py','common.py','throttle.py']:
        source=HERE/'provider'/name;shutil.copy2(source,dest/'provider'/name)
        sources[str(source)]=hashlib.sha256(source.read_bytes()).hexdigest()
    (dest/'provider/model_config.json').write_text(json.dumps(configs,indent=2)+'\n')
    for name in ['actor_trial.py','update_trial.py']:
        path=dest/name;text=path.read_text();old="choices=['lumen_qwen', 'lumen_glm']"
        assert text.count(old)==1
        path.write_text(text.replace(old,"choices=['lumen_beam']"))
    assert (dest/'correctness/native.py').read_bytes()==(SOURCE/'correctness/native.py').read_bytes()
    assert (dest/'strict_effects.py').read_bytes()==(HERE/'strict_effects.py').read_bytes()
    for name in ['common.py','throttle.py']:
        assert (dest/'provider'/name).read_bytes()==(SOURCE/'provider'/name).read_bytes()
    receipt={'source_files':sources,'changes':['Beam alias/configuration and provider model allowlist only',
             'Native gate, tools, supplied proposals, strict/legacy metrics, logical budgets and existing Lumen quota scope unchanged'],
             'files':{str(p.relative_to(dest)):hashlib.sha256(p.read_bytes()).hexdigest()for p in dest.rglob('*')if p.is_file()}}
    (dest/'source-sha256.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'runtime':str(dest),'models':list(configs),'native_gate_unchanged':True,'lumen_throttle_shared':True}))
if __name__=='__main__':main()
