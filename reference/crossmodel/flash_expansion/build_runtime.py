"""Freeze a copy of the existing experiment engine for four new API routes.

Original running inputs are never edited. Only provider selection, declared
token/mode budgets, and the new pre-outcome strict endpoint wrapper change.
"""
import argparse,hashlib,json,shutil
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parent
def replace_one(text,old,new):
    if text.count(old)!=1:raise ValueError('Unexpected source shape for frozen patch: '+old[:80])
    return text.replace(old,new)
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',default='runtime-v1');p.add_argument('--configs',default='model-configs.json');a=p.parse_args()
    dst=HERE/a.out
    if dst.exists():raise ValueError('Use a fresh runtime snapshot')
    dst.mkdir(parents=True)
    configs=json.loads((HERE/a.configs).read_text());aliases=list(configs)
    for name in ['actor_trial.py','update_trial.py','campaign.py']:
        shutil.copy2(ROOT/name,dst/name)
    (dst/'correctness').mkdir();shutil.copy2(ROOT/'correctness/native.py',dst/'correctness/native.py')
    (dst/'provider').mkdir()
    for name in ['canopy.py','common.py','throttle.py']:
        shutil.copy2(HERE/'provider'/name,dst/'provider'/name)
    shutil.copy2(HERE/'strict_effects.py',dst/'strict_effects.py')
    (dst/'provider/model_config.json').write_text(json.dumps(configs,indent=2)+'\n')
    (dst/'provider/luna.py').write_text('''"""Frozen factory bridge; exact allowlisted Flash routes, no fallback."""
import json
from pathlib import Path
from canopy import CanopyClient
CONFIGS=json.loads(Path(__file__).with_name('model_config.json').read_text())
def make_client(model,*,allow_network=False,timeout=120.0):
    if model not in CONFIGS:raise ValueError('Unregistered expansion model alias')
    c=CONFIGS[model]
    client=CanopyClient(c['model_id'],reasoning_mode=c['reasoning_mode'],allow_network=allow_network,timeout=timeout)
    client.actor_output_tokens=c['actor_output_tokens']
    client.policy_output_tokens=c['policy_output_tokens']
    client.experiment_profile=c
    return client
''')
    path=dst/'actor_trial.py';s=path.read_text()
    s=replace_one(s,"choices=['haiku','luna','deepseek']",'choices='+repr(aliases))
    s=replace_one(s,'response=client.complete_pi(context,max_tokens=1400,temperature=None)',
                  'response=client.complete_pi(context,max_tokens=client.actor_output_tokens,temperature=0.7)')
    marker="    out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(gzip.compress(json.dumps(r,ensure_ascii=False,default=str).encode()))"
    wrapper="""    from strict_effects import summaries_from_actor_raw,endpoint_values
    summaries=summaries_from_actor_raw(r,json.loads(Path(a.packet).read_text()))
    r['legacy_metrics']=dict(r['metrics'])
    r['selected_effect_recomputation']=summaries
    r['metrics'].update(endpoint_values(r,summaries['strict']))
    r['primary_effect_definition']='strict-selected-field-or-relation-change-v1'
    from luna import CONFIGS
    r['model_configuration']=CONFIGS[a.model]
"""
    s=replace_one(s,marker,wrapper+marker);path.write_text(s)
    path=dst/'update_trial.py';s=path.read_text()
    s=replace_one(s,"choices=['haiku','luna','deepseek']",'choices='+repr(aliases))
    s=replace_one(s,'max_tokens=8192,temperature=None)','max_tokens=self.client.policy_output_tokens,temperature=0.7)')
    s=replace_one(s,"'provider native default; requested Progent retry temperature not forwarded for either model'",
                  "'Requested temperature0.7 and model-specific thinking profile; Progent retry temperature logged but not forwarded'")
    path.write_text(s)
    # Include source hashes and the exact patch intention as an admission receipt.
    receipt={'source_engine_root':str(ROOT),'source_engine_files':{n:hashlib.sha256((ROOT/n).read_bytes()).hexdigest() for n in ['actor_trial.py','update_trial.py','campaign.py']},
             'changes':['Exact provider factory and model aliases','Explicit per-model actor/policy output caps and reasoning mode','Strict actor endpoint primary with legacy preserved; no native gate/proposal/state changes'],
             'files':{str(p.relative_to(dst)):hashlib.sha256(p.read_bytes()).hexdigest() for p in dst.rglob('*') if p.is_file()}}
    (dst/'source-sha256.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'runtime':str(dst),'models':aliases,'native_broker_sha256':receipt['files']['correctness/native.py']}))
if __name__=='__main__':main()
