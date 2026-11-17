"""Prepare controller registration from application config, separately from cases."""
import argparse,copy,hashlib,json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'multibench'))
from native import InjecNative
from registry import digest
EMPTY={'type':'object','properties':{},'additionalProperties':False}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def build_asb(root):
    # Tool membership comes ONLY from configured tool refs. The inventory supplies
    # interface descriptions, not achievements, attack targets or task answers.
    descriptions={r['Tool Name']:r['Description'] for r in (json.loads(s) for s in (root/'data/all_normal_tools.jsonl').read_text().splitlines() if s.strip())}
    adapter={'kind':'ASB constant-return normal simulator adapter','port_native_sha256':sha(Path(__file__).resolve().parents[1]/'multibench/native.py'),'port_dispatch_sha256':sha(Path(__file__).resolve().parents[1]/'multibench/broker.py'),'source_simulator_sha256':sha(root/'pyopenagi/tools/simulated_tool.py')}
    apps={};configs={}
    for path in sorted((root/'pyopenagi/agents').rglob('config.json')):
        cfg=json.loads(path.read_text());refs=cfg.get('tools',[])
        if not refs or not all(r.startswith('simulated_tools/') for r in refs):continue
        if cfg['name'] in apps:raise ValueError('Duplicate configured application')
        operations=[]
        for ref in refs:
            name=ref.rsplit('/',1)[-1]
            operations.append({'qualified_id':cfg['name']+'/'+ref,'spec':{'name':name,'description':descriptions[name],'parameters':copy.deepcopy(EMPTY)},'adapter':adapter})
        if len({o['spec']['name'] for o in operations})!=len(operations):raise ValueError('Qualified-name collision in flat actor interface')
        apps[cfg['name']]={'application':cfg['name'],'operations':operations};configs[str(path.relative_to(root))]=sha(path)
    return apps,configs
def main():
    p=argparse.ArgumentParser();p.add_argument('--asb',type=Path,required=True);p.add_argument('--injec',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    apps,configs=build_asb(a.asb);native=InjecNative(a.injec)
    registry={'kind':'Controller-owned registration input, not a task-authority oracle','applications':apps,'policy_sha256':digest(apps),'source_provenance':{'ASB_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=a.asb,text=True).strip(),'config_sha256':configs,'description_inventory_sha256':sha(a.asb/'data/all_normal_tools.jsonl')},'trust_premise':'The controller owns this pre-insertion configuration and adapter; model/tool text cannot modify it.'}
    save(a.out/'registry.json',registry)
    # Separate evaluation metadata. Never imported by the monitor.
    old=json.loads(a.manifest.read_text());case_rows=[];invent={'asb_cases':0,'asb_registered_offers':0,'asb_unregistered_offers':0,'asb_target_collisions':[],'injec_cases':0,'injec_registered_targets':0,'injec_unknown_offers':[]}
    for item in old['cases']:
        path=a.manifest.parent/item['path'];assert sha(path)==item['sha256'];case=json.loads(path.read_text())
        if case['benchmark']=='asb':
            app=apps[case['scenario']];registered={r['spec']['name']:r['spec'] for r in app['operations']};invent['asb_cases']+=1
            for t in case['tools']:
                if t['name'] in registered:assert t==registered[t['name']];invent['asb_registered_offers']+=1
                else:invent['asb_unregistered_offers']+=1
            if case['private']['target'] in registered:invent['asb_target_collisions'].append(case['case_id'])
            case_rows.append({**item,'path':str(path.resolve()),'application_policy_sha256':digest(app)})
        else:
            invent['injec_cases']+=1
            for t in case['tools']:
                if t['name'] not in native.tools or t!=native.tools[t['name']]:invent['injec_unknown_offers'].append(case['case_id'])
            invent['injec_registered_targets']+=case['private']['target'] in native.tools
    save(a.out/'inventory.json',invent)
    # Preserve original case files and full native manifest as immutable references.
    data={'kind':'Registry-control ASB study; original tasks/observations and scorers','original_manifest':str(a.manifest.resolve()),'original_manifest_sha256':sha(a.manifest),'registry':'registry.json','registry_sha256':sha(a.out/'registry.json'),'cases':case_rows,'smoke':['asb_clean_academic_search_agent_0'],'model':'gpt-6-luna','arms':['none','registry'],'scope':'Registration integrity with an added explicit trusted configuration premise; not task-level authorization or original-paper reproduction.'}
    assert len(case_rows)==451 and invent['asb_unregistered_offers']==400 and not invent['asb_target_collisions']
    save(a.out/'manifest.json',data);print(json.dumps(invent,indent=2))
if __name__=='__main__':main()
