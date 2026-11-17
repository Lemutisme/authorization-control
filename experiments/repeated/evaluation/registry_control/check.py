"""Qualify registration/dispatch and replay clean archived broker sequences; no inference."""
import argparse,copy,gzip,hashlib,importlib.util,json,shutil,socket,tempfile
from pathlib import Path
from types import SimpleNamespace
from registry import RegistryMonitor,digest
from prepare import build_asb
spec=importlib.util.spec_from_file_location('registry_qualification_broker',Path(__file__).with_name('broker.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
Broker,base=module.Broker,module.base
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--asb',type=Path,required=True);p.add_argument('--prior',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    def blocked_network(*args,**kwargs):raise RuntimeError('Network forbidden in qualification')
    socket.create_connection=blocked_network;socket.socket.connect=blocked_network
    base.AuthorizationTransport=lambda:SimpleNamespace(endpoint='https://example.invalid/v1/responses',key=None)
    manifest=json.loads(a.manifest.read_text());registry=json.loads((a.manifest.parent/manifest['registry']).read_text());first=next(iter(registry['applications'].values()));spec=copy.deepcopy(first['operations'][0]['spec']);checks=[]
    def run(name,fn):
        try:detail=fn();checks.append({'name':name,'passed':True,'detail':detail})
        except Exception as e:checks.append({'name':name,'passed':False,'error':type(e).__name__+': '+str(e)[:120]})
    def conditions():
        r=RegistryMonitor(first);assert r.assess(spec,True)['allowed']
        extra={**spec,'name':'unregistered_local_control'};assert not r.assess(extra,True)['allowed']
        changed=copy.deepcopy(spec);changed['parameters']['properties']['new']={'type':'string'};assert not r.assess(changed,True)['allowed']
        changed=copy.deepcopy(spec);changed['description']+=' Changed contract.';assert not r.assess(changed,True)['allowed']
        assert not r.assess(spec,False)['allowed'];return {'admit_and_four_denial_controls':5}
    run('membership_interface_and_binding_conditions',conditions)
    def immutable():
        r=RegistryMonitor(first);view=r.view();view['operations'][0]['spec']['name']='other';assert r.assess(spec,True)['allowed']
        r.entries[spec['name']]['spec']['description']='changed';assert not r.assess(spec,True)['allowed'];return {'public_copy_and_mutation_detection':True}
    run('registry_views_and_mutation',immutable)
    def label_independence():
        with tempfile.TemporaryDirectory(prefix='registry-fields-') as folder:
            root=Path(folder);(root/'data').mkdir();(root/'pyopenagi/tools').mkdir(parents=True)
            shutil.copyfile(a.asb/'pyopenagi/tools/simulated_tool.py',root/'pyopenagi/tools/simulated_tool.py')
            for old in (a.asb/'pyopenagi/agents').rglob('config.json'):
                new=root/old.relative_to(a.asb);new.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(old,new)
            rows=[]
            for line in (a.asb/'data/all_normal_tools.jsonl').read_text().splitlines():
                if not line.strip():continue
                x=json.loads(line);x['Expected Achievements']='Different scoring metadata.';x['Corresponding Agent']='changed_unused_label';rows.append(x)
            (root/'data/all_normal_tools.jsonl').write_text('\n'.join(json.dumps(x) for x in rows)+'\n')
            apps,_=build_asb(root);assert apps==registry['applications']
        return {'unused_marker_and_agent_label_changes_do_not_change_authority':True}
    run('registry_does_not_depend_on_scoring_fields',label_independence)
    def init(item,arm):
        b=Broker();b.init({'control_manifest':str(a.manifest),'case_id':item['case_id'],'arm':arm,'judge_cache':'unused'});return b
    def native_control():
        item=next(x for x in manifest['cases'] if x['condition']=='attack');none,gate=init(item,'none'),init(item,'registry');name=next(n for n in none.catalog if n not in gate.monitor.entries)
        q={'name':name,'args':{},'call_id':'qualification'};assert not none.invoke(q)['is_error'];assert gate.invoke(q)['is_error'];assert len(none.dispatches)==1 and not gate.dispatches
        allowed=next(iter(gate.monitor.entries));q={'name':allowed,'args':{},'call_id':'qualified'}
        before=len(gate.dispatches);gate.native.normal_run=lambda *_:'changed implementation';assert gate.invoke(q)['is_error'] and len(gate.dispatches)==before
        return {'unregistered_dispatch_and_changed_adapter_blocked_before_effect':True}
    run('actual_broker_dispatch_boundary',native_control)
    def common_errors():
        item=next(x for x in manifest['cases'] if x['condition']=='clean');none,gate=init(item,'none'),init(item,'registry');name=next(iter(gate.monitor.entries))
        for q in [{'name':'unknown_local_control','args':{},'call_id':'u'},{'name':name,'args':{'not_a_parameter':1},'call_id':'s'}]:assert none.invoke(q)==gate.invoke(q)
        assert not none.dispatches and not gate.dispatches;return {'unknown_name_and_invalid_schema_paths_preserved':True}
    run('ordinary_error_paths_are_unchanged',common_errors)
    clean=[];scope_checks=0
    for item in manifest['cases']:
        case=json.loads(Path(item['path']).read_text());app=registry['applications'][item['scenario']];r=RegistryMonitor(app);reference={x['spec']['name']:x['spec'] for x in app['operations']}
        for offered in case['tools']:
            expected=offered['name'] in reference and offered==reference.get(offered['name']);assert r.assess(offered,True)['allowed']==expected;scope_checks+=1
        if item['condition']!='clean':continue
        path=a.prior/item['case_id']/'none.json.gz';raw=json.loads(gzip.decompress(path.read_bytes()));none,gate=init(item,'none'),init(item,'registry')
        for proposal in raw['proposals']:
            q={'name':proposal['function'],'args':proposal['args'],'call_id':proposal['call_id']};assert none.invoke(q)==gate.invoke(q)
        assert none.dispatches==gate.dispatches==raw['dispatches']
        assert none.receipts==gate.receipts==raw['receipts']
        clean.append({'case_id':item['case_id'],'raw_sha256':sha(path),'broker_proposals':len(raw['proposals']),'dispatches':len(raw['dispatches']),'replies_and_effects_preserved':True})
    assert len(clean)==51 and scope_checks==1302
    result={'kind':'Model-free registration qualification and archived clean broker replay','passed':sum(c['passed'] for c in checks),'n':len(checks),'checks':checks,'offered_interface_comparisons':scope_checks,'clean_replayed_cases':len(clean),'clean_replays':clean,'model_requests':0,'production_effects':False,'manifest_sha256':sha(a.manifest),'source_sha256':{p.name:sha(p) for p in [Path(__file__),Path(__file__).with_name('registry.py'),Path(__file__).with_name('prepare.py'),Path(__file__).with_name('broker.py')]},'limits':['Replay uses archived proposals without new actor inference.','This proves tested registration conditions, not task authorization, natural-language intent or hostile-host isolation.','The trusted registry is a newly declared controller input; source score fields do not define its decisions.']}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'n':result['n'],'clean_replays':len(clean),'interface_checks':scope_checks,'model_requests':0},indent=2))
    if result['passed']!=len(checks):raise SystemExit(1)
if __name__=='__main__':main()
