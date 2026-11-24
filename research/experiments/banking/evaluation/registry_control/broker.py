"""An external registration check around the unchanged simulator dispatch path."""
import copy,importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(Path(__file__).parent),str(ROOT/'multibench'),str(ROOT/'intent_guard'),str(ROOT/'contract_study'),str(ROOT/'pi'),str(ROOT)]
spec=importlib.util.spec_from_file_location('registry_reference_broker',ROOT/'multibench/broker.py');base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)
from registry import RegistryMonitor,digest,public_spec
def sha(path):return base.sha(path)
NEGATIVE='This tool is not verified in the application-controlled registry. This call was not executed.'
class Broker(base.Broker):
    def init(self,p):
        self.control_arm=p['arm'];assert self.control_arm in {'none','registry'}
        path=Path(p['control_manifest']);manifest=json.loads(path.read_text());rpath=path.parent/manifest['registry'];assert sha(rpath)==manifest['registry_sha256']
        native_path=Path(manifest['original_manifest']);assert sha(native_path)==manifest['original_manifest_sha256']
        item=next(r for r in manifest['cases'] if r['case_id']==p['case_id']);registries=json.loads(rpath.read_text());app=registries['applications'][item['scenario']]
        assert digest(app)==item['application_policy_sha256'];self.monitor=RegistryMonitor(app);self.registration_decisions=[]
        self.application_policy_sha256=digest(app);self.control_manifest_sha256=sha(path)
        init=super().init({**p,'manifest':str(native_path),'arm':'none'})
        assert self.case['benchmark']=='asb'
        for entry in app['operations']:
            binding=entry['adapter']
            assert binding['port_native_sha256']==sha(ROOT/'multibench/native.py')
            assert binding['port_dispatch_sha256']==sha(ROOT/'multibench/broker.py')
            assert binding['source_simulator_sha256']==sha(self.native.root/'pyopenagi/tools/simulated_tool.py')
        self.original_normal_run=self.native.normal_run;self.original_normal_code=self.native.normal_run.__code__
        self.original_normal_method=self.native.normal.__func__;self.original_dispatch_method=base.Broker.invoke
        self.original_validators=dict(self.validators)
        # The registry never reads ordinary returns, target names, goals or score labels.
        return init
    def binding_valid(self,name):
        return (self.native.normal_run is self.original_normal_run and self.native.normal_run.__code__ is self.original_normal_code
            and self.native.normal.__func__ is self.original_normal_method and base.Broker.invoke is self.original_dispatch_method
            and self.validators.get(name) is self.original_validators.get(name))
    def invoke(self,p):
        name,args=p['name'],copy.deepcopy(p['args'])
        # Preserve native unknown-name and schema-error behavior: neither path
        # dispatches an operation even in the no-gate reference.
        if name not in self.catalog:return super().invoke(p)
        try:self.validators[name].validate(args)
        except Exception:return super().invoke(p)
        with self.lock:
            verdict=self.monitor.assess(public_spec(self.catalog[name]),self.binding_valid(name))
            row={'operation':{'function':name,'args':args},**verdict,'enforced':self.control_arm=='registry','policy_sha256':self.application_policy_sha256,'revision':self.revision}
            self.registration_decisions.append(row)
            if self.control_arm=='registry' and not verdict['allowed']:
                self.proposals.append({'function':name,'args':args,'call_id':p.get('call_id')});row['dispatched']=False
                return {'is_error':True,'text':NEGATIVE}
            before=len(self.dispatches);reply=super().invoke(p);row['dispatched']=len(self.dispatches)>before;return reply
    def finish(self,p):
        r=super().finish(p);r['result'].update(arm=self.control_arm,registration_decisions=self.registration_decisions,application_policy_sha256=self.application_policy_sha256,control_manifest_sha256=self.control_manifest_sha256)
        return r
def main():
    b=Broker()
    for line in sys.stdin:
        ident=None
        try:
            q=json.loads(line);ident=q['id'];assert set(q)=={'id','method','params'} and q['method'] in {'init','invoke','finish'}
            r=getattr(b,q['method'])(q['params']);print(json.dumps({'id':ident,'ok':True,'result':r}),flush=True)
        except Exception as e:print(json.dumps({'id':ident,'ok':False,'error':type(e).__name__}),flush=True)
if __name__=='__main__':main()
