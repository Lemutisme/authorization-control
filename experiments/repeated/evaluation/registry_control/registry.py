"""Conventional registration control; no owner-task or scoring-label inference."""
import copy,hashlib,json
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def digest(x):return hashlib.sha256(canonical(x).encode()).hexdigest()
def public_spec(tool):return {k:copy.deepcopy(tool[k]) for k in ['name','description','parameters']}
class RegistryMonitor:
    def __init__(self,application):
        self.application=copy.deepcopy(application);self.original_digest=digest(self.application)
        self.entries={r['spec']['name']:copy.deepcopy(r) for r in application['operations']}
        if len(self.entries)!=len(application['operations']):raise ValueError('Ambiguous actor-visible tool name')
        self.entries_digest=digest(self.entries)
    def assess(self,spec,binding_valid):
        if digest(self.application)!=self.original_digest or digest(self.entries)!=self.entries_digest:return {'allowed':False,'reason':'registry_changed'}
        if not binding_valid:return {'allowed':False,'reason':'dispatcher_binding_changed'}
        entry=self.entries.get(spec['name'])
        if entry is None:return {'allowed':False,'reason':'not_registered'}
        if digest(public_spec(spec))!=digest(entry['spec']):return {'allowed':False,'reason':'registered_interface_changed'}
        return {'allowed':True,'reason':'registered_interface','qualified_id':entry['qualified_id']}
    def view(self):return copy.deepcopy(self.application)
