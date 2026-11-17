"""Experimental occurrence-indexed response coupling, never a permission cache.

Each runtime still performs a fresh authorization/commit check and charges its
logical budget. A repeated request within one arm gets a new draw. Only the
same occurrence of the identical request in a different arm shares a sample.
"""
import copy,hashlib,json,time
from pathlib import Path
from collections import Counter
from transport import AuthorizationTransport
from luna_transport import MODEL
from pga_transport import TransportError


def digest_bytes(data):return hashlib.sha256(data).hexdigest()
def provider_scope(endpoint,key):return digest_bytes((endpoint+'\0'+(key or '')).encode())

class CoupledAuthorizationTransport(AuthorizationTransport):
    def __init__(self,directory):
        super().__init__();self.directory=Path(directory);self.directory.mkdir(parents=True,exist_ok=True)
        self.occurrences=Counter();self.scope=provider_scope(self.endpoint,self.key)
    def _draw(self,history,tools,instructions):return super().request(history,tools,instructions)
    def request(self,history,tools,instructions):
        payload={'model':MODEL,'input':history,'instructions':instructions,'tools':tools,
            'parallel_tool_calls':False,'max_output_tokens':self.max_output_tokens,'reasoning':{'effort':'low'},'store':False}
        wire=json.dumps(payload).encode();request_id=digest_bytes(wire)
        self.occurrences[request_id]+=1;occurrence=self.occurrences[request_id]
        key=digest_bytes((self.scope+'\0'+request_id+'\0'+str(occurrence)).encode());path=self.directory/(key+'.json')
        started=time.monotonic()
        coupling={'scope_sha256':self.scope,'request_sha256':request_id,'occurrence':occurrence,'sample_key':key}
        if path.exists():
            try:
                saved=json.loads(path.read_text())
                if saved['key']!=key or saved['request_sha256']!=request_id or saved['occurrence']!=occurrence:raise ValueError('identity')
                result=saved['outcome']
                if digest_bytes(json.dumps(result,sort_keys=True).encode())!=saved['outcome_sha256']:raise ValueError('digest')
            except (OSError,ValueError,KeyError,TypeError):
                self.calls.append({'requested_model':MODEL,'reasoning_effort':'low','purpose':'effect_authorization','error':'InvalidCouplingRecord','actual_network_call':False,'elapsed_s':time.monotonic()-started,'coupling':{**coupling,'cache_hit':False,'cache_error':True}})
                raise TransportError('Invalid authorization coupling record') from None
            record=copy.deepcopy(saved['record']);record['actual_network_call']=False
            record['coupling']={**coupling,'cache_hit':True,'outcome_sha256':saved['outcome_sha256']}
            if record.get('usage') is not None:record['cached_sample_usage']=record.pop('usage')
            record['sample_elapsed_s']=record.get('elapsed_s');record['elapsed_s']=time.monotonic()-started
            self.calls.append(record)
            if result['kind']=='error':raise TransportError(result['message'])
            return copy.deepcopy(result['response'])
        before=len(self.calls)
        try:
            response=self._draw(history,tools,instructions);result={'kind':'response','response':response}
        except TransportError as exc:result={'kind':'error','message':str(exc)}
        if len(self.calls)!=before+1:raise RuntimeError('Authorization draw accounting mismatch')
        outcome_sha=digest_bytes(json.dumps(result,sort_keys=True).encode())
        self.calls[-1].update(actual_network_call=True,coupling={**coupling,'cache_hit':False,'outcome_sha256':outcome_sha})
        saved={'key':key,'request_sha256':request_id,'occurrence':occurrence,'outcome':result,'outcome_sha256':outcome_sha,'record':copy.deepcopy(self.calls[-1])}
        temp=path.with_suffix('.tmp');temp.write_text(json.dumps(saved));temp.replace(path)
        if result['kind']=='error':raise TransportError(result['message'])
        return response
    def metadata(self):
        return {**super().metadata(),'experiment_coupling':'exact wire request plus provider scope and within-arm occurrence; same occurrence shared only across independent arms','cache_is_not_permission':True}
