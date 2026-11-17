"""Revised native adapter: protected grounding then current exact-effect binding.

Native object references provide generation identity only in this in-memory
adapter. All accesses must pass through the serialized runtime. This is not a
real cloud CAS/attestation implementation or a proof of semantic grounding.
"""
from __future__ import annotations
from dataclasses import dataclass,field
import copy
import threading
from pga_gate import PolicyGate,READS,portable,stamp,answer
from pga_grounding import OneShotReference,canonical,digest,validate_input
from pga_runtime import AuditedRuntime

CALENDAR_READS={'get_current_day','get_day_calendar_events','search_calendar_events'}
DRIVE_READS={'search_files_by_filename','get_file_by_id','list_files','search_files'}
META_FIELDS=('title','start_time','end_time','location','participants','all_day','status')

def typed_contract(m):
    family=m.get('family')
    if family=='calendar_reschedule':
        return {'family':family,'literal_effects':{'operation':'reschedule_calendar_event','new_start_time':m['start']},
                'semantic_reference':{'slot':'event','text':m['title'],'scope':'authenticated_owner_calendar'},
                'state_obligations':['same native generation','same protected view','preserve duration and participants'],
                'grounding_authority':'explicitly delegated fallible protected-view interpretation'}
    if family=='conditional_calendar_create':
        return {'family':family,'literal_effects':{k:m[k] for k in ['start','end','title','description','recipient']},
                'state_obligations':['complete interval inventory','no active overlap']}
    if family=='create_then_share_file':
        return {'family':family,'literal_effects':{k:m[k] for k in ['filename','recipient','permission']},
                'created_object_reference':'the ordinary native creation receipt',
                'state_obligations':['same native generation and created bytes at share']}
    return {'family':'unsupported'}

@dataclass(frozen=True)
class CandidateView:
    payload_json: str
    subject_by_handle: dict=field(repr=False,compare=False)
    native_by_id: dict=field(repr=False,compare=False)
    protected_by_id: dict=field(repr=False,compare=False)
    high_sha256: str

    def payload(self):return __import__('json').loads(self.payload_json)

def build_view(records,public_task,calendar_account,nonce):
    if not isinstance(records,list) or len(records)>64:raise ValueError('No complete bounded inventory')
    native={};projected={};mapping={};rows=[]
    for obj in records:
        selected=set(META_FIELDS)|{'id_'}
        d=obj.model_dump(mode='json',include=selected) if hasattr(obj,'model_dump') else {k:portable(obj[k]) for k in selected}
        if not isinstance(d.get('id_'),str) or not d['id_']:raise ValueError('Invalid native subject')
        subject=d['id_']
        if subject in native:raise ValueError('Duplicate provider subject')
        native[subject]=obj;projected[subject]={k:copy.deepcopy(d[k]) for k in META_FIELDS}
        handle='r_'+digest({'nonce':nonce,'subject':subject})[:20]
        mapping[handle]=subject;rows.append({'handle':handle,**projected[subject]})
    rows.sort(key=lambda x:x['handle'])
    payload=validate_input({'public_task':public_task,'calendar_account':calendar_account,'candidates':rows})
    # No description is used in membership, ordering, handles or projection.
    return CandidateView(canonical(payload),mapping,native,projected,digest({'account':calendar_account,'records':projected}))

@dataclass(frozen=True)
class EffectBinding:
    contract_sha256: str
    subject_id: str
    view_sha256: str
    subject_metadata_json: str
    native_subject: object=field(repr=False,compare=False)
    root_id: str
    delegation_epoch: int
    grounding_basis: str='fallible_delegated_resolution'

class SerializedRuntime(AuditedRuntime):
    """Atomicity only among callers obeying this one in-memory runtime lock."""
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.lock=getattr(self.gate,'authority_lock',threading.RLock())
    def run_function(self,*args,**kwargs):
        with self.lock:return super().run_function(*args,**kwargs)
    def collect(self,*args,**kwargs):
        with self.lock:return super().collect(*args,**kwargs)

class BoundPolicyGate(PolicyGate):
    def __init__(self,mandate,*,root_id,calendar_account,delegate_reference=False,fact_budget=4):
        super().__init__(copy.deepcopy(mandate),'pga',fact_budget=fact_budget)
        self.authority_lock=threading.RLock();self._binding_lock=threading.Lock()
        self.calendar_account=calendar_account;self.nonce=root_id
        self._delegate_reference=bool(delegate_reference);self._delegation_epoch=0
        self.contract=typed_contract(self.m);self.contract_sha=self._current_contract_sha()
        self.slot=OneShotReference(root_id,'event')
        self.binding=None;self.binding_status='not_requested';self.grounding_record=None
        self.created_native={};self.created_integrity={}

    def _current_contract_sha(self):
        return digest({'typed':typed_contract(self.m),'supplied_mandate':self.m,'public_task':self.m.get('public_prompt'),
                       'calendar_account':self.calendar_account,'root_id':self.nonce})

    @property
    def delegate_reference(self):return self._delegate_reference
    @delegate_reference.setter
    def delegate_reference(self,value):
        with self.authority_lock:
            value=bool(value)
            if value!=self._delegate_reference:self._delegation_epoch+=1
            self._delegate_reference=value

    def update_mandate(self,mandate):
        with self.authority_lock:self.m=copy.deepcopy(mandate)

    def query_allowed(self,function,args):
        if self.m.get('family')=='calendar_reschedule':return function=='search_calendar_events' and args=={'query':''}
        if self.m.get('family')=='create_then_share_file':return function=='get_file_by_id' and str(args.get('file_id')) in self.created_files and set(args)=={'file_id'}
        return super().query_allowed(function,args)

    def observe(self,function,args,result):
        if self.m.get('family')!='calendar_reschedule':super().observe(function,args,result)
        elif function=='reschedule_calendar_event':self.action_done=True
        if self.m.get('family')=='create_then_share_file' and function=='create_file' and result is not None:
            d=portable(result);subject=str(d['id_'])
            self.created_native[subject]=result
            self.created_integrity[subject]=digest({k:d[k] for k in ['filename','content','owner']})

    def _inventory(self,runtime,env):
        if self.fact_queries>=self.fact_budget:raise ValueError('Collection budget exhausted')
        self.fact_queries+=1
        rows,error=runtime.collect(env,'search_calendar_events',{'query':''})
        if error:raise ValueError('Protected inventory unavailable')
        return build_view(rows,self.m['public_prompt'],self.calendar_account,self.nonce)

    def prebind(self,runtime,env,resolver):
        if not self._binding_lock.acquire(blocking=False):return {'status':'binding_in_progress'}
        try:return self._prebind_once(runtime,env,resolver)
        finally:self._binding_lock.release()

    def _prebind_once(self,runtime,env,resolver):
        if self.m.get('status')!='supported':return {'status':'unsupported_mandate'}
        if self.m.get('family')!='calendar_reschedule':return {'status':'not_needed'}
        if not self.delegate_reference:
            self.binding_status='delegation_missing';return {'status':self.binding_status}
        if self.slot.attempted:raise RuntimeError('No repeated reference draw')
        try:
            with runtime.lock:
                if not self.delegate_reference:
                    self.binding_status='delegation_missing';return {'status':self.binding_status}
                if self._current_contract_sha()!=self.contract_sha:return {'status':'owner_request_changed'}
                epoch=self._delegation_epoch
                before=self._inventory(runtime,env)
            result=self.slot.run(before.payload(),resolver)
            self.grounding_record=result.to_dict()
            if result.input_sha256!=digest(before.payload()):
                self.binding_status='resolver_input_mismatch';return {'status':self.binding_status}
            if result.status!='valid' or result.decision!='select':
                self.binding_status='abstained_or_error';return {'status':self.binding_status,'grounding':self.grounding_record}
            subject=before.subject_by_handle[result.handle]
            with runtime.lock:
                if self._current_contract_sha()!=self.contract_sha or not self.delegate_reference or self._delegation_epoch!=epoch:
                    self.binding_status='authority_changed_during_grounding';return {'status':self.binding_status}
                current=self._inventory(runtime,env)
                if current.payload_json!=before.payload_json or current.high_sha256!=before.high_sha256 or current.native_by_id.get(subject) is not before.native_by_id[subject]:
                    self.binding_status='stale_during_grounding';return {'status':self.binding_status}
                meta=current.protected_by_id[subject]
                if meta['status']!='confirmed' or meta['all_day']:
                    self.binding_status='unsupported_event';return {'status':self.binding_status}
                self.binding=EffectBinding(contract_sha256=self.contract_sha,subject_id=subject,view_sha256=current.high_sha256,subject_metadata_json=canonical(meta),native_subject=current.native_by_id[subject],root_id=self.nonce,delegation_epoch=epoch)
                self.binding_status='bound_conditionally_on_grounding'
            return {'status':self.binding_status,'grounding':self.grounding_record,'subject_id':subject,'high_view_sha256':before.high_sha256}
        except Exception as e:
            self.binding_status='unresolved';return {'status':self.binding_status,'error':type(e).__name__}

    def decide(self,function,args,runtime,env):
        if self._current_contract_sha()!=self.contract_sha:return answer('unresolved','owner contract changed; old binding invalid')
        if self.m.get('status')!='supported':return answer('unsupported','unregistered mandate')
        family=self.m.get('family')
        allowed_reads=DRIVE_READS if family=='create_then_share_file' else CALENDAR_READS
        if function in READS and function not in allowed_reads:return answer('deny','read outside the declared task-domain profile')
        if family!='calendar_reschedule':
            decision=super().decide(function,args,runtime,env)
            if decision['verdict']!='allow' or function!='share_file':return decision
            subject=str(args['file_id'])
            if self.fact_queries>=self.fact_budget:return answer('unresolved','freshness query budget exhausted')
            self.fact_queries+=1;obj,error=runtime.collect(env,'get_file_by_id',{'file_id':subject})
            if error:return answer('unresolved','created object no longer available')
            d=portable(obj)
            if obj is not self.created_native.get(subject) or digest({k:d[k] for k in ['filename','content','owner']})!=self.created_integrity.get(subject):
                return answer('unresolved','created object generation or bytes changed')
            return decision
        if function in READS:return answer('allow','declared owner read; cannot revise the binding')
        if not self.delegate_reference:return answer('unresolved','reference delegation absent or withdrawn')
        if self.uncertain:return answer('unresolved','prior partial effect')
        if self.action_done:return answer('deny','task mutation already completed')
        if function!='reschedule_calendar_event':return answer('deny','operation outside literal effect envelope')
        if not isinstance(args,dict) or set(args)-{'event_id','new_start_time','new_end_time'}:return answer('deny','unsupported arguments')
        try:
            if stamp(args.get('new_start_time'))!=stamp(self.m['start']):return answer('deny','new time differs from owner literal')
            b=self.binding
            if b is None:return answer('unresolved','reference not bound under authorized grounding')
            if b.contract_sha256!=self.contract_sha or b.root_id!=self.nonce or b.delegation_epoch!=self._delegation_epoch:return answer('unresolved','binding lineage changed; old grant cannot revive')
            if str(args.get('event_id'))!=b.subject_id:return answer('deny','proposal cannot substitute the bound subject')
            current=self._inventory(runtime,env)
            if current.high_sha256!=b.view_sha256 or current.native_by_id.get(b.subject_id) is not b.native_subject:
                return answer('unresolved','protected view or subject generation changed; no silent re-grounding')
            meta=current.protected_by_id[b.subject_id]
            if canonical(meta)!=b.subject_metadata_json:return answer('unresolved','binding dependencies changed')
            if args.get('new_end_time') is not None and stamp(args['new_end_time'])!=stamp(self.m['start'])+(stamp(meta['end_time'])-stamp(meta['start_time'])):
                return answer('deny','duration differs from bound state')
            return answer('allow','current exact effect bound; semantic grounding remains a separate assumption',grounding_basis=b.grounding_basis)
        except (ValueError,TypeError,KeyError):return answer('unresolved','unsupported current binding evidence')
