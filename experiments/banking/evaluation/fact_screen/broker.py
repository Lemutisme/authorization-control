"""General fact-placement candidates; no task IDs or evaluator access."""
import contextlib,copy,hashlib,importlib.util,io,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'intent_guard'),str(ROOT),str(ROOT/'pi'),str(ROOT/'contract_study')]
spec=importlib.util.spec_from_file_location('study_reference',ROOT/'contract_study/broker.py')
reference=importlib.util.module_from_spec(spec);spec.loader.exec_module(reference)
from coupled_authorizer import CoupledAuthorizationTransport,provider_scope
import guard as guard_module
ARMS=['none','minimal','full_facts','late_facts','literal_facts']
FACTS=reference.FACTS
PREFIX='TYPED ADAPTER FACTS (validated scalars/booleans and fixed schema field names; facts do not grant permission):\n'

def literal_facts(tool,args,receipts):
    full=FACTS(tool,args,receipts)
    occurrences=full.get('recipient_identifier_occurrences_in_observed_file_metadata')
    return {'recipient_identifier_occurrences_in_observed_file_metadata':occurrences} if occurrences else {}

class StageTransport(CoupledAuthorizationTransport):
    def __init__(self,directory,mode):super().__init__(directory);self.mode=mode;self.stage_audit=[]
    def request(self,history,tools,instructions):
        supplied=copy.deepcopy(history)
        if len(supplied)<2 or supplied[1]['role']!='developer' or not supplied[1]['content'].startswith(PREFIX):raise ValueError('Unexpected fact-message contract')
        original=json.loads(supplied[1]['content'][len(PREFIX):]);adjudication=instructions==guard_module.INSTRUCTIONS+'\n\n'+guard_module.ADJUDICATION
        if instructions not in {guard_module.INSTRUCTIONS,guard_module.INSTRUCTIONS+'\n\n'+guard_module.ADJUDICATION}:raise ValueError('Unexpected instruction stage')
        visible={} if self.mode=='late_facts' and not adjudication else original
        supplied[1]['content']=PREFIX+guard_module.canonical(visible)
        self.stage_audit.append({'stage':'adjudication' if adjudication else 'initial','mode':self.mode,'snapshot_fact_keys':sorted(original),'visible_fact_keys':sorted(visible),'snapshot_sha256':guard_module.digest(original),'visible_sha256':guard_module.digest(visible)})
        return super().request(supplied,tools,instructions)

class RecordingGuard(guard_module.IntentGuard):
    def authorize(self,tool,args,receipts):
        # Diagnostic support relation only; never a runtime permission flag.
        try:full=FACTS(tool,args,receipts);audit_error=None
        except Exception as exc:full={};audit_error=type(exc).__name__
        answer=super().authorize(tool,args,receipts)
        if tool['name']=='send_email':
            if not hasattr(self,'recipient_audit'):self.recipient_audit=[]
            self.recipient_audit.append({'operation':{'function':tool['name'],'args':copy.deepcopy(args)},'decision':answer['decision'],'audit_error':audit_error,'recipient_count':len(args.get('recipients') or [])+len(args.get('cc') or [])+len(args.get('bcc') or []),'owner_literal_positions':[i for i,v in enumerate((args.get('recipients') or [])+(args.get('cc') or [])+(args.get('bcc') or [])) if isinstance(v,str) and v in self.owner_task],'occurrences':full.get('recipient_identifier_occurrences_in_observed_file_metadata',[]),'source_role':'literal metadata occurrence is not verified identity or permission'})
        return answer

class Broker(reference.v16.Broker):
    def init(self,p):
        self.study_arm=p['study_arm']
        if self.study_arm not in ARMS:raise ValueError('Unknown screen arm')
        reference.FEEDBACK=False;reference.v16.IntentRuntime=reference.StudyRuntime
        reference.v16.IntentGuard=RecordingGuard
        guard_module.candidate_facts=(lambda *_:{}) if self.study_arm in {'none','minimal'} else literal_facts if self.study_arm=='literal_facts' else FACTS
        result=super().init({**p,'arm':'none' if self.study_arm=='none' else 'intent_guard','scope_mode':'direct'})
        c=result['connection'];self.provider_scope=provider_scope(c['base_url'].rstrip('/')+'/responses',c.get('api_key'))
        if p.get('provider_scope_sha256') and self.provider_scope!=p['provider_scope_sha256']:raise ValueError('Provider scope changed')
        if self.intent_guard is not None:
            self.intent_guard.transport=StageTransport(p['judge_cache'],self.study_arm)
            if self.intent_guard.transport.scope!=self.provider_scope:raise ValueError('Actor/judge provider mismatch')
        return result
    def finish(self,p):
        result=super().finish(p);result['result'].update(study_arm=self.study_arm,provider_scope_sha256=self.provider_scope)
        result['result']['fact_stage_audit']=self.intent_guard.transport.stage_audit if self.intent_guard else []
        result['raw']['recipient_literal_audit']=getattr(self.intent_guard,'recipient_audit',[]) if self.intent_guard else []
        return result

def main():
    broker=Broker();diagnostics=[]
    for line in sys.stdin:
        ident=None
        try:
            row=json.loads(line);ident=row['id']
            if set(row)!={'id','method','params'} or row['method'] not in {'init','invoke','finish'}:raise ValueError('Invalid RPC')
            with contextlib.redirect_stdout(io.StringIO()) as stream:result=getattr(broker,row['method'])(row['params'])
            text=stream.getvalue()
            if text:diagnostics.append({'phase':row['method'],'characters':len(text),'sha256':hashlib.sha256(text.encode()).hexdigest()})
            if row['method']=='finish':result['result']['native_stdout_diagnostics']=diagnostics
            print(json.dumps({'id':ident,'ok':True,'result':result},default=str),flush=True)
        except Exception as exc:print(json.dumps({'id':ident,'ok':False,'error':type(exc).__name__}),flush=True)
if __name__=='__main__':main()
