"""Bounded, structured-policy gate for three development families.

Only public mandate fields and receipts of declared native queries/effects are
used. There is no task object, gold identifier, evaluator or direct environment
read in the gate. Trusted metadata projection is a common adapter assumption.
"""
from __future__ import annotations
import datetime as dt
import json

READS={'get_current_day','get_day_calendar_events','search_calendar_events',
       'search_files_by_filename','get_file_by_id','list_files','search_files',
       'get_received_emails','get_sent_emails','get_draft_emails',
       'search_emails','search_contacts_by_name','search_contacts_by_email'}

def portable(value):
    if hasattr(value,'model_dump'):return value.model_dump(mode='json')
    if isinstance(value,list):return [portable(x) for x in value]
    if isinstance(value,dict):return {k:portable(v) for k,v in value.items()}
    if isinstance(value,(dt.datetime,dt.date)):return value.isoformat()
    return value

def stamp(value):
    if not isinstance(value,str):raise ValueError('timestamp required')
    parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is not None:raise ValueError('timezone outside the reviewed naive-time profile')
    return parsed

def answer(verdict,reason,**extra):return {'verdict':verdict,'reason':reason,**extra}

class PolicyGate:
    def __init__(self, mandate, mode, *, fact_budget=4):
        self.m=mandate;self.mode=mode;self.fact_budget=fact_budget;self.fact_queries=0
        self.event_matches=None;self.day_events=None;self.day_partial=None;self.created_files={}
        self.action_done=False;self.uncertain=False
        self.fact_log=[]

    def query_allowed(self,function,args):
        family=self.m.get('family')
        if family=='calendar_reschedule':
            return function=='search_calendar_events' and args=={'query':self.m['title']}
        if family=='conditional_calendar_create':
            return function=='search_calendar_events' and args=={'query':''}
        return False

    def observe(self,function,args,result):
        value=portable(result);family=self.m.get('family')
        if family=='calendar_reschedule' and function=='search_calendar_events' and args.get('query','').casefold()==self.m['title'].casefold() and not args.get('date'):
            if isinstance(value,list):
                self.event_matches=[{k:e.get(k) for k in ['id_','title','start_time','end_time','participants']} for e in value if isinstance(e,dict) and e.get('title','').casefold()==self.m['title'].casefold()]
                self.fact_log.append({'producer':function,'predicate':'exact_title_target_and_duration','from_ordinary_or_collector_receipt':True})
        if family=='conditional_calendar_create' and isinstance(value,list):
            if function=='get_day_calendar_events' and args.get('day')==self.m['start'][:10]:
                self.day_partial=[{k:e.get(k) for k in ['id_','start_time','end_time','status']} for e in value if isinstance(e,dict)]
                self.fact_log.append({'producer':function,'predicate':'partial_start_day_inventory_not_full_interval_coverage','from_ordinary_or_collector_receipt':True})
            if function=='search_calendar_events' and args.get('query')=='' and not args.get('date'):
                self.day_events=[{k:e.get(k) for k in ['id_','start_time','end_time','status']} for e in value if isinstance(e,dict)]
                self.fact_log.append({'producer':function,'predicate':'complete_current_calendar_interval_inventory','from_ordinary_or_collector_receipt':True})
        if family=='create_then_share_file' and function=='create_file' and isinstance(value,dict) and args.get('filename')==self.m['filename']:
            self.created_files[str(value['id_'])]={'filename':value.get('filename'), 'receipt':True}
        if function in {'create_calendar_event','reschedule_calendar_event'} and family in {'calendar_reschedule','conditional_calendar_create'}:
            self.action_done=True;self.event_matches=None;self.day_events=None;self.day_partial=None
        if function=='share_file' and family=='create_then_share_file':self.action_done=True

    def mark_uncertain(self):self.uncertain=True

    def _obtain(self,runtime,env):
        family=self.m['family']
        if family=='calendar_reschedule' and self.event_matches is None:
            query=('search_calendar_events',{'query':self.m['title']})
        elif family=='conditional_calendar_create' and self.day_events is None:
            query=('search_calendar_events',{'query':''})
        else:return None
        if self.mode=='static':return 'missing justified fact; static arm does not collect'
        if self.fact_queries>=self.fact_budget:return 'fact collection budget exhausted'
        # Each selected development profile has at most one missing producer
        # here. Correct adaptive SOP and PGA therefore choose the same query;
        # this cohort cannot demonstrate a nontrivial selector advantage.
        self.fact_queries+=1
        _,error=runtime.collect(env,*query)
        return error

    def decide(self,function,args,runtime,env):
        if self.m.get('status')!='supported':return answer('unsupported','public mandate not supported')
        if not isinstance(args,dict):return answer('deny','arguments must be an object')
        # Reject nested executable requests before the native runtime can run
        # them. Ordinary JSON dictionaries are not needed by these write tools.
        if function not in READS and any(isinstance(v,dict) or hasattr(v,'function') for v in args.values()):
            return answer('deny','nested write arguments outside profile')
        if function in READS:
            return answer('allow','declared owner-workspace read interface; effects audited')
        if self.uncertain:return answer('unresolved','earlier partial effect requires reconciliation')
        if self.action_done:return answer('deny','task mutation already completed')
        family=self.m['family']
        expected={'calendar_reschedule':{'reschedule_calendar_event'},'conditional_calendar_create':{'create_calendar_event'},'create_then_share_file':{'create_file','share_file'}}[family]
        if function not in expected:return answer('deny','effect outside the public task mandate')
        if self.mode=='acquire_all':
            error=self._obtain(runtime,env)
            if error:return answer('unresolved',error)
        try:
            if family=='calendar_reschedule':
                if set(args)-{'event_id','new_start_time','new_end_time'}:return answer('deny','unexpected argument')
                if stamp(args.get('new_start_time'))!=stamp(self.m['start']):return answer('deny','requested time differs from mandate')
                error=self._obtain(runtime,env)
                if error:return answer('unresolved',error)
                if self.event_matches is None:return answer('unresolved','missing event lookup')
                if len(self.event_matches)!=1:return answer('unresolved','event title is absent or ambiguous')
                event=self.event_matches[0]
                if str(args.get('event_id'))!=str(event['id_']):return answer('deny','event identity differs from authoritative lookup')
                if args.get('new_end_time') is not None:
                    expected_end=stamp(self.m['start'])+(stamp(event['end_time'])-stamp(event['start_time']))
                    if stamp(args['new_end_time'])!=expected_end:return answer('deny','duration changed outside mandate')
                return answer('allow','target, start and duration justified by current receipt')
            if family=='conditional_calendar_create':
                if set(args)-{'title','start_time','end_time','description','participants','location'}:return answer('deny','unexpected argument')
                if args.get('title')!=self.m['title'] or args.get('description','')!=self.m['description']:return answer('deny','event text differs from explicit mandate')
                if stamp(args.get('start_time'))!=stamp(self.m['start']) or stamp(args.get('end_time'))!=stamp(self.m['end']):return answer('deny','time/duration differs from mandate')
                if args.get('participants')!=[self.m['recipient']]:return answer('deny','participants differ from explicit mandate')
                if args.get('location') is not None:return answer('deny','unrequested location')
                if self.day_partial:
                    start,end=stamp(self.m['start']),stamp(self.m['end'])
                    for e in self.day_partial:
                        if e.get('status')!='canceled' and stamp(e['start_time'])<end and start<stamp(e['end_time']):return answer('deny','known active interval overlaps requested slot')
                error=self._obtain(runtime,env)
                if error:return answer('unresolved',error)
                if self.day_events is None:return answer('unresolved','missing availability inventory')
                start,end=stamp(self.m['start']),stamp(self.m['end'])
                for e in self.day_events:
                    if e.get('status')!='canceled' and stamp(e['start_time'])<end and start<stamp(e['end_time']):return answer('deny','requested slot is not free')
                return answer('allow','explicit event fields and availability justified')
            if function=='create_file':
                if set(args)-{'filename','content'}:return answer('deny','unexpected argument')
                if args.get('filename')!=self.m['filename']:return answer('deny','filename differs from mandate')
                if self.created_files:return answer('deny','task file already created')
                return answer('allow','creation of one task file; content utility scored separately')
            if function=='share_file':
                if set(args)-{'file_id','email','permission'}:return answer('deny','unexpected argument')
                if args.get('email')!=self.m['recipient'] or args.get('permission')!=self.m['permission']:return answer('deny','recipient or permission differs from mandate')
                if str(args.get('file_id')) not in self.created_files:return answer('deny','not the file created for this task')
                return answer('allow','bound creation receipt and explicit sharing scope')
        except (ValueError,TypeError,KeyError):return answer('unresolved','malformed or unsupported fact/time representation')
        return answer('unsupported','operation not covered')
