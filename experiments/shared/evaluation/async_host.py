#!/usr/bin/env python3
"""Real reducer/SOP harness over an asynchronous loopback provider.

Local Withdraw is immediate; external revocation remains pending until backend ack.
This fixture assumes trusted callers and provider transport, not authenticated API.
"""
import argparse
import json
from pathlib import Path
import signal
import urllib.error
import urllib.parse
import urllib.request

from process_host import ProcessHost,DurableSOP,Rejected,enc

class Unresolved(Exception):pass

def rpc(endpoint,payload):
    if urllib.parse.urlsplit(endpoint).hostname!='127.0.0.1':raise ValueError('test endpoint must be loopback')
    request=urllib.request.Request(endpoint,data=enc(payload).encode(),headers={'Content-Type':'application/json'})
    try:
        with urllib.request.urlopen(request,timeout=1) as response:reply=json.load(response)
    except Exception as error:raise Unresolved(type(error).__name__) from error
    if not reply['ok']:raise Rejected(reply['error'])
    return reply['result']


class Remote:
    def __init__(self,root,binary,endpoint,fault=None):
        self.endpoint=endpoint
        super().__init__(root,binary,fault)
        with self.db(self.journal) as db:
            db.execute('CREATE TABLE IF NOT EXISTS remote_invalidations(logical_id TEXT PRIMARY KEY,identity TEXT,state TEXT)')

    def control(self,logical):
        with self.db(self.journal) as db:r=db.execute('SELECT * FROM remote_invalidations WHERE logical_id=?',(logical,)).fetchone()
        return dict(r) if r else None

    def prepare(self,logical):
        if self.control(logical):raise Rejected('invalidation pending/completed; no new dispatch')
        ticket=super().prepare(logical)
        authority=rpc(self.endpoint,{'action':'authority'})
        if not authority['active']:raise Rejected('provider grant revoked')
        ticket['provider_epoch']=authority['epoch'];return ticket

    def submit(self,ticket,hold=False,drop_reply=False,pause_before_enqueue=False):
        logical=ticket['logical_id']
        with self.lock():
            row=self._intent(logical);state=self.state(logical+':admission')
            with self.db(self.journal) as db:a=dict(db.execute('SELECT * FROM authority').fetchone())
            if self.control(logical):raise Rejected('invalidation pending/completed')
            if self.state(logical+':effect') is None:raise Rejected('no effect responsibility')
            if ticket['operation_id']!=row['op'] or ticket['intent_hash']!=row['subject']:raise Rejected('binding mismatch')
            if state['standing']!='discharged' or state['version']!=ticket['admission_version']:raise Rejected('stale admission')
            if not a['active'] or ticket['authority_epoch']!=a['epoch'] or ticket['executor_epoch']!=a['executor_epoch']:raise Rejected('stale caller grant')
            result=rpc(self.endpoint,{'action':'enqueue','request':dict(ticket,intent=row['body']),
                                      'drop_reply':drop_reply,'pause_before_enqueue':pause_before_enqueue})
            if hold:
                print(enc({'queued_while_lock_held':True}),flush=True)
                while True:signal.pause()
            return result

    def invalidate(self,logical,drop_reply=False):
        with self.lock():
            row=self._intent(logical);identity=row['op']+':invalidate'
            with self.db(self.journal) as db:
                db.execute('INSERT OR IGNORE INTO remote_invalidations VALUES(?,?,?)',(logical,identity,'pending'))
            old=self.control(logical)
            if old['state']=='done':return old
            state=self.state(logical+':admission')
            if state['standing']=='discharged':
                self._command(logical+':admission','verifier',{'type':'withdraw',
                    'target':{'type':'settlement','coordinate':state['settlement']['coordinate']},'cause':row['subject']})
            self.checkpoint('after_local_withdraw')
            response=rpc(self.endpoint,{'action':'invalidate','invalidation_id':identity,'drop_reply':drop_reply})
            self.checkpoint('after_provider_fence_ack')
            with self.db(self.journal) as db:db.execute("UPDATE remote_invalidations SET state='done' WHERE logical_id=?",(logical,))
            return response

    def receipt(self,logical,drop_reply=False):
        row=self._intent(logical);job=rpc(self.endpoint,{'action':'job','operation_id':row['op'],'drop_reply':drop_reply})
        if not job or job['status']!='applied':return None
        receipt=job['receipt'];intent=row['body']
        expected={'operation_id':row['op'],'logical_id':logical,'intent_hash':row['subject'],
                  'scope':intent['scope'],'artifact':intent['artifact'],'old_revision':intent['expected_revision'],
                  'new_revision':intent['expected_revision']+1,'outcome':'applied'}
        if any(receipt.get(key)!=value for key,value in expected.items()):raise Rejected('provider receipt binding mismatch')
        return receipt


class ProContractRemote(Remote,ProcessHost):pass
class SOPRemote(Remote,DurableSOP):pass

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--kernel',required=True)
    parser.add_argument('--endpoint',required=True);parser.add_argument('--arm',choices=['procontract','durable_sop'],required=True)
    parser.add_argument('--action',required=True);parser.add_argument('--payload',default='{}');parser.add_argument('--fault')
    args=parser.parse_args();payload=json.loads(args.payload);logical=payload.pop('logical_id','request-1')
    cls=ProContractRemote if args.arm=='procontract' else SOPRemote;host=cls(args.root,args.kernel,args.endpoint,args.fault)
    try:
        if args.action=='register':result=host.register(logical,payload['intent'])
        elif args.action=='approve':result=host.approve_fixture(logical)
        elif args.action=='prepare':result=host.prepare(logical)
        elif args.action=='submit':result=host.submit(**payload)
        elif args.action=='invalidate':result=host.invalidate(logical,**payload)
        elif args.action=='receipt':result=host.receipt(logical,**payload)
        elif args.action=='verify':result=host.verify_effect(logical)
        elif args.action=='settle':result=host.settle_effect_fixture(logical)
        else:raise ValueError('unknown action')
        print(enc({'ok':True,'result':result}),flush=True)
    except Rejected as error:print(enc({'ok':False,'rejection':str(error)}),flush=True)
    except Unresolved as error:print(enc({'ok':False,'unresolved':str(error)}),flush=True)

if __name__=='__main__':main()
