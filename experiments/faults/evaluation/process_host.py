"""Process-fault harness. Shared local effect adapter; two responsibility stores.

This is a trusted-local study, not a network security boundary. The original
qualification files remain unchanged. Faults kill only this worker process.
"""
import contextlib
import json
import os
from pathlib import Path
import signal
import sys
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'prototype'))
from registry_host import RegistryHost,Rejected,digest,enc


class Connection:
    def __init__(self,host,db,backend):
        self.host,self.db,self.backend=host,db,backend

    def execute(self,sql,args=()):
        h=self.host
        phase=self.backend and h.phase=='apply'
        if phase and sql.startswith('UPDATE registry SET artifact='):
            with RegistryHost.db(h,h.journal) as audit:
                cursor=audit.execute('INSERT INTO events(kind,body) VALUES(?,?)',
                    ('effect_admission',enc({'ticket':h.ticket})))
                h.effect_event=cursor.lastrowid
        if phase and sql.startswith('INSERT INTO effects VALUES'):
            receipt=json.loads(args[2]);receipt['coordinator_event_seq']=h.effect_event
            args=(args[0],args[1],enc(receipt))
        result=self.db.execute(sql,args)
        if phase:
            point=None
            if sql=='BEGIN IMMEDIATE':point='effect_after_begin'
            elif sql.startswith('UPDATE registry SET artifact='):point='effect_after_write'
            elif sql.startswith('INSERT INTO effects VALUES'):point='effect_after_receipt'
            elif sql=='COMMIT':point='effect_after_commit'
            if point:h.checkpoint(point)
        return result

    def __getattr__(self,name):return getattr(self.db,name)


class ProcessHost(RegistryHost):
    def __init__(self,root,binary,fault=None):
        self.fault=fault;self.phase=None;self.ticket=None;self.effect_event=None
        super().__init__(root,binary)

    def checkpoint(self,name):
        if name==self.fault:
            print(enc({'fault_reached':name}),flush=True)
            os.kill(os.getpid(),signal.SIGKILL)

    @contextlib.contextmanager
    def db(self,path):
        with RegistryHost.db(self,path) as db:
            yield Connection(self,db,Path(path)==self.backend)

    def _reduce_command(self,cid,role,command,provenance):
        return RegistryHost._command(self,cid,role,command,provenance)

    def _command(self,cid,role,command,provenance='automation'):
        result=self._reduce_command(cid,role,command,provenance)
        phase='admission' if cid.endswith(':admission') else 'effect'
        self.checkpoint(phase+'_after_'+command['type'])
        return result

    def register(self,logical_id,intent):
        """Durable binding first; idempotently repair the remaining intake steps."""
        with self.lock():
            if set(intent)!={'scope','artifact','expected_revision','resource_fence'} or intent['scope']!='staging':
                raise Rejected('invalid intent/scope')
            try:row=self._intent(logical_id)
            except Rejected:
                with self.db(self.journal) as db:
                    db.execute('INSERT INTO intents VALUES(?,?,?,?)',(logical_id,uuid.uuid4().hex,enc(intent),digest(intent)))
                row=self._intent(logical_id)
            if row['subject']!=digest(intent):raise Rejected('changed logical intent')
            self.checkpoint('register_after_binding')
            ca,ce=logical_id+':admission',logical_id+':effect'
            if self.state(ca) is None:self._issue(ca,'permission for exact registry intent')
            if self.state(ce) is None:self._issue(ce,'receipt of one exact registry transition')
            if self.state(ca)['candidate'] is None:
                self._command(ca,'executor',{'type':'propose','subject_hash':digest(intent)})
            return row['op']

    def approve_fixture(self,logical_id):
        with self.lock():
            cid=logical_id+':admission';st=self.state(cid)
            if st['standing']=='discharged':return st
            if st['support'] is None:self._support(cid,{'owner_permits':self._intent(logical_id)['subject']})
            return self._discharge(cid)

    def prepare(self,logical_id):
        if self.state(logical_id+':effect') is None:raise Rejected('effect responsibility missing')
        return super().prepare(logical_id)

    def apply(self,ticket,**kwargs):
        if self.state(ticket['logical_id']+':effect') is None:raise Rejected('effect responsibility missing')
        self.phase='apply';self.ticket=ticket
        try:
            super().apply(ticket,**kwargs)
            return self.receipt(ticket['logical_id'])
        finally:self.phase=None

    def settle_effect_fixture(self,logical_id):
        with self.lock():
            cid=logical_id+':effect';st=self.state(cid)
            if st['standing']=='discharged':return st
            return self._discharge(cid)

    def revoke(self):
        with self.lock(),self.db(self.journal) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE authority SET active=0,epoch=epoch+1 WHERE id=1')
            db.execute('INSERT INTO events(kind,body) VALUES(?,?)',('revoke','{}'))
            db.execute('COMMIT')

    def handoff(self):
        with self.lock(),self.db(self.journal) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE authority SET executor_epoch=executor_epoch+1 WHERE id=1')
            db.execute('INSERT INTO events(kind,body) VALUES(?,?)',('handoff','{}'))
            db.execute('COMMIT')


class DurableSOP(ProcessHost):
    """Competent slice-specific durable SOP, NOT Temporal or a general kernel.

Shares the effect adapter deliberately, isolating responsibility bookkeeping.
Only the five exercised transitions are implemented; other commands are denied.
"""
    def _reduce_command(self,cid,role,command,provenance):
        old=self.state(cid);st=json.loads(json.dumps(old));kind=command['type']
        required={'issue':'issuer','propose':'executor','support':'verifier','discharge':'settler','withdraw':'verifier'}
        if required.get(kind)!=role:raise Rejected('SOP role/command denied')
        if kind=='issue':
            if old is not None:raise Rejected('SOP already issued')
            st={'id':cid,'owner':command['owner'],'revision':0,'bindings':command['bindings'],
                'standing':'outstanding','generation':0,'candidate':None,'support':None,'settlement':None,'version':0}
        elif old is None:raise Rejected('SOP missing responsibility')
        elif kind=='propose':
            if st['standing']!='outstanding' or st['candidate'] is not None:raise Rejected('SOP unexpected proposal')
            st['generation']+=1;st['candidate']={'generation':st['generation'],'subject_hash':command['subject_hash']}
        elif kind=='support':
            if st['standing']!='outstanding' or st['candidate'] is None:raise Rejected('SOP unsupported state')
            coordinate=command['coordinate']
            expected={'contract_id':cid,'revision':st['revision'],**st['bindings'],**st['candidate']}
            if any(coordinate.get(k)!=v for k,v in expected.items()):raise Rejected('SOP coordinate mismatch')
            st['support']={'certificate':command['certificate'],'coordinate':coordinate}
        elif kind=='discharge':
            if st['standing']!='outstanding' or not st['support']:raise Rejected('SOP no current support')
            if provenance!='human' or command['decision']['type']!='explicit':raise Rejected('SOP no synthetic owner act')
            if command['coordinate']!=st['support']['coordinate']:raise Rejected('SOP settlement mismatch')
            st['standing']='discharged';st['settlement']={k:command[k] for k in ['attestation','coordinate','decision']}
        elif kind=='withdraw':
            if not st['settlement'] or command['target']!={'type':'settlement','coordinate':st['settlement']['coordinate']}:
                raise Rejected('SOP withdrawal mismatch')
            st['standing']='outstanding';st['generation']+=1
            st['candidate']['generation']=st['generation'];st['support']=None;st['settlement']=None
        st['version']+=1
        envelope={'contract_id':cid,'expected_version':old['version'] if old else 0,'role':role,'provenance':provenance,'command':command}
        with self.db(self.journal) as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('INSERT OR REPLACE INTO contracts VALUES(?,?)',(cid,enc(st)))
            db.execute('INSERT INTO events(kind,body) VALUES(?,?)',('kernel',enc(envelope)))
            db.execute('COMMIT')
        return st


def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True)
    p.add_argument('--kernel',required=True);p.add_argument('--arm',choices=['procontract','durable_sop'],required=True)
    p.add_argument('--action',required=True);p.add_argument('--fault');p.add_argument('--payload',default='{}')
    args=p.parse_args();payload=json.loads(args.payload)
    cls=ProcessHost if args.arm=='procontract' else DurableSOP
    host=cls(args.root,args.kernel,args.fault);logical=payload.get('logical_id','request-1')
    try:
        if args.action=='register':result=host.register(logical,payload['intent'])
        elif args.action=='approve':result=host.approve_fixture(logical)
        elif args.action=='prepare':result=host.prepare(logical)
        elif args.action=='apply':result=host.apply(payload['ticket'],**payload.get('unsafe',{}))
        elif args.action=='verify':result=host.verify_effect(logical)
        elif args.action=='settle':result=host.settle_effect_fixture(logical)
        elif args.action=='withdraw':result=host.withdraw(logical)
        elif args.action=='revoke':result=host.revoke()
        elif args.action=='handoff':result=host.handoff()
        elif args.action=='external':result=host.external_update(payload['artifact'])
        elif args.action=='receipt':result=host.receipt(logical)
        elif args.action=='false_settle':
            with host.lock():
                cid=logical+':effect';fake={'wrong':'permission is not effect'}
                host._command(cid,'executor',{'type':'propose','subject_hash':digest(fake)})
                host._support(cid,fake);result=host._discharge(cid)
        else:raise ValueError('unknown action')
        print(enc({'ok':True,'result':result}),flush=True)
    except Rejected as error:
        print(enc({'ok':False,'rejection':str(error)}),flush=True)


if __name__=='__main__':main()
