#!/usr/bin/env python3
"""Factorial async-provider qualification with forced causal order, not IID attacks."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import sqlite3
import subprocess
import sys
import time

from async_host import rpc
from async_oracle import inspect,violations

FAMILIES=['normal','caller_killed_then_fence','caller_killed_valid_then_reconcile',
          'queue_reply_lost_then_fence','fence_ack_lost_then_recover','coordinator_killed_after_fence',
          'effect_before_fence','provider_restart_pending_then_fence','provider_outage_during_fence',
          'resume_before_fence_after_outage','duplicate_delivery_after_reply_loss','receipt_reply_lost',
          'queued_not_settled','local_withdraw_crash_then_late_effect','notfound_inflight_request',
          'pending_revision_conflict','pending_resource_fence']
LATE_FAMILIES={'caller_killed_then_fence','queue_reply_lost_then_fence','fence_ack_lost_then_recover',
               'coordinator_killed_after_fence','provider_restart_pending_then_fence','provider_outage_during_fence'}
ZERO_FAMILIES={'notfound_inflight_request','pending_revision_conflict','pending_resource_fence'}
BOOKKEEPING=['durable_sop','procontract']
PROFILES=['local_snapshot','provider_fenced']


class Case:
    def __init__(self,root,kernel,bookkeeping,profile,family,seed):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=False);self.kernel=kernel
        self.bookkeeping,self.profile,self.family,self.seed=bookkeeping,profile,family,seed
        self.intent={'scope':'staging','artifact':hashlib.sha256(f'async-{seed}'.encode()).hexdigest(),
                     'expected_revision':0,'resource_fence':1}
        self.trace=[];self.observed_violations=[];self.provider=None;self.endpoint=None;self.op=None
        self.worker_calls=0;self.caller_kills=0;self.provider_kills=0;self.rpc_calls=0;self.actors=[]
        self.expected_external=None
        self.withdraw_seen_before_effect=False;self.effect_after_local_withdraw=False;self.pending_without_backend_fence=False

    def start_provider(self):
        self.provider=subprocess.Popen([sys.executable,'-B',str(Path(__file__).with_name('async_provider.py')),
            '--root',str(self.root/'provider'),'--profile',self.profile],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        if not select.select([self.provider.stdout],[],[],5)[0]:raise RuntimeError('provider startup timeout')
        line=self.provider.stdout.readline();message=json.loads(line)
        self.endpoint='http://127.0.0.1:'+str(message['port'])+'/rpc'
        self.trace.append({'provider_started':message})

    def stop_provider(self,crash=False):
        if self.provider and self.provider.poll() is None:
            if crash:self.provider.kill();self.provider_kills+=1
            else:self.provider.terminate()
            out,err=self.provider.communicate(timeout=5)
            self.trace.append({'provider_stopped':self.provider.returncode,'crash':crash,'stderr':err})
        self.provider=None

    def direct(self,action,**payload):
        self.rpc_calls+=1;result=rpc(self.endpoint,dict(action=action,**payload))
        if action=='external' and payload.get('artifact') is not None:self.expected_external=payload['artifact']
        self.trace.append({'fixture_rpc':action,'result':result});return result

    def command(self,action,payload,fault=None):
        cmd=[sys.executable,'-B',str(Path(__file__).with_name('async_host.py')),'--root',str(self.root/'caller'),
             '--kernel',str(self.kernel),'--endpoint',self.endpoint,'--arm',self.bookkeeping,
             '--action',action,'--payload',json.dumps(payload)]
        if fault:cmd+=['--fault',fault]
        return cmd

    def call(self,action,expect='ok',fault=None,**payload):
        self.worker_calls+=1;process=subprocess.Popen(self.command(action,payload,fault),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.actors.append(process)
        try:out,err=process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill();process.communicate();raise RuntimeError('worker supervision timeout')
        replies=[json.loads(x) for x in out.splitlines() if x]
        self.trace.append({'action':action,'expect':expect,'fault':fault,'returncode':process.returncode,'replies':replies,'stderr':err})
        if expect=='crash':
            assert process.returncode==-signal.SIGKILL and any(x.get('fault_reached')==fault for x in replies)
            self.caller_kills+=1;assert self.provider.poll() is None;result=None
        else:
            assert process.returncode==0,(action,process.returncode,err)
            reply=replies[-1]
            if expect=='ok':assert reply['ok'],reply
            elif expect=='unresolved':assert not reply['ok'] and 'unresolved' in reply,reply
            elif expect=='rejected':assert not reply['ok'] and 'rejection' in reply,reply
            else:raise ValueError('unknown expected response')
            result=reply.get('result')
        if action=='register':self.op=result
        self.observe(action)
        return result

    def observe(self,label):
        view=inspect(self.root);bad=violations(view,self.intent,self.op,self.expected_external)
        self.observed_violations+=bad
        applied=bool(view['jobs'] and view['jobs'][0]['status']=='applied')
        withdrawn=view['contracts']['request-1:admission']['standing']=='outstanding' and bool(view['controls'])
        if withdrawn and not applied:self.withdraw_seen_before_effect=True
        if applied and self.withdraw_seen_before_effect:self.effect_after_local_withdraw=True
        if view['controls'] and view['controls'][0]['state']=='pending' and not view['invalidations']:
            self.pending_without_backend_fence=True
        self.trace.append({'observation':label,'violations':bad,'view':view});return view

    def wait_for(self,predicate,label):
        deadline=time.monotonic()+4
        while time.monotonic()<deadline:
            view=inspect(self.root)
            if predicate(view):return self.observe(label)
            time.sleep(0.005)
        raise RuntimeError('provider condition timeout: '+label)

    def terminal(self):
        return self.wait_for(lambda v:bool(v['jobs']) and v['jobs'][0]['status']!='pending','provider_terminal')

    def queued_caller_death(self,ticket,inflight=False):
        payload={'ticket':ticket,'pause_before_enqueue':True} if inflight else {'ticket':ticket,'hold':True}
        process=subprocess.Popen(self.command('submit',payload),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.actors.append(process);self.worker_calls+=1
        first=''
        if inflight:
            self.wait_for(lambda v:any(e['kind']=='request_arrived' for e in v['events']),'request_arrived_not_enqueued')
            assert self.direct('job',operation_id=self.op) is None
        else:
            assert select.select([process.stdout],[],[],5)[0],'caller queue marker timeout'
            first=process.stdout.readline();assert json.loads(first).get('queued_while_lock_held')
        process.kill();out,err=process.communicate(timeout=5)
        assert process.returncode==-signal.SIGKILL and self.provider.poll() is None
        self.caller_kills+=1
        self.trace.append({'action':'submit','returncode':process.returncode,'inflight':inflight,
                           'replies':[json.loads(x) for x in (first+out).splitlines() if x],'stderr':err})
        self.observe('caller_dead_provider_alive')

    def run(self):
        self.start_provider();self.call('register',intent=self.intent);self.call('approve');ticket=self.call('prepare')
        family=self.family
        if family in ['caller_killed_then_fence','caller_killed_valid_then_reconcile']:
            self.queued_caller_death(ticket)
        elif family=='notfound_inflight_request':self.queued_caller_death(ticket,inflight=True)
        elif family in ['queue_reply_lost_then_fence','duplicate_delivery_after_reply_loss']:
            self.call('submit',ticket=ticket,drop_reply=True,expect='unresolved')
        else:self.call('submit',ticket=ticket)

        if family in ['caller_killed_then_fence','queue_reply_lost_then_fence']:
            self.call('invalidate');self.direct('release');self.terminal()
        elif family=='fence_ack_lost_then_recover':
            self.call('invalidate',drop_reply=True,expect='unresolved')
            self.call('prepare',expect='rejected');self.call('invalidate');self.direct('release');self.terminal()
        elif family=='coordinator_killed_after_fence':
            self.call('invalidate',fault='after_provider_fence_ack',expect='crash')
            self.call('prepare',expect='rejected');self.call('invalidate');self.direct('release');self.terminal()
        elif family=='effect_before_fence':
            self.direct('release');self.terminal();self.call('invalidate')
        elif family=='provider_restart_pending_then_fence':
            self.stop_provider(crash=True);self.start_provider();self.call('invalidate');self.direct('release');self.terminal()
        elif family in ['provider_outage_during_fence','resume_before_fence_after_outage']:
            self.stop_provider(crash=True);self.call('invalidate',expect='unresolved');self.call('prepare',expect='rejected')
            self.start_provider()
            if family=='resume_before_fence_after_outage':self.direct('release');self.terminal();self.call('invalidate')
            else:self.call('invalidate');self.direct('release');self.terminal()
        elif family=='duplicate_delivery_after_reply_loss':
            self.call('submit',ticket=ticket);self.call('submit',ticket=ticket);self.direct('release');self.terminal()
        elif family=='queued_not_settled':
            self.call('verify',expect='rejected');self.call('settle',expect='rejected');self.direct('release');self.terminal()
        elif family=='local_withdraw_crash_then_late_effect':
            self.call('invalidate',fault='after_local_withdraw',expect='crash');self.call('prepare',expect='rejected')
            self.direct('release');self.terminal();self.call('invalidate')
        elif family=='notfound_inflight_request':
            self.call('invalidate');self.direct('release_arrival')
            self.wait_for(lambda v:any(e['kind']=='enqueue_response' for e in v['events']),'late_enqueue_processed')
            self.direct('release');assert not inspect(self.root)['jobs']
        elif family=='pending_revision_conflict':
            self.direct('external',artifact='other-authorized-artifact');self.direct('release');self.terminal()
        elif family=='pending_resource_fence':
            self.direct('external');self.direct('release');self.terminal()
        else:self.direct('release');self.terminal()

        view=self.observe('before_effect_accounting')
        applied=bool(view['jobs'] and view['jobs'][0]['status']=='applied')
        if family=='receipt_reply_lost':self.call('receipt',drop_reply=True,expect='unresolved')
        if applied:self.call('verify');self.call('settle')
        else:self.call('verify',expect='rejected');self.call('settle',expect='rejected')
        final=self.observe('final')
        expect_effect=family not in ZERO_FAMILIES and not (family in LATE_FAMILIES and self.profile=='provider_fenced')
        assert applied==expect_effect,('effect outcome',applied,expect_effect)
        expect_bad={'effect_after_provider_revocation'} if family in LATE_FAMILIES and self.profile=='local_snapshot' else set()
        assert set(self.observed_violations)==expect_bad,('violations',self.observed_violations,expect_bad)
        assert final['contracts']['request-1:effect']['standing']==('discharged' if applied else 'outstanding')
        return applied

    def cleanup(self):
        for process in self.actors:
            if process.poll() is None:process.kill();process.communicate(timeout=5)
        self.stop_provider()


def execute(root,kernel,bookkeeping,profile,family,seed):
    start=time.monotonic();case=Case(root,kernel,bookkeeping,profile,family,seed);error=None;applied=None
    try:applied=case.run()
    except Exception as failure:error=type(failure).__name__+': '+str(failure)
    finally:case.cleanup()
    row={'bookkeeping':bookkeeping,'profile':profile,'family':family,'seed':seed,'expectation_met':error is None,
         'violations':sorted(set(case.observed_violations)),'error':error,'applied':applied,
         'effect_after_local_withdraw':case.effect_after_local_withdraw,'pending_without_backend_fence':case.pending_without_backend_fence,
         'caller_sigkills':case.caller_kills,'provider_sigkills':case.provider_kills,'worker_calls':case.worker_calls,
         'fixture_rpc_calls':case.rpc_calls,'elapsed_seconds':time.monotonic()-start}
    (case.root/'trace.json').write_text(json.dumps(case.trace,indent=2)+'\n')
    (case.root/'outcome.json').write_text(json.dumps(row,indent=2)+'\n');return row


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--work',type=Path,required=True);parser.add_argument('--kernel',type=Path,required=True)
    parser.add_argument('--seed-start',type=int,required=True);parser.add_argument('--seeds',type=int,required=True)
    parser.add_argument('--workers',type=int,default=2);args=parser.parse_args();args.work.mkdir(parents=True,exist_ok=False)
    os.environ['CUDA_VISIBLE_DEVICES']='';start=time.monotonic();rows=[]
    schedules=[(seed,family) for seed in range(args.seed_start,args.seed_start+args.seeds) for family in FAMILIES]
    status=Path(os.environ.get('AROS_ARTIFACTS',args.work))/'status.md'
    def quartet(spec):
        seed,family=spec;arms=[(b,p) for b in BOOKKEEPING for p in PROFILES]
        if seed%2:arms.reverse()
        return [execute(args.work/f'{seed}-{family}-{b}-{p}',args.kernel,b,p,family,seed) for b,p in arms]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for completed,group in enumerate(pool.map(quartet,schedules),1):
            rows+=group
            with (args.work/'outcomes.jsonl').open('a') as out:
                for row in group:out.write(json.dumps(row)+'\n')
            unexpected=sum(not x['expectation_met'] for x in rows)
            status.write_text(f'{completed}/{len(schedules)} factorial blocks; {unexpected} unexpected outcomes; elapsed {time.monotonic()-start:.1f} s\n')
            print(json.dumps({'blocks':completed,'total':len(schedules),'unexpected':unexpected}),flush=True)
    summary={'kind':'async provider factorial qualification; local_snapshot is an explicit ablation',
             'families':FAMILIES,'seeds':args.seeds,'seed_start':args.seed_start,'cases':len(rows),
             'unexpected':sum(not x['expectation_met'] for x in rows),'elapsed_seconds':time.monotonic()-start,
             'caller_sigkills':sum(x['caller_sigkills'] for x in rows),'provider_sigkills':sum(x['provider_sigkills'] for x in rows),
             'worker_calls':sum(x['worker_calls'] for x in rows),'model_calls':0,'gpu_used':False,
             'arms':[]}
    for bookkeeping in BOOKKEEPING:
        for profile in PROFILES:
            selected=[x for x in rows if x['bookkeeping']==bookkeeping and x['profile']==profile]
            summary['arms'].append({'bookkeeping':bookkeeping,'profile':profile,'cases':len(selected),
                'unexpected':sum(not x['expectation_met'] for x in selected),
                'cases_with_provider_auth_violation':sum('effect_after_provider_revocation' in x['violations'] for x in selected),
                'effects_after_local_withdraw':sum(x['effect_after_local_withdraw'] for x in selected)})
    (args.work/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
    if summary['unexpected']:raise SystemExit(1)

if __name__=='__main__':main()
