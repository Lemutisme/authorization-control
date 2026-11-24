#!/usr/bin/env python3
"""Paired CPU process-fault study. Every worker is an actual subprocess.

Named schedules are qualification coverage, not IID attacks. Synthetic payloads
and race delays are seeded. No model/API/GPU/production effects are used.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import sys
import time

from trace_oracle import inspect,violations

CRASHES={
    'intake_binding':('register','register_after_binding'),
    'intake_admission':('register','admission_after_issue'),
    'intake_effect':('register','effect_after_issue'),
    'intake_proposal':('register','admission_after_propose'),
    'approval_support':('approve','admission_after_support'),
    'approval_settlement':('approve','admission_after_discharge'),
    'effect_begin':('apply','effect_after_begin'),
    'effect_write':('apply','effect_after_write'),
    'effect_receipt':('apply','effect_after_receipt'),
    'effect_commit':('apply','effect_after_commit'),
    'verification_proposal':('verify','effect_after_propose'),
    'verification_support':('verify','effect_after_support'),
    'settlement':('settle','effect_after_discharge'),
}
FAMILIES=['normal',*CRASHES,'withdraw','revoke','handoff','revision_conflict',
          'duplicate_race','withdraw_race','committed_then_revoke','rolled_back_then_revoke',
          'intake_crash_then_handoff','changed_intent']
ARMS=['durable_sop','procontract']


class Case:
    def __init__(self,root,kernel,arm,family,seed,control=None):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=False)
        self.kernel,self.arm,self.family,self.seed=kernel,arm,family,seed
        self.rng=random.Random(seed);self.control=control
        self.intent={'scope':'staging','artifact':hashlib.sha256(f'artifact-{seed}'.encode()).hexdigest(),
                     'expected_revision':0,'resource_fence':1}
        self.external=None;self.trace=[];self.failures=[];self.calls=0;self.crashes=0;self.op=None

    def call(self,action,*,fault=None,expect='ok',delay=0,**payload):
        if delay:time.sleep(delay)
        cmd=[sys.executable,'-B',str(Path(__file__).with_name('process_host.py')),
             '--root',str(self.root),'--kernel',str(self.kernel),'--arm',self.arm,
             '--action',action,'--payload',json.dumps(payload)]
        if fault:cmd+=['--fault',fault]
        begin=time.monotonic();process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:out,err=process.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            process.kill();out,err=process.communicate();raise RuntimeError('supervision timeout; worker killed')
        elapsed=time.monotonic()-begin;self.calls+=1
        replies=[json.loads(line) for line in out.splitlines() if line]
        row={'action':action,'fault':fault,'returncode':process.returncode,'seconds':elapsed,'replies':replies}
        self.trace.append(row)
        if expect=='crash':
            assert process.returncode==-signal.SIGKILL,(action,process.returncode,err)
            assert any(x.get('fault_reached')==fault for x in replies),'injection point not reached'
            self.crashes+=1;result=None
        else:
            assert process.returncode==0,(action,process.returncode,err)
            reply=replies[-1]
            if expect=='ok':assert reply['ok'],reply
            elif expect=='rejected':assert not reply['ok'],reply
            result=reply.get('result')
        return result

    def observe(self,label):
        view=inspect(self.root);bad=violations(view,self.intent,external=self.external)
        if view['intents']:
            op=view['intents'][0]['op']
            if self.op is not None and op!=self.op:bad.append('operation_changed_across_recovery')
            self.op=op
        self.failures+=bad;self.trace.append({'observation':label,'violations':bad,'view':view})
        return view

    def action(self,action,**kwargs):
        result=self.call(action,**kwargs);self.observe(action);return result

    def run(self):
        family=self.family;crash=CRASHES.get(family)
        def step(action,**payload):
            if crash and crash[0]==action:
                self.action(action,fault=crash[1],expect='crash',**payload)
            return self.action(action,**payload)
        if family=='intake_crash_then_handoff':
            self.action('register',intent=self.intent,fault='register_after_binding',expect='crash')
            self.action('handoff')
        step('register',intent=self.intent)
        step('approve')
        ticket=self.action('prepare');want=1
        if family=='withdraw':
            self.action('withdraw')
            self.action('apply',ticket=ticket,expect='ok' if self.control=='skip_recheck' else 'rejected',
                        unsafe={'unsafe_skip_admission_recheck':True} if self.control=='skip_recheck' else {})
            want=0
        elif family=='revoke':
            self.action('revoke');self.action('apply',ticket=ticket,expect='rejected');want=0
        elif family=='handoff':
            self.action('handoff');self.action('apply',ticket=ticket,expect='rejected')
            ticket=self.action('prepare');self.action('apply',ticket=ticket)
        elif family=='revision_conflict':
            self.external='separately-authorized-version'
            self.action('external',artifact=self.external);self.action('apply',ticket=ticket,expect='rejected');want=0
        elif family in ['duplicate_race','withdraw_race']:
            if family=='duplicate_race':second=self.action('prepare')
            delays=[self.rng.random()/200 for _ in range(2)]
            with ThreadPoolExecutor(max_workers=2) as pool:
                a=pool.submit(self.call,'apply',ticket=ticket,expect='either',delay=delays[0])
                if family=='duplicate_race':b=pool.submit(self.call,'apply',ticket=second,expect='either',delay=delays[1])
                else:b=pool.submit(self.call,'withdraw',delay=delays[1])
                a.result();b.result()
            view=self.observe('concurrent_return')
            want=len(view['effects']) if family=='withdraw_race' else 1
        elif family in ['committed_then_revoke','rolled_back_then_revoke']:
            fault='effect_after_commit' if family=='committed_then_revoke' else 'effect_after_write'
            self.action('apply',ticket=ticket,fault=fault,expect='crash')
            self.action('revoke');self.action('apply',ticket=ticket,expect='rejected')
            want=int(family=='committed_then_revoke')
        elif family=='changed_intent':
            changed=dict(self.intent,artifact='changed')
            self.action('register',intent=changed,expect='rejected')
            self.action('apply',ticket=ticket)
        elif self.control=='false_settlement':
            self.action('false_settle');want=0
        elif self.control=='wrong_artifact':
            self.action('apply',ticket=ticket,unsafe={'unsafe_wrong_artifact':True})
        else:step('apply',ticket=ticket)
        if want:
            step('verify');step('settle')
        elif not self.control:
            self.action('verify',expect='rejected');self.action('settle',expect='rejected')
        view=self.observe('final')
        if len(view['effects'])!=want:self.failures.append('expected_effect_count')
        standing=view['contracts']['request-1:effect']['standing']
        if standing!=('discharged' if want else 'outstanding'):self.failures.append('expected_final_responsibility')
        return view


def execute(root,kernel,arm,family,seed,control=None):
    start=time.monotonic();case=Case(root,kernel,arm,family,seed,control)
    error=None;view=None
    try:view=case.run()
    except Exception as failure:error=type(failure).__name__+': '+str(failure)
    (case.root/'trace.json').write_text(json.dumps(case.trace,indent=2)+'\n')
    row={'arm':arm,'family':family,'seed':seed,'control':control,'passed':not error and not case.failures,
         'violations':sorted(set(case.failures)),'error':error,'worker_calls':case.calls,'process_crashes':case.crashes,
         'elapsed_seconds':time.monotonic()-start,'effects':len(view['effects']) if view else None}
    (case.root/'outcome.json').write_text(json.dumps(row,indent=2)+'\n');return row


def main():
    p=argparse.ArgumentParser();p.add_argument('--work',type=Path,required=True);p.add_argument('--kernel',type=Path,required=True)
    p.add_argument('--seed-start',type=int,required=True);p.add_argument('--seeds',type=int,required=True)
    p.add_argument('--workers',type=int,default=2);p.add_argument('--controls',action='store_true');args=p.parse_args()
    args.work.mkdir(parents=True,exist_ok=False);os.environ['CUDA_VISIBLE_DEVICES']=''
    schedules=[(seed,family) for seed in range(args.seed_start,args.seed_start+args.seeds) for family in FAMILIES]
    rows=[];start=time.monotonic()
    status=Path(os.environ.get('AROS_ARTIFACTS',args.work))/'status.md'
    def pair(spec):
        seed,family=spec;arms=ARMS if seed%2==0 else list(reversed(ARMS))
        return [execute(args.work/f'{seed}-{family}-{arm}',args.kernel,arm,family,seed) for arm in arms]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for completed,pair_rows in enumerate(pool.map(pair,schedules),1):
            rows+=pair_rows
            with (args.work/'outcomes.jsonl').open('a') as out:
                for row in pair_rows:out.write(json.dumps(row)+'\n')
            status.write_text(f'{completed}/{len(schedules)} paired schedules; {sum(not x["passed"] for x in rows)} failed cases; elapsed {time.monotonic()-start:.1f} s\n')
            print(json.dumps({'pairs_done':completed,'pairs_total':len(schedules),'failed_cases':sum(not x['passed'] for x in rows)}),flush=True)
    controls=[]
    if args.controls:
        for control,family in [('skip_recheck','withdraw'),('false_settlement','normal'),('wrong_artifact','normal')]:
            row=execute(args.work/('control-'+control),args.kernel,'procontract',family,args.seed_start,control)
            row['detected']=bool(row['violations']) and row['error'] is None;controls.append(row)
    summary={'scope':'paired local process-fault qualification, no IID efficacy inference',
             'families':FAMILIES,'seeds':args.seeds,'seed_start':args.seed_start,'case_count':len(rows),
             'failed_cases':sum(not x['passed'] for x in rows),'worker_calls':sum(x['worker_calls'] for x in rows),
             'process_crashes':sum(x['process_crashes'] for x in rows),'elapsed_seconds':time.monotonic()-start,
             'arms':{arm:{'cases':sum(x['arm']==arm for x in rows),'passed':sum(x['arm']==arm and x['passed'] for x in rows)} for arm in ARMS},
             'controls':controls,'model_calls':0,'gpu_used':False,'workers':args.workers}
    (args.work/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
    if summary['failed_cases'] or any(not x['detected'] for x in controls):raise SystemExit(1)


if __name__=='__main__':main()
