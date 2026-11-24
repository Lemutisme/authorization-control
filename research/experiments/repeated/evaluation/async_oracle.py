"""Selected async lifecycle predicates, independent of candidate decision code.

Direct provider storage/audit and fixture order are trusted; no host-root claim.
"""
import hashlib
import json
from pathlib import Path
import sqlite3

def fingerprint(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def inspect(root):
    root=Path(root)
    with sqlite3.connect(root/'provider/provider.sqlite') as db:
        db.row_factory=sqlite3.Row;db.execute('BEGIN')
        tables={name:[dict(x) for x in db.execute('SELECT * FROM '+name)] for name in ['authority','registry','jobs','events','invalidations','changes']}
    for event in tables['events']:event['body']=json.loads(event['body'])
    for job in tables['jobs']:
        job['intent']=json.loads(job['intent']);job['receipt']=json.loads(job['receipt']) if job['receipt'] else None
    with sqlite3.connect(root/'caller/harness.sqlite') as db:
        db.row_factory=sqlite3.Row;db.execute('BEGIN')
        tables['contracts']={x['id']:json.loads(x['state']) for x in db.execute('SELECT * FROM contracts')}
        tables['bindings']=[dict(x) for x in db.execute('SELECT * FROM intents')]
        tables['controls']=[dict(x) for x in db.execute('SELECT * FROM remote_invalidations')]
    return tables

def violations(view,intent,op,external_artifact=None):
    bad=[]
    def need(value,label):
        if not value:bad.append(label)
    binding=view['bindings'][0]
    need(binding['op']==op and binding['subject']==fingerprint(intent) and json.loads(binding['intent'])==intent,'stable_intent')
    effects=[change for change in view['changes'] if change['op'] is not None]
    external=[change for change in view['changes'] if change['op'] is None]
    need(len(external)==int(external_artifact is not None),'unexpected_external_effect')
    if external:need(external[0]['artifact']==external_artifact,'external_effect_binding')
    need(len(effects)<=1,'duplicate_effect')
    need(len(view['jobs'])<=1,'operation_rebinding')
    job=view['jobs'][0] if view['jobs'] else None
    if job:
        need(job['op']==op and job['logical_id']=='request-1','job_binding')
        need(job['intent']==intent and job['intent_hash']==fingerprint(intent),'job_intent')
    applied=bool(job and job['status']=='applied')
    need(len(effects)==int(applied),'effect_receipt_atomicity')
    target=view['registry'][0];expected_artifact='base'
    for revision,change in enumerate(view['changes']):
        need(change['old_revision']==revision and change['new_revision']==revision+1,'revision_history')
        if change['op'] is not None:
            need(change['op']==op and change['artifact']==intent['artifact'],'actual_effect_binding')
            need(change['old_revision']==intent['expected_revision'],'effect_cas')
        expected_artifact=change['artifact']
    need(target['revision']==len(view['changes']) and target['artifact']==expected_artifact,'actual_registry')
    active=True;epoch=1;resource_fence=1;effect_events=[]
    for event in sorted(view['events'],key=lambda item:item['seq']):
        body=event['body']
        if event['kind']=='fenced':
            need(body['epoch']==epoch+1,'revocation_epoch');epoch=body['epoch'];active=False
        elif event['kind']=='resource_fence_changed':resource_fence+=1
        elif event['kind']=='enqueued':
            need(active and body['epoch']==epoch,'enqueue_authority')
        elif event['kind']=='applied':
            effect_events.append(event)
            need(active and job is not None and job['epoch']==epoch,'effect_after_provider_revocation')
            need(resource_fence==intent['resource_fence'],'effect_resource_fence')
            need(body['epoch_at_commit']==epoch and bool(body['active_at_commit'])==active,'commit_authority_record')
            need(body['operation_id']==op,'commit_operation')
        elif event['kind']=='provider_error':bad.append('provider_error')
    need(len(effect_events)==len(effects),'actual_commit_events')
    need(target['fence']==resource_fence,'actual_resource_fence')
    if applied:
        receipt=job['receipt'];expected={'operation_id':op,'logical_id':'request-1','intent_hash':fingerprint(intent),
            'scope':intent['scope'],'artifact':intent['artifact'],'old_revision':intent['expected_revision'],
            'new_revision':intent['expected_revision']+1,'admission_epoch':job['epoch'],'outcome':'applied'}
        for key,value in expected.items():need(receipt.get(key)==value,'receipt_'+key)
        if effect_events:
            event=effect_events[0]
            need(receipt['provider_commit_seq']==event['seq']==effects[0]['event_seq'],'receipt_commit_order')
            need(receipt['provider_epoch_at_commit']==event['body']['epoch_at_commit'],'receipt_actual_epoch')
    local=view['contracts']['request-1:effect']
    if local['standing']=='discharged':need(applied,'false_effect_settlement')
    for control in view['controls']:
        if control['state']=='done':
            need(any(x['id']==control['identity'] for x in view['invalidations']),'false_revocation_confirmation')
            need(view['contracts']['request-1:admission']['standing']=='outstanding','local_withdraw_missing')
    need(len(view['invalidations'])<=1,'invalidation_not_idempotent')
    if view['invalidations']:need(epoch==2,'invalidation_repeated')
    return sorted(set(bad))
