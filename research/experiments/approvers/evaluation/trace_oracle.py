"""Fixture oracle: imports no candidate policy, reducer, or decision function.

Provider and audit storage are trusted in this experiment. This checks observed
prefixes, not arbitrary hidden intermediate states or a compromised audit store.
"""
import hashlib
import json
from pathlib import Path
import sqlite3


def hash_intent(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def inspect(root):
    root=Path(root)
    with sqlite3.connect(root/'harness.sqlite') as db:
        db.row_factory=sqlite3.Row
        contracts={row['id']:json.loads(row['state']) for row in db.execute('SELECT * FROM contracts')}
        intents=[dict(row) for row in db.execute('SELECT * FROM intents')]
        authority=dict(db.execute('SELECT * FROM authority WHERE id=1').fetchone())
        events=[dict(row)|{'body':json.loads(row['body'])} for row in db.execute('SELECT * FROM events ORDER BY seq')]
    with sqlite3.connect(root/'registry.sqlite') as db:
        db.row_factory=sqlite3.Row
        registry=dict(db.execute("SELECT * FROM registry WHERE name='staging'").fetchone())
        effects=[dict(row)|{'receipt':json.loads(row['receipt'])} for row in db.execute('SELECT * FROM effects')]
        changes=[dict(row) for row in db.execute('SELECT * FROM changes ORDER BY seq')]
    return dict(contracts=contracts,intents=intents,authority=authority,events=events,
                registry=registry,effects=effects,changes=changes)


def violations(view,intent,logical='request-1',external=None):
    errors=[]
    def need(test,name):
        if not test:errors.append(name)
    binding=next((x for x in view['intents'] if x['logical_id']==logical),None)
    if binding:
        need(json.loads(binding['intent'])==intent,'immutable_intent')
        need(binding['subject']==hash_intent(intent),'intent_digest')
    guarded=[x for x in view['changes'] if x['origin']=='guarded']
    need(len(guarded)<=1 and len(view['effects'])<=1,'at_most_once')
    need(len(guarded)==len(view['effects']),'effect_receipt_atomicity')
    need(len(view['changes'])==len(guarded)+int(external is not None),'unexpected_change')
    for revision,change in enumerate(view['changes']):
        need(change['old_revision']==revision and change['new_revision']==revision+1,'revision_history')
        want=intent['artifact'] if change['origin']=='guarded' else external
        need(change['artifact']==want,'history_artifact')
    final=view['changes'][-1]['artifact'] if view['changes'] else 'base'
    need(view['registry']['artifact']==final,'actual_artifact')
    need(view['registry']['revision']==len(view['changes']),'actual_revision')
    for effect in view['effects']:
        receipt=effect['receipt']
        need(binding is not None,'effect_requires_binding')
        if binding is None:continue
        need(effect['op']==binding['op'],'stable_operation')
        expected={'operation_id':binding['op'],'logical_id':logical,'intent_hash':hash_intent(intent),
                  'scope':intent['scope'],'artifact':intent['artifact'],
                  'old_revision':intent['expected_revision'],'new_revision':intent['expected_revision']+1,'outcome':'applied'}
        for key,want in expected.items():need(receipt.get(key)==want,'receipt_'+key)
        need(effect['intent_hash']==hash_intent(intent),'effect_intent_digest')
        need(bool(guarded) and guarded[0]['op']==binding['op'],'change_operation')
        # Reconstruct authority at the recorded admission point from events.
        active=True;epoch=executor=1;admitted=False;admission_version=0;effect_issued=False;found=False
        for event in view['events']:
            body=event['body']
            if event['kind']=='revoke':active=False;epoch+=1
            elif event['kind']=='handoff':executor+=1
            elif event['kind']=='kernel':
                if body['contract_id']==logical+':effect' and body['command']['type']=='issue':effect_issued=True
                if body['contract_id']==logical+':admission':
                    admission_version+=1
                    if body['command']['type']=='discharge':admitted=True
                    elif body['command']['type'] in ['issue','propose','withdraw']:admitted=False
            elif event['kind']=='effect_admission' and event['seq']==receipt.get('coordinator_event_seq'):
                found=True;ticket=body['ticket']
                need(active and admitted,'current_authority')
                need(effect_issued,'prior_effect_responsibility')
                need(ticket['authority_epoch']==epoch and ticket['executor_epoch']==executor,'authority_fences')
                need(ticket['admission_version']==admission_version,'admission_version')
                need(ticket['operation_id']==binding['op'] and ticket['intent_hash']==hash_intent(intent),'ticket_binding')
                need(receipt['authority_epoch']==epoch and receipt['admission_version']==admission_version,'receipt_authority')
                break
        need(found,'effect_admission_event')
    state=view['contracts'].get(logical+':effect')
    if view['effects']:need(state is not None,'durable_effect_responsibility')
    if state and state['standing']=='discharged':need(len(view['effects'])==1,'no_false_settlement')
    return sorted(set(errors))
