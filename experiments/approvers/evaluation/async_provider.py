#!/usr/bin/env python3
"""Instrumented asynchronous loopback provider; trusted synthetic principals only.

The gate is a test scheduling barrier. Pending jobs and invalidations survive a
provider restart. A local-snapshot profile deliberately omits COMMIT-time auth.
"""
import argparse
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import time

def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'))
def fingerprint(value):return hashlib.sha256(encode(value).encode()).hexdigest()


class Provider:
    def __init__(self,root,profile):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        self.path=self.root/'provider.sqlite';self.profile=profile;self.gate=threading.Event();self.arrival_gate=threading.Event()
        with self.db() as db:
            db.executescript('''PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS authority(id INTEGER PRIMARY KEY,active INTEGER,epoch INTEGER);
            INSERT OR IGNORE INTO authority VALUES(1,1,1);
            CREATE TABLE IF NOT EXISTS registry(id INTEGER PRIMARY KEY,artifact TEXT,revision INTEGER,fence INTEGER);
            INSERT OR IGNORE INTO registry VALUES(1,'base',0,1);
            CREATE TABLE IF NOT EXISTS jobs(op TEXT PRIMARY KEY,logical_id TEXT,intent TEXT,intent_hash TEXT,epoch INTEGER,status TEXT,receipt TEXT);
            CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,body TEXT);
            CREATE TABLE IF NOT EXISTS invalidations(id TEXT PRIMARY KEY,epoch INTEGER,seq INTEGER);
            CREATE TABLE IF NOT EXISTS changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,op TEXT,artifact TEXT,old_revision INTEGER,new_revision INTEGER,event_seq INTEGER);
            ''')

    @contextlib.contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=10,isolation_level=None);db.row_factory=sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        try:yield db
        finally:db.close()

    def event(self,db,kind,body):
        return db.execute('INSERT INTO events(kind,body) VALUES(?,?)',(kind,encode(body))).lastrowid

    def authority(self):
        with self.db() as db:return dict(db.execute('SELECT * FROM authority').fetchone())

    def job(self,op):
        with self.db() as db:row=db.execute('SELECT * FROM jobs WHERE op=?',(op,)).fetchone()
        if row is None:return None
        return {'operation_id':op,'status':row['status'],'receipt':json.loads(row['receipt']) if row['receipt'] else None}

    def enqueue(self,request):
        intent=request['intent'];op=request['operation_id'];h=fingerprint(intent)
        if intent['scope']!='staging' or h!=request['intent_hash']:raise ValueError('intent/scope mismatch')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT * FROM jobs WHERE op=?',(op,)).fetchone()
            if old:
                if old['intent_hash']!=h or old['logical_id']!=request['logical_id']:raise ValueError('operation rebinding')
            else:
                authority=dict(db.execute('SELECT * FROM authority').fetchone())
                if not authority['active'] or request['provider_epoch']!=authority['epoch']:raise ValueError('invalid enqueue authorization')
                db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?,?)',(op,request['logical_id'],encode(intent),h,authority['epoch'],'pending',None))
                self.event(db,'enqueued',{'operation_id':op,'intent_hash':h,'epoch':authority['epoch']})
            db.execute('COMMIT')
        return self.job(op)

    def invalidate(self,identity):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            old=db.execute('SELECT * FROM invalidations WHERE id=?',(identity,)).fetchone()
            if old:result=dict(old)
            else:
                epoch=db.execute('SELECT epoch FROM authority').fetchone()[0]+1
                db.execute('UPDATE authority SET active=0,epoch=?',(epoch,))
                seq=self.event(db,'fenced',{'invalidation_id':identity,'epoch':epoch})
                db.execute('INSERT INTO invalidations VALUES(?,?,?)',(identity,epoch,seq))
                result={'id':identity,'epoch':epoch,'seq':seq}
            db.execute('COMMIT');return result

    def external(self,artifact=None):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            if artifact is None:
                db.execute('UPDATE registry SET fence=fence+1')
                self.event(db,'resource_fence_changed',{})
            else:
                old=db.execute('SELECT revision FROM registry').fetchone()[0]
                seq=self.event(db,'external_update',{'artifact':artifact})
                db.execute('UPDATE registry SET artifact=?,revision=revision+1',(artifact,))
                db.execute('INSERT INTO changes(op,artifact,old_revision,new_revision,event_seq) VALUES(?,?,?,?,?)',(None,artifact,old,old+1,seq))
            db.execute('COMMIT');return {'changed':True}

    def commit_one(self):
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            job=db.execute("SELECT * FROM jobs WHERE status='pending' ORDER BY op LIMIT 1").fetchone()
            if job is None:db.execute('COMMIT');return
            authority=dict(db.execute('SELECT * FROM authority').fetchone())
            target=dict(db.execute('SELECT * FROM registry').fetchone());intent=json.loads(job['intent'])
            stale=not authority['active'] or authority['epoch']!=job['epoch']
            if self.profile=='provider_fenced' and stale:
                db.execute("UPDATE jobs SET status='rejected' WHERE op=?",(job['op'],))
                self.event(db,'rejected',{'operation_id':job['op'],'reason':'authorization','epoch':authority['epoch']})
            elif target['revision']!=intent['expected_revision'] or target['fence']!=intent['resource_fence']:
                db.execute("UPDATE jobs SET status='rejected' WHERE op=?",(job['op'],))
                self.event(db,'rejected',{'operation_id':job['op'],'reason':'revision/fence'})
            else:
                seq=self.event(db,'applied',{'operation_id':job['op'],'epoch_at_commit':authority['epoch'],'active_at_commit':authority['active']})
                receipt={'operation_id':job['op'],'logical_id':job['logical_id'],'intent_hash':job['intent_hash'],
                         'scope':intent['scope'],'artifact':intent['artifact'],'old_revision':target['revision'],
                         'new_revision':target['revision']+1,'provider_commit_seq':seq,'admission_epoch':job['epoch'],
                         'provider_epoch_at_commit':authority['epoch'],'outcome':'applied'}
                db.execute('UPDATE registry SET artifact=?,revision=revision+1',(intent['artifact'],))
                db.execute('INSERT INTO changes(op,artifact,old_revision,new_revision,event_seq) VALUES(?,?,?,?,?)',
                           (job['op'],intent['artifact'],target['revision'],target['revision']+1,seq))
                db.execute("UPDATE jobs SET status='applied',receipt=? WHERE op=?",(encode(receipt),job['op']))
            db.execute('COMMIT')

    def work(self):
        self.gate.wait()
        while True:
            try:self.commit_one()
            except Exception as failure:
                with self.db() as db:self.event(db,'provider_error',{'type':type(failure).__name__,'message':str(failure)})
                return
            time.sleep(0.005)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--profile',choices=['local_snapshot','provider_fenced'],required=True);args=parser.parse_args()
    provider=Provider(args.root,args.profile)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            body={}
            try:
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])));action=body['action']
                if action=='authority':result=provider.authority()
                elif action=='enqueue':
                    if body.get('pause_before_enqueue'):
                        with provider.db() as db:provider.event(db,'request_arrived',{'operation_id':body['request']['operation_id']})
                        provider.arrival_gate.wait()
                    result=provider.enqueue(body['request'])
                elif action=='job':result=provider.job(body['operation_id'])
                elif action=='invalidate':result=provider.invalidate(body['invalidation_id'])
                elif action=='release':provider.gate.set();result={'released':True}
                elif action=='release_arrival':provider.arrival_gate.set();result={'released':True}
                elif action=='external':result=provider.external(body.get('artifact'))
                else:raise ValueError('unknown provider action')
                reply={'ok':True,'result':result}
            except Exception as error:reply={'ok':False,'error':type(error).__name__+': '+str(error)}
            if body.get('action')=='enqueue' and 'request' in body:
                with provider.db() as db:provider.event(db,'enqueue_response',{
                    'operation_id':body['request']['operation_id'],'accepted':reply['ok']})
            if body.get('drop_reply'):
                self.close_connection=True;return
            data=encode(reply).encode();self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)));self.end_headers()
            try:self.wfile.write(data)
            except (BrokenPipeError,ConnectionResetError):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    threading.Thread(target=provider.work,daemon=True).start()
    print(encode({'port':server.server_port,'profile':args.profile}),flush=True)
    server.serve_forever(poll_interval=0.05)


if __name__=='__main__':main()
