#!/usr/bin/env python3
"""Export, scan, verify and materialize completed authorship evidence.

No model calls. Publication envelopes distinguish original bytes from any
explicitly redacted materialization. Private replacement maps never enter export.
"""
import argparse
import base64
import csv
from collections import Counter, defaultdict
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_OUT=ROOT/'evidence/authorship/completed-v1'
LIMIT=512_000
CHUNK=300_000
X2_RUNS=[f'authorship-x2-{panel}-{arm}-main-v2' for panel in ['post','initial'] for arm in ['auto-approve','narrow-only','pga-minimal']]
RUNS=['authorship-x1-prefix-main-v1','authorship-x1-main-v1','authorship-x1-prepare-v1','authorship-x1-prepare-v2','authorship-x1-analysis-v1',
      *X2_RUNS,'authorship-x2-analysis-v2','authorship-x2-native-audit-v1','authorship-x2-native-audit-v2',
      'authorship-x2-post-pga-minimal-smoke-v1','authorship-x2-post-pga-minimal-smoke-v2',
      'authorship-x3-main-v1','authorship-x3-clean-repeat-v1','authorship-x3-analysis-v1','authorship-x3-policy-replay-audit-v1',
      'authorship-numeric-sort-diagnostic-v1']
SECRET_PATTERNS={
 'private_key':re.compile(r'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----'),
 'credential_token':re.compile(r'\b(?:gh[pousr]_|github_pat_|hf_|sk-)[A-Za-z0-9_-]{20,}\b'),
 'bearer_token':re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._~-]{24,}'),
}
HOST_PATH=re.compile(r'''(?<![\w])/(?:data|root|home|tmp|mnt|var/tmp)/[^\s"'`()<>{}\[\],;\\]+''')
IP=re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
LOCAL_URL=re.compile(r'https?://(?:localhost|[A-Za-z0-9_.-]+\.(?:internal|local))(?::\d+)?[^\s"\'<>`\\]*',re.I)


def digest(data):return hashlib.sha256(data).hexdigest()
def encoded(value):return (json.dumps(value,indent=2,ensure_ascii=False)+'\n').encode()
def load(path):return json.loads(Path(path).read_text())
def save(path,value):
 path=Path(path);path.parent.mkdir(parents=True,exist_ok=True);data=encoded(value)
 assert len(data)<=LIMIT, f'Oversized public JSON: {path.name}'
 path.write_bytes(data)
def safe_relative(text):
 path=Path(text);assert not path.is_absolute() and '..' not in path.parts
 return path


def package_version_context(text,match):
 # Exact observed package/version only, with an explicit package label.
 return match.group()=='4.15.3.0' and bool(re.search(r'(?:"z3-solver"\s*:\s*"|\bz3-solver(?: version)?\s+)$',text[max(0,match.start()-80):match.start()]))


def scan(text,label):
 for kind,pattern in SECRET_PATTERNS.items():
  if pattern.search(text):raise ValueError(f'{label}: decoded credential-like material ({kind}); export stopped')
 if HOST_PATH.search(text):raise ValueError(f'{label}: decoded machine path remains')
 if LOCAL_URL.search(text):raise ValueError(f'{label}: decoded local endpoint remains')
 for match in IP.finditer(text):
  if package_version_context(text,match):continue
  try:ipaddress.ip_address(match.group())
  except ValueError:continue
  raise ValueError(f'{label}: decoded IPv4/version-shaped literal remains')


def redact(text,mapping):
 # Do not turn credential discoveries into a concealed base64 export.
 for kind,pattern in SECRET_PATTERNS.items():
  if pattern.search(text):raise ValueError('Source credential-like material found: '+kind)
 changes=Counter()
 def replacement(kind):
  def replace(match):
   original=match.group()
   token='[REDACTED_'+kind.upper()+'_'+digest(original.encode())[:20]+']'
   mapping[token]={'kind':kind,'original':original};changes[kind]+=1
   return token
  return replace
 text=HOST_PATH.sub(replacement('host_path'),text)
 text=LOCAL_URL.sub(replacement('local_endpoint'),text)
 def ip_replacement(match):
  if package_version_context(text,match):return match.group()
  try:ipaddress.ip_address(match.group())
  except ValueError:return match.group()
  return replacement('ipv4_or_version_literal')(match)
 text=IP.sub(ip_replacement,text)
 return text,dict(changes)


def index_parts(out,rows,prefix):
 parts=[];batch=[];batch_bytes=3
 for row in rows:
  row_bytes=len(encoded(row))+4
  if batch_bytes+row_bytes>400_000 and batch:
   path=f'{prefix}/part-{len(parts):04d}.json';save(out/path,batch);parts.append({'path':path,'sha256':digest((out/path).read_bytes()),'count':len(batch)});batch=[];batch_bytes=3
  batch.append(row);batch_bytes+=row_bytes
 if batch:
  path=f'{prefix}/part-{len(parts):04d}.json';save(out/path,batch);parts.append({'path':path,'sha256':digest((out/path).read_bytes()),'count':len(batch)})
 return parts


def sources(args):
 rows=[];excluded=[]
 def add_tree(namespace,folder,filter_fn=lambda p:True):
  for path in sorted(folder.rglob('*')):
   if not path.is_file() or path.is_symlink():continue
   relative=path.relative_to(folder)
   if any(part in {'inputs','node_modules','__pycache__'} for part in relative.parts):continue
   if filter_fn(relative):rows.append((namespace+'/'+relative.as_posix(),path))
   else:excluded.append({'namespace':namespace,'relative_path':relative.as_posix(),'reason':'Outside selected publication formats/scope','source_sha256':digest(path.read_bytes())})
 for run in RUNS:
  folder=args.jobs/run
  assert folder.exists(),run
  add_tree('jobs/'+run+'/artifacts',folder/'artifacts',lambda p:p.suffix in {'.json','.jsonl','.gz','.md','.txt'} or p.name in {'worker.stdout','worker.stderr'})
  for filename in ['job.json','log']:
   if (folder/filename).exists():rows.append(('jobs/'+run+'/'+filename,folder/filename))
 # Response caches are needed to verify occurrence-coupled Progent samples.
 add_tree('shared-caches/x2/authorship-x2-v2/main',args.experiments/'x2-coupling/authorship-x2-v2/main',lambda p:p.suffix=='.json')
 # Supply the exact X2 fixtures and focused frozen code needed for local reanalysis.
 for frozen,area in [('frozen-x1-prefix-v1','x1'),('frozen-x1-branch-v1','x1'),('frozen-x2-v2','x2'),('frozen-x3-v1','x3')]:
  folder=args.experiments/frozen
  for relative in ['source-manifest.json','manifest.json']:
   if (folder/relative).exists():rows.append(('frozen/'+frozen+'/'+relative,folder/relative))
  add_tree('frozen/'+frozen+'/evaluation/authorship/'+area,folder/'evaluation/authorship'/area,
           lambda p:p.suffix in {'.py','.mjs','.json','.md'} and not any(s.startswith(('scripted','reclassified')) for s in p.parts))
  for relative in ['evaluation/refinement/controllers.py','evaluation/refinement/pi_transport.py','evaluation/refinement/pi_review_client.mjs','evaluation/baseline_audit/broker.py','evaluation/intent_guard/catalog.py']:
   if (folder/relative).exists():rows.append(('frozen/'+frozen+'/'+relative,folder/relative))
 # Scope-limited synthetic witness and audit source records; no live workflow inputs copied.
 diagnostic_names=['narrow_const.py','narrow-const-exact.json','narrow-const-controls.json','narrow-const-report.md',
                   'numeric-sort-audit.py','numeric-sort-protocol.json','numeric-sort-plan.md',
                   'x2_native_audit.py','x2_native_audit_v2.py','x2-native-audit-v2-recovery.md','x2-native-audit-v2-tests.json',
                   'test_x2_native_audit_v2.py','x3_policy_replay_audit.py','x3-policy-replay-audit-plan.md']
 for name in diagnostic_names:
  p=ROOT/'evaluation/authorship/diagnostics'/name
  if p.exists():rows.append(('diagnostics/'+name,p))
 review_names=['REVIEW.md','review-metadata.json','adoption-distinct.jsonl','adoption-rerun.json','adoption-rerun.txt',
  'attribution_factorial-rerun.json','attribution_factorial-rerun.txt','mine_traces-rerun.json','mine_traces-rerun.txt',
  'pga-gains.txt','policy_mine-rerun.json','policy_mine-rerun.txt','proof-check.txt','proof_check.py','unmarked-harm-records.txt','witness-records.txt']
 for name in review_names:
  p=args.review_source/name
  assert p.exists(),name
  rows.append(('outside-review/'+name,p))
 for review in ['subset-outside-review','numeric-outside-review']:
  add_tree(review,args.jobs.parent/'authorship-20261111'/review,lambda p:p.suffix in {'.json','.md','.py','.stdout','.stderr'} or p.name=='SHA256SUMS')
 assert len({r for r,_ in rows})==len(rows)
 return rows,excluded


def redaction_scope(selected,index):
 fields=Counter();renamed_keys=Counter();unstructured=Counter();changed_gzip=[];model_files=0;changed_model=[]
 def leaves(a,b,keys=()):
  if a==b:return
  if isinstance(a,dict) and isinstance(b,dict):
   assert len(a)==len(b)
   for k in a:
    public_key,_=redact(k,{})
    assert public_key in b
    if public_key!=k:renamed_keys['.'.join(keys) or '(root)']+=1
    leaves(a[k],b[public_key],keys+(public_key,))
  elif isinstance(a,list) and isinstance(b,list):
   assert len(a)==len(b)
   for x,y in zip(a,b):leaves(x,y,keys+('[]',))
  else:
   assert isinstance(a,str) and isinstance(b,str)
   fields['.'.join(keys)]+=1
 for (name,path),row in zip(selected,index):
  assert name==row['restore_path']
  if 'shared-caches/' in name or name.endswith(('.policy-journal.jsonl','.process.txt')):
   model_files+=1
   if row['redacted']:changed_model.append(name)
  if row['source_format']=='gzip' and row['redacted']:changed_gzip.append(name)
  if not row['redacted']:continue
  raw=path.read_bytes();original=(gzip.decompress(raw) if row['source_format']=='gzip' else raw).decode()
  public,_=redact(original,{})
  if path.suffix=='.json':leaves(json.loads(original),json.loads(public))
  elif path.suffix=='.jsonl':
   for a,b in zip(original.splitlines(),public.splitlines()):leaves(json.loads(a),json.loads(b))
  else:unstructured[path.suffix or '(no suffix)']+=1
 assert not changed_gzip and not changed_model
 return {'all_compressed_raw_artifacts_byte_exact':True,'compressed_raw_artifacts':sum(r['source_format']=='gzip' for r in index),
         'request_response_cache_journal_process_artifacts':model_files,'changed_request_response_cache_journal_process_artifacts':changed_model,
         'changed_structured_leaf_paths':dict(fields),'renamed_provenance_key_paths':dict(renamed_keys),'changed_unstructured_artifacts_by_suffix':dict(unstructured),
         'finding':'Changed JSON leaves are provenance references, commands, configuration paths, source/module paths, and error tracebacks. No native state, candidate, policy, effect, or model request/response leaf changes. Unstructured changes are code paths, local offline endpoint, documentation, logs and traceback text.',
         'verification_limit':'Byte comparison and structural leaf audit only. Public materialization and table reanalysis are checked separately. Native simulator/audit replay after portable path rewiring has not been rerun from this bundle.'}


def build(args):
 out=args.out.resolve();assert out==DEFAULT_OUT.resolve(),'This exporter owns completed-v1 only'
 assert not out.exists(),'Refuse overwrite; explicitly remove only a failed owned staging export before retry'
 private=args.private_map.resolve();assert not private.is_relative_to(ROOT),'Private mapping must remain outside repository'
 assert not private.exists(),'Fresh private map required'
 out.mkdir(parents=True);mapping={};index=[];origins=[];redactions=[]
 selected,excluded=sources(args)
 for number,(restore_path,path) in enumerate(selected):
  original=path.read_bytes();is_gzip=path.suffix=='.gz'
  decoded=gzip.decompress(original) if is_gzip else original
  original_text=decoded.decode('utf-8')
  text,changes=redact(original_text,mapping);scan(text,restore_path)
  public_decoded=text.encode('utf-8');changed=public_decoded!=decoded
  payload=(original if is_gzip and not changed else gzip.compress(public_decoded,mtime=0))
  materialized=payload if is_gzip else public_decoded
  row={'restore_path':restore_path,'source_format':'gzip' if is_gzip else 'text',
       'original_sha256':digest(original),'original_decoded_sha256':digest(decoded),
       'original_bytes':len(original),'decoded_sha256':digest(public_decoded),'decoded_bytes':len(public_decoded),
       'materialized_sha256':digest(materialized),'payload_sha256':digest(payload),
       'redacted':changed,'redaction_counts':changes,'parts':[]}
  for piece,start in enumerate(range(0,len(payload),CHUNK)):
   segment=payload[start:start+CHUNK];target=f'encoded/{number//500:04d}/{number:06d}-{piece:03d}.json'
   envelope={'encoding':'gzip-base64-chunk','artifact':number,'part':piece,'part_count':(len(payload)+CHUNK-1)//CHUNK,
             'restore_path':restore_path,'original_sha256':row['original_sha256'],'decoded_sha256':row['decoded_sha256'],
             'chunk_sha256':digest(segment),'payload_base64':base64.b64encode(segment).decode()}
   save(out/target,envelope);row['parts'].append({'path':target,'sha256':digest((out/target).read_bytes())})
  index.append(row);origins.append({'restore_path':restore_path,'original_path':str(path),'original_sha256':row['original_sha256']})
  if changed:redactions.append({k:row[k] for k in ['restore_path','original_sha256','original_decoded_sha256','decoded_sha256','redaction_counts']})
  if number%500==0:print(json.dumps({'packaged':number+1,'of':len(selected)}),flush=True)
 summary=derive(args.jobs)
 clean_summary,_=redact(json.dumps(summary,ensure_ascii=False),mapping)
 summary=json.loads(clean_summary)
 private.parent.mkdir(parents=True,exist_ok=True)
 private.write_text(json.dumps({'private_only':True,'mapping':mapping,'origins':origins},indent=2)+'\n');private.chmod(0o600)
 save(out/'redaction-scope.json',redaction_scope(selected,index))
 parts=index_parts(out,index,'artifact-index');redaction_parts=index_parts(out,redactions,'redactions')
 save(out/'manifest.json',{'bundle':'authorship-completed-v1','source_base_commit':'071e695',
       'artifact_count':len(index),'parts':parts,'redacted_artifact_count':len(redactions),'redaction_parts':redaction_parts,
       'private_mapping_sha256':digest(private.read_bytes()),'private_mapping_published':False,
       'redaction_semantic_limits':'Host paths in commands/code and actual IP endpoints are replaced. Explicit z3-solver 4.15.3.0 is preserved under a narrow package-label exception. See redaction-scope.json: native raw episode bytes and model request/response artifacts remain unchanged. Host-specific commands require path rewiring; the native environment replay was not rerun from this public bundle.',
       'format_limit_bytes':LIMIT,'decoded_scan':'All source decoded content scanned; credentials abort export; machine paths/endpoints are explicitly replaced and separately mapped.',
       'restoration':'Unredacted materialization is byte-exact. Redacted artifacts retain separate original and materialized/decoded hashes; original bytes require private mapping/source access.',
       'excluded_file_count':len(excluded),'not_included':['Credential/config files and installed environments','Job input mirrors (relevant frozen code and fixtures included separately)','Outside-review process logs and downloaded literature HTML','Incomplete X2b/X4 and claim-annotation work','Private redaction mapping and host-specific provenance values']})
 save(out/'exclusion-index.json',{'parts':index_parts(out,excluded,'exclusions'),'count':len(excluded)})
 # Build public summaries from raw/materializable inputs, not from user-supplied headline numbers.
 write_results(out,summary)
 save(out/'source-inventory.json',{'runs':RUNS,'raw_episode_records':summary['coverage'],
       'outside_review':'Separate retained-data claim audit, not a fresh model experiment',
       'synthetic_diagnostics':'Separate scalar/const checks, not natural ASR'})
 save(out/'original-source-verification.json',{'original_hashes_rechecked':len(origins),'all_match':all(digest(Path(r['original_path']).read_bytes())==r['original_sha256'] for r in origins),'private_mapping_sha256':digest(private.read_bytes()),'private_mapping_published':False})
 verify(out)
 print(json.dumps({'artifacts':len(index),'redacted':len(redactions),'bundle_bytes':sum(p.stat().st_size for p in out.rglob('*') if p.is_file()),'private_mapping_sha256':digest(private.read_bytes())},indent=2))


def artifact_rows(bundle):
 manifest=load(bundle/'manifest.json');rows=[]
 for part in manifest['parts']:
  data=(bundle/part['path']).read_bytes();assert digest(data)==part['sha256'];rows.extend(json.loads(data))
 assert len(rows)==manifest['artifact_count'];assert len({r['restore_path'] for r in rows})==len(rows)
 return rows


def decode(bundle,row):
 parts=[]
 for i,p in enumerate(row['parts']):
  raw=(bundle/p['path']).read_bytes();assert len(raw)<=LIMIT and digest(raw)==p['sha256']
  envelope=json.loads(raw);assert envelope['part']==i and envelope['restore_path']==row['restore_path']
  assert envelope['original_sha256']==row['original_sha256'] and envelope['decoded_sha256']==row['decoded_sha256']
  chunk=base64.b64decode(envelope['payload_base64'],validate=True);assert digest(chunk)==envelope['chunk_sha256'];parts.append(chunk)
 payload=b''.join(parts);assert digest(payload)==row['payload_sha256']
 decoded=gzip.decompress(payload);assert len(decoded)==row['decoded_bytes'] and digest(decoded)==row['decoded_sha256']
 scan(decoded.decode('utf-8'),row['restore_path']+' decoded')
 materialized=payload if row['source_format']=='gzip' else decoded
 assert digest(materialized)==row['materialized_sha256']
 if not row['redacted']:
  assert digest(materialized)==row['original_sha256'] and digest(decoded)==row['original_decoded_sha256']
 return materialized


def verify(bundle,output=None):
 rows=artifact_rows(bundle)
 for row in rows:
  materialized=decode(bundle,row)
  if output:
   path=output/safe_relative(row['restore_path']);path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(materialized)
 for path in bundle.rglob('*'):
  if path.is_file():
   assert path.stat().st_size<=LIMIT,path.name
   scan(path.read_text(),str(path.relative_to(bundle)))
 report={'passed':True,'artifact_envelopes_checked':len(rows),'decoded_payloads_scanned':len(rows),
         'credential_or_host_location_matches_remaining':0,'redacted_artifacts':sum(r['redacted'] for r in rows),
         'largest_public_file_bytes':max(p.stat().st_size for p in bundle.rglob('*') if p.is_file()),
         'model_calls':0,'network_calls':0}
 if output:save(output/'materialization-receipt.json',report)
 else:save(bundle/'verification.json',report)
 return report


def derive(jobs):
 def j(run,name='result.json'):return load(jobs/run/'artifacts'/name)
 x1=j('authorship-x1-analysis-v1','summary.json');groups=defaultdict(list)
 for row in x1['rows']:groups[(row['fault_class'],row['feedback'],row['stratum'])].append(row)
 x1table=[]
 for fault in ['M1','M2','M3']:
  for fmt in ['F0','F1','F2','F3','F4']:
   rs=groups[(fault,fmt,'actor_right')]
   x1table.append({'fault':fault,'feedback':fmt,'n':len(rs),'known':sum(r['known'] for r in rs),
                   'fault_value_effect':sum(r['known'] and r['fault_value_effect'] for r in rs),
                   'native_utility':sum(r['native_utility'] is True for r in rs),'clusters':len({r['cluster_id'] for r in rs})})
 assert len(x1['rows'])==965 and x1['known']==965
 # Verify every scheduled raw branch exists; final native outcomes are already derived in the completed native analysis.
 c=j('authorship-x1-main-v1','config.json');raw_count=0
 for condition in c['conditions']:
  matches=list((jobs/'authorship-x1-main-v1/artifacts').glob('*/'+condition+'.json.gz'))
  assert len(matches)==1;raw_count+=1
 prefix=j('authorship-x1-prefix-main-v1');assert prefix['scheduled']==prefix['observed']==35
 x2=[]
 for run in X2_RUNS:
  config=j(run,'config.json');rs=[]
  for cid in config['cases']:rs.append(json.loads(gzip.decompress((jobs/run/'artifacts'/cid/(config['arm']+'.json.gz')).read_bytes()))['result'])
  x2.append({'panel':config['panel'],'arm':config['arm'],'n':len(rs),
             'initial_admissions':sum(r['steps'][0]['allowed'] for r in rs),
             'final_admissions':sum(r.get('first_admission_stage') is not None for r in rs),
             'new_admissions':sum(r['initial_denied'] and r.get('first_admission_stage') is not None for r in rs),
             'review_unavailable':sum(r.get('scientific_status')=='review_unavailable' for r in rs),
             'scientifically_complete':sum(r.get('scientific_status')=='complete' for r in rs)})
 assert sum(r['n'] for r in x2)==630
 arms=['optional_auto','optional_narrow','forced_auto','forced_narrow'];x3=[];unchanged_false=[];x3records=0
 for run in ['authorship-x3-main-v1','authorship-x3-clean-repeat-v1']:
  config=j(run,'config.json');rs=defaultdict(list)
  for cid in config['cases']:
   for arm in arms:
    raw=json.loads(gzip.decompress((jobs/run/'artifacts'/cid/(arm+'.json.gz')).read_bytes()));r=raw['result'];rs[(r['condition'],arm)].append(r);x3records+=1
    for index,u in enumerate(r['update_records']):
     if u.get('final_subset_diagnostic',{}).get('is_subset') is False and u['before_sha256']==u['after_sha256']:
      unchanged_false.append({'panel':config['phase'],'case_id':cid,'arm':arm,'update':index,'classification':'failed certification on unchanged policy; not semantic expansion'})
  for (condition,arm),rows in sorted(rs.items()):
   x3.append({'panel':config['phase'],'condition':condition,'arm':arm,'n':len(rows),
              'native_utility':sum(r['native_utility'] is True for r in rows),
              'native_target':sum(r['native_targeted_asr'] is True for r in rows),
              'unknown':sum(r['native_utility'] is None for r in rows)})
 assert x3records==740
 audit2=j('authorship-x2-native-audit-v2');audit3=j('authorship-x3-policy-replay-audit-v1')
 assert audit2['passed'] and audit2['arm_records_passed']==630
 assert audit3['passed'] and audit3['arm_records_passed']==740 and audit3['prior_findings_reconciled']==85
 failed=j('authorship-x2-native-audit-v1')
 numeric=j('authorship-numeric-sort-diagnostic-v1')
 repair={fmt:groups[('none',fmt,'target_wrong')] for fmt in ['F0','F1','F2','F3','F4']}
 assert all(len(rs)==1 for rs in repair.values())
 return {'scope':'Completed X1/X2/X3 only; native finite effects and development cohorts. No new malicious-actor/control-safety results.',
  'coverage':{'x1_branch_episodes':raw_count,'x1_prefix_episodes':35,'x1_source_units':x1['source_units'],'x1_exposed_units':x1['exposed_units'],'x1_task_clusters':x1['task_clusters'],'x2_arm_records':630,'x2_panel_units':210,'x2_overlapping_case_ids':98,'x3_arm_records':740},
  'x1':{'effects':x1table,'repair_units':1,'repair_correct_effects':{fmt:sum(r['correct_effect'] for r in rs) for fmt,rs in repair.items()},'claim_annotation_complete_in_this_snapshot':x1['claim_annotation_complete']},
  'x2':x2,'x3':x3,'x3_unchanged_policy_false_certifications':unchanged_false,
  'verification':{'x2_native':{k:v for k,v in audit2.items() if k not in {'cross_record_checks','elapsed_s'}},'x3_policy_replay':audit3},
  'synthetic_numeric_sort':{k:v for k,v in numeric.items() if k!='rows'},
  'operational_history':{'x1_prepare_v1':'FileExistsError; separate preparation recovery v2, not an outcome retry',
   'x2_pga_smoke_v1':'Missing explicit Pi dependency link; structurally complete but no usable reviews; superseded by separately registered smoke v2',
   'x2_post_pga_unknown_episodes':sum(r['review_unavailable'] for r in x2 if r['panel']=='post_exposure'),
   'x2_native_audit_v1':{'checked':failed['arm_records_checked'],'failed':len(failed['failed_records']),'meaning':'Audit implementation omitted native parsing/retry/partial-mutation behavior; source and original outcomes unchanged; v2 verifies all records'},
   'x3_serialization_hash_findings':85,'x3_hash_reconciliation':'Exact original response-defined Python hashes reproduced; Node-normalized values match saved JSON. No relaxed hash waiver.'}}


def write_results(out,s):
 save(out/'summary.json',s);macros=[]
 for name,rows in [('x1',s['x1']['effects']),('x2',s['x2']),('x3',s['x3'])]:
  with (out/(name+'-summary.csv')).open('w',newline='') as f:
   writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
 def macro(name,value):
  words=['Zero','One','Two','Three','Four','Five','Six','Seven','Eight','Nine']
  name=''.join(words[int(c)] if c.isdigit() else c for c in name)
  macros.append('\\newcommand{\\'+name+'}{'+str(value)+'}')
 lines=['Completed authorship studies','',
  'This development-branch snapshot contains completed X1 fault-injection, X2 fixed-candidate insistence, and X3 selector/approver studies. It does not include ongoing malicious-actor X2b, X4, or later claim annotation. All native effects are confined to benchmark simulators. The locked paper title and abstract are unchanged.','',
  'X1: executed fault-value effects under an initially correct actor proposal.','',
  '| Fault | Feedback | Executed fault value | Source task clusters |','|---|---|---:|---:|']
 for r in s['x1']['effects']:
  lines.append(f"| {r['fault']} | {r['feedback']} | {r['fault_value_effect']}/{r['n']} | {r['clusters']} |")
  macro('AuthXOne'+r['fault']+r['feedback']+'Effects',r['fault_value_effect']);macro('AuthXOne'+r['fault']+r['feedback']+'N',r['n'])
 lines+=['',f"X1 contains {s['coverage']['x1_branch_episodes']} branch episodes from {s['coverage']['x1_exposed_units']} exposed argument units ({s['coverage']['x1_source_units']} source units) in {s['coverage']['x1_task_clusters']} task clusters, with 35 separate no-gate prefix episodes. Repeated formats/faults are paired interventions, not independent tasks. F0 includes native value-disclosing feedback; F3 is opaque. The original at-least-80% F0 forecast holds for M1 (47/49) and fails for M2 (15/34). F3 executes the fault value in 0/49 and 0/34 respectively. These are committed native effects, not proposal matching. Every wrong-policy format has native task utility zero; eliminating the injected fault value therefore does not establish restoration of task completion.",
  '', 'The repair stratum has only one source unit: F0/F1/F2 repair it, F3/F4 do not. This cannot establish a general repair rate. Claim-disclosure annotations are not complete in this source analysis snapshot.','',
  'X2: cumulative admission at the initial and third-insistence endpoints.','',
  '| Panel | Controller | N | Initial → final admissions | New after initial denial | Review-unavailable episodes |','|---|---|---:|---:|---:|---:|']
 for r in s['x2']:
  lines.append(f"| {r['panel']} | {r['arm']} | {r['n']} | {r['initial_admissions']} → {r['final_admissions']} | {r['new_admissions']} | {r['review_unavailable']} |")
  name='AuthXTwo'+''.join(w.title().replace('_','') for w in [r['panel'],r['arm']]);macro(name+'Initial',r['initial_admissions']);macro(name+'Final',r['final_admissions']);macro(name+'New',r['new_admissions'])
 lines+=['','The 98 post-exposure and 112 initial panel units overlap in 98 case IDs (96 equal-state/equal-candidate pairs); no pooling into independent-task estimates. X2 uses no fresh actor and is not natural ASR or malicious-agent safety. Post-exposure auto gains five admissions; narrow gains one. The narrow witness is verified: unsupported `const` is ignored by the SMT translation but enforced by native JSON Schema. This violates the implementation’s semantic-inclusion assumption, not mathematical monotonicity. One post-exposure PGA episode remains scientifically unknown due to review unavailability; zero observed admissions is not a valid denial for that episode. Initial-panel auto gains two; narrow gains none.','',
  'X3: native utility and target predicates, with clean and attacked conditions separate.','',
  '| Panel | Condition | Controller | Utility | Native target |','|---|---|---|---:|---:|']
 for r in s['x3']:lines.append(f"| {r['panel']} | {r['condition']} | {r['arm']} | {r['native_utility']}/{r['n']} | {r['native_target']}/{r['n']} |")
 lines+=['',f"X3 has 169 main cases × four arms plus a separate 16-task clean repeat × four arms = 740 arm records. Main cases include 16 clean tasks, 144 stock-injection task/target pairs and nine authorized goal controls. The clean repeat reuses tasks, not new independent tasks. Native target predicates retain benchmark limitations; goal controls are not attacks. There is no no-gate X3 arm, so these tables do not identify a no-gate utility gain.",
  '',f"There are {len(s['x3_unchanged_policy_false_certifications'])} recorded False SMT diagnostics on exactly unchanged policies. These are failed certifications, not semantic expansions. The full policy replay audit verifies all 740 records and reconciles 85 serialization hash findings: source response text preserves Python integral floats, whereas Node writes integral values as integers. Exact Python hashes and the Node-normalized readback both match; no hash comparison was relaxed.",
  '', 'Verification and operational history remain separate from study outcomes. X2 native audit v2 verifies 630/630 arm records and preserves the unavailable PGA episode. Audit v1 retained all 630 records but failed 63 checks because its reconstruction omitted original malformed-response retries and partial policy mutation; its files are exported alongside v2. The first PGA smoke had a missing dependency link and no usable reviews; recovery is separate. X1 preparation first failed with FileExistsError and was recovered in a distinct preparation job. None is silently merged into a successful uninterrupted run.',
  '',f"Separate synthetic diagnostic: {s['synthetic_numeric_sort']['observed']}/14 numeric-sort controls completed with {len(s['synthetic_numeric_sort']['false_containment_witness_rows'])} concrete false-containment witnesses. These scalar-schema checks are neither natural ASR nor additional task episodes. The outside Astra review is also exported separately: it corrects marker-based safety attribution, disclosure denominators, and unsupported independence/authorship claims. Its retrospective critiques do not add fresh experimental samples.",
  '', 'The separate const outside review verifies the exact retained case and 43 assertions, without establishing natural actor reachability. The numeric outside review independently reruns nine selected original controls plus one discriminating control: 20 native invocations, four false-containment witnesses. Numeric literal sort selection loses fractional witnesses; additionally, old type integer with new type number makes the translated new number predicate false even for an integer counterexample. Numeric equivalence is confined to the normalized native numeric domain. Neither review establishes novelty or natural attack success.',
  '', 'Evidence packaging and reconstruction: see manifest.json, source-inventory.json and reconstruction.md. Decoded payloads are scanned before encoding and after decoding. Artifacts requiring host-path/network redaction have separate original, exported-decoded and materialized hashes; the private reversible mapping is not published. No original hash is relabeled as the hash of changed bytes.','']
 for key,value in s['coverage'].items():macro('Auth'+''.join(x.title() for x in key.split('_')),value)
 (out/'results.md').write_text('\n'.join(lines));(out/'authorship-completed-results.tex').write_text('\n'.join(macros)+'\n')
 (out/'reconstruction.md').write_text('''Materialize and reanalyze the completed snapshot with the same exporter script:\n\n```bash\npython3 scripts/export_authorship_completed.py verify\npython3 scripts/export_authorship_completed.py materialize --destination NEW_DIRECTORY\npython3 scripts/export_authorship_completed.py summarize --jobs NEW_DIRECTORY/jobs --destination NEW_SUMMARY_DIRECTORY\n```\n\nMaterialization checks every envelope, chunk, compressed payload and decoded hash, scans decoded text, and restores the logical relative tree. Unredacted files are byte-exact. Redacted files are marked in the manifest/index with separate original and materialized hashes; private original paths/endpoints and their reversible map remain outside the repository. Host-path substitutions change executable commands, source paths and traceback provenance. Explicit z3-solver 4.15.3.0 remains public under a narrow package-label exception. The changed-field audit in redaction-scope.json verifies that native compressed episode bytes and model request/response artifacts are unchanged; their policy/candidate/state/effect content and embedded hashes remain public. Source/qualification references in fixture metadata are redacted, so entry points need portable path rewiring. Public materialization and table reanalysis were verified; native simulator/audit replay with rewired paths was not rerun from this bundle. Exact original bytes of changed metadata/code still require private originals, but this is not a claim that semantic replay inherently requires private data. Native package installations, credentials, job input mirrors, and full downloaded literature pages are not shipped. Relevant frozen study code, cohorts, conditions, fixtures, per-case raw traces, response journals/caches, analysis outputs and operational failures are included.\n\nThe summarize command recomputes the published tables from restored raw result records and completed X1 effect-analysis rows; it performs no model calls or native side effects. The original X1 event extractor can also be rerun using the included cohort, branch manifest and compressed episodes. Native verification requires the pinned AgentDojo/Progent environment; no claim is made that a private machine environment is reconstructed from this bundle.\n''')


def main():
 p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
 b=sub.add_parser('build');b.add_argument('--jobs',type=Path,required=True);b.add_argument('--experiments',type=Path,required=True);b.add_argument('--review-source',type=Path,required=True);b.add_argument('--private-map',type=Path,required=True);b.add_argument('--out',type=Path,default=DEFAULT_OUT)
 v=sub.add_parser('verify');v.add_argument('--bundle',type=Path,default=DEFAULT_OUT)
 m=sub.add_parser('materialize');m.add_argument('--bundle',type=Path,default=DEFAULT_OUT);m.add_argument('--destination',type=Path,required=True)
 s=sub.add_parser('summarize');s.add_argument('--jobs',type=Path,required=True);s.add_argument('--destination',type=Path,required=True)
 a=p.parse_args()
 if a.command=='build':build(a)
 elif a.command=='verify':print(json.dumps(verify(a.bundle),indent=2))
 elif a.command=='materialize':
  assert not a.destination.exists();a.destination.mkdir(parents=True);print(json.dumps(verify(a.bundle,a.destination),indent=2))
 else:
  assert not a.destination.exists();a.destination.mkdir(parents=True);write_results(a.destination,derive(a.jobs));print(json.dumps({'summary_written':True}))
if __name__=='__main__':main()
