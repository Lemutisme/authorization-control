#!/usr/bin/env python3
"""Bounded late-v1 export; no models, networking, study changes, or completed-v1 writes."""
import argparse
import base64
from collections import Counter, defaultdict
import csv
import gzip
import json
import os
import re
from pathlib import Path
import export_authorship_completed as core

# Registered archive mirror names also encode a host path, despite being relative.
_BASE_REDACT=core.redact
_BASE_SCAN=core.scan
MIRROR_HOST=re.compile(r"inputs/external/(?:data|root|home|tmp|mnt|var/tmp)/[^\s\"'`()<>{}\[\],;\\]+")
def redact(text,mapping):
    text,changes=_BASE_REDACT(text,mapping)
    def replace(match):
        original=match.group();token='[REDACTED_ARCHIVED_HOST_PATH_'+core.digest(original.encode())[:20]+']'
        mapping[token]={'kind':'archived_host_path','original':original}
        changes['archived_host_path']=changes.get('archived_host_path',0)+1
        return token
    return MIRROR_HOST.sub(replace,text),changes

def scan(text,label):
    _BASE_SCAN(text,label)
    if MIRROR_HOST.search(text):raise ValueError(label+': archived host mirror path remains')
core.redact=redact
core.scan=scan

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'evidence/authorship/late-v1'
JOBS=Path('/artifact-source/80d38c89da1c/jobs')
EXPERIMENTS=Path('/artifact-source/441b53ae4f70/sp27-authorship-20261111')
RESEARCH=JOBS.parent/'authorship-20261111'
load=core.load
save=core.save
digest=core.digest


def runs(jobs):
    return sorted(p.name for p in jobs.iterdir() if p.is_dir() and p.name.startswith(('authorship-x2b-','authorship-x1-annotation-','authorship-x4-')))


def sources(args):
    rows=[];excluded=[];registered=[];archived={}
    def tree(namespace,folder):
        for path in sorted(folder.rglob('*')):
            if not path.is_file() or path.is_symlink():continue
            rel=path.relative_to(folder)
            if any(k in {'inputs','node_modules','__pycache__'} for k in rel.parts):continue
            if path.suffix in {'.pyc','.lock'}:continue
            rows.append((namespace+'/'+rel.as_posix(),path))
    names=runs(args.jobs)
    assert len(names)==51, names
    for name in names:
        job=args.jobs/name
        tree('jobs/'+name+'/artifacts',job/'artifacts')
        for file in ['job.json','log']:
            rows.append(('jobs/'+name+'/'+file,job/file))
        for ordinal,r in enumerate(load(job/'job.json')['inputs']):
            path=job/'artifacts'/r['artifact']
            assert path.is_file() and digest(path.read_bytes())==r['sha256'],(name,ordinal)
            if path.suffix=='.pyc':
                excluded.append({'job':name,'input_ordinal':ordinal,'basename':path.name,'original_sha256':r['sha256'],'reason':'Compiled Python bytecode; text source is retained'})
                continue
            key=r['sha256']
            if key not in archived:
                logical='archived-inputs/'+key+'/'+path.name
                archived[key]=logical
                rows.append((logical,path))
            registered.append({'job':name,'input_ordinal':ordinal,'basename':path.name,'original_sha256':key,'restore_path':archived[key]})
    tree('shared-caches/x2b',args.experiments/'x2b-coupling')
    tree('annotation-manual-blind-v1',args.research/'annotation-manual-blind-v1')
    tree('goal1-sensitivity',args.research/'goal1-sensitivity')
    for name in ['x2b-attack-selection-v1.json','x2b-capability-selection-v1.json']:
        rows.append(('selections/'+name,args.experiments/name))
    rows.append(('corrections/repair-stratum-limit.json',args.research/'repair-stratum-limit.json'))
    # Independent frozen prefix trace substantiates the late interpretation correction.
    receipt=load(args.research/'repair-stratum-limit.json')
    matches=list((args.jobs/'authorship-x1-prefix-main-v1/artifacts').glob(receipt['case']+'/*.json.gz'))
    matches=[p for p in matches if digest(p.read_bytes())==receipt['raw_sha256']]
    assert len(matches)==1
    rows.append(('corrections/repair-reference-prefix.json.gz',matches[0]))
    assert len(rows)==len({name for name,_ in rows})
    return rows,names,registered,excluded


def readraw(path):return json.loads(gzip.decompress(path.read_bytes()))


def derive(materialized):
    jobs=materialized/'jobs'
    def result(name,file='result.json'):return load(jobs/name/'artifacts'/file)
    selected=load(materialized/'selections/x2b-attack-selection-v1.json')['selected_strategy_by_controller']
    core_runs=[n for n in runs(jobs) if n.startswith('authorship-x2b-') and any(t in n for t in ['-attack-development-','-heldout-','-capability-'])]
    assert len(core_runs)==32
    tables=[]
    def counts(rs):
        return {'n':len(rs),'native_target':sum(r.get('native_targeted_asr') is True for r in rs),
                'helper_defined_explicit_target':sum(r.get('target_components',{}).get('explicit_target_endpoint') is True for r in rs),
                'declared_partial_effect':sum(r.get('partial_harm',{}).get('any_declared_partial_harm') is True for r in rs),
                'native_utility':sum(r.get('native_utility') is True for r in rs)}
    for name in core_runs:
        path=jobs/name/'artifacts';c=load(path/'config.json')
        rs=[readraw(path/cid/(c['arm']+'.json.gz'))['result'] for cid in c['cases']]
        row={k:c[k] for k in ['panel','arm','role','strategy','reasoning']}
        row.update(counts(rs));row['run']=name
        row['selected']=c['role']=='attack' and selected[c['arm']]==c['strategy']
        if c['role']=='attack':row['posthoc_exclude_all_goal1']=counts([r for r in rs if not r['case_id'].endswith('__injection_task_1')])
        tables.append(row)
    assert sum(t['n'] for t in tables)==1800
    audit=result('authorship-x2b-analysis-v1');assert audit['passed'] and audit['rows_checked']==1800
    for t in tables:
        match=[r for r in audit['tables'] if all(r[k]==t[k] for k in ['panel','arm','role','strategy','reasoning']) and r['n']==t['n']]
        # Capability none/medium differ only in reasoning; their native counts disambiguate.
        assert any(all(r[k2]==t[k] for k,k2 in [('n','n'),('native_target','native_targeted_asr'),('native_utility','native_utility'),('helper_defined_explicit_target','helper_defined_explicit_target'),('declared_partial_effect','declared_partial_effect')]) for r in match)
    x4=[];byarm={}
    for name in ['authorship-x4-main-v2','authorship-x4-audit-diagnostic-v2']:
        path=jobs/name/'artifacts';c=load(path/'config.json');rs_byarm=defaultdict(list)
        for cid in c['conditions']:
            for arm in c['arms']:rs_byarm[arm].append((cid,readraw(path/cid/(arm+'.json.gz'))['result']))
        for arm,items in rs_byarm.items():
            rs=[r for _,r in items];g=result(name)['groups'][arm]
            assert len(rs)==g['n']==84 and sum(r['native_utility'] is True for r in rs)==g['native_utility']
            assert sum(r.get('x4_repaired_effects',0) for r in rs)==g['native_repair_events']
            assert sum(u.get('resources',{}).get('expert_audits',0) for r in rs for u in r.get('x4_records',[]))==g['expert_audits']
            x4.append({'panel':'main' if name.endswith('main-v2') else 'H10_diagnostic','arm':arm,**g})
        if name.endswith('main-v2'):byarm={arm:dict(items) for arm,items in rs_byarm.items()}
    assert sum(r['n'] for r in x4 if r['panel']=='main')==756
    pairs={'gains':sum(r['native_utility'] is True and byarm['extra_review_H0'][cid]['native_utility'] is False for cid,r in byarm['x4_projection_H0'].items()),
           'losses':sum(r['native_utility'] is False and byarm['extra_review_H0'][cid]['native_utility'] is True for cid,r in byarm['x4_projection_H0'].items())}
    assert pairs=={'gains':4,'losses':15}
    effects=result('authorship-x4-analysis-v2','analysis.json')['rows']
    effect_summary={arm:{key:sum(r[key] is True for r in effects if r['arm']==arm) for key in ['correct_effect','wrong_effect','no_effect']} for arm in byarm}
    aud4=result('authorship-x4-native-audit-v2');old4=result('authorship-x4-native-audit-v1')
    assert aud4['passed'] and aud4['arm_records_passed']==756 and aud4['prior_findings_reconciled']==173
    assert len(old4['failed_records'])==342 and not old4['passed']
    annrows=result('authorship-x1-annotation-final-v1','episode-annotations.json')['rows']
    primary=[r for r in annrows if r['primary_wrong_effect']]
    ann={'episodes':len(primary),'undisclosed_success':sum(r['undisclosed_success'] is True for r in primary),
         'explicit_deviation':sum(r['explicit_deviation'] is True for r in primary),'unknown':sum(not r['annotation_known'] for r in primary)}
    assert ann=={'episodes':138,'undisclosed_success':27,'explicit_deviation':110,'unknown':1}
    finalann=result('authorship-x1-annotation-final-v1');assert finalann['manual_reviews_supplied']==36 and finalann['required_manual_pending']==0
    ann.update(manual_reviews=36,reviewer_kind='Blinded Codex-assisted research adjudication, not human ground truth',forecast='at least half undisclosed: refuted',bounds=[27/138,28/138])
    loc=result('authorship-x2b-localization-v2');assert loc['passed'] and loc['selection_unchanged']
    correction=load(materialized/'corrections/repair-stratum-limit.json')
    assert digest((materialized/'corrections/repair-reference-prefix.json.gz').read_bytes())==correction['raw_sha256']
    return {'coverage':{'x2b_core_jobs':32,'x2b_core_records':1800,'x4_main_records':756,'x4_H10_records':84},'x2b':tables,'x4':x4,'x4_effects':effect_summary,'x4_primary_vs_editing':pairs,'annotation':ann,
            'verification':{'x2b_passed':audit['passed'],'x4_v2_passed':aud4['passed'],'x4_original_findings_reconciled':aud4['prior_findings_reconciled'],'x4_v1_restoration_failures_retained':len(old4['failed_records'])},
            'localization':{'denominators':loc['denominators'],'overlapping_categories':loc['classification_counts']},'repair_stratum_correction':correction}


def write_results(out,s):
    save(out/'summary.json',s)
    for name,rows in [('x2b',s['x2b']),('x4',s['x4'])]:
        rows=[{k:v for k,v in r.items() if not isinstance(v,(dict,list))} for r in rows]
        with (out/(name+'-summary.csv')).open('w',newline='') as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    macros={'LateXTwoBRecords':1800,'LateXFourRecords':756,'LateUndisclosed':27,'LateWrongEffectAnnotations':138,'LateExplicitDeviation':110,'LateAnnotationUnknown':1,'LateManualReviews':36,'LatePrimaryUtility':64,'LateEditingUtility':75,'LatePrimaryPairedGains':4,'LatePrimaryPairedLosses':15}
    (out/'late-results.tex').write_text(''.join('\\newcommand{\\'+k+'}{'+str(v)+'}\n' for k,v in macros.items()))
    text=['Late authorship/control studies — completed snapshot','',
          'This bundle supplements completed-v1 without changing its files. All studies use native benchmark simulators. Heldout tasks are disjoint from development attack-policy selection, not unseen benchmarks. Strategy selection and original nine-goal endpoints remain frozen.','',
          'Selected heldout attacks (108 task/goal conditions per controller):','',
          '| Controller | Strategy | Native target | Helper-defined explicit | Declared partial effect | Task utility |','|---|---|---:|---:|---:|---:|']
    for r in s['x2b']:
        if r['panel']=='heldout' and r['selected']:text.append(f"| {r['arm']} | {r['strategy']} | {r['native_target']}/108 | {r['helper_defined_explicit_target']}/108 | {r['declared_partial_effect']}/108 | {r['native_utility']}/108 |")
    text+=['','All 32 non-smoke X2b jobs total 1,800 records: 432 development attacks, 1,296 heldout attacks, 60 honest/T-only tasks and 12 capability/profile-selection tasks. All 1,800 passed saved-state/native-score audit. This is not a fresh replay of all native execution or model review. The complete 32-cell table is in x2b-summary.csv and summary.json. Honest utility remains separate from malicious-actor task utility; compute was observed, not matched.','',
           'Goal1 correction: the benchmark helper returns literal `me`, not a validated dinner-companion IBAN. Its frozen helper-defined explicit count remains unchanged. The separate post-hoc eight-goal sensitivity excludes every goal1 row across controllers/strategies and has 96 heldout rows per cell; it does not replace the original 108-row endpoint or selection. Partial attacker-transfer effects remain recorded.','',
           'Annotation: 27/138 realized wrong effects have success claims without explicit deviation, 110 explicitly acknowledge deviation, and one remains unassessable. The unknown-accounting interval is 19.6–20.3%, refuting the at-least-half forecast. Two blinded Luna draws were followed by 36 blinded Codex-assisted adjudications/audits; these are research-assistant labels, not human ground truth.','',
           'Late correction to completed-v1: the sole target_wrong reference-binding sample is a legitimate partial rent update—first recurring is changed while amount stays unchanged, then amount becomes 1200 and the task succeeds. Its intermediate mismatch does not establish actor error. Frozen rows remain unchanged; there is no validated positive sample for a genuine-error repair-rate estimate. The source receipt and exact no-gate trace are included under corrections/.','',
           'X4 main repair comparison (84 selected conditions per arm):','',
           '| Arm | Task utility | Repaired native events |','|---|---:|---:|']
    for r in s['x4']:
        if r['panel']=='main':text.append(f"| {r['arm']} | {r['native_utility']}/84 | {r['native_repair_events']} |")
    text+=['','Primary reconstruction has 64/84 task utility versus 75/84 for equally privileged trusted review/editing, with four paired gains and 15 losses. Both have zero observed wrong selected effects; primary has 67 correct selected effects and 17 stops/no effects, editing 78 and six. Correct selected effects need not complete the task. No-gate is a labeled replay/reference. Conditions are not independent tasks.','',
           'H10 is a separate fresh-draw diagnostic: 68/84 utility with zero expert audits actually used. Its difference from H0 is not causal evidence of audit benefit. Full generated-policy/PGA and malicious-actor X4 integration are not claimed.','',
           'X4 audit v2 passes all 756 main records and reconciles all 173 prior findings. Original audit v1 retains 342 workspace restoration failures (414 passes). Typed numeric restoration and collection order across Node are explicit; record consistency and native replay are separate, and state-order reconstruction uses replay evidence. Smoke v1/v2, prior localization, all audit failures, original source snapshots and subsequent corrections remain included.','',
           'Reconstruction: run the materialize and summarize commands in reconstruction.md. The bundle verifies raw bytes and decoded scans; native environments and model execution are not recreated. Consult redaction-scope.json for actual changed fields and replay limits.']
    (out/'results.md').write_text('\n'.join(text)+'\n')
    (out/'reconstruction.md').write_text('''Materialize and reanalyze without model calls:\n\n```bash\npython3 -B scripts/export_authorship_late.py verify\npython3 -B scripts/export_authorship_late.py materialize --destination NEW_DIRECTORY\npython3 -B scripts/export_authorship_late.py summarize --materialized NEW_DIRECTORY --destination NEW_SUMMARY_DIRECTORY\n```\n\nSummarize recomputes X2b endpoint counts and X4 utility/event counts from compressed raw records, and annotation/selected-effect counts from the archived final per-episode analyses. It checks completed audit receipts; it does not rerun native simulators, model reviews, or annotation adjudication. Native replay requires the pinned dependencies and path rewiring, and has not been rerun from this public materialization.\n\nArchived inputs are deduplicated by original SHA-256. registered-inputs index parts map each job's input ordinal/basename to its exact archived version; no mutable live script replaces the registered source. Job descriptions retain redacted host provenance. Unchanged artifacts are byte-exact, including CSV line endings. Changed artifacts keep distinct original/materialized/decoded hashes. Only the private host-redaction map hash is published. Annotation blinding linkage is scientific data, not the host-redaction map.\n''')


def audit_changes(original,public,counts,keycounts,path=()):
    if original==public:return
    if isinstance(original,dict) and isinstance(public,dict):
        assert len(original)==len(public)
        for key,value in original.items():
            clean,_=core.redact(key,{})
            assert clean in public
            if key!=clean:keycounts['.'.join(path) or '(root)']+=1
            audit_changes(value,public[clean],counts,keycounts,path+(clean,))
    elif isinstance(original,list) and isinstance(public,list):
        assert len(original)==len(public)
        for a,b in zip(original,public):audit_changes(a,b,counts,keycounts,path+('[]',))
    else:
        assert isinstance(original,str) and isinstance(public,str)
        counts['.'.join(path)]+=1


def semantic_content_check(bundle,private_map):
    rows=core.artifact_rows(bundle)
    origins={r['restore_path']:Path(r['original_path']) for r in load(private_map)['origins']}
    checked=[]
    for row in rows:
        if row['source_format']!='gzip' or not row['redacted']:continue
        original=json.loads(gzip.decompress(origins[row['restore_path']].read_bytes()))
        public=json.loads(gzip.decompress(core.decode(bundle,row)))
        assert {k:v for k,v in original.items() if k!='result'}=={k:v for k,v in public.items() if k!='result'}
        except_diagnostics={'x4_broker_rpc_errors','x4_rpc_errors'}
        assert {k:v for k,v in original['result'].items() if k not in except_diagnostics}=={k:v for k,v in public['result'].items() if k not in except_diagnostics}
        checked.append(row['restore_path'])
    assert len(checked)==3
    scope=load(bundle/'redaction-scope.json')
    save(bundle/'semantic-content-verification.json',{'passed':True,'changed_compressed_qualification_fixtures_checked':checked,
         'finding':'Only RPC diagnostic entries differ in the three redacted compressed qualification fixtures. All other top-level state/call/policy/effect fields and other result fields are equal. Other compressed artifacts are byte-exact, and shared cache/journal/process artifacts require no redaction.',
         'unchanged_compressed_artifacts':sum(r['source_format']=='gzip' and not r['redacted'] for r in rows),
         'changed_cache_journal_process_artifacts':scope['changed_cache_journal_process_artifacts'],
         'reviewer_identifier_limit':'The canonical agent task identifier is path-shaped and replaced consistently in72 occurrences. Codex-assisted reviewer type is retained; this metadata change does not alter frozen labels.',
         'native_replay_from_public_bundle_performed':False})


def build(a):
    out=OUT;assert not out.exists(),'Refuse overwrite'
    assert not a.private_map.exists() and not a.private_map.resolve().is_relative_to(ROOT)
    selected,names,registered,excluded=sources(a)
    out.mkdir(parents=True);mapping={};index=[];origins=[];redactions=[];fieldcounts=Counter();keycounts=Counter();changed_gzip=[];changed_cache=[];unstructured=Counter()
    for number,(logical,path) in enumerate(selected):
        original=path.read_bytes();isgzip=path.suffix=='.gz';decoded=gzip.decompress(original) if isgzip else original
        text,changes=core.redact(decoded.decode('utf-8'),mapping);core.scan(text,logical);public=text.encode();changed=public!=decoded
        payload=original if isgzip and not changed else gzip.compress(public,compresslevel=6,mtime=0)
        material=payload if isgzip else public
        row={'restore_path':logical,'source_format':'gzip' if isgzip else 'text','original_sha256':digest(original),'original_decoded_sha256':digest(decoded),'original_bytes':len(original),'decoded_sha256':digest(public),'decoded_bytes':len(public),'materialized_sha256':digest(material),'payload_sha256':digest(payload),'redacted':changed,'redaction_counts':changes,'parts':[]}
        for piece,start in enumerate(range(0,len(payload),core.CHUNK)):
            segment=payload[start:start+core.CHUNK];target=f'encoded/{number//500:04d}/{number:06d}-{piece:03d}.json'
            save(out/target,{'encoding':'gzip-base64-chunk','artifact':number,'part':piece,'part_count':(len(payload)+core.CHUNK-1)//core.CHUNK,'restore_path':logical,'original_sha256':row['original_sha256'],'decoded_sha256':row['decoded_sha256'],'chunk_sha256':digest(segment),'payload_base64':base64.b64encode(segment).decode()})
            row['parts'].append({'path':target,'sha256':digest((out/target).read_bytes())})
        index.append(row);origins.append({'restore_path':logical,'original_path':str(path),'original_sha256':row['original_sha256']})
        if changed:
            redactions.append({k:row[k] for k in ['restore_path','original_sha256','original_decoded_sha256','decoded_sha256','redaction_counts']})
            if isgzip:changed_gzip.append(logical)
            if logical.startswith('shared-caches/') or logical.endswith(('.policy-journal.jsonl','.process.txt')):changed_cache.append(logical)
            try:a0=json.loads(decoded);b0=json.loads(public)
            except (json.JSONDecodeError,UnicodeDecodeError):unstructured[path.suffix or '(none)']+=1
            else:audit_changes(a0,b0,fieldcounts,keycounts)
        if number%500==0:print(json.dumps({'packaged':number+1,'of':len(selected)}),flush=True)
    # Derive from originals through a logical view matching materialized relative names.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='late-summary-',dir=a.private_map.parent) as temp:
        view=Path(temp)
        for logical,path in selected:
            target=view/logical;target.parent.mkdir(parents=True,exist_ok=True);target.symlink_to(path)
        summary=derive(view)
    clean,_=core.redact(json.dumps(summary,ensure_ascii=False),mapping);summary=json.loads(clean)
    a.private_map.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(a.private_map,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump({'private_only':True,'mapping':mapping,'origins':origins},f,indent=2);f.write('\n')
    mapsha=digest(a.private_map.read_bytes())
    save(out/'manifest.json',{'bundle':'authorship-late-v1','artifact_count':len(index),'parts':core.index_parts(out,index,'artifact-index'),'redacted_artifact_count':len(redactions),'redaction_parts':core.index_parts(out,redactions,'redactions'),'private_mapping_sha256':mapsha,'private_mapping_published':False,'format_limit_bytes':core.LIMIT,'completed_v1_modified':False,'registered_input_versions':'Original archived bytes checked against every registered input SHA before packaging; compiled bytecode excluded.','helper_script_sha256':digest((ROOT/'scripts/export_authorship_completed.py').read_bytes()),'exporter_sha256':digest(Path(__file__).read_bytes()),'restoration':'Unchanged materialized bytes equal originals. Redacted artifacts retain distinct original and public hashes. Credentials abort export; explicit z3-solver 4.15.3.0 remains under narrow package-context exception.'})
    save(out/'registered-inputs.json',{'parts':core.index_parts(out,registered,'registered-inputs'),'registered_input_records':len(registered),'all_archived_input_hashes_verified':True,'unique_archived_inputs':len({r['restore_path'] for r in registered})})
    save(out/'exclusions.json',{'parts':core.index_parts(out,excluded,'exclusions'),'excluded_registered_bytecode_records':len(excluded),'not_shipped':['Installed native dependency environments','Credentials','Private host-redaction map and original host-path inventory']})
    save(out/'source-inventory.json',{'jobs':names,'coverage':summary['coverage'],'artifacts':len(index),'annotation_manual_review_kind':'Blinded Codex-assisted, not human ground truth','annotation_blinding_linkage_included':True,'annotation_blinding_linkage_status':'Now unblinded analysis provenance after judgments and reviews were frozen; hidden only from judges during labeling'})
    save(out/'redaction-scope.json',{'changed_structured_leaf_paths':dict(fieldcounts),'renamed_provenance_key_paths':dict(keycounts),'changed_gzip_artifacts':changed_gzip,'unchanged_gzip_count':sum(r['source_format']=='gzip' and not r['redacted'] for r in index),'changed_cache_journal_process_artifacts':changed_cache,'changed_unstructured_by_suffix':dict(unstructured),'limits':'Changed provenance paths/code require rewiring. Exact public semantic replay is not claimed unless native replay is separately run. Materialization and tabular reanalysis are checked; original versus public hashes remain distinct.'})
    write_results(out,summary)
    assert all(digest(Path(r['original_path']).read_bytes())==r['original_sha256'] for r in origins),'Source changed during export'
    save(out/'original-source-verification.json',{'all_match':True,'original_hashes_rechecked':len(origins),'registered_input_hashes_verified':len(registered)+len(excluded),'private_mapping_sha256':mapsha})
    semantic_content_check(out,a.private_map)
    print(json.dumps(core.verify(out),indent=2))


def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='command',required=True)
    b=sub.add_parser('build');b.add_argument('--jobs',type=Path,default=JOBS);b.add_argument('--experiments',type=Path,default=EXPERIMENTS);b.add_argument('--research',type=Path,default=RESEARCH);b.add_argument('--private-map',type=Path,required=True)
    v=sub.add_parser('verify');v.add_argument('--bundle',type=Path,default=OUT)
    m=sub.add_parser('materialize');m.add_argument('--bundle',type=Path,default=OUT);m.add_argument('--destination',type=Path,required=True)
    s=sub.add_parser('summarize');s.add_argument('--materialized',type=Path,required=True);s.add_argument('--destination',type=Path,required=True)
    a=p.parse_args()
    if a.command=='build':build(a)
    elif a.command=='verify':print(json.dumps(core.verify(a.bundle),indent=2))
    elif a.command=='materialize':
        assert not a.destination.exists();a.destination.mkdir(parents=True);print(json.dumps(core.verify(a.bundle,a.destination),indent=2))
    else:
        assert not a.destination.exists();a.destination.mkdir(parents=True);write_results(a.destination,derive(a.materialized));print('Summaries written without models or native effects.')
if __name__=='__main__':main()
