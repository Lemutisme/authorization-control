"""Native-state, policy and cost audit of every strong banking comparison case."""
import argparse,collections,csv,gzip,hashlib,importlib.util,json,os,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[os.environ['BASELINE_VENDOR'],str(ROOT/'evaluation'),str(ROOT/'evaluation/intent_guard')]
spec=importlib.util.spec_from_file_location('baseline_costs',ROOT/'scripts/summarize_baseline_audit.py');old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import text_content_block_from_string
ARMS=['none','pga_minimal','progent'];INFRA={'adapter_error','inference_error','episode_timeout','no_response'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def analyze(path,manifest_path,frozen,progent_source,policy_replay=None):
    data=json.loads(path.read_text());cfgpath=path.with_name('run-config.json');cfg=json.loads(cfgpath.read_text());manifest=json.loads(manifest_path.read_text());cases={c['case_id']:c for c in manifest['cases']}
    assert data['complete'] and len(data['rows'])==data['scheduled']==len(cfg['cases']) and {r['case_id'] for r in data['rows']}==set(cfg['cases']) and len(set(cfg['cases']))==len(cfg['cases'])
    assert data['run_config_sha256']==sha(cfgpath) and cfg['manifest_sha256']==sha(manifest_path)
    for n,h in cfg['source_sha256'].items():assert sha(frozen/'evaluation'/n)==h,(n,'source changed')
    for n,h in cfg['progent_source_sha256'].items():assert sha(progent_source/n)==h,(n,'Progent changed')
    suite=get_suite(manifest['version'],'banking');env_type=type(suite.load_and_inject_default_environment({}));tools={f.name:f for f in suite.tools}
    js="""import {readFileSync,readdirSync} from 'node:fs';import {join} from 'node:path';import {createHash} from 'node:crypto';
const root=process.argv[1],out={};for(const d of readdirSync(root,{withFileTypes:true})){if(!d.isDirectory())continue;let names;const dir=join(root,d.name,'actor-cache');try{names=readdirSync(dir)}catch{continue}
for(const n of names){if(!n.endsWith('.json'))continue;const x=JSON.parse(readFileSync(join(dir,n),'utf8'));const h=createHash('sha256').update(JSON.stringify(x.message)).digest('hex');out[d.name+'/'+n.slice(0,-5)]={valid:x.request_sha256===n.slice(0,-5)&&x.response_sha256===h,response_sha256:h,tools:x.message.content.filter(c=>c.type==='toolCall').length};}}
console.log(JSON.stringify(out));"""
    cache=json.loads(subprocess.check_output(['node','--input-type=module','-e',js,str(path.parent)],text=True))
    replay_summary=json.loads((policy_replay/'summary.json').read_text()) if policy_replay else None
    replay_this=replay_summary is not None and replay_summary['input_results_sha256']==sha(path)
    if replay_this:
        assert replay_summary['passed']==replay_summary['scheduled']==data['scheduled']
        assert replay_summary['source_sha256']==sha(ROOT/'scripts/replay_progent_policies.py')
        replay_rows={r['case_id']:r for r in replay_summary['rows']}
    findings=[];episodes=[];pair_rows=[];details=[];totalcost=collections.Counter()
    for pair in data['rows']:
        cid=pair['case_id'];case=cases[cid];assert case['suite']=='banking' and not case['profile_supported'];task=suite.get_injection_task_by_id(case['task_id']) if case['condition']=='goal_control' else suite.get_user_task_by_id(case['task_id'])
        raws={};seen={};checks={}
        for arm in ARMS:
            ep=pair['arms'][arm];folder=path.parent/cid;rawpath=folder/(arm+'.json.gz');journal=folder/(arm+'.policy-journal.jsonl');policy_calls=[];issues=[];state_changes=None;policy_checks=0
            if journal.exists():
                for line in journal.read_text().splitlines():
                    row=json.loads(line)
                    if row['stage']=='policy_response':policy_calls.append(row['response']['meta'])
            if rawpath.exists():
                raw=json.loads(gzip.decompress(rawpath.read_bytes()));raws[arm]=raw
                if raw['result']!=ep:issues.append('raw_summary_mismatch')
                if ep['manifest_sha256']!=sha(manifest_path) or ep['case_id']!=cid:issues.append('input_identity')
                initial=env_type.model_validate(raw['initial']);final=env_type.model_validate(raw['final']);outputs=[text_content_block_from_string(raw['final_response'])];calls=[FunctionCall.model_validate(c) for c in raw['proposed_calls']]
                utility=suite._check_task_result(task,outputs,initial.model_copy(deep=True),final.model_copy(deep=True),calls)
                if utility!=ep['native_utility']:issues.append('native_utility')
                if case['condition']=='attack':
                    asr=suite._check_injection_task_security(suite.get_injection_task_by_id(case['injection_id']),outputs,initial.model_copy(deep=True),final.model_copy(deep=True),calls)
                    if asr!=ep['native_targeted_asr']:issues.append('native_asr')
                if arm=='progent':
                    if policy_calls!=ep['policy_calls'] or not all(c.get('policy_instruction_preserved') for c in policy_calls):issues.append('policy_journal_or_instructions')
                    policies={old.digest(p['policy']):p['policy'] for p in raw['policy_history']}
                    if replay_this:
                        support=policy_replay/(cid+'.json');assert sha(support)==replay_rows[cid]['record_sha256'];restored=json.loads(support.read_text())
                        assert restored['raw_sha256']==sha(rawpath) and restored['journal_sha256']==sha(journal) and restored['passed']
                        policies=restored['policies'];assert all(old.digest(v)==k for k,v in policies.items())
                    for d in ep['progent_decisions']:
                        key=d['policy_before_sha256']
                        if key not in policies:issues.append('missing_policy_state');continue
                        if old.eligible(policies[key],d['operation']['function'],d['operation']['args'])!=d['allowed']:issues.append('mechanical_policy_decision')
                        policy_checks+=1
                elif ep['policy_calls']:issues.append('unexpected_policy_calls')
                changes=[e for e in raw['events'] if e['entry_state_changed']];state_changes=len(changes)
                for event in changes:
                    if arm=='none':continue
                    op=event['operation'];normalized=tools[op['function']].parameters.model_validate(op['args']).model_dump(mode='json')
                    decisions=ep['progent_decisions'] if arm=='progent' else ep['guard_decisions']
                    if not any(d['operation']['function']==op['function'] and d['operation']['args']==normalized and (d.get('allowed') is True if arm=='progent' else d.get('decision')=='allow') for d in decisions):issues.append('state_change_without_permission')
                # Pi serializes JSON through JavaScript: e.g. 100.0 becomes
                # 100. Restore the declared native types before comparing the
                # broker's pre-serialization state hash.
                if ep['initial_state_sha256']!=old.digest(initial.model_dump(mode='json')):issues.append('initial_hash')
            else:issues.append('missing_raw')
            for call in ep.get('pi',{}).get('calls',[]):
                x=call.get('coupling',{});k=x.get('request_sha256');v=x.get('response_sha256');c=cache.get(cid+'/'+str(k))
                if not k or not v or x.get('cache_error') or k in seen and seen[k]!=v:issues.append('actor_coupling')
                seen[k]=v
                if not c or not c['valid'] or c['response_sha256']!=v:issues.append('actor_cache')
                if c and arm=='progent' and c['tools']>1:issues.append('policy_update_batch')
                if call.get('requested_model')!='gpt-6-luna':issues.append('actor_model')
                if x.get('cache_hit') and (call.get('actual_network_call') or call.get('provider_usage') is not None):issues.append('actor_double_charge')
            for call in policy_calls+ep.get('guard_calls',[]):
                if call.get('requested_model')!='gpt-6-luna':issues.append('review_model')
            cost=old.costs(ep,policy_calls)
            if ep.get('usage_unknown'):cost['episodes_with_unknown_usage']=1
            totalcost.update(cost)
            row={'case_id':cid,'task_id':case['task_id'],'condition':case['condition'],'arm':arm,'status':ep['status'],'native_utility':ep.get('native_utility'),'native_targeted_asr':ep.get('native_targeted_asr'),'audit_valid':not issues,'outcome_complete':ep['status'] not in INFRA,'raw_sha256':sha(rawpath) if rawpath.exists() else None,'policy_journal_sha256':sha(journal) if journal.exists() else None,'actual_state_changing_events':state_changes,'mechanical_policy_checks':policy_checks,'policy_snapshots':len(raws.get(arm,{}).get('policy_history',[])),'policy_changes':sum(old.digest(x['policy'])!=old.digest(y['policy']) for x,y in zip(raws.get(arm,{}).get('policy_history',[]),raws.get(arm,{}).get('policy_history',[])[1:])),'denials':sum(not d['allowed'] for d in ep.get('progent_decisions',[])) if arm=='progent' else sum(d['decision']!='allow' for d in ep.get('guard_decisions',[])),'cost':cost}
            episodes.append(row);checks[arm]=row
            if issues:findings.append({'case_id':cid,'arm':arm,'issues':sorted(set(issues))})
        if len(raws)==3:
            if any(raws[a]['initial']!=raws['none']['initial'] or raws[a]['prompt']!=raws['none']['prompt'] or pair['arms'][a]['pi']['registered_tools']!=pair['arms']['none']['pi']['registered_tools'] for a in ARMS):findings.append({'case_id':cid,'issues':['initial_prompt_or_tools_differ']})
        valid=all(checks[a]['audit_valid'] and checks[a]['outcome_complete'] for a in ARMS) and pair['pair_valid']
        pair_rows.append({'case_id':cid,'task_id':case['task_id'],'condition':case['condition'],'valid_complete':valid,**{a+'_utility':checks[a]['native_utility'] for a in ARMS},**{a+'_asr':checks[a]['native_targeted_asr'] for a in ARMS}})
        if valid and len({checks[a]['native_utility'] for a in ARMS})>1 or valid and case['condition']=='attack' and len({checks[a]['native_targeted_asr'] for a in ARMS})>1:
            details.append({'case_id':cid,'condition':case['condition'],'arms':{a:{'utility':checks[a]['native_utility'],'asr':checks[a]['native_targeted_asr'],'raw_sha256':checks[a]['raw_sha256'],'policy_snapshots':checks[a]['policy_snapshots'],'policy_changes':checks[a]['policy_changes'],'denials':checks[a]['denials'],'state_changes':checks[a]['actual_state_changing_events']} for a in ARMS}})
    groups={};contrasts=[]
    for condition in ['clean','attack','goal_control']:
        groups[condition]={}
        for arm in ARMS:
            es=[e for e in episodes if e['condition']==condition and e['arm']==arm];c=collections.Counter()
            for e in es:c.update(e['cost'])
            metrics={}
            for key in ['native_utility']+(['native_targeted_asr'] if condition=='attack' else []):
                pos=sum(e[key] is True and e['audit_valid'] for e in es);unknown=sum(not e['audit_valid'] or e[key] is None or not e['outcome_complete'] and e[key] is not True for e in es)
                metrics[key]={'positive':pos,'n':len(es),'unknown_or_incomplete':unknown,'all_case_bounds':[pos/len(es),(pos+unknown)/len(es)] if es else None}
            groups[condition][arm]={'metrics':metrics,'statuses':dict(collections.Counter(e['status'] for e in es)),'cost':dict(c)}
        ps=[r for r in pair_rows if r['condition']==condition]
        for reference,candidate in [('none','pga_minimal'),('none','progent'),('progent','pga_minimal')]:
            good=[r for r in ps if r['valid_complete']];contrasts.append({'condition':condition,'reference':reference,'candidate':candidate,'n':len(ps),'valid_pairs':len(good),'utility_gains':[r['case_id'] for r in good if r[candidate+'_utility'] is True and r[reference+'_utility'] is False],'utility_losses':[r['case_id'] for r in good if r[candidate+'_utility'] is False and r[reference+'_utility'] is True],'reference_only_asr':[r['case_id'] for r in good if r[reference+'_asr'] is True and r[candidate+'_asr'] is False],'candidate_only_asr':[r['case_id'] for r in good if r[reference+'_asr'] is False and r[candidate+'_asr'] is True]})
    metrics={'cases':len(pair_rows),'invalid_or_incomplete':sum(not p['valid_complete'] for p in pair_rows),'audit_findings':len(findings)}
    for condition in groups:
        for arm,g in groups[condition].items():
            for key,v in g['metrics'].items():metrics[condition+'_'+arm+'_'+key]=v['positive']
    return {'job':path.parent.parent.name,'scheduled':data['scheduled'],'complete':data['complete'],'elapsed_s':data['elapsed_s'],'metrics':metrics,'groups':groups,'contrasts':contrasts,'audit_findings':findings,'total_actual_cost':dict(totalcost),'policy_replay_summary_sha256':sha(policy_replay/'summary.json') if replay_this else None,'input_sha256':{'results':sha(path),'config':sha(cfgpath),'manifest':sha(manifest_path)},'episodes':episodes,'pairs':pair_rows,'discordances':details}
def main():
    p=argparse.ArgumentParser();p.add_argument('--runs',nargs='+',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--frozen',type=Path,required=True);p.add_argument('--progent',type=Path,required=True);p.add_argument('--policy-replay',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True);reports=[]
    for path in a.runs:
        r=analyze(path,a.manifest,a.frozen,a.progent,a.policy_replay)
        for field in ['episodes','pairs']:
            rows=r.pop(field);target=a.out/(r['job']+'-'+field+'.csv')
            with target.open('w',newline='') as f:
                w=csv.DictWriter(f,fieldnames=sorted({k for row in rows for k in row}),lineterminator='\n');w.writeheader();w.writerows({k:json.dumps(v,sort_keys=True) if isinstance(v,(dict,list)) else v for k,v in row.items()} for row in rows)
            r[field+'_csv_sha256']=sha(target)
        save(a.out/(r['job']+'-metrics.json'),r['metrics']);reports.append(r)
    save(a.out/'summary.json',{'kind':'Complete original-Progent/PGA-minimal banking development comparison','analysis_source_sha256':sha(Path(__file__)),'runs':reports,'limits':['Pi/Luna adaptation; not reproduction of published model scores.','Same actor/task/state, but complete policy inference mechanisms and budgets differ; measured costs do not isolate any one component.','Native labels are supplemented by state-changing-effect checks, not a new complete owner-intent oracle.','All banking tasks already used in development; task/attack combinations are correlated. No population or heldout superiority claim.']})
    print(json.dumps([{'job':r['job'],'metrics':r['metrics'],'contrasts':r['contrasts'],'cost':r['total_actual_cost']} for r in reports],indent=2))
if __name__=='__main__':main()
