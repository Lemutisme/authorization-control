#!/usr/bin/env python3
"""Read retained full-run artifacts; do not execute a task, model or evaluator."""
import argparse,gzip,hashlib,json
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('--runs',type=Path,nargs='+',required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();arms=[]
for root in a.runs:
    data=json.loads((root/'result.json').read_text());rows={r['case_id']:r for r in data['rows']}
    result={'arm':data['arm'],'scheduled_rows':len(rows),'raw_archives':0,'missing_raw':[],
        'pi_broker_trace_equal':0,'trace_differences':[],'unsupported_pga_rows':0,
        'unsupported_pga_unchanged_no_invocations':0,'unsupported_pga_state_exceptions':[],
        'native_asr_true_rows':[],'clean_success_no_invocations':[],'goal_success_no_invocations':[]}
    identities={}
    for cid,row in rows.items():
        path=root/(cid+'.json.gz')
        if not path.exists():result['missing_raw'].append({'case_id':cid,'status':row['status']});continue
        identities[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        with gzip.open(path,'rt') as f:raw=json.load(f)
        assert raw['result']['case_id']==cid
        for key in ['native_utility','native_targeted_asr','status','profile_supported']:assert raw['result'][key]==row[key],(cid,key)
        result['raw_archives']+=1
        pi=[{'function':e['name'],'args':e.get('args')} for e in raw['pi_tool_events'] if e['type']=='tool_execution_start']
        broker=[{'function':e['function'],'args':e['args']} for e in raw['proposed_calls']]
        if pi==broker:result['pi_broker_trace_equal']+=1
        else:result['trace_differences'].append({'case_id':cid,'pi_proposals':len(pi),'broker_proposals':len(broker),'same_length':len(pi)==len(broker)})
        unchanged=raw['initial']==raw['final'];zero=row['native_invocations']==0 and not raw['events']
        if data['arm']=='pga' and not row['profile_supported']:
            result['unsupported_pga_rows']+=1
            if unchanged and zero:result['unsupported_pga_unchanged_no_invocations']+=1
            else:result['unsupported_pga_state_exceptions'].append(cid)
        detail={'case_id':cid,'native_invocations':row['native_invocations'],'tool_proposals':row['tool_proposals'],
            'events':len(raw['events']),'unchanged_snapshot':unchanged}
        if row['native_targeted_asr'] is True:result['native_asr_true_rows'].append(detail)
        if row['native_utility'] is True and zero:
            if row['condition']=='clean':result['clean_success_no_invocations'].append(detail)
            elif row['condition']=='goal_control':result['goal_success_no_invocations'].append(detail)
    result['raw_archive_sha256']=identities;arms.append(result)
a.out.parent.mkdir(parents=True,exist_ok=True)
report={'kind':'post-measurement read-only trace/state audit, no new agent episodes or native rescoring','arms':arms,
    'limits':['Equality of recorded tool traces is not a complete confidentiality/effect audit.',
        'No-op successes can be intentional; native utility labels remain unchanged.',
        'Native trace ASR and invoked effects must not be conflated.']}
a.out.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps([{k:v for k,v in arm.items() if k!='raw_archive_sha256'} for arm in arms],indent=2))
