"""Read-only treatment/input checks on retained live outputs; no inference."""
from pathlib import Path
import argparse, json, re

ARMS = ['f0_u0', 'f0_u1', 'f1_u0', 'f1_u1', 'f0_off', 'f1_off']

def audit(folder):
    rows = {a: json.loads((folder / (a+'.json')).read_text()) for a in ARMS}
    failures = []
    def check(name, condition):
        if not condition: failures.append(name)
    first = {a: r['factorial_first_refusal'] for a,r in rows.items()}
    ref = first['f0_u0']
    for a,r in rows.items():
        f = first[a]
        check(a+':source_exact', r['source_actor_replay']['replayed_original_proposal'] is True)
        check(a+':same_initial_policy', f['decision_policy'] == ref['decision_policy'])
        check(a+':same_pending_call', f['proposal'] == ref['proposal'])
        check(a+':same_native_state', f['native_state_before_sha256'] == ref['native_state_before_sha256'])
        check(a+':refusal_no_effect', f['refusal_state_unchanged'] is True)
        check(a+':initial_denied', f['same_call_before_update'].get('known') is True and f['same_call_before_update'].get('allowed') is False)
        check(a+':cumulative_caps', r['factorial_resources']['actor_budget_slots'] <= 16 and r['factorial_resources']['total_policy_budget_slots'] <= 64)
        update=f['update']
        if a.endswith('off'):
            check(a+':skip_only_refusal', update['status']=='skipped' and update['actual_requests']==0)
        else:
            check(a+':forced_regeneration', update['kind']=='forced_refusal_regeneration' and update['selector_model_calls']==0)
            expected=[{'name':f['proposal']['name'],'args':f['proposal']['args']}] if a.endswith('u1') else []
            check(a+':proposal_visibility', update['public_call_params']==expected)
            check(a+':unchanged_result',update['tool_result']=="['']")
    for u in ['u0','u1']:
        a,b='f0_'+u,'f1_'+u
        check(u+':first_update_wire_identical_across_F',rows[a]['policy_calls'][0]['request_json']==rows[b]['policy_calls'][0]['request_json'])
        check(u+':first_installed_policy_identical_across_F',first[a]['policy_after_update']==first[b]['policy_after_update'])
    def hide_params(context):
        x=json.loads(context)
        for message in x['messages']:
            if isinstance(message.get('content'),str):
                message['content']=re.sub(r'(?<=\nTOOL_CALL_PARAM: ).*?(?=\nTOOL_CALL_RESULT:)', '[]', message['content'], flags=re.S)
        return x
    check('U_changes_only_proposal_field', hide_params(rows['f0_u0']['policy_calls'][0]['context_json'])==hide_params(rows['f0_u1']['policy_calls'][0]['context_json']))
    for f in ['f0','f1']:
        check(f+':actor_feedback_identical_across_U',first[f+'_u0']['actor_feedback']==first[f+'_u1']['actor_feedback']==first[f+'_off']['actor_feedback'])
    if not ref['feedback_detail']['constraint_available']:
        check('unavailable_constraint_feedback_identical',first['f0_u0']['actor_feedback']==first['f1_u0']['actor_feedback'])
    else:
        x,y=first['f0_u0']['feedback_detail'],first['f1_u0']['feedback_detail']
        check('F_same_prefix_suffix',x['common_prefix']==y['common_prefix'] and x['common_suffix']==y['common_suffix'])
    return {'unit':folder.parent.name,'failures':failures,'passed':not failures}

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--report',type=Path,required=True);args=p.parse_args()
    results=[]
    for folder in sorted(args.out.glob('*/repetition-*')):
        try: results.append(audit(folder))
        except Exception as e: results.append({'unit':folder.parent.name,'passed':False,'failures':[type(e).__name__+': '+str(e)]})
    report={'units':len(results),'passed':sum(r['passed'] for r in results),'rows':results}
    args.report.parent.mkdir(parents=True,exist_ok=True);args.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='rows'}))

if __name__=='__main__':main()
