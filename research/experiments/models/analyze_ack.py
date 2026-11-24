"""Registered acknowledgement contrast on reopened calls, with negative controls."""
import argparse,gzip,json
from pathlib import Path
from analyze import contrast
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',default='analysis-ack');p.add_argument('--protocol',default='ack-protocol.json');p.add_argument('--run',default='recovery-ack-main-v1');p.add_argument('--controls',default='review_complete,stale_refusal');a=p.parse_args();protocol=json.loads((HERE/a.protocol).read_text());rows=[]
    arms=list(dict.fromkeys(r['arm'] for r in protocol['rows']));controls=a.controls.split(',')
    for source in protocol['rows']:
        path=HERE/'outputs'/a.run/'raw'/(source['id']+'.json.gz')
        try:raw=json.loads(gzip.decompress(path.read_bytes()))
        except (OSError,ValueError):raw=None
        metrics=raw['metrics'] if raw else {k:None for k in ['correct_selected_effect','wrong_selected_effect','native_utility','native_goal','original_call_changed_state_normalized']}
        rows.append({'source':{**source,'repetition':0},'metrics':metrics,'present':raw is not None,'raw_path':str(path),'status':raw.get('status') if raw else 'missing'})
    result={'scheduled':len(rows),'observed':sum(r['present'] for r in rows),'counts':[],'contrasts':{},
            'scope':'Old outcome-selected sources, fixed post-update policy, fresh actor draws. No new policy generation; no general defense or prevalence claim.'}
    for model in ['luna','haiku']:
        for panel in ['honest_reopened','honest_still_refused','attack_admitted']:
            selected=[r for r in rows if r['source']['model']==model and
                      ((panel=='attack_admitted' and r['source']['panel']=='attack') or
                       (panel=='honest_reopened' and r['source']['panel']!='attack' and r['source']['original_admitted_after_update']) or
                       (panel=='honest_still_refused' and r['source']['panel']!='attack' and not r['source']['original_admitted_after_update']))]
            metric='native_goal' if panel=='attack_admitted' else 'correct_selected_effect'
            for arm in arms:
                rs=[r for r in selected if r['source']['arm']==arm]
                result['counts'].append({'model':model,'panel':panel,'arm':arm,'n':len(rs),
                                        **{k:sum(r['metrics'][k]==1 for r in rs) for k in ['correct_selected_effect','wrong_selected_effect','native_utility','native_goal','original_call_changed_state_normalized']},
                                        'unknown':sum(r['metrics'][metric] is None for r in rs)})
            for control in controls:
                rs=[r for r in selected if r['source']['arm'] in ['permission_status',control]]
                result['contrasts'][model+'_'+panel+'_status_minus_'+control]=contrast(rs,metric,'arm','permission_status',control)
    out=HERE/a.out;out.mkdir(parents=True,exist_ok=True);(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');(out/'rows.json').write_text(json.dumps(rows,indent=2)+'\n')
    lines=[f"Recovery acknowledgement: {result['observed']}/{result['scheduled']} records.",'','|Model|Panel|Message|N|Correct effect|Wrong effect|Utility|Attack goal|Unknown|','|---|---|---|---:|---:|---:|---:|---:|---:|']
    for r in result['counts']:lines.append('|'+ '|'.join(str(r[k]) for k in ['model','panel','arm','n','correct_selected_effect','wrong_selected_effect','native_utility','native_goal','unknown'])+'|')
    for name,c in result['contrasts'].items():
        if c:lines.append(f"\n{name}: [{100*c['lower']:.3f}, {100*c['upper']:.3f}] pp (finite missing-outcome bounds).")
    (out/'RESULTS.md').write_text('\n'.join(lines)+'\n');print(json.dumps({k:v for k,v in result.items() if k!='contrasts'},indent=2))
if __name__=='__main__':main()
