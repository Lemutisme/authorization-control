"""Paired task-macro analysis of the separately registered prompt follow-up."""
import argparse,gzip,json
from pathlib import Path
from analyze import contrast
HERE=Path(__file__).resolve().parent
def main():
    p=argparse.ArgumentParser();p.add_argument('--run',default='prompt-followup-main-v1');p.add_argument('--out',default='analysis-prompt');a=p.parse_args()
    protocol=json.loads((HERE/'prompt-protocol.json').read_text());rows=[]
    for source in protocol['rows']:
        path=HERE/'outputs'/a.run/'raw'/(source['id']+'.json.gz');raw=None
        try:raw=json.loads(gzip.decompress(path.read_bytes()))
        except (OSError,ValueError):pass
        metrics=raw['metrics'] if raw else {k:None for k in ['wrong_selected_effect','correct_selected_effect','native_utility']}
        rows.append({'source':{**source,'task':source['cluster_id'],'repetition':0},'metrics':metrics,'present':raw is not None,
                     'status':raw.get('status') if raw else 'missing','raw_path':str(path)})
    result={'scheduled':len(rows),'observed':sum(r['present'] for r in rows),'counts':[],'contrasts':{},
            'scope':'Post-main exploratory hypothesis with new draws on the same inspected states; no new task generalization.'}
    for direction,metric in [('corruption','wrong_selected_effect'),('correction','correct_selected_effect')]:
        selected=[r for r in rows if r['source']['direction']==direction]
        for arm in ['baseline','generic','task_policy']:
            cell=[r for r in selected if r['source']['arm']==arm]
            result['counts'].append({'direction':direction,'arm':arm,'n':len(cell),
                                    **{k:sum(r['metrics'][k]==1 for r in cell) for k in ['wrong_selected_effect','correct_selected_effect','native_utility']},
                                    'unknown':sum(r['metrics'][metric] is None for r in cell)})
        for other in ['baseline','generic']:
            cell=[r for r in selected if r['source']['arm'] in ['task_policy',other]]
            result['contrasts'][direction+'_task_policy_minus_'+other]=contrast(cell,metric,'arm','task_policy',other)
    out=HERE/a.out;out.mkdir(parents=True,exist_ok=True);(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');(out/'rows.json').write_text(json.dumps(rows,indent=2)+'\n')
    lines=[f"Exploratory prompt study: {result['observed']}/{result['scheduled']} records.",'', '|Direction|Prompt|N|Wrong|Correct|Utility|Unknown|','|---|---|---:|---:|---:|---:|---:|']
    for r in result['counts']:lines.append('|'+ '|'.join(str(r[k]) for k in ['direction','arm','n','wrong_selected_effect','correct_selected_effect','native_utility','unknown'])+'|')
    for name,c in result['contrasts'].items():
        if c:lines.append(f"\n{name}: [{100*c['lower']:.3f}, {100*c['upper']:.3f}] pp (missing-outcome bounds).")
    (out/'RESULTS.md').write_text('\n'.join(lines)+'\n');print(json.dumps({k:v for k,v in result.items() if k not in ['contrasts']},indent=2))
if __name__=='__main__':main()
