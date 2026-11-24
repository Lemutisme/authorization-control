"""Development replay of retained ordinary actor proposals; no fresh proposer."""
import argparse,concurrent.futures,gzip,json,os,time
from pathlib import Path
from broker import Broker

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--prior',type=Path,required=True)
    p.add_argument('--condition',choices=['clean','positive_attacks'],required=True);p.add_argument('--workers',type=int,default=6);p.add_argument('--out',type=Path);a=p.parse_args()
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    original=json.loads((a.prior/'result.json').read_text())
    selected=[r for r in original['rows'] if (r['condition']=='clean' if a.condition=='clean' else r.get('native_targeted_asr') is True)]
    def run(row):
        with gzip.open(a.prior/(row['case_id']+'.json.gz'),'rt') as f:old=json.load(f)
        b=Broker();init=b.init({'manifest':str(a.manifest),'case_id':row['case_id'],'arm':'intent_guard','model':'gpt-6-luna','delegate_reference':True})
        for i,call in enumerate(old['proposed_calls']):b.invoke({'name':call['function'],'args':call['args'],'call_id':call.get('id') or str(i)})
        finish=b.finish({'final_text':old['final_response']});result=finish['result']
        result['baseline_native_utility']=row['native_utility'];result['baseline_native_asr']=row['native_targeted_asr']
        result['not_a_new_actor_episode']=True
        with gzip.open(out/(row['case_id']+'.json.gz'),'wt') as f:json.dump(finish,f)
        (out/(row['case_id']+'.json')).write_text(json.dumps(result,indent=2)+'\n');return result
    rows=[];started=time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as ex:
        pending={ex.submit(run,r):r for r in selected}
        for future in concurrent.futures.as_completed(pending):
            result=future.result();rows.append(result)
            report={'kind':'retained-plan development replay; not fresh closed-loop efficacy','condition':a.condition,'n':len(rows),'scheduled':len(selected),'rows':rows,'elapsed_s':time.monotonic()-started}
            (out/'partial.json').write_text(json.dumps(report,indent=2)+'\n')
            (out/'status.md').write_text(f"Intent replay {a.condition}: {len(rows)}/{len(selected)}; losses {sum(r['baseline_native_utility'] is True and r['native_utility'] is not True for r in rows)}; no fresh proposer.\n")
            print(json.dumps({'case_id':result['case_id'],'utility':result['native_utility'],'asr':result['native_targeted_asr'],'guard_calls':result['guard_requests']}),flush=True)
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
