"""Diagnostic replay of selected retained baseline plans; no fresh actor claim."""
import argparse,contextlib,gzip,io,json,os
from pathlib import Path
from broker import Broker

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--prior',type=Path,required=True)
    p.add_argument('--source-arm',choices=['none','intent_guard'],default='none')
    p.add_argument('--cases',nargs='+',required=True);p.add_argument('--out',type=Path);a=p.parse_args()
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True);rows=[]
    config=json.loads((a.prior/'run-config.json').read_text())
    for case in a.cases:
        old=json.loads(gzip.decompress((a.prior/case/(a.source_arm+'.json.gz')).read_bytes()))
        b=Broker();b.init({'manifest':str(a.manifest),'case_id':case,'arm':'intent_guard','model':'gpt-6-luna','delegate_reference':True,'clock_anchor':config['clock_anchor']})
        for call in old['proposed_calls']:b.invoke({'name':call['function'],'args':call['args'],'call_id':call['id']})
        with contextlib.redirect_stdout(io.StringIO()):finished=b.finish({'final_text':old['final_response']})
        row=finished['result'];row.update(baseline_native_utility=old['result']['native_utility'],source_native_asr=old['result']['native_targeted_asr'],source_arm=a.source_arm,not_a_new_actor_episode=True)
        (out/(case+'.json.gz')).write_bytes(gzip.compress(json.dumps(finished).encode()));rows.append(row)
        (out/'status.md').write_text(f"Retained-plan diagnostic: {len(rows)}/{len(a.cases)}; no fresh actor.\n")
    report={'kind':'retained-plan diagnostic from paired baseline; not fresh actor efficacy','rows':rows,'n':len(rows),'scheduled':len(a.cases)}
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps([{'case_id':r['case_id'],'utility':r['native_utility'],'asr':r['native_targeted_asr'],'scope_status':r['owner_scope_status'],'guard_calls':r['guard_requests']} for r in rows],indent=2))
if __name__=='__main__':main()
