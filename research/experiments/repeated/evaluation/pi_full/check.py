"""Cross-suite initialization/scoring qualification; no model or API calls."""
import argparse,json,os,sys
from pathlib import Path
from broker import Broker

def main():
    p=argparse.ArgumentParser();p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args()
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    manifest=json.loads(a.manifest.read_text());cases=[c for c in manifest['cases'] if c['condition'] in {'clean','goal_control'}]
    rows=[]
    for arm in ['none','pga']:
        for c in cases:
            try:
                b=Broker();init=b.init({'manifest':str(a.manifest),'case_id':c['case_id'],'arm':arm,'model':'gpt-6-luna','delegate_reference':False})
                assert init['profile_supported']==c['profile_supported']
                if arm=='pga' and not c['profile_supported']:
                    name=init['tools'][0]['name']
                    # Empty args cannot execute even before native type parsing.
                    denied=b.invoke({'name':name,'args':{},'call_id':'unsupported-check'})
                    assert denied['is_error'] and b.runtime.calls_started==0
                result=b.finish({'final_text':''})['result']
                assert not result['grounding_calls']
                if not c['profile_supported']:assert result['structural_assessment']=={'violation':None,'unknown':True,'verdict':'oracle_not_covered'}
                if c['condition']!='attack':assert result['native_targeted_asr'] is None
                rows.append({'case_id':c['case_id'],'arm':arm,'passed':True,'empty_run_utility_error':result['utility_error']})
            except Exception as exc:rows.append({'case_id':c['case_id'],'arm':arm,'passed':False,'error':type(exc).__name__})
    result={'kind':'cross-suite broker/coverage qualification; no inference and no efficacy claim','checks':rows,'n':len(rows),'passed':sum(r['passed'] for r in rows)}
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'status.md').write_text(f"Cross-suite checks {result['passed']}/{result['n']}; no API calls.\n")
    print(json.dumps({'n':result['n'],'passed':result['passed']}))
    if result['passed']!=result['n']:raise SystemExit(1)

if __name__=='__main__':main()
