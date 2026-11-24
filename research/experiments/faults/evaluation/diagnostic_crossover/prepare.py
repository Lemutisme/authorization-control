"""Freeze three existing, outcome-selected denial boundaries; no model calls."""
import argparse,copy,gzip,hashlib,json
from pathlib import Path
CASES=['banking__user_task_3__injection_task_0','banking__user_task_10__injection_task_8','banking__user_task_12__injection_task_4']
BACKGROUNDS=['minimal','late_facts']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def save(p,x):p.write_text(json.dumps(x,indent=2)+'\n')
def main():
    p=argparse.ArgumentParser();p.add_argument('--prior',type=Path,required=True);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args();a.out.mkdir(parents=True,exist_ok=False)
    cfg=json.loads((a.prior/'run-config.json').read_text());assert sha(a.manifest)==cfg['manifest_sha256']
    native=json.loads(a.manifest.read_text());selected=[]
    for cid in CASES:
        envelope={'case_id':cid,'backgrounds':{},'clock_anchor':cfg['clock_anchor']}
        for arm in BACKGROUNDS:
            folder=a.prior/cid;path=folder/(arm+'.json.gz');raw=json.loads(gzip.decompress(path.read_bytes()));ep=raw['result'];denial=ep['guard_decisions'][0]
            assert denial['decision']=='deny' and not denial.get('operational_unavailable')
            prefix=[];found=False
            for c in ep['pi']['calls']:
                cached=json.loads((folder/'actor-cache'/(c['coupling']['request_sha256']+'.json')).read_text())
                prefix.append({'wire_request_sha256':c['request_sha256'],'message':cached['message'],'response_sha256':cached['response_sha256']})
                for item in cached['message']['content']:
                    if item.get('type')=='toolCall' and item['name']==denial['operation']['function']:
                        assert all(denial['operation']['args'].get(k)==v for k,v in item['arguments'].items());found=True
                if found:break
            assert found
            reviews=[]
            for call in ep['guard_calls'][:len(denial['stages'])]:
                saved=json.loads((folder/'judge-cache'/(call['coupling']['sample_key']+'.json')).read_text());assert saved['outcome']['kind']=='response'
                reviews.append({'wire_request_sha256':call['coupling']['request_sha256'],'response':saved['outcome']['response'],'record':call})
            assert len(reviews)==2
            # Before this first effect proposal, each native call is a read.
            first_effect=next((i for i,e in enumerate(raw['events']) if e.get('classified_mode')=='effect'),len(raw['events']))
            # Only the reads before the rejected call are part of the boundary.
            proposed_before=[]
            for call in raw['proposed_calls']:
                if call['function']==denial['operation']['function']:break
                proposed_before.append(call)
            events=[{k:v for k,v in e.items() if k!='elapsed_s'} for e in raw['events'][:len(proposed_before)]]
            assert all(e.get('classified_mode')=='internal_read' and not e['entry_state_changed'] for e in events)
            envelope['backgrounds'][arm]={'actor_prefix':prefix,'judge_prefix':reviews,'denial':denial,'native_prefix':events,'initial':raw['initial'],'raw_sha256':sha(path)}
        x,y=[envelope['backgrounds'][arm] for arm in BACKGROUNDS]
        assert x['actor_prefix']==y['actor_prefix'] and x['initial']==y['initial'] and x['denial']['operation']==y['denial']['operation']
        assert x['native_prefix']==y['native_prefix']
        path=a.out/(cid+'.json');save(path,envelope);selected.append({'case_id':cid,'path':path.name,'sha256':sha(path),'prefix_actor_calls':len(x['actor_prefix'])})
    native['cases']=[c for c in native['cases'] if c['case_id'] in CASES];save(a.out/'native-manifest.json',native)
    save(a.out/'manifest.json',{'kind':'Outcome-selected diagnostic crossover; not a defense efficacy benchmark','parent_commit':'c39530c4524cc5022c2691542f8fefada01aa09c','cases':selected,'native_manifest':'native-manifest.json','native_manifest_sha256':sha(a.out/'native-manifest.json'),'prior_config_sha256':sha(a.prior/'run-config.json'),'backgrounds':BACKGROUNDS,'messages':['minimal_reason','late_reason','status_only'],'replicates':3,'model':'gpt-6-luna','pi_version':'1.5.0','historical_prefix':'Exact archived requests/responses replayed in disposable native environment; fresh suffix inference; prior cost not billed as new calls.','limits':['Cases selected for prior discordance, not prevalence or holdout.','Donor reasons are experimental variables, not an implemented verified-diagnostic generator.','Native utility/ASR retain original meaning; no universal safe-completion oracle.']})
    print(json.dumps({'cases':len(selected),'suffix_episodes':54,'prefix_actor_calls':[c['prefix_actor_calls'] for c in selected]}))
if __name__=='__main__':main()
