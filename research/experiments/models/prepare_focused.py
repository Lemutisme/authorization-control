"""Quota-driven, explicitly exploratory DeepSeek panel; no new outcomes read."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
def key(value):return hashlib.sha256(('deepseek-focus-20261114:'+value).encode()).hexdigest()
def main():
    full=json.loads((HERE/'protocol-main.json').read_text())
    packets=json.loads((HERE/'correctness/frozen-v1/manifest.json').read_text())['rows']
    selected=[]
    for suite,number in [('banking',2),('workspace',2),('travel',1),('slack',1)]:
        tasks=sorted({r['cluster_id'] for r in packets if r['suite']==suite},key=key)[:number]
        for task in tasks:selected.append(min([r for r in packets if r['cluster_id']==task],key=lambda r:key(r['packet_id'])))
    packetpaths={r['path'] for r in selected}
    rows=[r for r in full['rows'] if r['model']=='deepseek' and r['kind']=='actor' and r['packet'] in packetpaths]
    unforced=json.loads((HERE/'correctness/frozen-v1/spontaneous-contexts.json').read_text())['contexts']
    contextids={r['context_id'] for r in selected}
    for r in full['rows']:
        if r['kind']=='unforced' and r['model']=='deepseek' and any(r['id']=='unforced__'+c+'__deepseek' for c in contextids):rows.append(r)
    units=json.loads((HERE/'updates/index.json').read_text())['units']
    # The four positive first-update witnesses in the PREVIOUS frozen Luna
    # study, identified in the review before this cross-model campaign.
    attacks={f'attack-banking__user_task_{task}__injection_task_{inj}' for task,inj in [(11,1),(11,2),(11,4),(9,5)]}
    chosen={u['unit_id'] for u in units if u['unit_id'] in attacks}
    for panel in ['honest_fault','honest_natural']:
        tasks=sorted({u['task_id'] for u in units if u['panel']==panel})
        for task in tasks:
            pool=[u for u in units if u['panel']==panel and u['task_id']==task]
            if panel=='honest_natural':
                wrong=[]
                for u in pool:
                    packet=json.loads(Path(u['packet']).read_text())
                    if packet['original_proposal']['function'] in packet['policy']:wrong.append(u)
                if wrong:pool=wrong
            chosen.add(min(pool,key=lambda u:key(u['unit_id']))['unit_id'])
    paths={u['packet'] for u in units if u['unit_id'] in chosen}
    rows += [r for r in full['rows'] if r['model']=='deepseek' and r['kind']=='update' and r['repetition']==0 and r['packet'] in paths]
    result={'version':'deepseek-focused-v1','phase':'focused','model':'deepseek','models':['deepseek'],
            'original_full_protocol':'protocol-main.json','original_full_deepseek_units':sum(r['model']=='deepseek' for r in full['rows']),
            'rows':rows,'scheduled':len(rows),'counts':{k:sum(r['kind']==k for r in rows) for k in ['actor','update','unforced']},
            'selected_actor_packets':selected,'selected_update_units':sorted(chosen),
            'scope':'Exploratory quota-driven diagnostic; four legacy attack witnesses are selected on OLD study outcomes and cannot estimate prevalence. Do not substitute this for the original full-panel DeepSeek predictions.',
            'selection':'SHA256 task/packet ordering fixed here, before any focused-run response; 2banking,2workspace,1travel,1Slack tasks. The original83-unit envelope remains retained.',
            'quota':'Observed x-ratelimit-limit-minute:3, x-ratelimit-limit-second:1. Serialize with21s after-completion gaps.'}
    (HERE/'protocol-focused.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'scheduled':len(rows),'counts':result['counts'],'tasks':[r['cluster_id'] for r in selected]}))
if __name__=='__main__':main()
