#!/usr/bin/env python3
"""Localize existing discordant episodes without modifying or rerunning them."""
import argparse,collections,gzip,hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def stable(x):return json.dumps(x,sort_keys=True,separators=(',',':'))
def read(p):return json.loads(gzip.decompress(p.read_bytes()))
def sequence(raw):return [(c['coupling']['request_sha256'],c['coupling']['response_sha256']) for c in raw['result']['pi']['calls']]

def localize(base,job,entry):
    case,on,off=entry['case_id'],entry['on'],entry['off']
    paths={a:base/job/'artifacts'/case/(a+'.json.gz') for a in [on,off]}
    raws={a:read(p) for a,p in paths.items()}
    for a,p in paths.items():assert sha(p)==entry['raw_sha256'][a]
    x,y=raws[on],raws[off];sx,sy=sequence(x),sequence(y)
    n=next((i for i,(u,v) in enumerate(zip(sx,sy)) if u!=v),min(len(sx),len(sy)))
    previous=[]
    if n:
        cache=paths[on].parent/'actor-cache'/(sx[n-1][0]+'.json')
        message=json.loads(cache.read_text())['message']
        previous=[c for c in message.get('content',[]) if c.get('type')=='toolCall']
    feedback_on=lambda a:job.startswith('contract-') and a in {'pga','no_facts'}
    ds={a:raws[a]['result'].get('guard_decisions',[]) for a in [on,off]}
    witness=None
    for i,(a,b) in enumerate(zip(ds[on],ds[off])):
        if a['operation']!=b['operation']:
            witness={'index':i,'classification':'operation_sequences_already_differ'};break
        ma=(a['decision'],a.get('reason'),feedback_on(on) if a['decision']!='allow' else None)
        mb=(b['decision'],b.get('reason'),feedback_on(off) if b['decision']!='allow' else None)
        # Allowed review prose is not delivered as the native tool result.
        if ma!=mb and (a['decision']!='allow' or b['decision']!='allow'):
            op=a['operation'];shared=any(c.get('name')==op['function'] and all(op['args'].get(k)==v for k,v in c.get('arguments',{}).items()) for c in previous)
            witness=dict(index=i,classification='operational_failure' if a.get('operational_unavailable') or b.get('operational_unavailable') else 'same_verdict_nonadmission' if a['decision']==b['decision'] else 'different_admission_verdict',
                operation=op,decisions=[a['decision'],b['decision']],reasons=[a.get('reason'),b.get('reason')],
                same_reason=a.get('reason')==b.get('reason'),suffix_present=[feedback_on(on),feedback_on(off)],
                matches_previous_shared_actor_proposal=shared,initial_review_decisions=[(a.get('stages') or [{}])[0].get('decision'),(b.get('stages') or [{}])[0].get('decision')])
            break
    effects={a:[e['operation'] for e in raws[a]['events'] if e.get('classified_mode')=='effect' and not e['error']] for a in [on,off]}
    return dict(job=job,case_id=case,on=on,off=off,raw_sha256={a:sha(p) for a,p in paths.items()},
        initial_states_equal=x['initial']==y['initial'],owner_tasks_equal=x['prompt']==y['prompt'],
        shared_actor_calls=n,first_actor_request_forks=n<len(sx) and n<len(sy) and sx[n][0]!=sy[n][0],
        previous_shared_actor_tools=[c['name'] for c in previous],witness=witness,
        utility=[raws[a]['result']['native_utility'] for a in [on,off]],asr=[raws[a]['result'].get('native_targeted_asr') for a in [on,off]],
        successful_effects=effects,exact_effect_multisets_equal=collections.Counter(map(stable,effects[on]))==collections.Counter(map(stable,effects[off])),
        final_response={a:raws[a]['final_response'] for a in [on,off]})

def main():
    p=argparse.ArgumentParser();p.add_argument('--jobs',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    paths=[ROOT/'evidence/contract-study/summary.json',ROOT/'evidence/fact-screen/summary.json']
    old,screen=[json.loads(p.read_text()) for p in paths]
    entries=[]
    for run in old['runs']:
        entries += [(run['job'],e) for e in run['score_discordance_localization']]
    entries += [('fact-placement-screen-v1',e) for e in screen['discordances']]
    records=[localize(a.jobs,j,e) for j,e in entries]
    counts={}
    for job in sorted({r['job'] for r in records}):
        selected=[r for r in records if r['job']==job]
        counts[job]=dict(pairs=len(selected),distinct_cases=len({r['case_id'] for r in selected}),
            classification=dict(collections.Counter((r['witness'] or {}).get('classification','unlocalized') for r in selected)),
            shared_verdict_and_proposal=sum((r['witness'] or {}).get('classification')=='same_verdict_nonadmission' and r['witness']['matches_previous_shared_actor_proposal'] for r in selected))
    result=dict(kind='Read-only localization of all previously published utility/ASR-discordant contrasts',
        source_sha256=sha(Path(__file__)),inputs={str(p.relative_to(ROOT)):sha(p) for p in paths},counts=counts,records=records,
        limits=['Outcome-selected case localization, not a prevalence or causal effect estimate.',
                'Shared SDK prefixes and matched proposals locate a first information boundary. Subsequent judgments may differ; message-only effects require a prospective intervention.',
                'Allowed judge explanations are not actor feedback. Only non-admission messages or verdict differences are classified.',
                'Recorded reasons are fallible assertions; no semantic truth is inferred from a model rationale.',
                'Primary native endpoints, selection, denominators and raw episodes are unchanged.'])
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(counts,indent=2))

if __name__=='__main__':main()
