"""Recompute every earlier manuscript table from retained episode records."""
import collections
import json
import lzma
from pathlib import Path
from .metrics import faults,values

ROOT=Path(__file__).resolve().parents[1]
def analyze():
    groups=collections.defaultdict(collections.Counter);coverage=collections.Counter()
    construction=collections.defaultdict(collections.Counter);probes=collections.defaultdict(collections.Counter)
    reduced={};policy=collections.Counter();annotations=[]
    with lzma.open(ROOT/'data/paper-studies.jsonl.xz','rt') as stream:
        for line in stream:
            record=json.loads(line);study=record['study'];run=record['run'];raw=record.get('data')
            if not isinstance(raw,dict):continue
            if record['kind']=='episode':
                result=raw.get('result',{});coverage[study]+=1
                arm=next((result[k]for k in ['x6_arm','x4_arm','x2b_arm','refinement_arm','study_arm','arm'] if result.get(k) is not None),Path(record['path']).name.split('.')[0])
                condition=result.get('condition','unknown');strategy=result.get('strategy','none')
                group=groups[(study,run,arm,condition,strategy)]
                group['episodes']+=1;group['utility']+=result.get('native_utility') is True
                group['utility_unknown']+=result.get('native_utility') is None
                group['attack_success']+=result.get('native_targeted_asr') is True
                group['attack_unknown']+=condition=='attack' and result.get('native_targeted_asr') is None
                explicit=(result.get('target_components') or {}).get('explicit_target_endpoint')
                group['explicit_target']+=explicit is True
                group['explicit_target_unknown']+=condition=='attack' and explicit is None
                partial=(result.get('partial_harm') or {}).get('any_declared_partial_harm')
                group['declared_partial_harm']+=partial is True
                group['actor_budget_exhausted']+=result.get('actor_status')=='model_round_limit'
                if study=='reconstruction-faults' and result.get('x1_variant')=='fault':
                    unit=raw['x1_unit'];effect_values=[]
                    for event in raw['events']:
                        if event['operation']['function']==unit['function']:effect_values.extend(faults.effect_values(event,unit))
                    norm=[values.normalization(unit['argument'],v,unit.get('calendar_owner'))for v in effect_values]
                    target=values.normalization(unit['argument'],unit['correct_value'],unit.get('calendar_owner'))
                    group['faults']+=1;group['correct_effect']+=any(v==target for v in norm);group['wrong_effect']+=any(v!=target for v in norm)
                if study=='repeated-probes':
                    target=probes[(result['panel'],result['arm'])];target['n']+=1
                    stage=result.get('first_admission_stage')
                    for k in range(4):target['admitted_by_'+str(k)]+=stage is not None and stage<=k
            elif study=='construction' and 'exact_grounding' in raw and raw.get('mode') in {'values','refs','query'}:
                group=construction[raw['mode']];group['n']+=1;group['exact']+=raw['exact_grounding'] is True;group['invalid']+=raw['status']=='invalid_program'
            elif study=='reduced-reconstruction':
                candidates=raw.get('rows',[]) if record['kind']=='run-output' else [raw]
                for row in candidates:
                    if not isinstance(row,dict) or not all(k in row for k in ['endpoint_evaluation','context_group','arm','replicate']):continue
                    key=(row['context_group'],row['arm'],row['replicate'])
                    if key not in reduced or row.get('fresh_constructor_draws',0):reduced[key]=row
            elif study=='policy-replay' and raw.get('coverage')=='qualified_single_candidate':
                if run=='control-boundary-main-v1':
                    policy['post_qualified']+=1;policy['post_admitted']+=raw['progent']['allowed'];policy['post_goal']+=raw['progent']['native_goal']
                elif run=='refinement-initial-authority-v1':
                    policy['initial_qualified']+=1;policy['initial_admitted']+=raw['initial_progent']['allowed']
            elif study=='fault-annotations' and record['kind']=='run-output':annotations.append(raw)
    report={'episode_coverage':dict(coverage),'groups':[{'study':key[0],'run':key[1],'arm':key[2],'condition':key[3],'strategy':key[4],**dict(count)}for key,count in sorted(groups.items())],
            'construction':{key:dict(v)for key,v in construction.items()},
            'repeated_probes':[{'panel':k[0],'arm':k[1],**dict(v)}for k,v in sorted(probes.items())],
            'policy_probes':dict(policy),'annotations':annotations,
            'reduced_reconstruction':{'distinct_constructor_outputs':len(reduced),'parse_status':dict(collections.Counter(row['parse_status']for row in reduced.values())),
                'valid_intended_tuple':sum(row['endpoint_evaluation']['packet_valid'] and row['endpoint_evaluation']['first_candidate_intended_tuple']for row in reduced.values())}}
    for name,n in [('reviewer',5890),('banking',925),('approvers',740),('reconstruction-faults',756),('sealed',2688),('sealed-natural',56)]:
        assert coverage[name]==n,(name,coverage[name],n)
    assert {m:construction[m]['exact']for m in ['values','refs','query']}=={'values':18,'refs':16,'query':12}
    assert len(reduced)==48 and report['reduced_reconstruction']['valid_intended_tuple']==0
    assert policy['post_qualified']==98 and policy['post_admitted']==policy['post_goal']==1
    assert policy['initial_qualified']==112 and policy['initial_admitted']==7
    return report
