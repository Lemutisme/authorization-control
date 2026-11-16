#!/usr/bin/env python3
"""Bounded qualification plus explicit countermodels; no agent experiment."""
import argparse,hashlib,importlib.util,itertools,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('negative',ROOT/'theory/negative_constraints.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    effects=frozenset(range(3));worlds=frozenset(range(2));checks=0;current_only=0
    for row0,row1 in itertools.product(m.subsets(effects),repeat=2):
        allowed={0:row0,1:row1}
        for belief in m.subsets(worlds):
            if not belief:continue
            for excluded in m.subsets(effects):
                direct=m.justified_exclusion(belief,allowed,excluded)
                # Independent enumeration: does any permitted singleton/world
                # witness invalidate an exclusion after some refinement?
                oracle=not any(effect in excluded and effect in allowed[w]
                               for w in belief for effect in effects)
                refinement=m.persistent_exclusion_is_safe(belief,allowed,excluded)
                assert direct==oracle==refinement
                checks+=1
                current_only+=m.preserves_current_admission(belief,allowed,excluded) and not refinement
    allowed={0:frozenset({0}),1:frozenset({1})};belief=frozenset({0,1});excluded=frozenset({0})
    assert not m.admitted(belief,allowed)
    assert m.preserves_current_admission(belief,allowed,excluded)
    assert not m.persistent_exclusion_is_safe(belief,allowed,excluded)
    assert m.admitted(frozenset({0}),allowed)==frozenset({0})
    unknown_is_not_forbidden={'belief':[0,1],'allowed_by_world':{'0':[0],'1':[1]},'excluded':[0],
        'current_admission':[],'refined_belief':[0],'refined_admission':[0],
        'finding':'No current permission does not justify a persistent prohibition.'}
    # The current illegal proposal is 0. Both diagnostic policies deny it.
    # One additionally excludes the sole legitimate completion, action 1.
    allowed={0:frozenset({1})};belief=frozenset({0})
    exact=frozenset({0});broad=frozenset({0,1})
    assert m.justified_exclusion(belief,allowed,exact)
    assert not m.justified_exclusion(belief,allowed,broad)
    assert (m.admitted(belief,allowed)-exact)==frozenset({1})
    assert not (m.admitted(belief,allowed)-broad)
    correct_verdict_wrong_scope={'current_proposal':0,'allowed_effects':[1],
        'exact_exclusion':[0],'broad_exclusion':[0,1],
        'both_current_decisions':'deny','completion_available_after_exclusion':[True,False]}
    # Sound advice does not compel an uncontrolled actor to take an available action.
    actor_may_stop={'sound_exclusion':[0],'allowed_completion':1,'actual_actor_choice':'stop',
        'security_violation':False,'task_complete':False}
    assert not m.justified_exclusion(frozenset(),allowed,frozenset())
    result=dict(kind='Finite qualification of a specification; no runtime safety or model-performance claim',
        domains={'worlds':2,'effects':3,'all_policy_tables':64,'nonempty_beliefs':3,'exclusion_sets':8},
        equivalence_checks=checks,current_only_but_not_refinement_safe=current_only,
        countermodels=[unknown_is_not_forbidden,correct_verdict_wrong_scope,actor_may_stop],
        source_sha256={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),ROOT/'theory/negative_constraints.py']},
        limits=['Explicit finite policy/compatibility tables are assumptions; no natural-language policy compilation.',
                'Evidence refinements preserve the world domain and policy. Changed authority/state requires new dependencies.',
                'A persistent exclusion model does not assert that an LLM literally stores or obeys such a set.',
                'The general equivalence has a direct set-theoretic proof; finite agreement is code qualification, not that proof.',
                'Availability of an allowed completion is not guaranteed realization by the actual actor.'])
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k in ['domains','equivalence_checks','current_only_but_not_refinement_safe']},indent=2))

if __name__=='__main__':main()
