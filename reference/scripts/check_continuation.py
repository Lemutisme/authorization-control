#!/usr/bin/env python3
"""Independent bounded policy-tree oracle plus explicit countermodels.

No agent, network, attack, benchmark or GPU. Oracle never calls Game.post or
Game.layers; it enumerates uniform observation trees and computes each tree's
winning *physical-state set*. Sharing a STOP leaf cannot inspect hidden state.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import sys
import time
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'theory'))
from continuation import Game, feedback_sufficient, minimum_repair_cover


def tree_sets(game, horizon):
    levels = [[game.goal]]  # explicit STOP
    for _ in range(horizon):
        trees = [game.goal]
        for action in range(game.actions):
            for children in itertools.product(levels[-1], repeat=game.observations):
                good = 0
                for state in range(game.states):
                    outcomes = game.transitions[state][action]
                    if (game.permitted[state][action] and outcomes
                        and all(children[obs] & (1 << target) for target, obs in outcomes)):
                        good |= 1 << state
                trees.append(good)
        levels.append(trees)
    return levels


def compare(game, stats):
    layers = game.layers(3)
    oracle = tree_sets(game, 3)
    stats['models'] += 1
    for h in range(4):
        stats['policy_trees'] += len(oracle[h])
        possible = set(oracle[h])
        for belief in range(1, 1 << game.states):
            actual = belief in layers[h]
            expected = any(belief & ~mask == 0 for mask in possible)
            assert actual == expected, (game, h, belief, actual, expected)
            stats['membership_comparisons'] += 1
            if actual:
                # A witness chosen at an earlier rank is still decreasing at h.
                action = layers[h][belief]
                if action is None:
                    assert belief & ~game.goal == 0
                else:
                    successors = game.post(belief, action)
                    assert h and successors and all(b in layers[h-1] for b in successors.values())
            for sub in range(1, 1 << game.states):
                if actual and sub & ~belief == 0:
                    assert sub in layers[h]
            if h:
                assert set(layers[h-1]) <= set(layers[h])


def exhaustive():
    deterministic = dict(models=0, policy_trees=0, membership_comparisons=0)
    for codes in itertools.product(range(4), repeat=4):
        transitions = tuple(tuple(((codes[2*s+a] // 2, codes[2*s+a] % 2),) for a in range(2)) for s in range(2))
        for safe in range(16):
            permitted = tuple(tuple(bool(safe & (1 << (2*s+a))) for a in range(2)) for s in range(2))
            for goal in range(4):
                compare(Game(2, 2, 2, transitions, permitted, goal), deterministic)
    nondeterministic = dict(models=0, policy_trees=0, membership_comparisons=0)
    outcomes = [(t, o) for t in range(2) for o in range(2)]
    for codes in itertools.product(range(16), repeat=2):
        transitions = tuple((tuple(outcomes[i] for i in range(4) if codes[s] & (1 << i)),) for s in range(2))
        for safe in range(4):
            permitted = tuple((bool(safe & (1 << s)),) for s in range(2))
            for goal in range(4):
                compare(Game(2, 1, 2, transitions, permitted, goal), nondeterministic)
    return deterministic, nondeterministic


def controls():
    # Two possible non-goal worlds require opposite repairs. Query reveals the
    # world, spends one round, and is legal in both. State 2 is the goal.
    transitions = ((((2,0),),((2,0),),((0,0),)),
                   (((2,0),),((2,0),),((1,1),)),
                   (((2,0),),((2,0),),((2,0),)))
    g = Game(3,3,2,transitions,((True,False,True),(False,True,True),(True,True,True)),4)
    assert 1 in g.layers(1)[1] and 2 in g.layers(1)[1]
    assert 3 not in g.layers(1)[1] and 3 in g.layers(2)[2]
    assert g.preserving_actions(3,2) == (2,)
    # A safe query can destroy the last opportunity despite returning true data.
    idle = Game(2,2,1,((((1,0),),((0,0),)),(((1,0),),((1,0),))),((True,True),(True,True)),2)
    assert idle.post(1,1) == {0:1} and idle.preserving_actions(1,1) == (0,)
    # Stop cannot branch on hidden state, even though each state has a plan.
    stop = Game(2,1,1,((((1,0),),), ((),)),((True,),(True,)),2)
    assert 1 in stop.layers(1)[1] and 2 in stop.layers(1)[1]
    assert 3 not in stop.layers(3)[3]
    # Disabled actions must not be admitted through a vacuous universal.
    disabled = Game(1,1,1,(((),),),((True,),),0)
    assert disabled.post(1,0) is None and not disabled.layers(3)[3]
    # Existence of a repair does not force an actor to take it after veto.
    actor = {'reject': 'stop', 'specific_advice': 'stop'}
    assert 1 in idle.layers(1)[1] and all(v == 'stop' for v in actor.values())
    # Pairwise-compatible repair sets need not share a common repair.
    repairs = ({0,1},{1,2},{0,2})
    assert all(a & b for a,b in itertools.combinations(repairs,2))
    assert not feedback_sufficient(repairs,(0,0,0)) and minimum_repair_cover(repairs)==2
    # A new grant is not a task-level effect allowance: naive unique-grant
    # checks accept two effects, whereas a one-effect policy rejects the second.
    seen=set(); accepted=0; task_count=0
    for grant in ['fresh-0','fresh-1']:
        assert grant not in seen
        seen.add(grant);accepted+=1
        if task_count<1:task_count+=1
    assert accepted==2 and task_count==1
    return {'incompatible_hidden_repairs':'query wins at 2 rounds, not 1',
            'costly_true_query':'safe self-loop loses last completion opportunity',
            'uniform_stop':'singleton winning does not imply union winning',
            'disabled_action':'no vacuous admission',
            'uncontrollable_actor_stop':'repair exists; feedback cannot force execution',
            'feedback_pairwise_fallacy':'all pairs overlap; global intersection empty; two labels needed',
            'fresh_grant_multiplicity':'two distinct one-use grants exceed a one-effect task budget'}


def feedback_check():
    count=0
    subsets=[set(i for i in range(3) if mask & (1<<i)) for mask in range(8)]
    for rows in itertools.product(subsets,repeat=3):
        # Independent oracle searches concrete message encoders and decoders.
        optimum=None
        for k in range(1,4):
            possible=False
            for labels in itertools.product(range(k),repeat=3):
                exists=any(all(decoder[labels[i]] in rows[i] for i in range(3))
                           for decoder in itertools.product(range(3),repeat=k))
                assert exists == feedback_sufficient(rows,labels)
                if exists:possible=True
                count+=1
            if possible and optimum is None:optimum=k
        assert minimum_repair_cover(rows)==optimum
    assert minimum_repair_cover(())==0
    return {'repair_families':512,'encoder_comparisons':count}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    start=time.monotonic();d,n=exhaustive();f=feedback_check();c=controls()
    report={'kind':'Bounded finite-model qualification; not an empirical defense evaluation or a Lean proof',
            'parent_commit':'184ea1d636f3db3aa6c64924656b7c5c7cd907fc','exit_code':0,
            'source_sha256':{p:hashlib.sha256((ROOT/p).read_bytes()).hexdigest() for p in ['theory/continuation.py','scripts/check_continuation.py']},
            'deterministic_2state_2action_2observation_h0to3':d,
            'nondeterministic_2state_1action_2observation_h0to3_including_disabled':n,
            'feedback':f,'countermodels':c,'elapsed_seconds':round(time.monotonic()-start,3),
            'limits':['Exact finite inputs, pointwise permission and faithful transitions are premises.',
                      'Explicit uniform STOP; no fairness or statistical success assumptions.',
                      'Reference algorithm is not integrated into the v16 Pi/Luna guard.',
                      'Enumeration checks code in the stated domain; general statements have written proofs only.']}
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report,indent=2))
if __name__=='__main__':main()
