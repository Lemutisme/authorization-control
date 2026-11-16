#!/usr/bin/env python3
"""Exact finite decision-model check, not an attack or defense experiment.

Two states have the same initial cue. A fixed one-test protocol chooses a test,
then acts/continues using only the result available by the common deadline.
The script enumerates deterministic rules and exact vertices of their mixture
polytope. Independent linear certificates check the reported optimality and
infeasibility. All payoffs, probabilities and latencies are assumed model data.
"""
import argparse
from dataclasses import dataclass
from fractions import Fraction as F
import hashlib
from itertools import combinations, product
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
P_GOOD = F(99, 100)
BENEFIT, DAMAGE = F(10), F(100)
ALPHA, BETA = F(1, 20), F(9, 10)


@dataclass(frozen=True)
class Test:
    name: str
    cost: F
    duration: F
    pass_good: F
    pass_bad: F


TESTS = (
    Test('none', F(0), F(0), F(1), F(1)),
    Test('cheap', F(1, 4), F(1), F(1), F(1, 2)),
    Test('specific', F(2), F(2), F(1), F(0)),
    Test('late', F(2), F(4), F(1), F(0)),
)


def signals(test, deadline):
    # Costs are reserved in full, without refund; action latency is zero.
    # A result completed exactly at the deadline is available. Otherwise the
    # rule sees only timeout and may act/continue at the deadline without it.
    if test.name == 'none':
        return ('cue',), (F(1),), (F(1),)
    if test.duration > deadline:
        return ('timeout',), (F(1),), (F(1),)
    return ('pass', 'fail'), (test.pass_good, 1-test.pass_good), (test.pass_bad, 1-test.pass_bad)


def protocols(deadline):
    rows = []
    for test in TESTS:
        names, good, bad = signals(test, deadline)
        for decision in product((0, 1), repeat=len(names)):
            qg = sum((p*a for p, a in zip(good, decision)), F(0))
            qb = sum((p*a for p, a in zip(bad, decision)), F(0))
            utility = P_GOOD*BENEFIT*qg - (1-P_GOOD)*DAMAGE*qb - test.cost
            rows.append({'name': test.name+':' + ','.join(n+'='+str(a) for n, a in zip(names, decision)),
                         'test': test.name, 'rule': decision, 'qg': qg, 'qb': qb,
                         'utility': utility, 'cost': test.cost})
    return rows


def solve_square(matrix, rhs):
    """Rational Gaussian elimination; singular active sets are skipped."""
    n = len(rhs)
    a = [[F(x) for x in row] + [F(y)] for row, y in zip(matrix, rhs)]
    for col in range(n):
        pivot = next((i for i in range(col, n) if a[i][col]), None)
        if pivot is None:
            return None
        a[col], a[pivot] = a[pivot], a[col]
        p = a[col][col]
        a[col] = [x/p for x in a[col]]
        for i in range(n):
            if i != col:
                m = a[i][col]
                a[i] = [x-m*y for x, y in zip(a[i], a[col])]
    return tuple(row[-1] for row in a)


def optimize_mixture(rows, alpha, beta):
    """All vertices: normalization plus at most two active global constraints.

    The feasible set is a bounded simplex intersected with a risk upper bound
    and coverage lower bound. A vertex has at most three positive weights.
    The result is also checked by a separate analytic certificate below.
    """
    best, examined = None, 0
    constraints = [('qb', alpha), ('qg', beta)]
    for size in range(1, min(3, len(rows))+1):
        for support in combinations(range(len(rows)), size):
            for active in combinations(constraints, size-1):
                matrix = [[F(1)]*size] + [[rows[i][name] for i in support] for name, _ in active]
                rhs = [F(1)] + [bound for _, bound in active]
                weights = solve_square(matrix, rhs)
                examined += 1
                if weights is None or any(w < 0 for w in weights):
                    continue
                values = {name: sum((w*rows[i][name] for i, w in zip(support, weights)), F(0))
                          for name in ['qb', 'qg', 'utility']}
                if values['qb'] > alpha or values['qg'] < beta:
                    continue
                result = dict(values, mixture=[(rows[i]['name'], w) for i, w in zip(support, weights) if w])
                if best is None or result['utility'] > best['utility']:
                    best = result
    return best, examined


def tv(good, bad):
    return sum((abs(a-b) for a, b in zip(good, bad)), F(0))/2


def model_check():
    long_deadline, short_deadline = F(3), F(3, 2)
    long, short = protocols(long_deadline), protocols(short_deadline)
    assert (len(long), len(short)) == (12, 10)
    find = lambda test, rule: next(p for p in long if p['test'] == test and p['rule'] == rule)
    direct = find('none', (1,))
    keep = find('none', (0,))
    cheap = find('cheap', (1, 0))
    specific = find('specific', (1, 0))
    assert [p['utility'] for p in [direct, keep, cheap, specific]] == [F(89, 10), F(0), F(183, 20), F(79, 10)]
    nominal = max(long, key=lambda p: p['utility'])
    assert nominal == cheap and nominal['qb'] == F(1, 2)
    # This models a perfectly accurate mean-value selector: its residual
    # conditional harm is an objective distinction, not prediction error.
    optimum, long_vertices = optimize_mixture(long, ALPHA, BETA)
    assert optimum is not None and optimum['utility'] == F(321, 40)
    assert (optimum['qg'], optimum['qb']) == (F(1), ALPHA)
    # Independent upper certificate: valid for every vertex and thus every mix.
    assert all(p['utility'] <= F(79, 10) + F(5, 2)*p['qb'] for p in long)
    assert F(79, 10) + F(5, 2)*ALPHA == optimum['utility']
    # Independent attaining witness, without reading the optimizer's support.
    for name, expected in [('utility', F(321, 40)), ('qg', F(1)), ('qb', ALPHA)]:
        assert F(1, 10)*cheap[name] + F(9, 10)*specific[name] == expected
    impossible, short_vertices = optimize_mixture(short, ALPHA, BETA)
    assert impossible is None
    assert all(p['qg'] <= 2*p['qb'] for p in short)
    assert 2*ALPHA < BETA  # Independent infeasibility certificate for all mixtures.

    # Check the transcript bound on every enumerated deterministic decision rule;
    # the general shared-kernel inequality and convex-mixture extension are written.
    tv_checks = 0
    for deadline, rows in [(long_deadline, long), (short_deadline, short)]:
        for test in TESTS:
            _, good, bad = signals(test, deadline)
            distance = tv(good, bad)
            for p in rows:
                if p['test'] == test.name:
                    assert p['qg'] - p['qb'] <= distance
                    tv_checks += 1

    # TV >= beta-alpha is necessary, not sufficient at a specified risk cap.
    pg, pb = (F(17, 20), F(3, 20)), (F(0), F(1))
    assert tv(pg, pb) == BETA-ALPHA
    max_coverage_at_alpha = pg[0] + pg[1]*ALPHA
    assert max_coverage_at_alpha == F(343, 400) < BETA

    # Explicit regression checks for assumptions commonly lost in a replay.
    assert signals(TESTS[2], F(2))[0] == ('pass', 'fail')
    assert signals(TESTS[2], short_deadline)[0] == ('timeout',)
    assert signals(TESTS[3], long_deadline)[1:] == ((F(1),), (F(1),))
    return {'model': {'prior_good': P_GOOD, 'act_gain_good': BENEFIT,
                      'act_loss_bad': DAMAGE, 'alpha': ALPHA, 'beta': BETA,
                      'long_deadline': long_deadline, 'short_deadline': short_deadline,
                      'tests': [dict(name=t.name, cost=t.cost, duration=t.duration,
                                     pass_good=t.pass_good, pass_bad=t.pass_bad) for t in TESTS],
                      'conventions': 'Identical initial cue; stationary states; action by deadline inclusive with zero latency; unfinished result unavailable; full reserved test cost, no refund; continuation inert only in this model.'},
            'long_protocols': long, 'short_protocols': short,
            'nominal_optimum': nominal, 'risk_constrained_optimum': optimum,
            'short_deadline_feasible': False,
            'tv_not_sufficient': {'tv': tv(pg, pb), 'best_coverage_at_alpha': max_coverage_at_alpha},
            'checks': {'deterministic_protocols': len(long)+len(short),
                       'lp_active_sets_examined': long_vertices+short_vertices,
                       'transcript_inequalities': tv_checks,
                       'long_dual_bound': 'U <= 79/10 + (5/2) q_bad for every protocol',
                       'long_attaining_mix': '1/10 cheap-pass + 9/10 specific-pass',
                       'short_infeasibility': 'q_good <= 2 q_bad <= 1/10 < 9/10'}}


def three_state_check():
    """A distinct construction: the Bayes-optimal no-test rule continues.

    N is ordinary self-recovery; B is the attacker-selectable sensitive state.
    The protected cheap test distinguishes N but not G from B. Its higher
    nominal value is exact, yet it introduces harm absent from continuation.
    """
    tests = (Test('none', F(0), F(0), F(1), F(1)),
             Test('cheap', F(1, 10), F(1), F(1), F(1)),
             Test('specific', F(6, 5), F(2), F(1), F(0)),
             Test('late', F(6, 5), F(4), F(1), F(0)))

    def rows_at(deadline):
        rows = []
        for test in tests:
            names, good, bad = signals(test, deadline)
            normal = (F(1),) if len(names) == 1 else (F(0), F(1))
            for decision in product((0, 1), repeat=len(names)):
                qg = sum((p*a for p, a in zip(good, decision)), F(0))
                qb = sum((p*a for p, a in zip(bad, decision)), F(0))
                qn = sum((p*a for p, a in zip(normal, decision)), F(0))
                utility = F(1, 2)*10*qg - F(49, 100)*10*qn - F(1, 100)*100*qb - test.cost
                rows.append({'name': test.name+':' + ','.join(n+'='+str(a) for n, a in zip(names, decision)),
                             'test': test.name, 'rule': decision, 'qg': qg, 'qb': qb,
                             'qn': qn, 'utility': utility, 'cost': test.cost})
        return rows

    long, short = rows_at(F(3)), rows_at(F(3, 2))
    assert (len(long), len(short)) == (12, 10)
    find = lambda test, rule: next(p for p in long if p['test'] == test and p['rule'] == rule)
    cheap, specific = find('cheap', (1, 0)), find('specific', (1, 0))
    no_test = max((p for p in long if p['test'] == 'none'), key=lambda p: p['utility'])
    assert no_test['utility'] == 0 and no_test['qb'] == 0
    assert find('none', (1,))['utility'] == -F(9, 10)
    assert cheap['utility'] == F(39, 10) and specific['utility'] == F(19, 5)
    assert max(long, key=lambda p: p['utility']) == cheap and cheap['qb'] == 1
    optimum, long_vertices = optimize_mixture(long, ALPHA, BETA)
    assert optimum is not None and optimum['utility'] == F(761, 200)
    assert (optimum['qg'], optimum['qb']) == (F(1), ALPHA)
    assert all(p['utility'] <= F(19, 5)+F(1, 10)*p['qb'] for p in long)
    for name, expected in [('utility', F(761, 200)), ('qg', F(1)), ('qb', ALPHA)]:
        assert F(1, 20)*cheap[name]+F(19, 20)*specific[name] == expected
    impossible, short_vertices = optimize_mixture(short, ALPHA, BETA)
    assert impossible is None and all(p['qg'] == p['qb'] for p in short)
    assert ALPHA < BETA
    return {'model': {'priors': {'G': F(1, 2), 'N': F(49, 100), 'B': F(1, 100)},
                      'act_payoffs': {'G': F(10), 'N': -F(10), 'B': -F(100)},
                      'tests': [dict(name=t.name, cost=t.cost, duration=t.duration,
                                     pass_good=t.pass_good, pass_bad=t.pass_bad,
                                     pass_normal=F(1) if t.name == 'none' else F(0)) for t in tests],
                      'conventions': 'Same timing/charging rules as two-state model; N is not the cue-conditioned security-risk denominator.'},
            'long_protocols': long, 'short_protocols': short,
            'no_test_optimum': no_test, 'nominal_optimum': cheap,
            'risk_constrained_optimum': optimum, 'short_deadline_feasible': False,
            'checks': {'deterministic_protocols': 22,
                       'lp_active_sets_examined': long_vertices+short_vertices,
                       'long_dual_bound': 'U <= 19/5 + (1/10) q_bad for every protocol',
                       'long_attaining_mix': '1/20 cheap-pass + 19/20 specific-pass',
                       'short_infeasibility': 'q_good = q_bad <= 1/20 < 9/10'}}


def main():
    p = argparse.ArgumentParser(); p.add_argument('--work', type=Path, required=True)
    p.add_argument('--publication-root', type=Path, help=argparse.SUPPRESS)
    a = p.parse_args(); work = a.work.resolve(); root = a.publication_root.resolve() if a.publication_root else ROOT
    if work.is_relative_to(root):
        raise ValueError('Use a fresh directory outside the publication repository')
    if a.publication_root is None:
        work.mkdir(parents=True, exist_ok=False)
        frozen = work/Path(__file__).name; shutil.copyfile(Path(__file__), frozen)
        subprocess.run([sys.executable, '-B', str(frozen), '--work', str(work),
                        '--publication-root', str(root)], check=True)
        return
    if Path(__file__).resolve() != work/'check_initiative_risk.py':
        raise ValueError('Internal invocation must execute the frozen checker')
    result = {'kind': 'Exact finite mathematical model check; not empirical security performance',
              'exit_code': 0, 'results': model_check(), 'three_state_results': three_state_check(),
              'source_sha256': {'scripts/check_initiative_risk.py': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
              'limits': ['Likelihoods, payoffs, costs and reachability are assumed model inputs.',
                         'No learned model, live test runner, production action or attack was executed.',
                         'Known risk-aware optimization attains the bound; no learning advantage follows.',
                         'General transcript inequality is a written argument, not mechanically proved here.']}
    encoded = json.dumps(result, indent=2, default=lambda x: str(x) if isinstance(x, F) else x)+'\n'
    (work/'result.json').write_text(encoded)
    (root/'theory/initiative-risk-verification.json').write_text(encoded)
    print(json.dumps({'exit_code': 0, 'nominal_utility': str(result['results']['nominal_optimum']['utility']),
                      'constrained_utility': str(result['results']['risk_constrained_optimum']['utility']),
                      'three_state_nominal_utility': str(result['three_state_results']['nominal_optimum']['utility']),
                      'three_state_constrained_utility': str(result['three_state_results']['risk_constrained_optimum']['utility']),
                      'short_deadline_feasible': False, 'checks': result['results']['checks']}, indent=2))


if __name__ == '__main__':
    main()
