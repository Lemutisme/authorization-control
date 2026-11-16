#!/usr/bin/env python3
"""Exhaustive small-model qualification of the finite algorithm and certificate checks.

This is an algorithm regression, not an agent-security benchmark or a proof
for unbounded tables. The oracle examines every proper subset independently.
"""
import argparse
import copy
import hashlib
import importlib.util
import itertools
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'theory/finite_profiles.py'


def table(n, f, bits, labels):
    return {'requests': ['q'], 'histories': ['h' + str(i) for i in range(n)],
            'features': ['f' + str(i) for i in range(f)], 'policy': [list(labels)],
            'observations': [[list(bits[h*f:(h+1)*f]) for h in range(n)]]}


def exact(data, names):
    """Brute-force equivalence-class oracle on raw input, independent of algorithm."""
    indices = [data['features'].index(name) for name in names]
    for policy, observations in zip(data['policy'], data['observations']):
        for a in range(len(policy)):
            labels = {policy[b] for b in range(len(policy)) if all(
                json.dumps(observations[a][f], sort_keys=True) ==
                json.dumps(observations[b][f], sort_keys=True) for f in indices)}
            if len(labels) > 1:
                return False
    return True


def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--frozen-root', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(); work = args.work.resolve()
    root = args.frozen_root.resolve() if args.frozen_root else ROOT
    if work.is_relative_to(root):
        raise ValueError('Use a fresh directory outside the publication repository')
    if args.frozen_root is None:
        work.mkdir(parents=True, exist_ok=False)
        for source in [SOURCE, Path(__file__).resolve()]:
            shutil.copyfile(source, work / source.name)
        # Execute the frozen harness as well as importing the frozen algorithm.
        subprocess.run([sys.executable, '-B', str(work/Path(__file__).name),
                        '--work', str(work), '--frozen-root', str(root)], check=True)
        return
    if Path(__file__).resolve() != work/'check_finite_profiles.py':
        raise ValueError('Internal frozen invocation must execute the copied harness')
    spec = importlib.util.spec_from_file_location('finite_profiles', work / SOURCE.name)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    counts = {'tables': 0, 'ordered_runs': 0, 'minimal': 0, 'insufficient': 0,
              'corrupted_certificates_rejected': 0, 'edge_checks': 0}

    def check(data, order):
        model = module.Model.from_data(data)
        result = module.minimize(model, order)
        if not module.verify_certificate(model, result):
            raise AssertionError('certificate rejected')
        adequate = exact(data, data['features'])
        if (result['status'] == 'minimal') != adequate:
            raise AssertionError('full observation adequacy mismatch')
        if adequate:
            chosen = result['features']
            if not exact(data, chosen):
                raise AssertionError('chosen features inadequate')
            for size in range(len(chosen)):
                if any(exact(data, subset) for subset in itertools.combinations(chosen, size)):
                    raise AssertionError('a proper subset is adequate')
        counts[result['status']] += 1; counts['ordered_runs'] += 1
        return model, result

    # Exhaustive Boolean observations and policies, not random seeds.
    for n, f in [(0, 0), (1, 0), (2, 0), (2, 3), (3, 2)]:
        for bits in itertools.product([False, True], repeat=n*f):
            for labels in itertools.product([False, True], repeat=n):
                data = table(n, f, bits, labels); counts['tables'] += 1
                for order in itertools.permutations(data['features']):
                    check(data, order)

    # Two requests can require different, jointly indispensable observations.
    multi = {'requests': ['left', 'right'], 'histories': ['00', '01', '10', '11'],
             'features': ['x', 'y'],
             'policy': [[False, False, True, True], [False, True, False, True]],
             'observations': [[[False, False], [False, True], [True, False], [True, True]]]*2}
    check(multi, multi['features']); counts['edge_checks'] += 1

    # Exact equality of JSON values must not merge Boolean true with integer 1.
    typed = table(2, 1, [True, 1], [True, False])
    check(typed, ['f0']); counts['edge_checks'] += 1

    # Request-dependent observations, zero requests, and duplicate feature values.
    dependent = {'requests': ['q0', 'q1'], 'histories': ['h0', 'h1'], 'features': ['x'],
                 'policy': [[False, False], [False, True]],
                 'observations': [[[0], [0]], [[0], [1]]]}
    # Reusing request 0's observations would incorrectly report insufficiency.
    check(dependent, ['x']); counts['edge_checks'] += 1
    empty_q = {'requests': [], 'histories': ['h'], 'features': ['f'], 'policy': [], 'observations': []}
    check(empty_q, ['f']); counts['edge_checks'] += 1

    # The documented XOR example must demonstrate order-sensitive cardinality.
    xor = table(4, 3, [False, False, False, True, False, True,
                      True, True, False, False, True, True], [False, True, True, False])
    model, result = check(xor, ['f0', 'f1', 'f2'])
    _, other = check(xor, ['f1', 'f2', 'f0'])
    if len(result['features']) != 2 or len(other['features']) != 1:
        raise AssertionError('inclusion/cardinality distinction lost')
    counts['edge_checks'] += 1

    mutations = []
    bad = copy.deepcopy(result); bad['model_sha256'] = '0'*64; mutations.append(bad)
    bad = copy.deepcopy(result); bad['features'] = []; bad['witnesses'] = {}; mutations.append(bad)
    bad = copy.deepcopy(result); bad['witnesses'].pop(next(iter(bad['witnesses']))); mutations.append(bad)
    bad = copy.deepcopy(result); key = next(iter(bad['witnesses'])); bad['witnesses'][key] = ['q', 'h0', 'h0']; mutations.append(bad)
    bad = copy.deepcopy(result); bad['features'].append('unknown'); mutations.append(bad)
    bad = copy.deepcopy(result); bad['order'] = ['f0']*3; mutations.append(bad)
    bad = copy.deepcopy(result); bad['schema'] = True; mutations.append(bad)
    bad = copy.deepcopy(result); bad['status'] = []; mutations.append(bad)
    bad = copy.deepcopy(result); bad['status'] = {}; mutations.append(bad)
    for bad in mutations:
        try:
            module.verify_certificate(model, bad)
        except ValueError:
            counts['corrupted_certificates_rejected'] += 1
        else:
            raise AssertionError('corrupted certificate accepted')

    for bad in [dict(typed, policy=[[1, 0]]), dict(typed, histories=['h0', 'h0']),
                dict(typed, observations=[[[float('nan')], [False]]])]:
        try:
            module.Model.from_data(bad)
        except ValueError:
            counts['edge_checks'] += 1
        else:
            raise AssertionError('malformed model accepted')

    report = {'kind': 'Finite algorithm regression; not security efficacy or a general proof',
              'exit_code': 0, 'counts': counts,
              'source_sha256': {name: hashlib.sha256((work/Path(name).name).read_bytes()).hexdigest()
                                for name in ['theory/finite_profiles.py', 'scripts/check_finite_profiles.py']},
              'scope': 'Exhaustive Boolean tables of declared sizes, all deletion orders, plus named edge/mutation checks.',
              'limits': ['The authored policy and history model are not validated against a deployment.',
                         'Python algorithm and certificate verifier are not machine-proved.',
                         'Inclusion-minimality is not minimum cardinality or query cost.']}
    (work/'result.json').write_text(json.dumps(report, indent=2)+'\n')
    (root/'theory/finite-verification.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
