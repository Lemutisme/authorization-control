"""Freeze X4 conditions and audit allocation from completed X1 pretreatment."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil

from kernel import AuditPlan


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cohort', type=Path, required=True)
    parser.add_argument('--branches', type=Path, required=True)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--suites', default='banking,workspace,travel,slack')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    cohort = json.loads(args.cohort.read_text())
    branches = json.loads(args.branches.read_text())
    prefix = json.loads((args.prefix / 'summary.json').read_text())
    assert prefix['complete']
    assert branches['manifest_sha256'] == sha(args.cohort)
    assert branches['prefix_summary_sha256'] == sha(args.prefix / 'summary.json')
    units = {unit['unit_id']: unit for unit in cohort['units']}
    suites = set(args.suites.split(','))
    rows = []
    for condition in branches['condition_rows']:
        if condition['feedback'] != 'F0' or units[condition['unit_id']]['suite'] not in suites:
            continue
        fault = condition['variant'] == 'fault' and condition['fault_class'] in {'M1', 'M2'} and condition['stratum'] == 'actor_right'
        repair = condition['variant'] == 'oracle_correct' and condition['stratum'] == 'target_wrong'
        if not fault and not repair:
            continue
        filename = 'conditions/' + condition['condition_id'] + '.json'
        save(args.out / filename, condition)
        rows.append({**condition, 'condition_file': filename, 'suite': units[condition['unit_id']]['suite']})
    plans = {}
    for key in sorted({row['fault_class'] + '/' + row['stratum'] for row in rows}):
        ids = sorted({row['unit_id'] for row in rows if row['fault_class'] + '/' + row['stratum'] == key})
        for h in [0, 1]:
            plan = AuditPlan.create(ids, scope='x4-v1/' + key, numerator=h)
            filename = 'audit-plans/' + key.replace('/', '-') + ('-H10' if h else '-H0') + '.json'
            save(args.out / filename, vars(plan))
            plans[key + ('/H10' if h else '/H0')] = filename
    shutil.copyfile(args.cohort, args.out / 'cohort.json')
    result = {
        'kind': 'X4 fixed diagnostic conditions and prospective audit allocation',
        'cohort': 'cohort.json', 'cohort_sha256': sha(args.out / 'cohort.json'),
        'source_branches_sha256': sha(args.branches),
        'prefix_summary_sha256': sha(args.prefix / 'summary.json'),
        'rows': rows, 'audit_plans': plans, 'conditions': len(rows),
        'units': len({row['unit_id'] for row in rows}), 'task_clusters': len({row['cluster_id'] for row in rows}),
        'source_coverage': branches['rows'],
        'scope': 'Same frozen X1 pre-treatment strata/faults; values are controller-fault fixtures/evaluator labels only. No source truth enters fresh actor or constructor model input.',
    }
    save(args.out / 'manifest.json', result)
    print(json.dumps({key: result[key] for key in ['conditions', 'units', 'task_clusters']}))


if __name__ == '__main__':
    main()
