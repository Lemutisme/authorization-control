#!/usr/bin/env python3
"""Read-only audit of the declared fact-placement development screen.

Native endpoints are never replaced by the effect-level diagnostics below.
No provider calls, candidate decisions, or runtime task inputs are generated.
"""
import argparse
import collections
import csv
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path

ARMS = ['none', 'minimal', 'full_facts', 'late_facts', 'literal_facts']
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('prior_analysis', ROOT / 'scripts/summarize_contract_study.py')
prior = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prior)
prior.ARMS = ARMS


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'))


def effects(raw):
    return [e['operation'] for e in raw['events'] if e.get('classified_mode') == 'effect' and not e['error']]


def logical_usage(ep):
    """Token exposures, including reused samples; not billed dollars."""
    out = collections.Counter()
    for role, calls in [('actor', ep.get('pi', {}).get('calls', [])), ('judge', ep.get('guard_calls', []))]:
        for call in calls:
            if role == 'actor':
                usage = call.get('usage') or call.get('cached_sample_usage')
                if usage:
                    out[role + '_input_tokens'] += sum(usage.get(k, 0) or 0 for k in ['input', 'cacheRead', 'cacheWrite'])
                    out[role + '_output_tokens'] += usage.get('output', 0) or 0
            else:
                usage = call.get('usage') or call.get('cached_sample_usage')
                if usage:
                    out[role + '_input_tokens'] += usage.get('input_tokens', 0) or 0
                    out[role + '_output_tokens'] += usage.get('output_tokens', 0) or 0
            if not usage:
                out[role + '_unknown_usage_calls'] += 1
    return out


def extended_audit(pair, base, config):
    audit = prior.audit(pair, base, config)
    empty_sha = hashlib.sha256(b'{}').hexdigest()
    raw_by_arm = {}
    for arm in ARMS:
        raw = json.loads(gzip.decompress((base / pair['case_id'] / (arm + '.json.gz')).read_bytes()))
        raw_by_arm[arm] = raw
        row = raw['result']
        stages = row.get('fact_stage_audit', [])
        if len(stages) != len(row.get('guard_calls', [])):
            audit['issues'].append(arm + ':stage_call_count')
        for stage in stages:
            if stage['mode'] != arm or stage['stage'] not in {'initial', 'adjudication'}:
                audit['issues'].append(arm + ':wrong_stage_mode')
            masked = arm == 'late_facts' and stage['stage'] == 'initial'
            if masked:
                if stage['visible_fact_keys'] or stage['visible_sha256'] != empty_sha:
                    audit['issues'].append(arm + ':initial_not_masked')
            elif stage['visible_sha256'] != stage['snapshot_sha256'] or stage['visible_fact_keys'] != stage['snapshot_fact_keys']:
                audit['issues'].append(arm + ':unexpected_fact_transform')
            if arm in {'minimal', 'none'} and stage['snapshot_sha256'] != empty_sha:
                audit['issues'].append(arm + ':unexpected_facts')
            if arm == 'literal_facts' and set(stage['visible_fact_keys']) - {'recipient_identifier_occurrences_in_observed_file_metadata'}:
                audit['issues'].append(arm + ':unexpected_literal_fact')
        if any(x['audit_error'] for x in raw.get('recipient_literal_audit', [])):
            audit['issues'].append(arm + ':recipient_diagnostic_error')
        for call in row.get('pi', {}).get('calls', []):
            x = call['coupling']
            path = base / pair['case_id'] / 'actor-cache' / (x['request_sha256'] + '.json')
            if not path.exists():
                audit['issues'].append(arm + ':actor_cache_missing')
                continue
            saved = json.loads(path.read_text())
            if saved['request_sha256'] != x['request_sha256'] or saved['response_sha256'] != x['response_sha256']:
                audit['issues'].append(arm + ':actor_cache_identity')
    audit['issues'] = sorted(set(audit['issues']))
    audit['valid'] = not audit['issues']
    return audit, raw_by_arm


def contrast(rows, on, off):
    known = [r for r in rows if all(r['arms'][a].get('native_utility') is not None for a in [on, off])]
    gains = [r['case_id'] for r in known if r['arms'][on]['native_utility'] and not r['arms'][off]['native_utility']]
    losses = [r['case_id'] for r in known if not r['arms'][on]['native_utility'] and r['arms'][off]['native_utility']]
    return dict(candidate=on, reference=off, known=len(known), unknown=len(rows)-len(known), gains=gains, losses=losses, net=len(gains)-len(losses))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--run', type=Path, required=True)
    p.add_argument('--protocol', type=Path, required=True)
    p.add_argument('--manifest', type=Path, required=True)
    p.add_argument('--native-source', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    data = json.loads(a.run.read_text())
    config_path = a.run.with_name('run-config.json')
    config = json.loads(config_path.read_text())
    protocol = json.loads(a.protocol.read_text())
    rows = sorted(data['rows'], key=lambda x: x['case_id'])
    assert data['run_config_sha256'] == sha(config_path)
    assert config['manifest_sha256'] == sha(a.manifest)
    assert config['python_hash_seed'] == protocol['controls']['python_hash_seed']
    assert config['clock_anchor'] == protocol['controls']['clock_anchor']
    assert config['sources']['fact_screen/protocol.json'] == sha(a.protocol)
    assert data['complete'] and len(rows) == len(protocol['screen_cases']) == len(set(r['case_id'] for r in rows))
    assert set(config['cases']) == set(protocol['screen_cases']) == {r['case_id'] for r in rows}
    assert all(r['run_config_sha256'] == sha(config_path) and set(r['arms']) == set(ARMS) for r in rows)
    native_checks = {}
    for rel in ['default_suites/v1/workspace/user_tasks.py', 'default_suites/v1/banking/user_tasks.py']:
        native_checks[rel] = sha(a.native_source / rel)
        assert native_checks[rel] == config['native_sources'][rel]
    audits, raw = [], {}
    for row in rows:
        audit, contents = extended_audit(row, a.run.parent, config)
        audits.append(audit)
        raw[row['case_id']] = contents
    strata = {}
    for condition in ['clean', 'attack']:
        selected = [r for r in rows if r['condition'] == condition]
        arms = {}
        for arm in ARMS:
            eps = [r['arms'][arm] for r in selected]
            arms[arm] = prior.counts(eps)
            arms[arm]['logical_token_exposure'] = dict(sum((logical_usage(e) for e in eps), collections.Counter()))
            if condition == 'attack':
                arms[arm]['asr'] = sum(e.get('native_targeted_asr') is True for e in eps)
                arms[arm]['asr_unknown'] = sum(e.get('native_targeted_asr') is None for e in eps)
        contrasts = [contrast(selected, arm, ref) for ref in ['none', 'minimal', 'full_facts'] for arm in ARMS[1:] if arm != ref]
        strata[condition] = dict(n=len(selected), arms=arms, contrasts=contrasts)
    discordances = []
    for row in rows:
        for on, off in [('full_facts', 'minimal'), ('late_facts', 'minimal'), ('literal_facts', 'minimal'), ('late_facts', 'full_facts'), ('literal_facts', 'full_facts')]:
            first, second = row['arms'][on], row['arms'][off]
            if first['native_utility'] == second['native_utility']:
                continue
            item = prior.localize_discordance(row, on, off, a.run.parent, next(x['valid'] for x in audits if x['case_id'] == row['case_id']))
            ea, eb = effects(raw[row['case_id']][on]), effects(raw[row['case_id']][off])
            item.update(successful_effects={on: ea, off: eb}, exact_effect_sequence_equal=ea == eb,
                        exact_effect_multiset_equal=collections.Counter(map(canonical, ea)) == collections.Counter(map(canonical, eb)))
            discordances.append(item)
    witness_id = 'workspace__user_task_25__injection_task_8'
    witness = {}
    for arm in ARMS:
        episode = raw[witness_id][arm]
        sends = [op for op in effects(episode) if op['function'] == 'send_email']
        files = episode['initial']['cloud_drive']['files']
        designated = [f for f in files.values() if f['filename'] == 'team-meeting-minutes.docx']
        witness[arm] = dict(native_utility=episode['result']['native_utility'], sends=sends,
                           recipient_literal_audit=episode.get('recipient_literal_audit', []),
                           designated_file_metadata=[{k: f[k] for k in ['id_', 'filename', 'owner', 'shared_with'] if k in f} for f in designated],
                           raw_sha256=sha(a.run.parent/witness_id/(arm+'.json.gz')))
    a.out.mkdir(parents=True, exist_ok=True)
    csv_hashes = {}
    for arm in ARMS:
        path = a.out / (arm + '-episodes.csv')
        records = [dict(case_id=r['case_id'], condition=r['condition'], arm=arm, utility=r['arms'][arm]['native_utility'],
                        asr=r['arms'][arm].get('native_targeted_asr'), status=r['arms'][arm]['status'],
                        actor_calls=len(r['arms'][arm]['pi']['calls']), judge_calls=len(r['arms'][arm]['guard_calls'])) for r in rows]
        with path.open('w', newline='') as f:
            w = csv.DictWriter(f, fieldnames=list(records[0]), lineterminator='\n')
            w.writeheader()
            w.writerows(records)
        csv_hashes[path.name] = sha(path)
    totals = prior.counts([r['arms'][arm] for r in rows for arm in ARMS])
    report = dict(kind='Post-run read-only audit; native endpoints retained; selected development screen',
                  analysis_source_sha256=sha(Path(__file__)), input_sha256=dict(results=sha(a.run), config=sha(config_path), protocol=sha(a.protocol), manifest=sha(a.manifest)),
                  native_source_sha256=native_checks, observed=len(rows), episodes=len(rows)*len(ARMS), elapsed_s=data['elapsed_s'],
                  strata=strata, totals=totals, audit_findings=[x for x in audits if not x['valid']],
                  audit_checks=audits, discordances=discordances, episode_csv_sha256=csv_hashes,
                  stage_visibility_limit='Checks instrumented wrapper logs plus pinned qualification; not independent capture of provider requests.',
                  cost_limit='Logical tokens include reused samples. Actual network usage is shared across arms; arm timing is not standalone deployment latency. No billed dollar total is inferred.',
                  scope='32 outcome-informed development cases, no held-out or full-registry performance inference; no native endpoint normalized or replaced.')
    (a.out/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
    (a.out/'email-order-witness.json').write_text(json.dumps(dict(case_id=witness_id, arms=witness,
        finding='minimal and late_facts have identical successful send_email operation multisets but different order and native utility; the evaluator ignores recipients and pairs deadlines with increasing email IDs.',
        limit='Literal occurrence is inspectable source support, not proof of identity or permission. No runtime gold access or new endpoint.'), indent=2)+'\n')
    print(json.dumps(dict(observed=len(rows), audit_findings=report['audit_findings'], strata={k: {a: v['utility'] for a,v in g['arms'].items()} for k,g in strata.items()}, cost=totals['cost']), indent=2))
    if report['audit_findings']:
        raise SystemExit('Audit findings require inspection; all cases retained.')


if __name__ == '__main__':
    main()
