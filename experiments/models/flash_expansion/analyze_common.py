"""Common429-row readback, strict primary plus legacy secondary from raw traces.

Never changes or completes the original full909/model study. Missing files and
endpoint failures remain unknown. This module performs no model/native calls.
"""
from __future__ import annotations
import argparse
import collections
import gzip
import hashlib
import json
import random
import statistics
from fractions import Fraction
from pathlib import Path

from strict_effects import summaries_from_actor_raw, endpoint_values, source_metadata

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent
FIELDS = ['correct_selected_effect', 'wrong_selected_effect', 'fault_selected_effect']


def load(path):
    path = Path(path); data = path.read_bytes()
    return json.loads(gzip.decompress(data) if path.suffix == '.gz' else data)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def paired_contrast(rows, metric, arm_field, positive, negative):
    tasks = collections.defaultdict(lambda: collections.defaultdict(dict))
    for row in rows:
        s = row['source']
        key = (s['packet'], s['repetition'])
        if s[arm_field] in tasks[s['task']][key]:
            raise ValueError('Duplicate scheduled contrast cell')
        tasks[s['task']][key][s[arm_field]] = row['metrics'].get(metric)
    task_rows = []
    for task, units in sorted(tasks.items()):
        lower, upper = Fraction(), Fraction()
        for values in units.values():
            if set(values) != {positive, negative}:
                raise ValueError('Incomplete declared pairing, rather than a missing result')
            for arm, coefficient in [(positive, 1), (negative, -1)]:
                value = values[arm]
                if value is None:
                    lower += min(0, coefficient); upper += max(0, coefficient)
                else:
                    lower += coefficient*value; upper += coefficient*value
        task_rows.append({'task': task, 'source_repetitions': len(units),
                          'lower': float(lower/len(units)), 'upper': float(upper/len(units)),
                          'lower_exact': str(lower/len(units)), 'upper_exact': str(upper/len(units))})
    if not task_rows:
        return None
    lower = sum(Fraction(r['lower_exact']) for r in task_rows)/len(task_rows)
    upper = sum(Fraction(r['upper_exact']) for r in task_rows)/len(task_rows)
    sensitivity = []
    if len(task_rows) > 1:
        for removed in task_rows:
            retained = [r for r in task_rows if r is not removed]
            sensitivity.append({'removed_task': removed['task'],
                                'lower': statistics.mean(r['lower'] for r in retained),
                                'upper': statistics.mean(r['upper'] for r in retained)})
    interval = None
    if lower == upper:
        rng = random.Random(20261114)
        values = [r['lower'] for r in task_rows]
        boot = sorted(statistics.mean(rng.choices(values, k=len(values))) for _ in range(10000))
        interval = [boot[249], boot[9749]]
    return {'lower': float(lower), 'upper': float(upper), 'lower_exact': str(lower), 'upper_exact': str(upper),
            'task_count': len(task_rows), 'tasks': task_rows, 'leave_one_task_out': sensitivity,
            'descriptive_task_bootstrap95': interval,
            'uncertainty_scope': 'Exact binary missing-outcome bounds. Bootstrap only describes this inspected source-task panel; not a randomly sampled deployment population.'}


def binary(value):
    if value is None:
        return None
    if value is True or value == 1:
        return 1
    if value is False or value == 0:
        return 0
    raise ValueError('Nonbinary endpoint')


def raw_path(source, origin, phase, version, versions, flash_layout, outputs_root):
    model = source['model']
    if origin == 'reference':
        chosen = versions.get(model, source['reference_output_version'])
        return STUDY/'outputs'/f"main-{model}-{source['kind']}-{chosen}"/'raw'/(source['id']+'.json.gz'), chosen
    chosen = versions.get(model, version)
    kind = 'all' if phase == 'pilot' or flash_layout == 'all' else source['kind']
    return outputs_root/f"{phase}-{model}-{kind}-{chosen}"/'raw'/(source['id']+'.json.gz'), chosen


def observed_profile(request):
    provider = request.get('provider') if isinstance(request.get('provider'), dict) else {}
    wire = request.get('request') if isinstance(request.get('request'), dict) else {}
    return {'returned_model': request.get('returned_model'),
            'provider': {k: provider[k] for k in ['requested_model', 'reasoning_effort', 'requested_reasoning_mode', 'reasoning_fields'] if k in provider},
            'request': {k: wire[k] for k in ['model', 'max_tokens', 'max_output_tokens', 'temperature', 'thinking', 'reasoning', 'reasoning_effort', 'chat_template_kwargs'] if k in wire},
            'identity_matches': request.get('model_label_matches')}


def analyze(scope, phase, models, versions, version, flash_layout, outputs_root, out):
    protocols = []
    if scope in {'reference', 'combined'}:
        if phase != 'main':
            raise ValueError('Reference comparison is defined only for the exact main panel')
        path = HERE/'protocol-reference-main.json'
        protocols.append(('reference', path, load(path)))
    if scope in {'flash', 'combined'}:
        path = HERE/f'protocol-{phase}.json'
        protocols.append(('flash', path, load(path)))
    planned_models = [m for _, _, p in protocols for m in p['models']]
    selected_models = set(planned_models if models is None else models)
    if not selected_models or selected_models - set(planned_models):
        raise ValueError('Model selection must name scheduled models')
    if set(versions) - set(planned_models):
        raise ValueError('Version override names an unscheduled model')
    rows, packet_cache = [], {}
    usage = collections.defaultdict(collections.Counter)
    profiles = collections.defaultdict(collections.Counter)
    flat_disagreements = []
    for origin, protocol_path, protocol in protocols:
        for source in protocol['rows']:
            path, chosen_version = raw_path(source, origin, phase, version, versions, flash_layout, outputs_root)
            metrics = {'admission': None, 'native_utility': None,
                       **{definition+'_'+key: None for definition in ['strict', 'legacy'] for key in FIELDS}}
            row = {'source': source, 'origin': origin, 'raw_path': str(path), 'output_version': chosen_version,
                   'model_selected': source['model'] in selected_models, 'present': False, 'usable': False,
                   'metrics': metrics, 'status': 'unknown', 'reason': None}
            if source['model'] not in selected_models:
                row['reason'] = 'model_not_selected_for_this_readback'; rows.append(row); continue
            try:
                if source['packet'] not in packet_cache:
                    if sha(source['packet']) != source['packet_sha256']:
                        raise ValueError('Source packet hash changed')
                    packet_cache[source['packet']] = load(source['packet'])
                packet = packet_cache[source['packet']]
                raw = load(path); row['present'] = True; row['raw_sha256'] = sha(path)
                if raw.get('dry'):
                    raise ValueError('Dry output cannot enter efficacy analysis')
                if raw.get('model') != source['model'] or raw.get('repetition') != source['repetition']:
                    raise ValueError('Raw model/repetition differs from schedule')
                row['status'] = raw.get('status', 'update_returned')
                if source['kind'] == 'update':
                    if raw.get('proposal_visible') != source['visible'] or raw.get('unit_id') != source['unit_id']:
                        raise ValueError('Raw update assignment differs from schedule')
                    metrics['admission'] = binary(raw.get('admission'))
                    row['transport_failed'] = raw.get('transport_failed')
                elif source['kind'] == 'actor':
                    if raw.get('direction') != source['direction'] or raw.get('feedback') != source['feedback'] or raw.get('unforced'):
                        raise ValueError('Raw actor assignment differs from schedule')
                    summaries = summaries_from_actor_raw(raw, packet)
                    row['effect_summaries'] = summaries
                    for definition in ['strict', 'legacy']:
                        metrics.update({definition+'_'+k: v for k,v in endpoint_values(raw, summaries[definition]).items()})
                    # Utility is an independently scored task endpoint, not
                    # reconstructed from the selected effect projection.
                    metrics['native_utility'] = binary((raw.get('metrics') or {}).get('native_utility'))
                    flat = raw.get('metrics') or {}
                    # Existing reference flat metrics used the legacy endpoint.
                    # New Flash flat metrics must use strict, but both definitions
                    # above are always recomputed directly from event traces.
                    expected = 'legacy' if origin == 'reference' else 'strict'
                    mismatches = {k: {'recorded': flat.get(k), 'recomputed': metrics[expected+'_'+k]}
                                  for k in FIELDS if flat.get(k) != metrics[expected+'_'+k]}
                    if mismatches:
                        flat_disagreements.append({'id': source['id'], 'expected_flat_definition': expected, 'mismatches': mismatches})
                    row['first_action'] = raw.get('first_action')
                else:
                    if raw.get('unforced') is not True:
                        raise ValueError('Unforced schedule has another kind of trial')
                    row['first_action'] = raw.get('first_action')
                    row['unforced_scope'] = 'First response only; its native boundary metrics are not capability or execution scores.'
                row['usable'] = True
                for request in raw.get('requests', []):
                    usage[source['model']]['network_requests'] += request.get('network_requests', 1)
                    usage[source['model']]['identity_mismatch_requests'] += bool(request.get('ok') and request.get('model_label_matches') is not True)
                    profile = observed_profile(request)
                    profiles[source['model']][json.dumps(profile, sort_keys=True)] += 1
                    u = request.get('usage')
                    if not isinstance(u, dict) or not u:
                        usage[source['model']]['usage_missing_requests'] += 1; continue
                    usage[source['model']]['input_tokens'] += u.get('input_tokens', u.get('prompt_tokens', 0))
                    usage[source['model']]['output_tokens'] += u.get('output_tokens', u.get('completion_tokens', 0))
                    usage[source['model']]['cache_read_tokens'] += u.get('cache_read_input_tokens', 0)
                    usage[source['model']]['cache_write_tokens'] += u.get('cache_creation_input_tokens', 0)
                    reasoning = (u.get('completion_tokens_details') or {}).get('reasoning_tokens')
                    if reasoning is None:
                        reasoning = (u.get('output_tokens_details') or {}).get('reasoning_tokens', (u.get('output_tokens_details') or {}).get('thinking_tokens'))
                    if reasoning is None:
                        usage[source['model']]['reasoning_usage_unknown_requests'] += 1
                    else:
                        usage[source['model']]['reported_reasoning_tokens'] += reasoning
            except Exception as exc:
                row['reason'] = type(exc).__name__ + ': ' + str(exc)
            rows.append(row)
    counts, contrasts = [], {}
    for model in planned_models:
        for direction, effect in [('corruption', 'wrong_selected_effect'), ('correction', 'correct_selected_effect')]:
            selected = [r for r in rows if r['source']['model'] == model and r['source']['kind'] == 'actor' and r['source']['direction'] == direction]
            for definition in ['strict', 'legacy']:
                contrasts[model+'_'+direction+'_'+definition] = paired_contrast(selected, definition+'_'+effect, 'feedback', 'value_stating', 'value_free')
                for arm in ['value_stating', 'value_free']:
                    cell = [r for r in selected if r['source']['feedback'] == arm]
                    counts.append({'model': model, 'panel': direction, 'definition': definition, 'arm': arm, 'n': len(cell),
                                   'owner_tasks': len({r['source']['task'] for r in cell}),
                                   'wrong': sum(r['metrics'][definition+'_wrong_selected_effect'] == 1 for r in cell),
                                   'correct': sum(r['metrics'][definition+'_correct_selected_effect'] == 1 for r in cell),
                                   'utility': sum(r['metrics']['native_utility'] == 1 for r in cell),
                                   'unknown_primary': sum(r['metrics'][definition+'_'+effect] is None for r in cell)})
        for panel in ['attack', 'honest_fault', 'honest_natural']:
            selected = [r for r in rows if r['source']['model'] == model and r['source']['kind'] == 'update' and r['source']['panel'] == panel]
            contrasts[model+'_update_'+panel] = paired_contrast(selected, 'admission', 'visible', True, False)
            for visible in [False, True]:
                cell = [r for r in selected if r['source']['visible'] == visible]
                counts.append({'model': model, 'panel': 'update_'+panel, 'definition': 'original_call_admission',
                               'arm': 'visible' if visible else 'hidden', 'n': len(cell),
                               'owner_tasks': len({r['source']['task'] for r in cell}),
                               'admitted': sum(r['metrics']['admission'] == 1 for r in cell),
                               'unknown_primary': sum(r['metrics']['admission'] is None for r in cell)})
    completion = {m: {'planned': sum(r['source']['model']==m for r in rows),
                      'present': sum(r['source']['model']==m and r['present'] for r in rows),
                      'usable_artifacts': sum(r['source']['model']==m and r['usable'] for r in rows),
                      'selected_for_readback': m in selected_models,
                      'unforced_first_responses_retained': sum(r['source']['model']==m and r['source']['kind']=='unforced' and r['usable'] for r in rows)}
                  for m in planned_models}
    result = {'scope': scope, 'phase': phase, 'planned_rows': len(rows), 'selected_models': sorted(selected_models),
              'completion_on_common_panel_only': completion, 'counts': counts, 'contrasts': contrasts,
              'flat_metric_disagreements': flat_disagreements,
              'usage_on_selected_common_rows_only': {m: dict(v) for m,v in usage.items()},
              'observed_request_mode_strata': {m: [{'profile': json.loads(k), 'requests': n} for k,n in v.items()] for m,v in profiles.items()},
              'planned_flash_modes': next((p['model_modes'] for origin,_,p in protocols if origin=='flash'), None),
              'strict_effect_provenance': source_metadata(),
              'protocol_sha256': {str(path): sha(path) for _,path,_ in protocols},
              'raw_output_versions_override': versions, 'flash_layout': flash_layout,
              'original_full909_results_unchanged': True,
              'original_full909_completion_not_inferred': True,
              'scientific_scope': 'Common source rows only. Strict state-change endpoint is new Flash primary; legacy secondary is separately recomputed. Existing3-model common-row analysis is retrospective and never replaces original full909 results. Configuration modes/output budgets differ, so comparisons are not pure weights or uniform-compute effects.'}
    out.mkdir(parents=True, exist_ok=True)
    (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    (out/'rows.json').write_text(json.dumps(rows, indent=2)+'\n')
    lines = [f"Common transfer panel: {scope}; {len(rows)} planned rows retained, including missing/failed rows.",
             'Strict selected-field/member changes are primary for Flash; legacy counts remain separate. Full909/model results and completion status are unchanged.',
             'Target mismatch is not automatically an authorization violation; partial/compositional progress and native-utility limitations require a separate semantic audit. See semantic-scope-addendum.md. Correctness is of the selected projection, not an entire task trace.', '',
             '|Model|Panel|Definition|Arm|N|Target mismatch|Correct target effect|Utility|Admitted|Unknown primary|',
             '|---|---|---|---|---:|---:|---:|---:|---:|---:|']
    for row in counts:
        lines.append('|'+'|'.join(str(row.get(k, '—')) for k in ['model','panel','definition','arm','n','wrong','correct','utility','admitted','unknown_primary'])+'|')
    lines += ['', 'Paired task-macro contrasts:']
    for name, value in contrasts.items():
        if value:
            lines.append(f"- {name}: {100*value['lower']:.3f} to {100*value['upper']:.3f} pp over {value['task_count']} owner tasks; bounds reflect missingness.")
    lines += ['', 'Unforced rows retain first responses only. Use correctness/score_spontaneous.py with the corresponding protocol/output root for separate projection-level labels; native boundary metrics are not unforced capability scores.',
              'Observed provider modes and output caps are retained in result.json. No uniform no-thinking or pure-weights interpretation is claimed.']
    (out/'RESULTS.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'scope': scope, 'planned_rows': len(rows), 'completion_on_common_panel_only': completion,
                      'flat_metric_disagreements': len(flat_disagreements), 'out': str(out)}, indent=2))


def self_test():
    rows = []
    for task, a, b in [('a', 1, 0), ('b', None, 0)]:
        for arm, value in [('on', a), ('off', b)]:
            rows.append({'source': {'packet': task, 'repetition': 0, 'task': task, 'arm': arm}, 'metrics': {'metric': value}})
    result = paired_contrast(rows, 'metric', 'arm', 'on', 'off')
    assert result['lower'] == .5 and result['upper'] == 1
    for row in rows:
        row['metrics']['metric'] = None
    result = paired_contrast(rows, 'metric', 'arm', 'on', 'off')
    assert result['lower'] == -1 and result['upper'] == 1
    reference = load(HERE/'protocol-reference-main.json')
    assert len(reference['rows']) == 1287 and all(r['repetition']==0 for r in reference['rows'])
    for source in reference['rows']:
        path, chosen = raw_path(source, 'reference', 'main', 'v1', {}, 'split', HERE/'outputs')
        assert str(path) == source['reference_raw_path']
        assert chosen == ('v4' if source['model']=='deepseek' else 'v1')
    print(json.dumps({'self_test': 'passed', 'missing_pairs_not_safe': True,
                      'exact_reference_paths_checked': 1287, 'efficacy_outputs_opened': 0, 'model_calls': 0}))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope', choices=['reference','flash','combined'], default='reference')
    p.add_argument('--phase', choices=['main','pilot'], default='main')
    p.add_argument('--models', help='Comma-separated readback subset; unselected planned rows remain unknown.')
    p.add_argument('--model-versions', type=json.loads, default={})
    p.add_argument('--version', default='v1')
    p.add_argument('--flash-layout', choices=['split','all'], default='split', help='Explicit new Flash output layout; no automatic fallback.')
    p.add_argument('--outputs-root', type=Path, default=HERE/'outputs')
    p.add_argument('--out', type=Path)
    p.add_argument('--self-test', action='store_true')
    args = p.parse_args()
    if args.self_test:
        self_test()
    else:
        models = [m.strip() for m in args.models.split(',')] if args.models else None
        out = args.out or HERE/('analysis-common-'+args.scope)
        analyze(args.scope, args.phase, models, args.model_versions, args.version, args.flash_layout, args.outputs_root, out)
