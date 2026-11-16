"""Lumen429-row readback and read-only cross-provider common-panel comparison.

Never changes or completes the original full909/model study. Missing files and
endpoint failures remain unknown. This module performs no model/native calls.
"""
from __future__ import annotations
import argparse
import ast
import collections
import contextlib
import gzip
import hashlib
import io
import json
import random
import statistics
import tempfile
from fractions import Fraction
from pathlib import Path

from strict_effects import summaries_from_actor_raw, endpoint_values, source_metadata

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent
CANOPY = STUDY/'flash_expansion'
FIELDS = ['correct_selected_effect', 'wrong_selected_effect', 'fault_selected_effect']
FROZEN_V1_SHA256 = '7bf61349c36b73a172a587d48cb4b4b80be2b2e6aafc4774e1fbd051b2d92e89'


def reasoning_usage_observation(request):
    """Resolve one reported counter, preferring parsed provider metadata.

    Top-level and nested counters are alternate reports, not quantities to sum.
    Provider conflict/invalid flags prevent fallback to a convenient raw value.
    Metadata/raw disagreements also remain unknown. Missing is never zero.
    """
    metadata = request.get('reasoning_metadata')
    metadata = metadata if isinstance(metadata, dict) else {}
    usage = request.get('usage')
    usage = usage if isinstance(usage, dict) else {}
    completion = usage.get('completion_tokens_details')
    output = usage.get('output_tokens_details')
    completion = completion if isinstance(completion, dict) else {}
    output = output if isinstance(output, dict) else {}
    raw_paths = [('usage.reasoning_tokens', usage, 'reasoning_tokens'),
                 ('usage.completion_tokens_details.reasoning_tokens', completion, 'reasoning_tokens'),
                 ('usage.output_tokens_details.reasoning_tokens', output, 'reasoning_tokens'),
                 ('usage.output_tokens_details.thinking_tokens', output, 'thinking_tokens')]
    raw_sources = {path: container[key] for path, container, key in raw_paths if key in container}
    provider_sources = metadata.get('reasoning_token_sources')
    malformed_sources = provider_sources is not None and not isinstance(provider_sources, dict)
    provider_sources = provider_sources if isinstance(provider_sources, dict) else {}
    candidates = dict(raw_sources)
    candidates.update({'reasoning_metadata.reasoning_token_sources.'+str(k): v for k,v in provider_sources.items()})
    for name in ['reported_reasoning_tokens', 'reported_thinking_tokens']:
        if name in metadata:
            candidates['reasoning_metadata.'+name] = metadata[name]
    valid = {k:v for k,v in candidates.items() if isinstance(v, int) and not isinstance(v, bool) and v >= 0}
    invalid = {k:v for k,v in candidates.items() if v is not None and k not in valid}
    explicit_invalid = metadata.get('invalid_reasoning_counter_sources')
    explicit_invalid = explicit_invalid if isinstance(explicit_invalid, dict) else {}
    invalid.update({'provider_invalid.'+str(k): v for k,v in explicit_invalid.items()})
    if malformed_sources:
        invalid['reasoning_metadata.reasoning_token_sources'] = metadata['reasoning_token_sources']
    distinct = set(valid.values())
    provider_status = metadata.get('reasoning_counter_status')
    conflict = metadata.get('reasoning_token_conflict') is True or provider_status == 'conflicting' or len(distinct) > 1
    invalid_flag = bool(invalid) or provider_status == 'invalid'
    value, resolution = None, None
    if conflict:
        status = 'conflicting'
    elif invalid_flag:
        status = 'invalid'
    elif not valid:
        status = 'missing'
    else:
        status = 'reported'
        value = next(iter(distinct))
        if 'reasoning_metadata.reported_reasoning_tokens' in valid:
            resolution = 'provider_reported_reasoning_tokens'
        elif 'reasoning_metadata.reported_thinking_tokens' in valid:
            resolution = 'provider_reported_thinking_tokens'
        elif any(k.startswith('reasoning_metadata.reasoning_token_sources.') for k in valid):
            resolution = 'provider_source_counters'
        else:
            resolution = 'raw_usage_counters'
    return {'status': status, 'reported_reasoning_tokens': value, 'resolution_source': resolution,
            'raw_counter_sources': raw_sources, 'provider_counter_sources': provider_sources,
            'provider_counter_status': provider_status,
            'provider_conflict_flag': metadata.get('reasoning_token_conflict'),
            'conflict': conflict, 'invalid_sources': invalid}


def accumulate_reasoning_usage(counter, request):
    """Account once per request; duplicated equal counters are not summed."""
    observation = reasoning_usage_observation(request)
    value = observation['reported_reasoning_tokens']
    if value is None:
        counter['reasoning_usage_unknown_requests'] += 1
        counter['reasoning_usage_'+observation['status']+'_requests'] += 1
    else:
        counter['reasoning_usage_reported_requests'] += 1
        counter['reported_reasoning_tokens'] += value
        counter['reasoning_usage_explicit_zero_requests'] += value == 0
        counter['reasoning_usage_'+observation['resolution_source']+'_requests'] += 1
    return observation


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


def raw_path(source, origin, phase, version, versions, canopy_layout, outputs_root, canopy_outputs_root):
    model = source['model']
    if origin == 'reference':
        chosen = versions.get(model, source['reference_output_version'])
        return STUDY/'outputs'/f"main-{model}-{source['kind']}-{chosen}"/'raw'/(source['id']+'.json.gz'), chosen
    chosen = versions.get(model, version)
    if origin == 'lumen':
        return outputs_root/f"{phase}-{model}-all-{chosen}"/'raw'/(source['id']+'.json.gz'), chosen
    if origin != 'canopy':
        raise ValueError('Unknown provider origin')
    kind = 'all' if phase == 'pilot' or canopy_layout == 'all' else source['kind']
    return canopy_outputs_root/f"{phase}-{model}-{kind}-{chosen}"/'raw'/(source['id']+'.json.gz'), chosen


def observed_profile(request):
    provider = request.get('provider') if isinstance(request.get('provider'), dict) else {}
    wire = request.get('request') if isinstance(request.get('request'), dict) else {}
    return {'returned_model': request.get('returned_model'),
            'provider': {k: provider[k] for k in ['provider', 'provider_name', 'api', 'endpoint_sha256', 'requested_model', 'model_id', 'registry_root', 'registry_reported_root', 'reasoning_effort', 'requested_reasoning_mode', 'reasoning_fields'] if k in provider},
            'request': {k: wire[k] for k in ['model', 'max_tokens', 'max_output_tokens', 'max_completion_tokens', 'temperature', 'thinking', 'reasoning', 'reasoning_effort', 'chat_template_kwargs'] if k in wire},
            'identity_matches': request.get('model_label_matches')}


def analyze(scope, phase, models, versions, version, canopy_layout, outputs_root, canopy_outputs_root, out):
    protocols = []
    if scope in {'reference', 'existing', 'combined'}:
        if phase != 'main':
            raise ValueError('Reference comparison is defined only for the exact main panel')
        path = HERE/'protocol-reference-main.json'
        protocols.append(('reference', path, load(path)))
    if scope in {'canopy', 'existing', 'combined'}:
        path = HERE/f'protocol-canopy-{phase}.json'
        protocols.append(('canopy', path, load(path)))
    if scope in {'lumen', 'combined'}:
        path = HERE/f'protocol-{phase}.json'
        protocols.append(('lumen', path, load(path)))
    planned_models = [m for _, _, p in protocols for m in p['models']]
    selected_models = set(planned_models if models is None else models)
    if not selected_models or selected_models - set(planned_models):
        raise ValueError('Model selection must name scheduled models')
    if set(versions) - set(planned_models):
        raise ValueError('Version override names an unscheduled model')
    rows, packet_cache = [], {}
    usage = collections.defaultdict(collections.Counter)
    profiles = collections.defaultdict(collections.Counter)
    reasoning_resolutions = collections.defaultdict(collections.Counter)
    reasoning_issues = []
    flat_disagreements = []
    for origin, protocol_path, protocol in protocols:
        for source in protocol['rows']:
            path, chosen_version = raw_path(source, origin, phase, version, versions, canopy_layout, outputs_root, canopy_outputs_root)
            metrics = {'admission': None, 'native_utility': None,
                       **{definition+'_'+key: None for definition in ['strict', 'legacy'] for key in FIELDS}}
            row = {'source': source, 'origin': origin, 'provider_configuration_stratum': origin+'::'+source['model'],
                   'raw_path': str(path), 'output_version': chosen_version,
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
                    # New Canopy/Lumen flat metrics must use strict, but both definitions
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
                for request_ordinal, request in enumerate(raw.get('requests', [])):
                    usage[source['model']]['network_requests'] += request.get('network_requests', 1)
                    usage[source['model']]['identity_mismatch_requests'] += bool(request.get('ok') and request.get('model_label_matches') is not True)
                    profile = observed_profile(request)
                    profiles[source['model']][json.dumps(profile, sort_keys=True)] += 1
                    reasoning = accumulate_reasoning_usage(usage[source['model']], request)
                    resolution_key = json.dumps({'status': reasoning['status'],
                        'resolution_source': reasoning['resolution_source'],
                        'raw_counter_paths': sorted(reasoning['raw_counter_sources']),
                        'provider_counter_paths': sorted(reasoning['provider_counter_sources'])}, sort_keys=True)
                    reasoning_resolutions[source['model']][resolution_key] += 1
                    if reasoning['status'] in {'conflicting', 'invalid'}:
                        reasoning_issues.append({'id': source['id'], 'model': source['model'],
                            'raw_path': str(path), 'request_ordinal': request_ordinal, 'observation': reasoning})
                    u = request.get('usage')
                    if not isinstance(u, dict) or not u:
                        usage[source['model']]['usage_missing_requests'] += 1; continue
                    usage[source['model']]['input_tokens'] += u.get('input_tokens', u.get('prompt_tokens', 0))
                    usage[source['model']]['output_tokens'] += u.get('output_tokens', u.get('completion_tokens', 0))
                    usage[source['model']]['cache_read_tokens'] += u.get('cache_read_input_tokens', 0)
                    usage[source['model']]['cache_write_tokens'] += u.get('cache_creation_input_tokens', 0)
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
              'reasoning_usage_resolution_counts': {m: [{'resolution': json.loads(k), 'requests': n} for k,n in v.items()]
                                                   for m,v in reasoning_resolutions.items()},
              'reasoning_usage_conflicts_or_invalid': reasoning_issues,
              'reasoning_usage_definition': 'One nonnegative integer counter per request. Prefer provider parsed report/source metadata, validate raw top-level/nested alternatives, count equal duplicates once, and retain conflicts/invalid/missing as unknown. Explicit zero remains reported zero. No token count is inferred from reasoning text.',
              'observed_request_mode_strata': {m: [{'profile': json.loads(k), 'requests': n} for k,n in v.items()] for m,v in profiles.items()},
              'declared_provider_mode_budget_strata': {origin: {'models': p['models'],
                  'requested_models': p.get('requested_models'), 'model_modes': p.get('model_modes'),
                  'provider': p.get('provider', 'Canopy Wave' if origin=='canopy' else 'Retained original providers; inspect observed request receipts'),
                  'modes_provisional': p.get('modes_provisional'), 'model_configurations': p.get('model_configurations')}
                  for origin,_,p in protocols},
              'strict_effect_provenance': source_metadata(),
              'protocol_sha256': {str(path): sha(path) for _,path,_ in protocols},
              'raw_output_versions_override': versions, 'lumen_layout': 'all', 'canopy_layout': canopy_layout,
              'output_roots': {'lumen': str(outputs_root), 'canopy': str(canopy_outputs_root), 'reference': str(STUDY/'outputs')},
              'analysis_source_sha256': sha(Path(__file__)),
              'original_full909_results_unchanged': True,
              'original_full909_completion_not_inferred': True,
              'scientific_scope': 'Common source rows only. Strict state-change endpoint is shared Canopy/Lumen primary; legacy secondary is separately recomputed. Existing3-model common-row analysis is retrospective and never replaces original full909 results. Provider/model/mode/output-budget strata remain separate. Lumen GLM-5.3 is not Canopy GLM-5.3-Flash; the registry-described Lumen Qwen NVFP4 deployment is not assumed weight-equivalent to Canopy. Comparisons are not pure weights, equal-serving, or uniform-compute effects.'}
    out.mkdir(parents=True, exist_ok=True)
    (out/'result.json').write_text(json.dumps(result, indent=2)+'\n')
    (out/'rows.json').write_text(json.dumps(rows, indent=2)+'\n')
    lines = [f"Common transfer panel: {scope}; {len(rows)} planned rows retained, including missing/failed rows.",
             'Strict selected-field/member changes are primary for Canopy/Lumen; legacy counts remain separate. Full909/model results and existing Canopy results/completion status are unchanged.',
             'Lumen and Canopy model aliases are separate provider/model/mode/budget configurations; shared family names do not establish equal weights or serving.',
             'Target mismatch is not automatically an authorization violation; partial/compositional progress and native-utility limitations require a separate semantic audit. See ../flash_expansion/semantic-scope-addendum.md. Correctness is of the selected projection, not an entire task trace.', '',
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
        path, chosen = raw_path(source, 'reference', 'main', 'v1', {}, 'all', HERE/'outputs', CANOPY/'outputs')
        assert str(path) == source['reference_raw_path']
        assert chosen == ('v4' if source['model']=='deepseek' else 'v1')
    lumen = load(HERE/'protocol-main.json')
    canopy = load(HERE/'protocol-canopy-main.json')
    pilot = load(HERE/'protocol-pilot.json')
    canopy_pilot = load(HERE/'protocol-canopy-pilot.json')
    assert len(lumen['rows']) == 858 and len(pilot['rows']) == 44
    assert len(canopy['rows']) == 1716
    def assignment(row):
        return json.dumps({k:v for k,v in row.items() if k not in {'id','model'}}, sort_keys=True)
    for lp, cp in [(lumen, canopy), (pilot, canopy_pilot)]:
        expected = sorted(assignment(r) for r in cp['rows'] if r['model'] == cp['models'][0])
        for model in lp['models']:
            assert sorted(assignment(r) for r in lp['rows'] if r['model'] == model) == expected
    for source in lumen['rows']:
        path, chosen = raw_path(source, 'lumen', 'main', 'v1', {}, 'all', HERE/'outputs', CANOPY/'outputs')
        assert path.parent.parent.name == 'main-'+source['model']+'-all-v1'
    for source in canopy['rows']:
        path, chosen = raw_path(source, 'canopy', 'main', 'v1', {}, 'all', HERE/'outputs', CANOPY/'outputs')
        assert path.parent.parent.parent == CANOPY/'outputs'
    assert sha(HERE/'selected-actor-panel.json') == sha(CANOPY/'selected-actor-panel.json')
    assert sha(HERE/'strict_effects.py') == sha(CANOPY/'strict_effects.py')
    # Source-reference scoring only. No response/efficacy artifacts are opened.
    selected = load(HERE/'selected-actor-panel.json')['selected_rows']
    from strict_effects import summarize_effects
    noops = 0
    for source in selected:
        packet = load(source['path'])
        correct = packet['cells']['actor_correct__gate_correct']['native_reference']['native_event']
        faulty = packet['cells']['actor_wrong__gate_wrong']['native_reference']['native_event']
        cs = summarize_effects([correct], packet['unit'], packet['fault_value'])
        fs = summarize_effects([faulty], packet['unit'], packet['fault_value'])
        assert cs['correct_selected_effect'] and not cs['extraction_errors'] and not fs['extraction_errors']
        noops += not fs['fault_selected_effect']
    assert noops == 2
    # End-to-end dry readback against a deliberately empty namespace. It never
    # opens existing efficacy files and leaves no persistent output behind.
    with tempfile.TemporaryDirectory(prefix='.panel-dry-', dir=HERE) as directory:
        temp = Path(directory)
        with contextlib.redirect_stdout(io.StringIO()):
            analyze('lumen', 'main', None, {}, 'v1', 'all', temp/'absent-lumen',
                    temp/'absent-canopy', temp/'readback')
        dry = load(temp/'readback/result.json')
        assert dry['planned_rows'] == 858
        assert all(c['present'] == c['usable_artifacts'] == 0 for c in dry['completion_on_common_panel_only'].values())
        assert all(c['lower'] == -1 and c['upper'] == 1 for c in dry['contrasts'].values() if c is not None)
        assert all(row['unknown_primary'] == row['n'] for row in dry['counts'])
    print(json.dumps({'self_test': 'passed', 'missing_pairs_not_safe': True,
                      'exact_reference_paths_checked': 1287, 'lumen_main_rows':858, 'lumen_pilot_rows':44,
                      'common_source_assignments_match':True, 'copied_panel_and_strict_helper_identical':True,
                      'source_reference_effects_checked':62, 'selected_strict_noops':noops,
                      'combined_planned_rows':3861, 'empty_namespace_dry_rows':858,
                      'all_missing_primary_endpoints_remain_unknown':True,
                      'efficacy_outputs_opened': 0, 'model_calls': 0}))


def reasoning_usage_self_test():
    """Cost-accounting fixtures only; no formal efficacy artifact is opened."""
    fixtures = [
        ('top_zero', {'usage': {'reasoning_tokens': 0}}, 0, 'reported'),
        ('top_one', {'usage': {'reasoning_tokens': 1}}, 1, 'reported'),
        ('nested_completion', {'usage': {'completion_tokens_details': {'reasoning_tokens': 7}}}, 7, 'reported'),
        ('nested_output', {'usage': {'output_tokens_details': {'thinking_tokens': 3}}}, 3, 'reported'),
        ('missing', {'usage': {'completion_tokens': 12}}, None, 'missing'),
        ('raw_conflict', {'usage': {'reasoning_tokens': 1, 'completion_tokens_details': {'reasoning_tokens': 2}}}, None, 'conflicting'),
        ('duplicate_equal_locations', {'usage': {'reasoning_tokens': 4, 'completion_tokens_details': {'reasoning_tokens': 4},
                                                'output_tokens_details': {'reasoning_tokens': 4, 'thinking_tokens': 4}}}, 4, 'reported'),
        ('provider_zero_priority', {'usage': {'reasoning_tokens': 0}, 'reasoning_metadata': {
            'reported_reasoning_tokens': 0, 'reasoning_token_sources': {'usage.reasoning_tokens': 0},
            'reasoning_token_conflict': False, 'reasoning_counter_status': 'reported'}}, 0, 'reported'),
        ('provider_conflict_blocks_fallback', {'usage': {'reasoning_tokens': 1}, 'reasoning_metadata': {
            'reported_reasoning_tokens': None, 'reasoning_token_sources': {'usage.reasoning_tokens': 1},
            'reasoning_token_conflict': True, 'reasoning_counter_status': 'conflicting'}}, None, 'conflicting'),
        ('provider_raw_disagreement', {'usage': {'reasoning_tokens': 0}, 'reasoning_metadata': {
            'reported_reasoning_tokens': 1, 'reasoning_token_sources': {'usage.reasoning_tokens': 1},
            'reasoning_token_conflict': False, 'reasoning_counter_status': 'reported'}}, None, 'conflicting'),
        ('old_metadata_raw_fallback', {'usage': {'reasoning_tokens': 1}, 'reasoning_metadata': {
            'reported_reasoning_tokens': None, 'reported_thinking_tokens': None}}, 1, 'reported'),
        ('metadata_without_usage', {'reasoning_metadata': {'reported_reasoning_tokens': 2,
            'reasoning_token_sources': {'usage.reasoning_tokens': 2}, 'reasoning_counter_status': 'reported'}}, 2, 'reported'),
        ('invalid_boolean_counter', {'usage': {'reasoning_tokens': False}}, None, 'invalid'),
        ('provider_invalid_blocks_fallback', {'usage': {'reasoning_tokens': 1}, 'reasoning_metadata': {
            'reported_reasoning_tokens': None, 'reasoning_counter_status': 'invalid',
            'invalid_reasoning_counter_sources': {'usage.reasoning_tokens': 'unparseable'}}}, None, 'invalid'),
    ]
    fixture_results = []
    counter = collections.Counter()
    for name, request, expected, status in fixtures:
        observed = accumulate_reasoning_usage(counter, request)
        assert observed['reported_reasoning_tokens'] == expected and observed['status'] == status, name
        if name == 'provider_zero_priority':
            assert observed['resolution_source'] == 'provider_reported_reasoning_tokens'
        fixture_results.append({'name': name, 'expected': expected, 'observation': observed, 'passed': True})
    assert counter['reported_reasoning_tokens'] == sum(expected for _,_,expected,_ in fixtures if expected is not None)
    assert counter['reasoning_usage_reported_requests'] + counter['reasoning_usage_unknown_requests'] == len(fixtures)
    smoke_dir = HERE/'qualification/provider-smoke-v2'
    actual_counter = collections.Counter()
    actual_results = []
    for name, expected in [('qwen-first', 0), ('qwen-continuation', 0), ('glm-first', 1), ('glm-continuation', 1)]:
        path = smoke_dir/(name+'.json')
        request = load(path)
        assert request.get('ok') is True and request.get('model_label_matches') is True
        observed = accumulate_reasoning_usage(actual_counter, request)
        assert observed['status'] == 'reported' and observed['reported_reasoning_tokens'] == expected
        assert observed['resolution_source'] == 'provider_reported_reasoning_tokens'
        actual_results.append({'sample': name, 'path': str(path), 'sha256': sha(path),
            'returned_model': request.get('returned_model'), 'reasoning_tokens': observed['reported_reasoning_tokens'],
            'resolution_source': observed['resolution_source'], 'raw_sources': observed['raw_counter_sources'],
            'provider_sources': observed['provider_counter_sources'], 'passed': True})
    assert actual_counter['reported_reasoning_tokens'] == 2
    assert actual_counter['reasoning_usage_reported_requests'] == 4
    assert actual_counter['reasoning_usage_explicit_zero_requests'] == 2
    assert actual_counter['reasoning_usage_unknown_requests'] == 0
    # Assert the requested scientific logic is unchanged from the queued v1.
    old_path = HERE/'analyze_common.py'
    assert sha(old_path) == FROZEN_V1_SHA256, 'Queued v1 must remain unchanged'
    old_tree = ast.parse(old_path.read_text())
    new_tree = ast.parse(Path(__file__).read_text())
    def funcs(tree):
        return {n.name:n for n in tree.body if isinstance(n, ast.FunctionDef)}
    old_funcs, new_funcs = funcs(old_tree), funcs(new_tree)
    for name in ['load', 'sha', 'paired_contrast', 'binary', 'raw_path', 'observed_profile', 'self_test']:
        assert ast.dump(old_funcs[name], include_attributes=False) == ast.dump(new_funcs[name], include_attributes=False), name
    def endpoint_branch(function):
        found = [n for n in ast.walk(function) if isinstance(n, ast.If)
                 and ast.dump(n.test, include_attributes=False) == ast.dump(ast.parse("source['kind'] == 'update'", mode='eval').body, include_attributes=False)]
        assert len(found) == 1
        return found[0]
    assert ast.dump(endpoint_branch(old_funcs['analyze']), include_attributes=False) == ast.dump(endpoint_branch(new_funcs['analyze']), include_attributes=False)
    def contrast_loop(function):
        found = [n for n in function.body if isinstance(n, ast.For) and isinstance(n.target, ast.Name)
                 and n.target.id == 'model' and isinstance(n.iter, ast.Name) and n.iter.id == 'planned_models']
        assert len(found) == 1
        return found[0]
    assert ast.dump(contrast_loop(old_funcs['analyze']), include_attributes=False) == ast.dump(contrast_loop(new_funcs['analyze']), include_attributes=False)
    result = {'passed': True, 'synthetic_fixture_count': len(fixtures), 'fixtures': fixture_results,
              'synthetic_aggregation': dict(counter), 'actual_infrastructure_samples': actual_results,
              'actual_aggregation': dict(actual_counter), 'actual_reasoning_counts': [0,0,1,1],
              'actual_reasoning_sum': 2, 'actual_unknown_requests': 0,
              'equal_counter_locations_counted_once': True, 'conflicts_and_missing_remain_unknown': True,
              'effect_extraction_and_pairing_ast_unchanged': True,
              'queued_v1_sha256': sha(old_path), 'v2_sha256': sha(Path(__file__)),
              'formal_efficacy_outputs_opened': 0, 'model_calls': 0, 'native_tool_calls': 0}
    (HERE/'reasoning-usage-v2-check.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in {'fixtures','synthetic_aggregation','actual_infrastructure_samples','actual_aggregation'}}, indent=2))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope', choices=['lumen','reference','canopy','existing','combined'], default='lumen')
    p.add_argument('--phase', choices=['main','pilot'], default='main')
    p.add_argument('--models', help='Comma-separated readback subset; unselected planned rows remain unknown.')
    p.add_argument('--model-versions', type=json.loads, default={})
    p.add_argument('--version', default='v1')
    p.add_argument('--canopy-layout', choices=['split','all'], default='all', help='Explicit existing Canopy output layout; Lumen always uses all-role layout. No fallback.')
    p.add_argument('--outputs-root', type=Path, default=HERE/'outputs')
    p.add_argument('--canopy-outputs-root', type=Path, default=CANOPY/'outputs')
    p.add_argument('--out', type=Path)
    p.add_argument('--self-test', action='store_true')
    p.add_argument('--reasoning-self-test', action='store_true', help='Offline reasoning-counter fixtures and four retained infrastructure samples only.')
    args = p.parse_args()
    if args.self_test:
        self_test()
        reasoning_usage_self_test()
    elif args.reasoning_self_test:
        reasoning_usage_self_test()
    else:
        models = [m.strip() for m in args.models.split(',')] if args.models else None
        out = args.out or HERE/('analysis-common-'+args.scope)
        analyze(args.scope, args.phase, models, args.model_versions, args.version, args.canopy_layout, args.outputs_root, args.canopy_outputs_root, out)
