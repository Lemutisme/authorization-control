"""Prepare the fixed common Flash transfer panel without opening efficacy data."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from strict_effects import DEFINITION as STRICT_DEFINITION, source_metadata as strict_source_metadata

HERE = Path(__file__).resolve().parent
STUDY = HERE.parent
MODELS = ['glm', 'minimax', 'mimo', 'qwen']
REFERENCE_MODELS = ['luna', 'haiku', 'deepseek']
DEFAULT_MODES = {
    'glm': {'model_id': 'zai/glm-5.3-flash', 'reasoning_mode': 'low', 'actor_output_tokens': 8192,
            'policy_output_tokens': 8192, 'temperature': 0.7,
            'mode_scope': 'Documented always-thinking family; requested low effort.'},
    'minimax': {'model_id': 'minimax/minimax-m3.1-flash', 'reasoning_mode': 'low', 'actor_output_tokens': 8192,
                'policy_output_tokens': 8192, 'temperature': 0.7,
                'mode_scope': 'Documented always-thinking family; requested low effort.'},
    'mimo': {'model_id': 'xiaomimimo/mimo-v2.6-flash', 'reasoning_mode': 'default', 'actor_output_tokens': 8192,
             'policy_output_tokens': 8192, 'temperature': 0.7,
             'mode_scope': 'Native default; no undocumented no-thinking claim.'},
    'qwen': {'model_id': 'qwen/qwen3.8-flash-next', 'reasoning_mode': 'off', 'actor_output_tokens': 1400,
             'policy_output_tokens': 8192, 'temperature': 0.7,
             'mode_scope': 'Candidate off control; Canopy behavior requires infrastructure qualification.'},
}


def load(path):
    return json.loads(Path(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def selection_hash(packet_id):
    return hashlib.sha256(('flash-transfer-v1:' + packet_id).encode('utf-8')).hexdigest()


def choose_actor_panel(rows):
    tasks = defaultdict(list)
    for row in rows:
        tasks[row['cluster_id']].append(row)
    chosen, audit = [], []
    for task, candidates in sorted(tasks.items()):
        ordered = sorted(candidates, key=lambda r: (selection_hash(r['packet_id']), r['packet_id']))
        selected = ordered[0]
        chosen.append({**selected, 'selection_sha256': selection_hash(selected['packet_id'])})
        audit.append({'task': task, 'selected_packet_id': selected['packet_id'],
                      'candidates': [{'packet_id': r['packet_id'], 'selection_sha256': selection_hash(r['packet_id']),
                                      'selected': r['packet_id'] == selected['packet_id'],
                                      'packet_path': r['path'], 'packet_sha256': r['sha256']} for r in ordered]})
    return chosen, audit


def make_rows(actor, updates, contexts, models):
    rows = []
    for unit in actor:
        for model in models:
            for direction in ['corruption', 'correction']:
                for feedback in ['value_stating', 'value_free']:
                    rows.append({'id': 'actor__' + unit['packet_id'] + '__' + model + '__' + direction + '__' + feedback,
                                 'kind': 'actor', 'model': model, 'packet': unit['path'], 'packet_sha256': unit['sha256'],
                                 'packet_id': unit['packet_id'], 'suite': unit['suite'], 'fault_class': unit['fault_class'],
                                 'direction': direction, 'feedback': feedback, 'repetition': 0, 'task': unit['cluster_id']})
    for unit in updates:
        for model in models:
            for visible in [False, True]:
                rows.append({'id': 'update__' + unit['unit_id'] + '__' + model + '__r0__u' + str(int(visible)),
                             'kind': 'update', 'model': model, 'packet': unit['packet'], 'packet_sha256': unit['sha256'],
                             'unit_id': unit['unit_id'], 'visible': visible, 'repetition': 0, 'panel': unit['panel'],
                             'task': 'banking__' + unit['task_id']})
    for unit in contexts:
        for model in models:
            rows.append({'id': 'unforced__' + unit['context_id'] + '__' + model,
                         'kind': 'unforced', 'model': model, 'packet': unit['packet_path'],
                         'packet_sha256': sha(unit['packet_path']), 'context_id': unit['context_id'],
                         'direction': 'corruption', 'feedback': 'value_free', 'repetition': 0, 'task': unit['cluster_id']})
    return rows


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def prepare(mode_file=None):
    source_paths = {'actor_manifest': STUDY/'correctness/frozen-v1/manifest.json',
                    'update_index': STUDY/'updates/index.json',
                    'unforced_contexts': STUDY/'correctness/frozen-v1/spontaneous-contexts.json',
                    'original_main_protocol': STUDY/'protocol-main.json',
                    'strict_effect_helper': HERE/'strict_effects.py',
                    'source_noop_correction': STUDY/'correctness/SOURCE-NOOP-CORRECTION.md'}
    actor_all = load(source_paths['actor_manifest'])['rows']
    updates = load(source_paths['update_index'])['units']
    contexts = load(source_paths['unforced_contexts'])['contexts']
    original = load(source_paths['original_main_protocol'])
    assert len(actor_all) == 83 and len(updates) == 136 and len(contexts) == 33
    actor, audit = choose_actor_panel(actor_all)
    assert len(actor) == 31 and len({r['cluster_id'] for r in actor}) == 31
    # Inspect hashes and declared source metadata only, never new model results.
    for row in actor_all:
        assert sha(row['path']) == row['sha256']
    for row in updates:
        assert sha(row['packet']) == row['sha256']
    source = {name: {'path': str(path), 'sha256': sha(path)} for name, path in source_paths.items()}
    modes = copy.deepcopy(DEFAULT_MODES)
    for cfg in modes.values():
        cfg['qualification_status'] = 'provisional_pending_infrastructure'
    if mode_file is not None:
        supplied = load(mode_file)
        if set(supplied) != set(MODELS):
            raise ValueError('Mode finalization must explicitly retain all four requested aliases')
        for model, config in supplied.items():
            if config.get('model_id') != DEFAULT_MODES[model]['model_id']:
                raise ValueError('Cannot substitute a different requested model route')
            modes[model].update(config)
        source['mode_finalization'] = {'path': str(mode_file), 'sha256': sha(mode_file)}
    provisional = any(c['qualification_status'].startswith('provisional') for c in modes.values())
    selected_noops = []
    for row in actor:
        packet = load(row['path'])
        reference = packet['cells']['actor_wrong__gate_wrong']['native_reference']
        legacy_noop = reference['selected_field_noop']
        strict_noop = legacy_noop
        if packet['unit']['function'] == 'update_scheduled_transaction':
            event = reference['native_event']; field = packet['unit']['argument']; identifier = str(event['operation']['args']['id'])
            before = {str(x['id']): x for x in event['before']['bank_account']['scheduled_transactions']}
            after = {str(x['id']): x for x in event['after']['bank_account']['scheduled_transactions']}
            strict_noop = before[identifier][field] == after[identifier][field]
        if legacy_noop or strict_noop:
            selected_noops.append({'packet_id': row['packet_id'], 'legacy_no_selected_effect': legacy_noop,
                                   'strict_selected_field_noop': strict_noop})
    panel = {'version': 'flash-transfer-v1', 'selection_rule': "Within each owner task, minimize SHA256(UTF8('flash-transfer-v1:' + packet_id)); lexical packet_id breaks a hypothetical hash tie.",
             'original_faults': 83, 'selected_faults': 31, 'retained_owner_tasks': 31,
             'by_suite': dict(Counter(r['suite'] for r in actor)), 'by_fault_class': dict(Counter(r['fault_class'] for r in actor)),
             'selected_reference_noops': selected_noops, 'selected_rows': actor, 'all_candidate_hashes': audit,
             'source_inputs': source, 'efficacy_outputs_opened_for_selection': 0,
             'selection_scope': 'Prospective fixed source panel for new routes; retrospective outcome-independent common-row readback for existing routes. No winner/outcome-based pruning.'}
    save(HERE/'selected-actor-panel.json', panel)
    updater_pilot = [min([r for r in updates if r['panel'] == panel_name],
                        key=lambda r: (hashlib.sha256(('flash-updater-pilot-v1:' + r['unit_id']).encode()).hexdigest(), r['unit_id']))
                     for panel_name in ['honest_fault', 'attack', 'honest_natural']]
    actor_pilot = [min([r for r in actor if r['suite'] == suite], key=lambda r: (r['selection_sha256'], r['packet_id']))
                   for suite in ['banking', 'workspace', 'travel', 'slack']]
    common = {'version': 'flash-transfer-v1', 'models': MODELS,
              'requested_models': {m: modes[m]['model_id'] for m in MODELS}, 'model_modes': modes,
              'modes_provisional': provisional, 'source_inputs': source,
              'source_actor_panel': {'path': str(HERE/'selected-actor-panel.json'), 'sha256': sha(HERE/'selected-actor-panel.json')},
              'actor_sampling': 'Both off-diagonal correctness conditions and both feedback messages at each selected owner-task fault; one fresh draw sequence per cell.',
              'generator_sampling': 'All136 source prefixes, both proposal-visibility arms, one fresh repetition per source/arm; no first-update source pruning.',
              'primary_unit': 'Owner task; one selected actor fault per each of31 tasks. Updater source prefixes are averaged within owner task before task-macro contrasts.',
              'model_comparison_scope': 'Configuration strata, not pure weights effects or uniform reasoning/output budgets. Preserve actual provider mode, identity, reasoning use and token costs.',
              'actor_primary_endpoint': STRICT_DEFINITION,
              'actor_secondary_endpoint': 'Original X1 effect_values, reported separately as legacy; never substituted for strict actual selected-field/member changes.',
              'endpoint_amendment': {'timing': 'Before any new Flash model efficacy sampling.',
                  'reason': 'Known inherited scheduled-transaction extractor counted a selected amount whenever its row changed, even when only the recipient changed. Duplicate memberships are likewise not new relations.',
                  'scope': 'New Flash primary and exact common-row descriptive readback only. All31 sources remain fixed, including2 strict no-op references. Original full909-study registered primary/results are unchanged.',
                  'source_issue': source['source_noop_correction'], 'strict_helper': strict_source_metadata()},
              'budget': {'cumulative_actor_draws': 16, 'historical_draws_count': True,
                         'generator_output_tokens': 8192, 'generator_total_calls_cap': 64},
              'stopping': 'Complete all fixed scheduled rows. Operational failures and unsupported configurations remain explicit; no efficacy-based early stopping or unreported replacement.',
              'old_main_unchanged': 'The original909-unit schedule for each of Luna, Haiku and DeepSeek remains unchanged. In particular DeepSeekv4 must complete its full909; this new429-unit transfer panel is not its replacement.',
              'launch_status': 'Preparation only. No model calls or launches by this script. Shared Canopy quota and the running DeepSeek campaign are managed by the root.'}
    for phase in ['pilot', 'main']:
        rows = make_rows(actor_pilot if phase == 'pilot' else actor,
                         updater_pilot if phase == 'pilot' else updates,
                         [] if phase == 'pilot' else contexts, MODELS)
        count = Counter(r['kind'] for r in rows)
        expected = 22 if phase == 'pilot' else 429
        assert len(rows) == len(MODELS)*expected
        protocol = {**common, 'phase': phase, 'rows': rows, 'scheduled': len(rows),
                    'per_model_scheduled': expected, 'counts': dict(count),
                    'per_model_counts': {kind: count[kind]//len(MODELS) for kind in count},
                    'pilot_scope': 'Pilot reuses preselected source contexts with disjoint draws/output namespaces; feasibility only, excluded from main. Actor pilot: minimum selection hash within each suite; updater pilot: minimum flash-updater-pilot-v1 hash within each panel.'}
        save(HERE/f'protocol-{phase}.json', protocol)
    reference_rows = make_rows(actor, updates, contexts, REFERENCE_MODELS)
    original_by_id = {r['id']: r for r in original['rows']}
    versions = {'luna': 'v1', 'haiku': 'v1', 'deepseek': 'v4'}
    for row in reference_rows:
        old = original_by_id[row['id']]
        for field in ['kind', 'model', 'packet', 'packet_sha256', 'repetition', 'task']:
            assert row[field] == old[field]
        if row['kind'] == 'actor':
            assert row['direction'] == old['direction'] and row['feedback'] == old['feedback']
        elif row['kind'] == 'update':
            assert row['visible'] == old['visible'] and row['panel'] == old['panel'] and row['repetition'] == 0
        row['reference_raw_path'] = str(STUDY/'outputs'/f"main-{row['model']}-{row['kind']}-{versions[row['model']]}"/'raw'/(row['id']+'.json.gz'))
        row['reference_output_version'] = versions[row['model']]
    assert len(reference_rows) == 1287
    reference = {'version': 'flash-transfer-reference-v1', 'phase': 'reference_readback_only',
                 'models': REFERENCE_MODELS, 'requested_models': {m: original['requested_models'][m] for m in REFERENCE_MODELS},
                 'model_output_versions': versions, 'rows': reference_rows, 'scheduled': len(reference_rows),
                 'per_model_scheduled': 429, 'per_model_counts': {'actor': 124, 'update': 272, 'unforced': 33},
                 'original_full_per_model_scheduled': {m: sum(r['model']==m for r in original['rows']) for m in REFERENCE_MODELS},
                 'original_full_schedule_unchanged': True, 'original_full_completion_not_inferred': True,
                 'source_inputs': source, 'source_actor_panel_sha256': sha(HERE/'selected-actor-panel.json'),
                 'scope': 'Retrospective common-row analysis of existing original outputs; exact actor rows and updater repetition0 only. No replacement of full results, no new draws, no reading outcomes to select rows, no treatment of missing outputs as safe.',
                 'actor_endpoints': {'strict': STRICT_DEFINITION, 'legacy': 'Inherited X1 effect_values; recompute both definitions from raw native traces.'},
                 'endpoint_comparison_scope': 'Strict is the new common-panel comparison definition, not a retroactive replacement of the original full909 primary.',
                 'model_modes': 'Retain actual original request/provider metadata from each raw record; do not assume new Flash modes or uniform output caps.'}
    save(HERE/'protocol-reference-main.json', reference)
    validation = {'selected_actor_faults': len(actor), 'owner_tasks': len({r['cluster_id'] for r in actor}),
                  'all83_candidate_hashes_retained': sum(len(x['candidates']) for x in audit),
                  'actor_suite_counts': panel['by_suite'], 'actor_fault_class_counts': panel['by_fault_class'],
                  'selected_reference_noops': selected_noops, 'updater_sources': len(updates),
                  'updater_panel_counts': dict(Counter(r['panel'] for r in updates)), 'unforced_contexts': len(contexts),
                  'main_per_model': 429, 'pilot_per_model': 22, 'new_main_total': 1716, 'new_pilot_total': 88,
                  'reference_common_rows': len(reference_rows), 'all_reference_rows_match_original_schedule': True,
                  'original_full_per_model_scheduled': reference['original_full_per_model_scheduled'],
                  'modes_provisional': provisional, 'model_calls': 0, 'efficacy_files_opened': 0,
                  'protocol_sha256': {str(p): sha(p) for p in [HERE/'protocol-main.json', HERE/'protocol-pilot.json', HERE/'protocol-reference-main.json']}}
    save(HERE/'panel-qualification.json', validation)
    print(json.dumps(validation, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--modes', type=Path, help='Explicit finalized mode metadata for all four aliases, after infrastructure qualification; cannot change requested route IDs.')
    args = parser.parse_args()
    prepare(args.modes)
