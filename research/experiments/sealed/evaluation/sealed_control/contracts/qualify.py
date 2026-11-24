"""Model-free source/native qualification. No task/scorer data or model is used.

Run with the pinned native Python:
  python -B evaluation/sealed_control/contracts/qualify.py --out /tmp/x6-contracts.json
"""
from __future__ import annotations
from pipeline.paths import resolve as research_path
import argparse
import ast
from copy import deepcopy
import hashlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import socket
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from contracts import CONTRACT_VERSION, DEFAULT_PROFILE, ContractError, PROGENT_COMMIT, materialize, matches, project, protected_fields, registry_packet, strict_eq, strict_match_details, validate_binding

def blocked(*args, **kwargs):
    raise RuntimeError('Contract qualification network disabled')
socket.create_connection = blocked
socket.socket.connect = blocked

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--progent-source', type=Path, default=Path(research_path('progent')))
    args = parser.parse_args()
    from agentdojo.task_suite import get_suite
    from agentdojo.default_suites.v1.tools import banking_client as bank, user_account as user, file_reader
    suite = get_suite('v1.2.2', 'banking')
    functions = {function.name: function for function in suite.tools}
    checks = []
    records = {}

    def passed(name, condition=True):
        if not condition:
            raise AssertionError(name)
        checks.append(name)

    def normalized(function, values):
        return functions[function].parameters.model_validate(values).model_dump()

    def binding(function, assignments, selector=None):
        return {'status': 'bind', 'authorizations': [{'function': function, 'selector': selector or {}, 'assignments': assignments}]}

    def rejects(value, profile=DEFAULT_PROFILE):
        try:
            validate_binding(value, profile=profile)
        except ContractError:
            return True
        return False
    packet = registry_packet()
    passed('registry_exactly_all_native_suite_tools', set(packet['functions']) == set(functions))
    for name, function in functions.items():
        schema = function.parameters.model_json_schema()
        contract = packet['functions'][name]
        passed(f'{name}_native_fields', set(schema['properties']) == set(contract['fields']))
        passed(f'{name}_native_required', set(schema.get('required', [])) == {key for key, value in contract['fields'].items() if value['required']})
        for field, description in contract['fields'].items():
            if not description['required']:
                passed(f'{name}_{field}_native_default', schema['properties'][field]['default'] == description['default'])
    packet['functions'].pop('send_money')
    passed('registry_not_proposal_conditioned', list(inspect.signature(registry_packet).parameters) == ['profile'] and 'send_money' in registry_packet()['functions'])
    passed('helpers_not_registered', 'set_balance' not in packet['functions'] and 'set_iban' not in packet['functions'])

    def account():
        return bank.BankAccount(balance=2000, iban='fixture-owner', transactions=[], scheduled_transactions=[bank.Transaction(id=7, sender='fixture-owner', recipient='fixture-payee', amount=850, subject='fixture-old', date='2030-01-01', recurring=False)])
    authorized = binding('update_scheduled_transaction', {'amount': 1200, 'recurring': True}, {'id': 7})
    first = normalized('update_scheduled_transaction', {'id': 7, 'recurring': True, 'amount': None})
    second = normalized('update_scheduled_transaction', {'id': 7, 'amount': 1200})
    passed('staged_recurring_then_amount_both_compatible', matches(project('update_scheduled_transaction', first), authorized) and matches(project('update_scheduled_transaction', second), authorized))
    passed('strict_rejects_partial_steps_against_full_tuple', not strict_eq(project('update_scheduled_transaction', first), authorized) and (not strict_eq(project('update_scheduled_transaction', second), authorized)))
    combined = normalized('update_scheduled_transaction', {'id': 7, 'amount': 1200, 'recurring': True})
    passed('strict_accepts_exact_full_actual_write_map', strict_eq(project('update_scheduled_transaction', combined), authorized) and strict_match_details(project('update_scheduled_transaction', combined), authorized)['reason'] == 'exact_owner_tuple')
    partial_binding = binding('update_scheduled_transaction', {'recurring': True}, {'id': 7})
    passed('strict_accepts_independently_bound_partial_action', strict_eq(project('update_scheduled_transaction', first), partial_binding))
    no_write_defaults = normalized('update_scheduled_transaction', {'id': 7, 'recurring': True, 'amount': 0, 'recipient': '', 'subject': None})
    passed('strict_compares_effects_not_omitted_or_no_write_argument_syntax', strict_eq(project('update_scheduled_transaction', no_write_defaults), partial_binding))
    passed('strict_rejects_empty_or_unbound_tuples', not strict_eq(project('update_scheduled_transaction', {'id': 7}), authorized) and (not strict_eq(project('update_scheduled_transaction', combined), {'status': 'bind', 'authorizations': []})) and (not strict_eq(project('update_scheduled_transaction', combined), {'status': 'abstain', 'authorizations': []})) and (not strict_eq(project('update_scheduled_transaction', combined), binding('update_scheduled_transaction', {}, {'id': 7}))))
    passed('strict_protects_function_selector_and_values', not strict_eq(project('update_scheduled_transaction', {**combined, 'id': 8}), authorized) and (not strict_eq(project('update_scheduled_transaction', {**combined, 'amount': 1199}), authorized)) and (not strict_eq(project('update_password', {'password': 'same'}), binding('update_user_info', {'street': 'same'}))))
    state = account()
    bank.update_scheduled_transaction(state, **first)
    passed('first_partial_update_preserves_amount', state.scheduled_transactions[0].amount == 850 and state.scheduled_transactions[0].recurring is True)
    bank.update_scheduled_transaction(state, **second)
    passed('second_partial_update_preserves_recurring', state.scheduled_transactions[0].amount == 1200 and state.scheduled_transactions[0].recurring is True)
    fixtures = [{'id': 7}, {'id': 7, 'recipient': None, 'amount': None, 'recurring': None}, {'id': 7, 'recipient': '', 'amount': 0, 'subject': '', 'date': '', 'recurring': False}, {'id': 7, 'recipient': 'fixture-new', 'amount': -3, 'subject': 'changed', 'date': 'arbitrary', 'recurring': True}, {'id': 7, 'amount': '125.5', 'recurring': 'true'}]
    for index, fixture in enumerate(fixtures):
        state = account()
        before = state.scheduled_transactions[0].model_dump()
        call = normalized('update_scheduled_transaction', fixture)
        projection = project('update_scheduled_transaction', call, profile='all_writes')
        bank.update_scheduled_transaction(state, **call)
        passed(f'native_scheduled_partial_effect_{index}', state.scheduled_transactions[0].model_dump() == {**before, **projection['writes']})
    state = account()
    state.scheduled_transactions[0].recurring = True
    bank.update_scheduled_transaction(state, **normalized('update_scheduled_transaction', {'id': 7, 'recurring': False}))
    passed('false_does_not_cancel_native_recurrence', state.scheduled_transactions[0].recurring is True)
    state = account()
    before = state.model_dump()
    try:
        bank.update_scheduled_transaction(state, id=999, amount=5)
    except ValueError:
        passed('missing_target_is_native_error_without_mutation', state.model_dump() == before)
    else:
        raise AssertionError('native missing target must raise')
    state = account()
    transfer = normalized('send_money', {'recipient': '', 'amount': 0, 'subject': '', 'date': ''})
    bank.send_money(state, **transfer)
    transaction = state.transactions[-1].model_dump()
    passed('send_writes_even_zero_and_empty', all((transaction[key] == value for key, value in project('send_money', transfer, profile='all_writes')['writes'].items())))
    passed('send_source_implicit_fields_and_no_balance_debit', transaction['id'] == 8 and transaction['sender'] == 'fixture-owner' and (transaction['recurring'] is False) and (state.balance == 2000))
    scheduled = normalized('schedule_transaction', {**transfer, 'amount': -2, 'recurring': False})
    bank.schedule_transaction(state, **scheduled)
    passed('schedule_writes_false_negative_amount', state.scheduled_transactions[-1].id == 9 and all((getattr(state.scheduled_transactions[-1], key) == value for key, value in project('schedule_transaction', scheduled, profile='all_writes')['writes'].items())))
    passed('native_zero_transaction_count_returns_all', bank.get_most_recent_transactions(state, n=0) == state.transactions)
    profile = user.UserAccount(first_name='First', last_name='Last', street='Old', city='City', password='fixture-old')
    call = normalized('update_user_info', {'street': 'New', 'first_name': '', 'city': None})
    before = profile.model_dump()
    user.update_user_info(profile, **call)
    passed('native_profile_partial_effect', profile.model_dump() == {**before, **project('update_user_info', call)['writes']})
    password = binding('update_password', {'password': ''})
    passed('empty_password_is_actual_authorized_write', matches(project('update_password', {'password': ''}), password))
    user.update_password(profile, password='')
    passed('native_empty_password_is_assigned', profile.password == '')
    passed('password_not_in_profile_read', 'password' not in user.get_user_info(profile))
    passed('missing_file_returns_empty', file_reader.read_file(file_reader.Filesystem(files={}), 'missing') == '')
    passed('function_identity_protected', not matches(project('update_password', {'password': 'same'}), binding('update_user_info', {'street': 'same'})))
    passed('target_identity_protected', not matches(project('update_scheduled_transaction', {'id': 8, 'amount': 1200}), authorized))
    passed('unmentioned_writes_rejected', not matches(project('update_scheduled_transaction', {'id': 7, 'amount': 1200, 'recipient': 'fixture-other'}), authorized))
    passed('wrong_written_value_rejected', not matches(project('update_scheduled_transaction', {'id': 7, 'amount': 1199}), authorized))
    passed('vacuous_no_write_not_agreement', not matches(project('update_scheduled_transaction', {'id': 7}), authorized))
    two = binding('update_scheduled_transaction', {'amount': 10, 'recipient': 'A'}, {'id': 7})
    two['authorizations'].append({'function': 'update_scheduled_transaction', 'selector': {'id': 7}, 'assignments': {'amount': 20, 'recipient': 'B'}})
    passed('no_cross_tuple_cartesian_mix', not matches(project('update_scheduled_transaction', {'id': 7, 'amount': 10, 'recipient': 'B'}), two))
    passed('binding_empty_or_missing_fields_rejected', rejects({'status': [], 'authorizations': []}) and rejects({'status': 'bind', 'authorizations': []}) and rejects(binding('update_scheduled_transaction', {}, {'id': 7})) and rejects(binding('send_money', {'recipient': 'fixture-payee', 'amount': 10})))
    passed('binding_no_write_values_rejected', rejects(binding('update_scheduled_transaction', {'recurring': False}, {'id': 7})) and rejects(binding('update_scheduled_transaction', {'amount': None}, {'id': 7})))
    passed('unknown_binding_fields_rejected', rejects(binding('update_user_info', {'unknown': 'value'})))
    passed('nonfinite_binding_fails_closed', rejects(binding('update_scheduled_transaction', {'amount': float('nan')}, {'id': 7})) and rejects(binding('update_scheduled_transaction', {'amount': 10 ** 1000}, {'id': 7})))
    passed('read_does_not_authorize_effect', rejects(binding('get_balance', {'balance': 5})))
    passed('abstention_cannot_match', not matches(project('update_scheduled_transaction', second), {'status': 'abstain', 'authorizations': []}))
    passed('materialization_has_no_actor_fields', materialize(authorized) == {'function': 'update_scheduled_transaction', 'args': {'id': 7, 'amount': 1200, 'recurring': True}})
    passed('primary_declared_financial_projection_and_target_selector', protected_fields('send_money') == ('recipient', 'amount') and protected_fields('schedule_transaction') == ('recipient', 'amount', 'recurring') and (protected_fields('update_scheduled_transaction') == ('id', 'recipient', 'amount', 'recurring')) and (protected_fields('update_user_info') == ('first_name', 'last_name', 'street', 'city')) and (protected_fields('update_password') == ('password',)) and (protected_fields('read_file') == ()))
    passed('all_writes_sensitivity_preserves_full_write_scope', protected_fields('send_money', profile='all_writes') == ('recipient', 'amount', 'subject', 'date') and protected_fields('update_scheduled_transaction', profile='all_writes') == ('id', 'recipient', 'amount', 'subject', 'date', 'recurring'))
    primary_packet = registry_packet()
    sensitivity_packet = registry_packet(profile='all_writes')
    passed('both_profiles_expose_all_tools_and_full_operational_schemas', set(primary_packet['functions']) == set(sensitivity_packet['functions']) == set(functions) and all((primary_packet['functions'][name]['fields'] == sensitivity_packet['functions'][name]['fields'] for name in functions)))
    passed('primary_packet_declares_subject_date_residual', primary_packet['profile'] == 'banking_financial' and primary_packet['functions']['send_money']['residual_argument_fields'] == ['subject', 'date'] and (primary_packet['functions']['update_scheduled_transaction']['residual_argument_fields'] == ['subject', 'date']))
    complete = {'recipient': 'fixture-payee', 'amount': 25, 'subject': 'constructor memo', 'date': '2030-01-02'}
    independently_bound = binding('send_money', complete)
    different_residual = {**complete, 'subject': 'actor memo', 'date': '2030-02-03'}
    passed('primary_exact_and_compatible_compare_only_declared_projection', strict_eq(project('send_money', different_residual), independently_bound) and matches(project('send_money', different_residual), independently_bound))
    passed('all_writes_still_rejects_subject_or_date_difference', not strict_eq(project('send_money', different_residual, profile='all_writes'), independently_bound) and (not matches(project('send_money', different_residual, profile='all_writes'), independently_bound)))
    passed('materialize_retains_independent_complete_constructor_residuals', materialize(independently_bound) == {'function': 'send_money', 'args': complete} and materialize(independently_bound)['args']['subject'] != different_residual['subject'])
    passed('incomplete_creation_binding_never_filled_from_actor', rejects(binding('send_money', {'recipient': 'fixture-payee', 'amount': 25})) and rejects(binding('schedule_transaction', {'recipient': 'fixture-payee', 'amount': 25, 'recurring': True})))
    residual_only = {'id': 7, 'subject': 'updated memo', 'date': '2030-03-04'}
    residual_binding = binding('update_scheduled_transaction', {'subject': 'updated memo', 'date': '2030-03-04'}, {'id': 7})
    passed('residual_only_update_has_no_primary_repair_coverage', not project('update_scheduled_transaction', residual_only)['writes'] and (not strict_eq(project('update_scheduled_transaction', residual_only), residual_binding)) and (not matches(project('update_scheduled_transaction', residual_only), residual_binding)) and rejects(residual_binding))
    passed('residual_only_update_is_explicit_all_writes_sensitivity_coverage', strict_eq(project('update_scheduled_transaction', residual_only, profile='all_writes'), residual_binding) and materialize(residual_binding, profile='all_writes')['args'] == residual_only)
    partial_with_residual = {'id': 7, 'amount': 1200, 'subject': 'actor memo'}
    amount_binding = binding('update_scheduled_transaction', {'amount': 1200, 'subject': 'constructor memo'}, {'id': 7})
    passed('partial_financial_comparison_leaves_residual_write_to_policy', strict_eq(project('update_scheduled_transaction', partial_with_residual), amount_binding) and (not strict_eq(project('update_scheduled_transaction', partial_with_residual, profile='all_writes'), amount_binding)))
    missing_protected_binding = binding('update_scheduled_transaction', {'amount': 1200}, {'id': 7})
    extra_protected_write = {'id': 7, 'amount': 1200, 'recipient': 'fixture-other', 'subject': 'memo'}
    passed('every_active_protected_write_requires_one_tuple_coverage', not strict_eq(project('update_scheduled_transaction', extra_protected_write), missing_protected_binding) and (not matches(project('update_scheduled_transaction', extra_protected_write), missing_protected_binding)))
    forged = project('send_money', complete)
    forged['writes']['subject'] = 'not a primary protected field'
    missing_required = project('send_money', complete)
    del missing_required['writes']['amount']
    invalid_profile = project('send_money', complete)
    invalid_profile['profile'] = 'unregistered'
    passed('projection_profile_and_required_coordinates_cannot_be_forged', not strict_eq(forged, independently_bound) and (not matches(forged, independently_bound)) and (not strict_eq(missing_required, independently_bound)) and (not strict_eq(invalid_profile, independently_bound)))
    commit = subprocess.check_output(['git', '-C', str(args.progent_source), 'rev-parse', 'HEAD'], text=True).strip()
    passed('progent_source_commit_pinned', commit == PROGENT_COMMIT)
    source_receipts = []
    for module in (bank, user, file_reader):
        installed = Path(inspect.getsourcefile(module))
        upstream = args.progent_source / 'agentdojo/src' / Path(*module.__name__.split('.')).with_suffix('.py')
        passed(f'native_matches_progent_{module.__name__.rsplit('.', 1)[-1]}', installed.read_bytes() == upstream.read_bytes())
        source_receipts.append({'native_path': str(installed), 'progent_path': str(upstream), 'sha256': hashlib.sha256(installed.read_bytes()).hexdigest()})
    registration_path = args.progent_source / 'agentdojo/src/agentdojo/default_suites/v1/banking/task_suite.py'
    tree = ast.parse(registration_path.read_text())
    registered = next((node.value for node in tree.body if isinstance(node, ast.Assign) and any((isinstance(target, ast.Name) and target.id == 'TOOLS' for target in node.targets))))
    passed('progent_registered_tools_equal_native', [node.id for node in registered.elts] == list(functions))
    records.update(staged_partial_binding=authorized, source_receipts=source_receipts)
    result = {'ok': True, 'model_calls': 0, 'network': 'blocked', 'checks': checks, 'contract_version': CONTRACT_VERSION, 'primary_profile': DEFAULT_PROFILE, 'check_count': len(checks), 'python': sys.executable, 'python_version': sys.version, 'agentdojo_package_version': importlib.metadata.version('agentdojo'), 'agentdojo_suite_version': 'v1.2.2', 'progent_commit': commit, 'records': records}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'ok': True, 'checks': len(checks), 'out': str(args.out)}))
if __name__ == '__main__':
    main()
