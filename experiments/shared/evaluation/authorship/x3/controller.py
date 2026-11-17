"""Observe the pinned Progent approver without replacing its decision rule."""
import copy
import importlib.util
import os
from pathlib import Path

EVALUATION = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    'x3_refinement_controllers', EVALUATION / 'refinement/controllers.py'
)
_reference = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_reference)
CoupledPolicyClient = _reference.CoupledPolicyClient
digest = _reference.digest

ARMS = ['optional_auto', 'optional_narrow', 'forced_auto', 'forced_narrow']


def split_arm(arm):
    if arm not in ARMS:
        raise ValueError('Unknown X3 arm: ' + str(arm))
    selector, approver = arm.split('_')
    return selector, approver


def non_generated(policy):
    """The original checker confines generated priority-100 rules only."""
    if policy is None:
        return None
    return {
        tool: [copy.deepcopy(rule) for rule in rules if rule[0] != 100]
        for tool, rules in policy.items()
        if any(rule[0] != 100 for rule in rules)
    }


def generated_tools(policy):
    return sorted(
        tool for tool, rules in (policy or {}).items()
        if any(rule[0] == 100 for rule in rules)
    )


def check_candidate(progent, policy, candidate, checker):
    """Pure admission diagnostic on a policy copy; never invoke a native effect."""
    prior = progent.security_policy
    progent.security_policy = copy.deepcopy(policy)
    try:
        checker(candidate['function'], copy.deepcopy(candidate['args']))
        return {'allowed': True, 'error': None}
    except Exception as error:
        return {'allowed': False, 'error': type(error).__name__, 'reason': str(error)}
    finally:
        progent.security_policy = prior


def diagnostic_subset(checker, before, after):
    """Record unsupported/exception outcomes rather than equating them to false."""
    try:
        return {'is_subset': bool(checker(copy.deepcopy(before), copy.deepcopy(after))), 'error': None}
    except Exception as error:
        return {'is_subset': None, 'error': type(error).__name__, 'message': str(error)}


def update_with_approval(progent, client, arm, params, result, *, eligible,
                         candidate=None, admission_checker=None):
    selector, approver = split_arm(arm)
    prior_flag = os.environ.get('SECAGENT_ONLY_ALLOW_NARROW')
    original_subset = progent.security_policy_subset_check
    before = copy.deepcopy(progent.security_policy)
    observed_checks = []

    def observed_subset(old, new):
        row = {
            'before': copy.deepcopy(old), 'candidate': copy.deepcopy(new),
            'before_sha256': digest(old), 'candidate_sha256': digest(new),
        }
        observed_checks.append(row)
        try:
            answer = original_subset(old, new)
            row.update(is_subset=bool(answer), error=None)
            return answer
        except Exception as error:
            row.update(is_subset=None, error=type(error).__name__, message=str(error))
            raise

    # The pinned library reads this flag at tool.py:464 for each update.
    # All source generation, parsing, retry and deletion code stays untouched.
    os.environ['SECAGENT_ONLY_ALLOW_NARROW'] = 'True' if approver == 'narrow' else 'False'
    progent.security_policy_subset_check = observed_subset
    record = None
    try:
        record = _reference.update_policy(progent, client, selector, params, result, eligible)
    finally:
        progent.security_policy_subset_check = original_subset
        if prior_flag is None:
            os.environ.pop('SECAGENT_ONLY_ALLOW_NARROW', None)
        else:
            os.environ['SECAGENT_ONLY_ALLOW_NARROW'] = prior_flag

    after = copy.deepcopy(progent.security_policy)
    record.update(
        x3_arm=arm, selector=selector, approver=approver,
        narrow_flag=approver == 'narrow', approver_checks=observed_checks,
        approver_accepts=sum(row.get('is_subset') is True for row in observed_checks),
        approver_rejects=sum(row.get('is_subset') is False for row in observed_checks),
        approver_errors=sum(row.get('is_subset') is None for row in observed_checks),
        non_generated_before=non_generated(before),
        non_generated_after=non_generated(after),
        non_generated_unchanged=non_generated(before) == non_generated(after),
        generated_tools_added=sorted(set(generated_tools(after)) - set(generated_tools(before))),
        generated_tools_removed=sorted(set(generated_tools(before)) - set(generated_tools(after))),
        final_subset_diagnostic=diagnostic_subset(original_subset, before, after),
        instrumentation_limit='applied/applications means entry to deletion, not completed installation; final state is authoritative',
    )
    if candidate is not None:
        assert admission_checker is not None
        pre = check_candidate(progent, before, candidate, admission_checker)
        post = check_candidate(progent, after, candidate, admission_checker)
        record['current_call_probe'] = {
            'operation': copy.deepcopy(candidate), 'before': pre, 'after': post,
            'new_admission': pre['allowed'] is False and post['allowed'] is True,
            'scope': 'Same full native argument tuple, no effect; this finite probe does not enumerate the policy language',
        }
    return record
