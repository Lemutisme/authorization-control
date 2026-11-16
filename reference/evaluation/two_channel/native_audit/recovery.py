"""Recover JSON numeric spelling only when the recorded Python digest proves it.

Node's JSON serialization turns schema numbers such as 4.0 into 4. We never edit
the trace, normalize errors, or accept a replacement without the original policy
SHA. Authoritative frozen source policies are checked before bounded search.
"""
from __future__ import annotations

import copy
import hashlib
import itertools
import json
import math

MAX_CANDIDATES = 1 << 20
_CACHE = {}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def semantic_equal(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return math.isfinite(a) and math.isfinite(b) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(semantic_equal(a[k], b[k]) for k in a)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        return len(a) == len(b) and all(semantic_equal(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and a == b


def schema_integer_paths(policy):
    paths = []
    def walk(value, path):
        if type(value) is int:
            try:
                converted = float(value)
            except OverflowError:
                return
            if math.isfinite(converted) and int(converted) == value:
                paths.append(path)
        elif isinstance(value, dict):
            for key, item in value.items():
                walk(item, path + [key])
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, path + [index])
    for name, rules in policy.items():
        for index, rule in enumerate(rules):
            if len(rule) < 3:
                raise ValueError('Malformed recorded policy rule')
            walk(rule[2], [name, index, 2])
    return paths


def spelling_changes(before, after, path=None):
    path = [] if path is None else path
    if type(before) is int and type(after) is float:
        return [{'path': path, 'serialized': repr(before), 'restored': repr(after)}]
    if isinstance(before, dict) and isinstance(after, dict):
        return [change for key in before for change in spelling_changes(before[key], after[key], path + [key])]
    if isinstance(before, list) and isinstance(after, (list, tuple)):
        return [change for index, (a, b) in enumerate(zip(before, after)) for change in spelling_changes(a, b, path + [index])]
    return []


def recover_policy(policy, expected_sha256, source_policy=None, *, max_candidates=MAX_CANDIDATES):
    """Return a verified representation or None with an explicit uncertain receipt.

    Search changes only integer leaves inside policy schemas to exactly
    representable floats. It enumerates the entire bounded candidate space and
    requires exactly one hash match. Missing/mismatched hashes never pass.
    """
    original_hash = digest(policy)
    receipt = {'expected_sha256': expected_sha256, 'serialized_sha256': original_hash,
        'source_checked': source_policy is not None, 'max_candidates': max_candidates}
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        return None, {**receipt, 'status': 'uncertain', 'reason': 'missing_decision_policy_hash'}
    # The immutable packet is authoritative and was loaded in Python, avoiding
    # the gzip artifact's Node round trip. Check it before any converted search.
    if source_policy is not None:
        source_hash = digest(source_policy)
        receipt['source_sha256'] = source_hash
        if source_hash == expected_sha256:
            if not semantic_equal(policy, source_policy):
                return None, {**receipt, 'status': 'uncertain', 'reason': 'source_policy_semantic_disagreement'}
            return copy.deepcopy(source_policy), {**receipt, 'status': 'verified',
                'method': 'frozen_source', 'hash_matches': 1, 'candidates_tested': 0,
                'changed': spelling_changes(policy, source_policy)}
    if original_hash == expected_sha256:
        return copy.deepcopy(policy), {**receipt, 'status': 'verified',
            'method': 'serialized_exact', 'hash_matches': 1, 'candidates_tested': 0, 'changed': []}
    key = (original_hash, expected_sha256, max_candidates)
    if key in _CACHE:
        recovered, cached = _CACHE[key]
        return copy.deepcopy(recovered), {**receipt, **copy.deepcopy(cached), 'cache_hit': True}
    paths = schema_integer_paths(policy)
    count = 1 << len(paths)
    details = {'schema_integer_paths': paths, 'candidate_count': count, 'cache_hit': False}
    if count > max_candidates:
        return None, {**receipt, **details, 'status': 'uncertain', 'reason': 'candidate_bound_exceeded', 'candidates_tested': 0}
    matches = []
    for mask in itertools.product((False, True), repeat=len(paths)):
        candidate = copy.deepcopy(policy)
        for path, convert in zip(paths, mask):
            if convert:
                cursor = candidate
                for component in path[:-1]:
                    cursor = cursor[component]
                cursor[path[-1]] = float(cursor[path[-1]])
        if digest(candidate) == expected_sha256:
            matches.append(candidate)
    details.update(candidates_tested=count, hash_matches=len(matches))
    if len(matches) != 1:
        details.update(status='uncertain', reason='no_unique_hash_match')
        _CACHE[key] = (None, copy.deepcopy(details))
        return None, {**receipt, **details}
    recovered = matches[0]
    if not semantic_equal(recovered, policy):
        raise AssertionError('Numeric representation recovery changed policy semantics')
    details.update(status='verified', method='bounded_schema_numeric_search',
        changed=spelling_changes(policy, recovered))
    _CACHE[key] = (copy.deepcopy(recovered), copy.deepcopy(details))
    return recovered, {**receipt, **details}
