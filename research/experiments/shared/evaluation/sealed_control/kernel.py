"""Algorithm 1 one-use grants. No task IDs, scorer values, or environment access."""
import copy
import hashlib
import json

ARMS = ('no_gate', 'originalauto', 'sealed_exact', 'no_agreement', 'unsealed_ctor_exact', 'opaque_no_update', 'trusted_edit', 'sealed_compatible')
OPAQUE = {'text': 'This call is not authorized.', 'is_error': True}

def text_digest(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()

def residual_policy(policy, function, protected):
    """Remove only generated positive K restrictions; retain explicit negatives/base.

    Missing generated permission is repairable. An explicit deny is never removed.
    No generated non-K condition is discarded. This is a one-call policy only.
    """
    result = copy.deepcopy(policy or {})
    rules = result.get(function, [])
    generated = False
    for index, rule in enumerate(rules):
        if rule[0] >= 100 and rule[1] == 0:
            generated = True
            replacement = list(rule)
            replacement[2] = {k: v for k, v in rule[2].items() if k not in protected}
            rules[index] = replacement
    if not generated:
        rules.append([100, 0, {}, 0])
    result[function] = sorted(rules, key=lambda r: (r[0], -r[1]))
    return result

def checked_context(context_json, actor_meta):
    if not isinstance(context_json, str):
        raise ValueError('Missing exact UTF-8 actor context')
    digest = text_digest(context_json)
    if actor_meta.get('pre_proposal_context_sha256') != digest:
        raise ValueError('Captured context byte hash mismatch')
    if actor_meta.get('feedback_disclosed') is not False:
        raise ValueError('Repair actor was shown pending refusal')
    return {'context_json': context_json, 'context_utf8_sha256': digest,
            'context_utf8_bytes': len(context_json.encode('utf-8'))}
