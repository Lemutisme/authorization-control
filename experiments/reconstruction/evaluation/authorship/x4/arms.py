"""Frozen X1-lifecycle arm definitions; no dynamic-update ablation on a static gate."""
from kernel import Config

CONFIGS = {
    'x4_projection_H0': Config(),
    'fresh_rebinding_H0': Config(require_actor_agreement=False),
    'extra_review_H0': Config(mode='extra_review'),
    'full_call_H0': Config(comparison='full_call'),
    'disclosed_feedback_H0': Config(disclose_refusal=True),
    'proposal_conditioned_H0': Config(constructor_sees_current_proposal=True),
    'x4_projection_H10_diagnostic': Config(),
}
SMOKE_ARMS = ['base_F0', 'x4_projection_H0', 'fresh_rebinding_H0', 'extra_review_H0']
MAIN_ARMS = ['no_gate', 'base_F0', 'base_F3', *[name for name in CONFIGS if name != 'x4_projection_H10_diagnostic']]
DIAGNOSTIC_ARMS = ['x4_projection_H10_diagnostic']
ALL_ARMS = MAIN_ARMS + DIAGNOSTIC_ARMS
