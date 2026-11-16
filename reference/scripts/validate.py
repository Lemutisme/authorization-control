#!/usr/bin/env python3
"""Validate the curated publication bundle, not the underlying incident or defense."""
from pathlib import Path
import base64
import csv
import hashlib
import html
import ipaddress
import json
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from urllib.parse import unquote,urlsplit

ROOT=Path(__file__).resolve().parents[1]
EXPECTED={
    'docs/research-strengths.md',
    'scripts/prepare_strengths_presentation.py',
    'scripts/build_strengths_presentation.py',
    'presentation/README.md',
    'presentation/build-manifest.json',
    'presentation/strengths-data.tex',
    'presentation/strengths.pdf',
    'presentation/strengths.tex',
    'evidence/strengths-presentation/checked-evidence.json',
    'evidence/strengths-presentation/claims.json',
    'evidence/strengths-presentation/prior-active-provenance.json',
    'evidence/strengths-presentation/prior-baseline-provenance.json',
    'evidence/strengths-presentation/prior-continuation-provenance.json',
    'evidence/strengths-presentation/prior-contract-provenance.json',
    'evidence/strengths-presentation/prior-contribution-provenance.json',
    'evidence/strengths-presentation/prior-diagnostic-provenance.json',
    'evidence/strengths-presentation/prior-explicit-grants-provenance.json',
    'evidence/strengths-presentation/prior-fact-screen-provenance.json',
    'evidence/strengths-presentation/prior-full-provenance.json',
    'evidence/strengths-presentation/prior-intent-provenance.json',
    'evidence/strengths-presentation/prior-intervention-provenance.json',
    'evidence/strengths-presentation/prior-method-provenance.json',
    'evidence/strengths-presentation/prior-multibench-provenance.json',
    'evidence/strengths-presentation/prior-novelty-provenance.json',
    'evidence/strengths-presentation/prior-pi-provenance.json',
    'evidence/strengths-presentation/publication-record.json',
    'evidence/strengths-presentation/review-notes.md',
    'evidence/strengths-presentation/provenance.json',
    'docs/strong-baselines.md',
    'scripts/summarize_baseline_audit.py',
    'scripts/capture_progent_context.py',
    'paper/latex/baseline-audit-supplement.tex',
    'evaluation/baseline_audit/README.md',
    'evaluation/baseline_audit/agent.mjs',
    'evaluation/baseline_audit/broker.py',
    'evaluation/baseline_audit/check_context.mjs',
    'evaluation/baseline_audit/policy_client.mjs',
    'evaluation/baseline_audit/protocol.json',
    'evaluation/baseline_audit/qualify.py',
    'evaluation/baseline_audit/smoke.py',
    'evidence/baseline-audit/case-details.json',
    'evidence/baseline-audit/context-qualification.json',
    'evidence/baseline-audit/prior-active-provenance.json',
    'evidence/baseline-audit/prior-continuation-provenance.json',
    'evidence/baseline-audit/prior-contract-provenance.json',
    'evidence/baseline-audit/prior-contribution-provenance.json',
    'evidence/baseline-audit/prior-diagnostic-provenance.json',
    'evidence/baseline-audit/prior-explicit-grants-provenance.json',
    'evidence/baseline-audit/prior-fact-screen-provenance.json',
    'evidence/baseline-audit/prior-full-provenance.json',
    'evidence/baseline-audit/prior-intent-provenance.json',
    'evidence/baseline-audit/prior-intervention-provenance.json',
    'evidence/baseline-audit/prior-method-provenance.json',
    'evidence/baseline-audit/prior-multibench-provenance.json',
    'evidence/baseline-audit/prior-novelty-provenance.json',
    'evidence/baseline-audit/prior-pi-provenance.json',
    'evidence/baseline-audit/protocol.json',
    'evidence/baseline-audit/qualification.json',
    'evidence/baseline-audit/run-records.json',
    'evidence/baseline-audit/source-review.json',
    'evidence/baseline-audit/summary.json',
    'evidence/baseline-audit/provenance.json',
    'evidence/diagnostic-crossover/native-source-check.json',
    'docs/diagnostic-crossover.md',
    'paper/latex/diagnostic-crossover-supplement.tex',
    'scripts/qualify_diagnostic_crossover.py',
    'scripts/summarize_diagnostic_crossover.py',
    'scripts/render_diagnostic_crossover.py',
    'scripts/audit_diagnostic_exposure.py',
    'evaluation/diagnostic_crossover/README.md',
    'evaluation/diagnostic_crossover/agent.mjs',
    'evaluation/diagnostic_crossover/broker.py',
    'evaluation/diagnostic_crossover/campaign.py',
    'evaluation/diagnostic_crossover/prepare.py',
    'evaluation/diagnostic_crossover/protocol.json',
    'evidence/diagnostic-crossover/case-details.json',
    'evidence/diagnostic-crossover/cohort-manifest.json',
    'evidence/diagnostic-crossover/contrasts.json',
    'evidence/diagnostic-crossover/episodes.csv',
    'evidence/diagnostic-crossover/preparation-history.json',
    'evidence/diagnostic-crossover/prior-active-provenance.json',
    'evidence/diagnostic-crossover/prior-continuation-provenance.json',
    'evidence/diagnostic-crossover/prior-contract-provenance.json',
    'evidence/diagnostic-crossover/prior-contribution-provenance.json',
    'evidence/diagnostic-crossover/prior-explicit-grants-provenance.json',
    'evidence/diagnostic-crossover/prior-fact-screen-provenance.json',
    'evidence/diagnostic-crossover/prior-full-provenance.json',
    'evidence/diagnostic-crossover/prior-intent-provenance.json',
    'evidence/diagnostic-crossover/prior-intervention-provenance.json',
    'evidence/diagnostic-crossover/prior-method-provenance.json',
    'evidence/diagnostic-crossover/prior-multibench-provenance.json',
    'evidence/diagnostic-crossover/prior-novelty-provenance.json',
    'evidence/diagnostic-crossover/prior-pi-provenance.json',
    'evidence/diagnostic-crossover/protocol.json',
    'evidence/diagnostic-crossover/qualification.json',
    'evidence/diagnostic-crossover/results.md',
    'evidence/diagnostic-crossover/run-records.json',
    'evidence/diagnostic-crossover/smoke-summary.json',
    'evidence/diagnostic-crossover/source-review.json',
    'evidence/diagnostic-crossover/summary.json',
    'evidence/diagnostic-crossover/provenance.json',
    'evidence/diagnostic-crossover/exposure-audit.json',
    'docs/explicit-grants.md',
    'paper/latex/explicit-grants-supplement.tex',
    'scripts/summarize_explicit_grants.py',
    'evaluation/explicit_grants/README.md',
    'evaluation/explicit_grants/agent.mjs',
    'evaluation/explicit_grants/broker.py',
    'evaluation/explicit_grants/campaign.py',
    'evaluation/explicit_grants/check.py',
    'evaluation/explicit_grants/kernel.py',
    'evaluation/explicit_grants/native_check.py',
    'evaluation/explicit_grants/prepare.py',
    'evaluation/explicit_grants/protocol.json',
    'evaluation/explicit_grants/provider.py',
    'evidence/explicit-grants/analysis-first.json',
    'evidence/explicit-grants/analysis-revision.json',
    'evidence/explicit-grants/control-manifest.json',
    'evidence/explicit-grants/explicit-grant-screen-v1-episodes.csv',
    'evidence/explicit-grants/explicit-grant-smoke-v1-episodes.csv',
    'evidence/explicit-grants/kernel-qualification-v1.json',
    'evidence/explicit-grants/kernel-qualification-v2.json',
    'evidence/explicit-grants/native-qualification-v1.json',
    'evidence/explicit-grants/native-qualification-v2.json',
    'evidence/explicit-grants/prior-active-provenance.json',
    'evidence/explicit-grants/prior-continuation-provenance.json',
    'evidence/explicit-grants/prior-contract-provenance.json',
    'evidence/explicit-grants/prior-contribution-provenance.json',
    'evidence/explicit-grants/prior-fact-screen-provenance.json',
    'evidence/explicit-grants/prior-full-provenance.json',
    'evidence/explicit-grants/prior-intent-provenance.json',
    'evidence/explicit-grants/prior-intervention-provenance.json',
    'evidence/explicit-grants/prior-method-provenance.json',
    'evidence/explicit-grants/prior-multibench-provenance.json',
    'evidence/explicit-grants/prior-novelty-provenance.json',
    'evidence/explicit-grants/prior-pi-provenance.json',
    'evidence/explicit-grants/protocol.json',
    'evidence/explicit-grants/run-records.json',
    'evidence/explicit-grants/summary.json',
    'evidence/explicit-grants/provenance.json',
    'docs/multibench.md',
    'evaluation/multibench/README.md',
    'evaluation/multibench/agent.mjs',
    'evaluation/multibench/broker.py',
    'evaluation/multibench/campaign.py',
    'evaluation/multibench/check.py',
    'evaluation/multibench/loop.mjs',
    'evaluation/multibench/native.py',
    'evaluation/multibench/prepare.py',
    'evaluation/multibench/protocol.json',
    'evaluation/multibench/requirements.txt',
    'evidence/multibench/analysis-revision-check.json',
    'evidence/multibench/case-audit.json',
    'evidence/multibench/case-identities-base_dh.json',
    'evidence/multibench/case-identities-base_ds.json',
    'evidence/multibench/case-identities-clean.json',
    'evidence/multibench/case-identities-enhanced_dh.json',
    'evidence/multibench/case-identities-enhanced_ds.json',
    'evidence/multibench/case-identities-opi_context_ignoring.json',
    'evidence/multibench/inventory.json',
    'evidence/multibench/metric-contracts.json',
    'evidence/multibench/multibench-asb-main-v1-clean-minimal.csv',
    'evidence/multibench/multibench-asb-main-v1-clean-none.csv',
    'evidence/multibench/multibench-asb-main-v1-clean-repeat_task.csv',
    'evidence/multibench/multibench-asb-main-v1-opi_context_ignoring-minimal.csv',
    'evidence/multibench/multibench-asb-main-v1-opi_context_ignoring-none.csv',
    'evidence/multibench/multibench-asb-main-v1-opi_context_ignoring-repeat_task.csv',
    'evidence/multibench/multibench-injecagent-main-v1-base_dh-minimal.csv',
    'evidence/multibench/multibench-injecagent-main-v1-base_dh-none.csv',
    'evidence/multibench/multibench-injecagent-main-v1-base_dh-repeat_task.csv',
    'evidence/multibench/multibench-injecagent-main-v1-base_ds-minimal.csv',
    'evidence/multibench/multibench-injecagent-main-v1-base_ds-none.csv',
    'evidence/multibench/multibench-injecagent-main-v1-base_ds-repeat_task.csv',
    'evidence/multibench/multibench-injecagent-main-v1-enhanced_dh-minimal.csv',
    'evidence/multibench/multibench-injecagent-main-v1-enhanced_dh-none.csv',
    'evidence/multibench/multibench-injecagent-main-v1-enhanced_dh-repeat_task.csv',
    'evidence/multibench/multibench-injecagent-main-v1-enhanced_ds-minimal.csv',
    'evidence/multibench/multibench-injecagent-main-v1-enhanced_ds-none.csv',
    'evidence/multibench/multibench-injecagent-main-v1-enhanced_ds-repeat_task.csv',
    'evidence/multibench/multibench-pilot-v1-base_dh-late_facts.csv',
    'evidence/multibench/multibench-pilot-v1-base_dh-minimal.csv',
    'evidence/multibench/multibench-pilot-v1-base_dh-none.csv',
    'evidence/multibench/multibench-pilot-v1-base_dh-repeat_task.csv',
    'evidence/multibench/multibench-pilot-v1-base_dh-scope_only.csv',
    'evidence/multibench/multibench-pilot-v1-base_ds-late_facts.csv',
    'evidence/multibench/multibench-pilot-v1-base_ds-minimal.csv',
    'evidence/multibench/multibench-pilot-v1-base_ds-none.csv',
    'evidence/multibench/multibench-pilot-v1-base_ds-repeat_task.csv',
    'evidence/multibench/multibench-pilot-v1-base_ds-scope_only.csv',
    'evidence/multibench/multibench-pilot-v1-clean-late_facts.csv',
    'evidence/multibench/multibench-pilot-v1-clean-minimal.csv',
    'evidence/multibench/multibench-pilot-v1-clean-none.csv',
    'evidence/multibench/multibench-pilot-v1-clean-repeat_task.csv',
    'evidence/multibench/multibench-pilot-v1-clean-scope_only.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_dh-late_facts.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_dh-minimal.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_dh-none.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_dh-repeat_task.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_dh-scope_only.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_ds-late_facts.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_ds-minimal.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_ds-none.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_ds-repeat_task.csv',
    'evidence/multibench/multibench-pilot-v1-enhanced_ds-scope_only.csv',
    'evidence/multibench/multibench-pilot-v1-opi_context_ignoring-late_facts.csv',
    'evidence/multibench/multibench-pilot-v1-opi_context_ignoring-minimal.csv',
    'evidence/multibench/multibench-pilot-v1-opi_context_ignoring-none.csv',
    'evidence/multibench/multibench-pilot-v1-opi_context_ignoring-repeat_task.csv',
    'evidence/multibench/multibench-pilot-v1-opi_context_ignoring-scope_only.csv',
    'evidence/multibench/multibench-smoke-v1-base_dh-minimal.csv',
    'evidence/multibench/multibench-smoke-v1-base_dh-none.csv',
    'evidence/multibench/multibench-smoke-v1-clean-minimal.csv',
    'evidence/multibench/multibench-smoke-v1-clean-none.csv',
    'evidence/multibench/multibench-smoke-v2-base_dh-minimal.csv',
    'evidence/multibench/multibench-smoke-v2-base_dh-none.csv',
    'evidence/multibench/multibench-smoke-v2-clean-minimal.csv',
    'evidence/multibench/multibench-smoke-v2-clean-none.csv',
    'evidence/multibench/prior-active-provenance.json',
    'evidence/multibench/prior-continuation-provenance.json',
    'evidence/multibench/prior-contract-provenance.json',
    'evidence/multibench/prior-contribution-provenance.json',
    'evidence/multibench/prior-fact-screen-provenance.json',
    'evidence/multibench/prior-full-provenance.json',
    'evidence/multibench/prior-intent-provenance.json',
    'evidence/multibench/prior-intervention-provenance.json',
    'evidence/multibench/prior-method-provenance.json',
    'evidence/multibench/prior-novelty-provenance.json',
    'evidence/multibench/prior-pi-provenance.json',
    'evidence/multibench/protocol.json',
    'evidence/multibench/provenance.json',
    'evidence/multibench/qualification-v2.json',
    'evidence/multibench/qualification-v3.json',
    'evidence/multibench/residual-cases.json',
    'evidence/multibench/run-ledger.json',
    'evidence/multibench/source-map.json',
    'evidence/multibench/summary.json',
    'paper/latex/multibench-results.tex',
    'paper/latex/multibench-supplement.tex',
    'scripts/render_multibench.py',
    'scripts/summarize_multibench.py',

    'evidence/intervention-semantics/method-map.json',
    'docs/intervention-semantics.md',
    'evidence/intervention-semantics/bank-witnesses.json',
    'evidence/intervention-semantics/localization.json',
    'evidence/intervention-semantics/prior-active-provenance.json',
    'evidence/intervention-semantics/prior-continuation-provenance.json',
    'evidence/intervention-semantics/prior-contract-provenance.json',
    'evidence/intervention-semantics/prior-contribution-provenance.json',
    'evidence/intervention-semantics/prior-fact-screen-provenance.json',
    'evidence/intervention-semantics/prior-full-provenance.json',
    'evidence/intervention-semantics/prior-intent-provenance.json',
    'evidence/intervention-semantics/prior-method-provenance.json',
    'evidence/intervention-semantics/prior-novelty-provenance.json',
    'evidence/intervention-semantics/prior-pi-provenance.json',
    'evidence/intervention-semantics/provenance.json',
    'evidence/intervention-semantics/run-ledger.json',
    'evidence/intervention-semantics/source-review.json',
    'paper/latex/intervention-semantics-supplement.tex',
    'scripts/audit_intervention_semantics.py',
    'scripts/check_negative_constraints.py',
    'theory/negative-constraint-verification.json',
    'theory/negative_constraints.py',

    'docs/fact-screen.md',
    'evaluation/fact_screen/README.md',
    'evaluation/fact_screen/agent.mjs',
    'evaluation/fact_screen/broker.py',
    'evaluation/fact_screen/campaign.py',
    'evaluation/fact_screen/check.py',
    'evaluation/fact_screen/protocol.json',
    'evidence/fact-screen/email-order-witness.json',
    'evidence/fact-screen/full_facts-episodes.csv',
    'evidence/fact-screen/late_facts-episodes.csv',
    'evidence/fact-screen/literal_facts-episodes.csv',
    'evidence/fact-screen/minimal-episodes.csv',
    'evidence/fact-screen/none-episodes.csv',
    'evidence/fact-screen/prior-active-provenance.json',
    'evidence/fact-screen/prior-continuation-provenance.json',
    'evidence/fact-screen/prior-contract-provenance.json',
    'evidence/fact-screen/prior-contribution-provenance.json',
    'evidence/fact-screen/prior-full-provenance.json',
    'evidence/fact-screen/prior-intent-provenance.json',
    'evidence/fact-screen/prior-method-provenance.json',
    'evidence/fact-screen/prior-novelty-provenance.json',
    'evidence/fact-screen/prior-pi-provenance.json',
    'evidence/fact-screen/protocol.json',
    'evidence/fact-screen/provenance.json',
    'evidence/fact-screen/qualification.json',
    'evidence/fact-screen/run-ledger.json',
    'evidence/fact-screen/summary.json',
    'paper/latex/fact-screen-supplement.tex',
    'scripts/summarize_fact_screen.py',

    'docs/contract-study.md',
    'evaluation/contract_study/README.md',
    'evaluation/contract_study/agent.mjs',
    'evaluation/contract_study/broker.py',
    'evaluation/contract_study/campaign.py',
    'evaluation/contract_study/check.py',
    'evaluation/contract_study/check_before_clock.py',
    'evaluation/contract_study/coupled_authorizer.py',
    'evaluation/contract_study/protocol.json',
    'evidence/contract-study/case-audit.json',
    'evidence/contract-study/contract-factorial-clean-repeat-v1-no_facts-episodes.csv',
    'evidence/contract-study/contract-factorial-clean-repeat-v1-no_facts_no_feedback-episodes.csv',
    'evidence/contract-study/contract-factorial-clean-repeat-v1-no_feedback-episodes.csv',
    'evidence/contract-study/contract-factorial-clean-repeat-v1-none-episodes.csv',
    'evidence/contract-study/contract-factorial-clean-repeat-v1-pga-episodes.csv',
    'evidence/contract-study/contract-factorial-main-v1-no_facts-episodes.csv',
    'evidence/contract-study/contract-factorial-main-v1-no_facts_no_feedback-episodes.csv',
    'evidence/contract-study/contract-factorial-main-v1-no_feedback-episodes.csv',
    'evidence/contract-study/contract-factorial-main-v1-none-episodes.csv',
    'evidence/contract-study/contract-factorial-main-v1-pga-episodes.csv',
    'evidence/contract-study/forecast-readback.json',
    'evidence/contract-study/native-ordering-audit.json',
    'evidence/contract-study/prior-active-provenance.json',
    'evidence/contract-study/prior-continuation-provenance.json',
    'evidence/contract-study/prior-contribution-provenance.json',
    'evidence/contract-study/prior-full-provenance.json',
    'evidence/contract-study/prior-intent-provenance.json',
    'evidence/contract-study/prior-method-provenance.json',
    'evidence/contract-study/prior-novelty-provenance.json',
    'evidence/contract-study/prior-pi-provenance.json',
    'evidence/contract-study/protocol.json',
    'evidence/contract-study/provenance.json',
    'evidence/contract-study/qualification-first.json',
    'evidence/contract-study/qualification.json',
    'evidence/contract-study/results.md',
    'evidence/contract-study/run-ledger.json',
    'evidence/contract-study/summary.json',
    'paper/latex/contract-study-results.tex',
    'paper/latex/contract-study-supplement.tex',
    'preview/contract-study.html',
    'scripts/render_contract_study.py',
    'scripts/summarize_contract_study.py',

    'docs/contribution-case.md',
    'preview/contribution-case.html',
    'evidence/contribution-case/claims.json',
    'evidence/contribution-case/provenance.json',
    'evidence/contribution-case/prior-active-provenance.json',
    'evidence/contribution-case/prior-method-provenance.json',
    'evidence/contribution-case/prior-pi-provenance.json',
    'evidence/contribution-case/prior-full-provenance.json',
    'evidence/contribution-case/prior-intent-provenance.json',
    'evidence/contribution-case/prior-continuation-provenance.json',
    'evidence/contribution-case/prior-novelty-provenance.json',

    'docs/novelty-frontier.md',
    'paper/latex/novelty-frontier-supplement.tex',
    'preview/novelty-frontier.html',
    'evidence/novelty-frontier/source-review.json',
    'evidence/novelty-frontier/provenance.json',
    'evidence/novelty-frontier/prior-active-provenance.json',
    'evidence/novelty-frontier/prior-method-provenance.json',
    'evidence/novelty-frontier/prior-pi-provenance.json',
    'evidence/novelty-frontier/prior-full-provenance.json',
    'evidence/novelty-frontier/prior-intent-provenance.json',
    'evidence/novelty-frontier/prior-continuation-provenance.json',

    'docs/continuation-theory.md',
    'paper/latex/continuation-supplement.tex',
    'theory/continuation.py',
    'theory/continuation-verification.json',
    'scripts/check_continuation.py',
    'evidence/continuation-theory/source-review.json',
    'evidence/continuation-theory/provenance.json',
    'preview/continuation-theory.html',
    'evidence/continuation-theory/prior-active-provenance.json',
    'evidence/continuation-theory/prior-method-provenance.json',
    'evidence/continuation-theory/prior-pi-provenance.json',
    'evidence/continuation-theory/prior-full-provenance.json',
    'evidence/continuation-theory/prior-intent-provenance.json',

    '.gitignore','.gitattributes','README.md','MOTIVATION.md','requirements.txt',
    'paper/manuscript.zh-CN.md','paper/references.bib','paper/figures/security-domains.svg',
    'paper/motivation.zh-CN.md','paper/methodology.zh-CN.md',
    'paper/paper-en.pdf','paper/latex/main.tex','paper/latex/method.tex','paper/latex/evaluation.tex','paper/latex/discussion.tex',
    'paper/technical-supplement.pdf','paper/latex/supplement.tex','paper/latex/theory-summary.tex','paper/latex/supplement-manifest.json',
    'paper/latex/intro.tex','paper/latex/related.tex','paper/latex/prelim.tex','paper/latex/evidence.tex','paper/latex/reference-catalog.json',
    'paper/latex/references.bib','paper/latex/README.md','paper/latex/build-manifest.json','paper/latex/format-source.json',
    'paper/latex/research-questions.tex',
    'theory/finite_profiles.py','theory/finite-verification.json','scripts/check_finite_profiles.py',
    'docs/rq-theory-review.md',
    'docs/incident-method-worked-case.md','evidence/implementation-scope.json',
    'docs/proactive-security.md','evidence/proactive-source-review.json',
    'docs/test2act-draft.md','docs/venue-fit.md','evidence/test2act-design-provenance.json',
    'evaluation/benchmark-plan.json','evidence/benchmark-plan-source-ledger.json',
    'docs/experiment-setup.md','paper/latex/experiment-tables.tex',
    'evidence/experiment-setup-source-ledger.json',
    'preview/experiment-setup.html',
    'docs/pga-active-evidence.md','evidence/pga-active-evidence-provenance.json',
    'evidence/pga-methodology-provenance-before-binding-20261104.json',
    'docs/pga-method-revision.md','preview/pga-method-revision.html',
    'evaluation/pi/README.md','evaluation/pi/package.json','evaluation/pi/package-lock.json',
    'evaluation/pi/agent.mjs','evaluation/pi/broker.py','evaluation/pi/luna_transport.py',
    'evaluation/pi/check.mjs','evaluation/pi/campaign.py','scripts/summarize_pi.py',
    'evidence/pi-luna/qualification-first.json','evidence/pi-luna/qualification.json',
    'evidence/pi-luna/none-results.json','evidence/pi-luna/pga-results.json','evidence/pi-luna/smoke-results.json',
    'evidence/pi-luna/summary.json','evidence/pi-luna/results.md','evidence/pi-luna/provenance.json',
    'evidence/pi-luna/source-record.json','evidence/pi-luna/prior-method-provenance.json',
    'evaluation/pi_full/README.md','evaluation/pi_full/prepare.py','evaluation/pi_full/broker.py',
    'evaluation/pi_full/agent.mjs','evaluation/pi_full/campaign.py','evaluation/pi_full/check.py',
    'evaluation/pi_full/check_failure.py','scripts/summarize_pi_full.py',
    'evidence/pi-full/inventory.json','evidence/pi-full/qualification.json','evidence/pi-full/failure-check.json',
    'evidence/pi-full/none-pilot.json','evidence/pi-full/pga-pilot.json','evidence/pi-full/status.json',
    'evidence/pi-full/summary.json','evidence/pi-full/provenance.json',
    'evidence/pi-full/prior-pi-provenance.json','evidence/pi-full/prior-method-provenance.json',
    'evidence/pi-full/readiness-summary.json','evidence/pi-full/readiness-status.json','evidence/pi-full/readiness-provenance.json',
    'evidence/pi-full/pre-results-pi-provenance.json','evidence/pi-full/pre-results-method-provenance.json',
    'evidence/pi-full/pre-results-active-provenance.json','evidence/pi-full/results.md',
    'evidence/pi-full/none-episodes.csv','evidence/pi-full/pga-episodes.csv','evidence/pi-full/trace-audit.json',
    'evidence/pi-full/score-interpretation.md','evidence/pi-full/positive-score-audit.json',
    'scripts/audit_pi_full.py','scripts/check_pi_full_positive_scores.py','scripts/render_pi_full.py',
    'paper/latex/pi-full-results.tex',
    'evaluation/pga_grounding.py','evaluation/pga_bound_gate.py',
    'evaluation/check_pga_binding.py','evaluation/pga_grounding_study.py',
    'scripts/summarize_pga_revision.py',
    'paper/latex/binding-revision-results.tex','paper/latex/binding-revision-supplement.tex',
    'evidence/pga-revision/provenance.json','evidence/pga-revision/source-review.json',
    'evidence/pga-revision/summary.json','evidence/pga-revision/results.md',
    'evidence/pga-revision/contract-checks.json','evidence/pga-revision/grounding-results.json',
    'evidence/pga-revision/contract-checks-before-admission-fix.json',
    'evidence/pga-revision/replay-results.json','evidence/pga-revision/grounding-cases.json',
    'paper/latex/active-evidence.tex','paper/latex/active-evidence-supplement.tex',
    'docs/test2act-experiment-setup-20261103.md',
    'paper/latex/test2act-rqs-20261103.tex','paper/latex/test2act-tables-20261103.tex',
    'evaluation/test2act-benchmark-plan-20261103.json','preview/pga-active-evidence.html',
    'evaluation/PGA.md','evaluation/pga-requirements.txt',
    'evaluation/pga_benchmark.py','evaluation/pga_campaign.py','evaluation/pga_gate.py',
    'evaluation/pga_oracle.py','evaluation/pga_oracle_refined.py','evaluation/pga_oracle_controls.py',
    'evaluation/pga_prepare.py','evaluation/pga_qualify.py','evaluation/pga_runtime.py','evaluation/pga_transport.py',
    'scripts/summarize_pga.py','scripts/render_pga_tables.py','scripts/plot_pga.py','scripts/rescore_pga.py',
    'paper/latex/pga-study-results.tex','paper/figures/pga-task-utility.svg',
    'evidence/pga-methodology-provenance-20261103.json',
    'evidence/pga-study/summary.json','evidence/pga-study/episodes.csv','evidence/pga-study/results.md',
    'evidence/pga-study/cohort.json','evidence/pga-study/native-qualification.json',
    'evidence/pga-study/runtime-manifest.json','evidence/pga-study/native-source-audit.json',
    'evidence/pga-study/provenance.json','evidence/pga-study/oracle-controls.json',
    'evidence/pga-study/oracle-controls-refined.json','evidence/pga-study/refined-rescore.json',
    'preview/pga-results.html',
    'docs/active-security.md','evidence/active-security-provenance.json',
    'docs/restart-probe-contract.md','evidence/restart-contract-provenance.json',
    'docs/restart-source-followup.md','evidence/restart-followup-provenance.json',
    'paper/latex/provider-semantic-supplement.tex',
    'paper/latex/security-contract.tex','paper/latex/initiative-risk-supplement.tex',
    'scripts/check_initiative_risk.py','theory/initiative-risk-verification.json',
    'paper/latex/test2act-supplement.tex',
    'docs/review-v3-response.md','docs/approval-identity-case-status.md',
    'docs/postgres-bridge-review.md','docs/cancellation-contract-review.md',
    'evidence/postgres-bridge-provenance.json','evidence/cancellation-source-provenance.json',
    'evidence/approval-identity-provenance.json','paper/paper-approval-identity.pdf',
    'paper/icml2026/postgres-gate-appendix.tex','paper/icml2026/cancellation-appendix.tex','paper/icml2026/cancellation.tex',
    'paper/approval-identity/fancyhdr.sty','paper/approval-identity/main.tex',
    'paper/approval-identity/icml2026.sty','paper/approval-identity/icml2026.bst',
    'paper/approval-identity/build-manifest.json','paper/approval-identity/references.bib','paper/approval-identity/README.md',
    'paper/latex/proactive.tex','paper/latex/proactive-supplement.tex','paper/latex/incident-case.tex',
    'docs/provider-contract-review.md','evidence/provider-contract-provenance.json',
    'paper/icml2026/provider.tex','paper/icml2026/provider-appendix.tex',
    'paper/paper-icml.pdf','scripts/build_icml.py',
    'paper/icml2026/README.md','paper/icml2026/analysis.tex','paper/icml2026/appendix.tex',
    'paper/icml2026/build-manifest.json','paper/icml2026/discussion.tex','paper/icml2026/evidence-provenance.json',
    'paper/icml2026/evidence.tex','paper/icml2026/fancyhdr.sty','paper/icml2026/icml2026.bst',
    'paper/icml2026/icml2026.sty','paper/icml2026/introduction.tex','paper/icml2026/main.tex',
    'paper/icml2026/method.tex','paper/icml2026/model.tex','paper/icml2026/references.bib',
    'paper/icml2026/related.tex','paper/icml2026/template-provenance.json','paper/icml2026/review-status.md',
    'paper/figures/async-revocation.svg',
    'docs/defense.zh-CN.md','docs/study-protocol.zh-CN.md','docs/related-work.md','docs/review-summary.md',
    'docs/safecontract-product.md','docs/procontract-security-fit.md','docs/safecontract-novelty.md',
    'docs/first-principles.md','docs/benchmark-selection.md',
    'docs/async-effect-boundary.md',
    'evidence/README.md','evidence/case-summary.json','evidence/claim-ledger.md',
    'evidence/procontract-source-audit.json',
    'evidence/registry-pilot-summary.json','evidence/benchmark-source-ledger.json',
    'evidence/process-study-summary.json','evidence/process-study-results.md',
    'evidence/process-study-outcomes.csv',
    'evidence/ongoing-control-source-ledger.json',
    'evidence/async-study-summary.json','evidence/async-study-outcomes.csv','evidence/async-study-results.md','evidence/method-panel-source-ledger.json',
    'evidence/async-counterexamples.json',
    'prototype/README.md','prototype/Cargo.lock','prototype/kernel_bridge.rs','prototype/registry_host.py','prototype/pilot.py',
    'scripts/build_kernel_bridge.py','scripts/summarize_pilot.py',
    'scripts/summarize_process_study.py',
    'scripts/export_process_outcomes.py',
    'scripts/summarize_async_study.py',
    'scripts/export_async_witnesses.py',
    'scripts/build_paper.py',
    'scripts/build_supplement.py','scripts/check_theory.py',
    'theory/RecoveryAuthorization.lean','theory/README.md','theory/lean-toolchain','theory/verification.json',
    'scripts/audit_references.py','evidence/reference-audit.json',
    'evaluation/README.md','evaluation/process_host.py','evaluation/trace_oracle.py','evaluation/campaign.py',
    'evaluation/ASYNC.md','evaluation/async_provider.py','evaluation/async_host.py','evaluation/async_oracle.py','evaluation/async_campaign.py',
    'scripts/build.py','scripts/validate.py',
    'preview/paper.html','preview/motivation.html','preview/defense.html','preview/study-protocol.html','preview/manifest.json',
    'preview/safecontract.html','preview/procontract-fit.html','preview/novelty.html',
    'preview/first-principles.html','preview/benchmarks.html',
    'preview/paper-motivation.html','preview/methodology.html',
    'preview/async-boundary.html',
}
EXPECTED.update({
    'docs/zero-regression.md','preview/zero-regression.html',
    'evaluation/intent_guard/README.md','evaluation/intent_guard/agent.mjs',
    'evaluation/intent_guard/broker.py','evaluation/intent_guard/campaign.py',
    'evaluation/intent_guard/catalog.py','evaluation/intent_guard/check.py',
    'evaluation/intent_guard/check_protocol.py','evaluation/intent_guard/guard.py',
    'evaluation/intent_guard/native-contracts.json','evaluation/intent_guard/native_clock.py',
    'evaluation/intent_guard/owner_scope.py','evaluation/intent_guard/replay.py',
    'evaluation/intent_guard/replay_pairs.py','evaluation/intent_guard/runtime.py',
    'evaluation/intent_guard/transport.py','evaluation/pi/coupling.mjs',
    'evaluation/pi/check_coupling.mjs','scripts/summarize_intent_guard.py',
    'scripts/export_intent_guard.py','scripts/render_intent_guard.py',
    'scripts/check_intent_summary.py','scripts/audit_intent_effects.py',
    'paper/latex/intent-guard-supplement.tex','paper/latex/intent-guard-results.tex',
    'evidence/intent-guard/summary.json','evidence/intent-guard/results.md',
    'evidence/intent-guard/development-ledger.json','evidence/intent-guard/qualification.json',
    'evidence/intent-guard/coupling-checks.json','evidence/intent-guard/measurement-checks.json',
    'evidence/intent-guard/protocol-checks.json','evidence/intent-guard/effect-audit.json',
    'evidence/intent-guard/source-review.json','evidence/intent-guard/provenance.json',
    'evidence/intent-guard/prior-active-provenance.json','evidence/intent-guard/prior-method-provenance.json',
    'evidence/intent-guard/prior-pi-provenance.json','evidence/intent-guard/prior-full-provenance.json',
})
EXPECTED.update('evidence/intent-guard/'+name+'-pairs.csv' for name in [
    'intent-clean-paired-main-v3','intent-clean-paired-main-v4','intent-clean-paired-main-v5',
    'intent-clean-paired-main-v6','intent-clean-paired-main-v7','intent-clean-paired-main-v8',
    'intent-clean-controls-main-v9','intent-full-paired-main-v8','intent-full-paired-main-v10',
    'intent-full-paired-main-v11','intent-full-paired-main-v14','intent-clean-repeat-main-v14',
    'intent-full-comparison-main-v15--direct','intent-full-comparison-main-v15--owner-scope',
    'intent-clean-comparison-repeat-v15--direct','intent-clean-comparison-repeat-v15--owner-scope',
    'intent-full-paired-main-v16','intent-clean-repeat-main-v16',
])
SKIP={'.git','.venv','__pycache__','node_modules'}
PATTERNS={
    'private key':r'-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----',
    'credential-like token':r'\b(?:gh[pousr]_|github_pat_|hf_)[A-Za-z0-9_]{20,}\b',
    'provider-key-like token':r'\bsk-[A-Za-z0-9_-]{20,}\b',
    'machine-specific path':r'(?<![A-Za-z0-9_])/(?:data|root|home)/[^\s`"\)<>]+',
}

def check_text(name,text,errors):
    # This exact typed dependency value is the installed Z3 package version,
    # not an IPv4 endpoint. Preserve the original report bytes and other scans.
    if name in {'evidence/baseline-audit/qualification.json','scripts/validate.py'}:
        text=text.replace('"z3-solver": "4.15.3.0"','"z3-solver": "package-version"')
    # This exact frozen fixture field (also spelled in this checker) names a
    # collaboration agent, not a host path. Inspect all other text unchanged.
    if name in {'evidence/pga-revision/grounding-cases.json','scripts/validate.py'}:
        text=text.replace('"author": "/artifact-source/a2f2ed1a0210/sp_design_critic"','"author": "agent:sp_design_critic"')
    for label,pattern in PATTERNS.items():
        if re.search(pattern,text):errors.append(name+': '+label)
    for match in re.finditer(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])',text):
        try:address=ipaddress.ip_address(match[0])
        except ValueError:continue
        if not address.is_loopback:errors.append(name+': non-loopback IPv4 literal')

def check_link(source,url,errors):
    url=html.unescape(url);parsed=urlsplit(url)
    if parsed.scheme or url.startswith('#'):return
    target=(source.parent/unquote(parsed.path)).resolve()
    if not target.is_relative_to(ROOT) or not target.exists():errors.append(str(source.relative_to(ROOT))+': missing/outside link '+url)

EXPECTED.update({
    'docs/runtime-control.md',
    'evaluation/registry_control/README.md',
    'evaluation/registry_control/agent.mjs',
    'evaluation/registry_control/broker.py',
    'evaluation/registry_control/campaign.py',
    'evaluation/registry_control/check.py',
    'evaluation/registry_control/prepare.py',
    'evaluation/registry_control/protocol.json',
    'evaluation/registry_control/registry.py',
    'evidence/runtime-control/inventory.json',
    'evidence/runtime-control/prior-active-provenance.json',
    'evidence/runtime-control/prior-baseline-provenance.json',
    'evidence/runtime-control/prior-continuation-provenance.json',
    'evidence/runtime-control/prior-contract-provenance.json',
    'evidence/runtime-control/prior-contribution-provenance.json',
    'evidence/runtime-control/prior-diagnostic-provenance.json',
    'evidence/runtime-control/prior-explicit-grants-provenance.json',
    'evidence/runtime-control/prior-fact-screen-provenance.json',
    'evidence/runtime-control/prior-full-provenance.json',
    'evidence/runtime-control/prior-intent-provenance.json',
    'evidence/runtime-control/prior-intervention-provenance.json',
    'evidence/runtime-control/prior-method-provenance.json',
    'evidence/runtime-control/prior-multibench-provenance.json',
    'evidence/runtime-control/prior-novelty-provenance.json',
    'evidence/runtime-control/prior-pi-provenance.json',
    'evidence/runtime-control/prior-strengths-provenance.json',
    'evidence/runtime-control/protocol.json',
    'evidence/runtime-control/provenance.json',
    'evidence/runtime-control/publication-record.json',
    'evidence/runtime-control/qualification.json',
    'evidence/runtime-control/registry-control-main-v1-episode_rows.csv',
    'evidence/runtime-control/registry-control-main-v1-pair_rows.csv',
    'evidence/runtime-control/registry-control-smoke-v1-episode_rows.csv',
    'evidence/runtime-control/registry-control-smoke-v1-pair_rows.csv',
    'evidence/runtime-control/results.md',
    'evidence/runtime-control/review-notes.md',
    'evidence/runtime-control/run-records.json',
    'evidence/runtime-control/summary.json',
    'scripts/summarize_registry_control.py',
})

EXPECTED.update({
    'docs/relational-authority.md',
    'docs/substance-retro.md',
    'evaluation/strong_comparison/README.md',
    'evaluation/strong_comparison/campaign.py',
    'evaluation/strong_comparison/protocol.json',
    'evidence/strong-comparison/cross-project-review.json',
    'evidence/strong-comparison/first-main-analysis.json',
    'evidence/strong-comparison/first-smoke-analysis.json',
    'evidence/strong-comparison/localization.json',
    'evidence/strong-comparison/policy-replay.json',
    'evidence/strong-comparison/prior-active-provenance.json',
    'evidence/strong-comparison/prior-baseline-provenance.json',
    'evidence/strong-comparison/prior-continuation-provenance.json',
    'evidence/strong-comparison/prior-contract-provenance.json',
    'evidence/strong-comparison/prior-contribution-provenance.json',
    'evidence/strong-comparison/prior-diagnostic-provenance.json',
    'evidence/strong-comparison/prior-explicit-grants-provenance.json',
    'evidence/strong-comparison/prior-fact-screen-provenance.json',
    'evidence/strong-comparison/prior-full-provenance.json',
    'evidence/strong-comparison/prior-intent-provenance.json',
    'evidence/strong-comparison/prior-intervention-provenance.json',
    'evidence/strong-comparison/prior-method-provenance.json',
    'evidence/strong-comparison/prior-multibench-provenance.json',
    'evidence/strong-comparison/prior-novelty-provenance.json',
    'evidence/strong-comparison/prior-pi-provenance.json',
    'evidence/strong-comparison/prior-runtime-control-provenance.json',
    'evidence/strong-comparison/prior-strengths-provenance.json',
    'evidence/strong-comparison/protocol.json',
    'evidence/strong-comparison/provenance.json',
    'evidence/strong-comparison/publication-record.json',
    'evidence/strong-comparison/results.md',
    'evidence/strong-comparison/review-notes.md',
    'evidence/strong-comparison/run-records.json',
    'evidence/strong-comparison/strong-banking-main-v1-episodes.csv',
    'evidence/strong-comparison/strong-banking-main-v1-metrics.json',
    'evidence/strong-comparison/strong-banking-main-v1-pairs.csv',
    'evidence/strong-comparison/strong-banking-smoke-v1-episodes.csv',
    'evidence/strong-comparison/strong-banking-smoke-v1-metrics.json',
    'evidence/strong-comparison/strong-banking-smoke-v1-pairs.csv',
    'evidence/strong-comparison/summary.json',
    'scripts/localize_strong_comparison.py',
    'scripts/replay_progent_policies.py',
    'scripts/summarize_strong_comparison.py',
})

EXPECTED.update({
    'docs/clm-story.md',
    'evaluation/relation_diagnostic/campaign.py',
    'evaluation/relation_diagnostic/check.py',
    'evaluation/relation_diagnostic/construct.py',
    'evaluation/relation_diagnostic/README.md',
    'evaluation/relation_diagnostic/prepare.py',
    'evaluation/relation_diagnostic/protocol.json',
    'evaluation/relation_format/campaign.py',
    'evaluation/relation_format/construct.py',
    'evidence/clm-relations/clm-source.json',
    'evidence/clm-relations/policy-diversity.json',
    'evidence/clm-relations/prior-active-provenance.json',
    'evidence/clm-relations/prior-baseline-provenance.json',
    'evidence/clm-relations/prior-continuation-provenance.json',
    'evidence/clm-relations/prior-contract-provenance.json',
    'evidence/clm-relations/prior-contribution-provenance.json',
    'evidence/clm-relations/prior-diagnostic-provenance.json',
    'evidence/clm-relations/prior-explicit-grants-provenance.json',
    'evidence/clm-relations/prior-fact-screen-provenance.json',
    'evidence/clm-relations/prior-full-provenance.json',
    'evidence/clm-relations/prior-intent-provenance.json',
    'evidence/clm-relations/prior-intervention-provenance.json',
    'evidence/clm-relations/prior-method-provenance.json',
    'evidence/clm-relations/prior-multibench-provenance.json',
    'evidence/clm-relations/prior-novelty-provenance.json',
    'evidence/clm-relations/prior-pi-provenance.json',
    'evidence/clm-relations/prior-runtime-control-provenance.json',
    'evidence/clm-relations/prior-strengths-provenance.json',
    'evidence/clm-relations/prior-strong-comparison-provenance.json',
    'evidence/clm-relations/protocol.json',
    'evidence/clm-relations/provenance.json',
    'evidence/clm-relations/publication-record.json',
    'evidence/clm-relations/qualification-checker-preservation.json',
    'evidence/clm-relations/qualification.json',
    'evidence/clm-relations/relation-construction-main-v1-samples.csv',
    'evidence/clm-relations/relation-construction-smoke-v1-samples.csv',
    'evidence/clm-relations/relation-format-main-v1-samples.csv',
    'evidence/clm-relations/results.md',
    'evidence/clm-relations/review-notes.md',
    'evidence/clm-relations/run-records.json',
    'evidence/clm-relations/summary.json',
    'paper/latex/construction-diagnostic.tex',
    'scripts/summarize_relation_diagnostic.py',
})

EXPECTED.update({
    'docs/witness-construction.md',
    'evaluation/witness_compiler/analyze.py',
    'evaluation/witness_compiler/campaign.py',
    'evaluation/witness_compiler/check.py',
    'evaluation/witness_compiler/construct.py',
    'evaluation/witness_compiler/kernel.py',
    'evaluation/witness_compiler/policy_client.mjs',
    'evaluation/witness_compiler/prepare.py',
    'evaluation/witness_compiler/prepare_banking.py',
    'evaluation/witness_compiler/protocol.json',
    'evaluation/witness_native/README.md',
    'evaluation/witness_native/agent.mjs',
    'evaluation/witness_native/broker.py',
    'evaluation/witness_native/campaign.py',
    'evaluation/witness_native/requirements.txt',
    'evaluation/witness_native/scripted_lifecycle.py',
    'evidence/witness-construction/cohort-v1/dojo_banking_11.json',
    'evidence/witness-construction/cohort-v1/dojo_banking_4.json',
    'evidence/witness-construction/cohort-v1/dojo_banking_6.json',
    'evidence/witness-construction/cohort-v1/dojo_workspace25.json',
    'evidence/witness-construction/cohort-v1/manifest.json',
    'evidence/witness-construction/cohort-v1/toolsandbox_contact_message.json',
    'evidence/witness-construction/compiler-qualification-v1.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-0/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-0/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-0/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-1/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-1/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-1/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-2/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-2/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-2/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-3/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-3/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_11/replicate-3/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-0/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-0/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-0/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-1/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-1/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-1/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-2/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-2/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-2/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-3/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-3/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_4/replicate-3/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-0/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-0/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-0/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-1/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-1/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-1/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-2/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-2/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-2/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-3/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-3/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_banking_6/replicate-3/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-0/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-0/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-0/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-1/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-1/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-1/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-2/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-2/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-2/values.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-3/query.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-3/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/dojo_workspace25/replicate-3/values.raw.json',
    'evidence/witness-construction/construction-main-v1/result.json',
    'evidence/witness-construction/construction-main-v1/results.json',
    'evidence/witness-construction/construction-main-v1/run-config.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-0/query.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-0/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-0/values.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-1/query.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-1/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-1/values.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-2/query.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-2/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-2/values.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-3/query.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-3/refs.raw.json',
    'evidence/witness-construction/construction-main-v1/toolsandbox_contact_message/replicate-3/values.raw.json',
    'evidence/witness-construction/construction-smoke-v1/dojo_workspace25/replicate-0/query.raw.json',
    'evidence/witness-construction/construction-smoke-v1/dojo_workspace25/replicate-0/refs.raw.json',
    'evidence/witness-construction/construction-smoke-v1/dojo_workspace25/replicate-0/values.raw.json',
    'evidence/witness-construction/construction-smoke-v1/result.json',
    'evidence/witness-construction/construction-smoke-v1/results.json',
    'evidence/witness-construction/construction-smoke-v1/run-config.json',
    'evidence/witness-construction/fee-analysis.json',
    'evidence/witness-construction/fee-recovery-cohort-v2/dojo_banking_11.json',
    'evidence/witness-construction/fee-recovery-cohort-v2/manifest.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-0/query.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-0/refs.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-0/values.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-1/query.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-1/refs.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-1/values.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-2/query.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-2/refs.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-2/values.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-3/query.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-3/refs.raw.json',
    'evidence/witness-construction/fee-recovery-v2/dojo_banking_11/replicate-3/values.raw.json',
    'evidence/witness-construction/fee-recovery-v2/result.json',
    'evidence/witness-construction/fee-recovery-v2/results.json',
    'evidence/witness-construction/fee-recovery-v2/run-config.json',
    'evidence/witness-construction/main-analysis.json',
    'evidence/witness-construction/native-pi-v1/config.json',
    'evidence/witness-construction/native-pi-v1/none-0.json',
    'evidence/witness-construction/native-pi-v1/none-1.json',
    'evidence/witness-construction/native-pi-v1/query-0.json',
    'evidence/witness-construction/native-pi-v1/query-1.json',
    'evidence/witness-construction/native-pi-v1/refs-0.json',
    'evidence/witness-construction/native-pi-v1/refs-1.json',
    'evidence/witness-construction/native-pi-v1/results.json',
    'evidence/witness-construction/native-pi-v1/values-0.json',
    'evidence/witness-construction/native-pi-v1/values-1.json',
    'evidence/witness-construction/native-pi-v2/config.json',
    'evidence/witness-construction/native-pi-v2/none-0.failure.json',
    'evidence/witness-construction/native-pi-v2/none-1.failure.json',
    'evidence/witness-construction/native-pi-v2/query-0.failure.json',
    'evidence/witness-construction/native-pi-v2/query-1.failure.json',
    'evidence/witness-construction/native-pi-v2/refs-0.failure.json',
    'evidence/witness-construction/native-pi-v2/refs-1.failure.json',
    'evidence/witness-construction/native-pi-v2/results.json',
    'evidence/witness-construction/native-pi-v2/values-0.failure.json',
    'evidence/witness-construction/native-pi-v2/values-1.failure.json',
    'evidence/witness-construction/native-pi-v3/config.json',
    'evidence/witness-construction/native-pi-v3/none-0.json',
    'evidence/witness-construction/native-pi-v3/none-1.json',
    'evidence/witness-construction/native-pi-v3/query-0.json',
    'evidence/witness-construction/native-pi-v3/query-1.json',
    'evidence/witness-construction/native-pi-v3/refs-0.json',
    'evidence/witness-construction/native-pi-v3/refs-1.json',
    'evidence/witness-construction/native-pi-v3/results.json',
    'evidence/witness-construction/native-pi-v3/values-0.json',
    'evidence/witness-construction/native-pi-v3/values-1.json',
    'evidence/witness-construction/outside-review.md',
    'evidence/witness-construction/prior-active-provenance.json',
    'evidence/witness-construction/prior-baseline-provenance.json',
    'evidence/witness-construction/prior-clm-provenance.json',
    'evidence/witness-construction/prior-continuation-provenance.json',
    'evidence/witness-construction/prior-contract-provenance.json',
    'evidence/witness-construction/prior-contribution-provenance.json',
    'evidence/witness-construction/prior-diagnostic-provenance.json',
    'evidence/witness-construction/prior-explicit-grants-provenance.json',
    'evidence/witness-construction/prior-fact-screen-provenance.json',
    'evidence/witness-construction/prior-full-provenance.json',
    'evidence/witness-construction/prior-intent-provenance.json',
    'evidence/witness-construction/prior-intervention-provenance.json',
    'evidence/witness-construction/prior-method-provenance.json',
    'evidence/witness-construction/prior-multibench-provenance.json',
    'evidence/witness-construction/prior-novelty-provenance.json',
    'evidence/witness-construction/prior-pi-provenance.json',
    'evidence/witness-construction/prior-runtime-control-provenance.json',
    'evidence/witness-construction/prior-strengths-provenance.json',
    'evidence/witness-construction/prior-strong-comparison-provenance.json',
    'evidence/witness-construction/provenance.json',
    'evidence/witness-construction/publication-record.json',
    'evidence/witness-construction/raw-publication-index.json',
    'evidence/witness-construction/smoke-analysis.json',
    'evidence/witness-construction/source-history/agent-v1.mjs',
    'evidence/witness-construction/source-history/agent-v2.mjs',
    'evidence/witness-construction/source-history/prepare-v1.py',
    'evidence/witness-construction/summary.json',
    'scripts/summarize_witness.py',
})

EXPECTED.update({
    'docs/agent-control.md',
    'evaluation/control_boundary/README.md',
    'evaluation/control_boundary/check_packets.py',
    'evaluation/control_boundary/protocol.json',
    'evaluation/control_boundary/replay.py',
    'evidence/control-boundary/artifact-index.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_0__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_10__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_11__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_12__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_13__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_14__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_15__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_1__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_2__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_3__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_4__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_5__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_6__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_7__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_8__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/banking__user_task_9__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/config.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_0__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_0__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_0__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_10__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_11__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_12__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_13__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_14__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_15__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_1__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_2__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_2__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_2__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_2__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_3__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_4__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_5__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_6__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_7__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_0.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_1.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_2.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_3.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_5.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_6.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_7.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_8__injection_task_8.json',
    'evidence/control-boundary/control-boundary-main-v1/packets/banking__user_task_9__injection_task_4.json',
    'evidence/control-boundary/control-boundary-main-v1/result.json',
    'evidence/control-boundary/control-boundary-main-v1/summary.json',
    'evidence/control-boundary/control-boundary-smoke-v1/banking__user_task_0__injection_task_0.json',
    'evidence/control-boundary/control-boundary-smoke-v1/banking__user_task_4__injection_task_2.json',
    'evidence/control-boundary/control-boundary-smoke-v1/banking__user_task_4__injection_task_6.json',
    'evidence/control-boundary/control-boundary-smoke-v1/config.json',
    'evidence/control-boundary/control-boundary-smoke-v1/packets/banking__user_task_0__injection_task_0.json',
    'evidence/control-boundary/control-boundary-smoke-v1/packets/banking__user_task_4__injection_task_2.json',
    'evidence/control-boundary/control-boundary-smoke-v1/packets/banking__user_task_4__injection_task_6.json',
    'evidence/control-boundary/control-boundary-smoke-v1/result.json',
    'evidence/control-boundary/control-boundary-smoke-v1/summary.json',
    'evidence/control-boundary/localization.json',
    'evidence/control-boundary/update-trigger-localization.json',
    'evidence/control-boundary/outside-review.md',
    'evidence/control-boundary/packet-check.json',
    'evidence/control-boundary/primary-sources.json',
    'evidence/control-boundary/prior-active-provenance.json',
    'evidence/control-boundary/prior-baseline-provenance.json',
    'evidence/control-boundary/prior-clm-provenance.json',
    'evidence/control-boundary/prior-continuation-provenance.json',
    'evidence/control-boundary/prior-contract-provenance.json',
    'evidence/control-boundary/prior-contribution-provenance.json',
    'evidence/control-boundary/prior-diagnostic-provenance.json',
    'evidence/control-boundary/prior-explicit-grants-provenance.json',
    'evidence/control-boundary/prior-fact-screen-provenance.json',
    'evidence/control-boundary/prior-full-provenance.json',
    'evidence/control-boundary/prior-intent-provenance.json',
    'evidence/control-boundary/prior-intervention-provenance.json',
    'evidence/control-boundary/prior-method-provenance.json',
    'evidence/control-boundary/prior-multibench-provenance.json',
    'evidence/control-boundary/prior-novelty-provenance.json',
    'evidence/control-boundary/prior-pi-provenance.json',
    'evidence/control-boundary/prior-runtime-control-provenance.json',
    'evidence/control-boundary/prior-strengths-provenance.json',
    'evidence/control-boundary/prior-strong-comparison-provenance.json',
    'evidence/control-boundary/prior-witness-provenance.json',
    'evidence/control-boundary/provenance.json',
    'evidence/control-boundary/publication-record.json',
    'evidence/control-boundary/results.md',
})

def retained_publication_sha256(record, section, path, expected):
    """Resolve only explicitly archived historical publication-document claims."""
    ledger=json.loads((ROOT/'evidence/control-paper/historical-document-snapshots.json').read_text())
    if section in {'unchanged_prior_sha256','source_sha256'}:
        for item in ledger['entries']:
            if (record,section,path,expected)==(item['record'],item['section'],item['path'],item['sha256']):
                if path not in {'paper/paper-en.pdf','paper/latex/build-manifest.json','paper/latex/references.bib'}:raise ValueError('Non-publication snapshot resolution')
                return hashlib.sha256((ROOT/item['archive']).read_bytes()).hexdigest()
    return hashlib.sha256((ROOT/path).read_bytes()).hexdigest()

EXPECTED.update({
    'docs/submission-readiness.md',
    'evidence/control-paper/bibliography-revision.json',
    'evidence/control-paper/cfp-source.json',
    'evidence/control-paper/historical-document-snapshots.json',
    'evidence/control-paper/prior-active-provenance.json',
    'evidence/control-paper/prior-baseline-provenance.json',
    'evidence/control-paper/prior-clm-provenance.json',
    'evidence/control-paper/prior-continuation-provenance.json',
    'evidence/control-paper/prior-contract-provenance.json',
    'evidence/control-paper/prior-contribution-provenance.json',
    'evidence/control-paper/prior-control-boundary-provenance.json',
    'evidence/control-paper/prior-diagnostic-provenance.json',
    'evidence/control-paper/prior-explicit-grants-provenance.json',
    'evidence/control-paper/prior-fact-screen-provenance.json',
    'evidence/control-paper/prior-full-provenance.json',
    'evidence/control-paper/prior-intent-provenance.json',
    'evidence/control-paper/prior-intervention-provenance.json',
    'evidence/control-paper/prior-method-provenance.json',
    'evidence/control-paper/prior-multibench-provenance.json',
    'evidence/control-paper/prior-novelty-provenance.json',
    'evidence/control-paper/prior-pi-provenance.json',
    'evidence/control-paper/prior-runtime-control-provenance.json',
    'evidence/control-paper/prior-strengths-provenance.json',
    'evidence/control-paper/prior-strong-comparison-provenance.json',
    'evidence/control-paper/prior-witness-provenance.json',
    'evidence/control-paper/provenance.json',
    'evidence/control-paper/publication-record.json',
    'evidence/control-paper/qualitative-review.md',
    'evidence/control-paper/review-record.json',
    'evidence/control-paper/revision-summary.json',
    'evidence/control-paper/snapshots/parent-build-manifest.json',
    'evidence/control-paper/snapshots/parent-paper.pdf',
    'evidence/control-paper/snapshots/parent-reference-catalog.json',
    'evidence/control-paper/snapshots/parent-references.bib',
    'evidence/control-paper/submission-window.json',
    'paper/latex/control-appendix.tex',
    'paper/latex/control-results.tex',
    'paper/submission-abstract.txt',
})

def refinement_publication_manifest():
    index=json.loads((ROOT/'evidence/refinement/file-manifest.json').read_text())
    files={}
    part_paths=set()
    for item in index['parts']:
        raw=(ROOT/item['path']).read_bytes()
        if hashlib.sha256(raw).hexdigest()!=item['sha256']:raise ValueError('Refinement manifest digest mismatch')
        part=json.loads(raw)
        if files.keys() & part.keys():raise ValueError('Duplicate refinement publication path')
        files.update(part);part_paths.add(item['path'])
    if len(files)!=index['count']:raise ValueError('Refinement manifest count mismatch')
    for name in files:
        path=Path(name)
        if not name.startswith('evidence/refinement/') or path.is_absolute() or '..' in path.parts:
            raise ValueError('Refinement publication path outside its declared evidence directory')
    return files,part_paths

REFINEMENT_FILES,REFINEMENT_PARTS=refinement_publication_manifest()
EXPECTED.update(REFINEMENT_FILES)
EXPECTED.update(REFINEMENT_PARTS)
EXPECTED.update({
    'evidence/refinement/file-manifest.json',
    'evidence/refinement/provenance.json',
    'scripts/materialize_refinement.py',
    'paper/latex/refinement-results.tex',
    'evaluation/refinement/README.md',
    'evaluation/refinement/protocol.json',
    'evaluation/refinement/controllers.py',
    'evaluation/refinement/qualify.py',
    'evaluation/refinement/pi_transport.py',
    'evaluation/refinement/conditional.py',
    'evaluation/refinement/pi_review_client.mjs',
    'evaluation/refinement/check_wire.mjs',
    'evaluation/refinement/agent.mjs',
    'evaluation/refinement/broker.py',
    'evaluation/refinement/episodes.py',
    'evaluation/refinement/prepare.py',
    'evaluation/refinement/analyze.py',
    'evaluation/refinement/narrowing_witness.py',
    'evaluation/refinement_initial/protocol.json',
    'evaluation/refinement_initial/README.md',
    'evaluation/refinement_initial/initial.py',
})

def main():
    errors=[];actual=set()
    for path in ROOT.rglob('*'):
        relative=path.relative_to(ROOT)
        if any(p in SKIP for p in relative.parts):continue
        if path.is_symlink():errors.append(str(relative)+': symlink not allowed in bundle');continue
        if not path.is_file():continue
        name=relative.as_posix();actual.add(name)
        if name not in EXPECTED:errors.append(name+': not in reviewed publication allowlist')
        data=path.read_bytes()
        if len(data)>512_000:errors.append(name+': unexpectedly large file')
        if name in {'paper/paper-en.pdf','paper/technical-supplement.pdf','paper/paper-icml.pdf','paper/paper-approval-identity.pdf','presentation/strengths.pdf','evidence/control-paper/snapshots/parent-paper.pdf','evidence/refinement/previous-paper.pdf'}:
            if not data.startswith(b'%PDF-'):errors.append(name+': invalid PDF signature')
            extracted=subprocess.run(['pdftotext',str(path),'-'],capture_output=True,text=True)
            if extracted.returncode:errors.append(name+': cannot inspect PDF text')
            else:check_text(name+' text',extracted.stdout,errors)
            continue
        try:text=data.decode('utf-8')
        except UnicodeDecodeError:errors.append(name+': binary file not allowed');continue
        check_text(name,text,errors)
        if path.suffix=='.md':
            for url in re.findall(r'\]\(([^)]+)\)',text):check_link(path,url,errors)
        if path.suffix=='.html':
            if '<script' in text.lower():errors.append(name+': script element')
            for url in re.findall(r'(?:href|src)="([^"]+)"',text):check_link(path,url,errors)
            for payload in re.findall(r'data:image/svg\+xml;base64,([A-Za-z0-9+/=]+)',text):
                svg=base64.b64decode(payload).decode();ET.fromstring(svg);check_text(name+' embedded SVG',svg,errors)
        if path.suffix=='.svg':ET.fromstring(text)
    for missing in EXPECTED-actual:errors.append(missing+': missing required file (run scripts/build.py first)')
    from materialize_refinement import validate as validate_refinement_traces
    validate_refinement_traces(lambda name,text:check_text(name,text,errors))
    for name,expected in REFINEMENT_FILES.items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected:errors.append(name+': refinement evidence hash mismatch')
    refinement=json.loads((ROOT/'evidence/refinement/provenance.json').read_text())
    for section in ['source_sha256','publication_sha256']:
        for name,expected in refinement[section].items():
            if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=expected:errors.append(name+': refinement provenance mismatch')
    for current,archive in refinement['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': old measurements changed during refinement study')
    benchmark_plan=json.loads((ROOT/'evidence/benchmark-plan-source-ledger.json').read_text())
    if hashlib.sha256((ROOT/benchmark_plan.get('plan_path','evaluation/benchmark-plan.json')).read_bytes()).hexdigest()!=benchmark_plan['plan_sha256']:errors.append('Historical benchmark plan differs from its source-review ledger')
    setup_ledger=json.loads((ROOT/'evidence/experiment-setup-source-ledger.json').read_text())
    for path,expected in setup_ledger['publication_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from experiment-setup source record')
    pga_record=json.loads((ROOT/'evidence/pga-active-evidence-provenance.json').read_text())
    for path,expected in pga_record['publication_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from PGA source/review record')
    pga_study=json.loads((ROOT/'evidence/pga-study/provenance.json').read_text())
    for section in ['source_sha256','result_sha256']:
        for path,expected in pga_study[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from PGA study record')
    pga_summary=json.loads((ROOT/'evidence/pga-study/summary.json').read_text())
    with (ROOT/'evidence/pga-study/episodes.csv').open(newline='') as source:pga_rows=list(csv.DictReader(source))
    if len(pga_rows)!=pga_summary['observed'] or len({(r['arm'],r['case_id']) for r in pga_rows})!=len(pga_rows):errors.append('PGA study: case coverage or duplicates')
    if any(r['native_targeted_asr'] for r in pga_rows if r['condition']!='attack'):errors.append('PGA study: non-attack in ASR')
    revision=json.loads((ROOT/'evidence/pga-revision/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256']:
        for path,expected in revision[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from PGA binding revision record')
    revision_summary=json.loads((ROOT/'evidence/pga-revision/summary.json').read_text())
    contract=json.loads((ROOT/'evidence/pga-revision/contract-checks.json').read_text())
    grounding=json.loads((ROOT/'evidence/pga-revision/grounding-results.json').read_text())
    replay=json.loads((ROOT/'evidence/pga-revision/replay-results.json').read_text())
    for label,filename in [('contract','contract-checks.json'),('diagnostics','grounding-results.json'),('replay','replay-results.json')]:
        if revision_summary['input_sha256'][label]!=hashlib.sha256((ROOT/'evidence/pga-revision'/filename).read_bytes()).hexdigest():errors.append('PGA revision: stale summary input '+label)
    if contract['n']!=len(contract['checks']) or contract['passed']!=sum(row['passed'] for row in contract['checks']):errors.append('PGA revision: inconsistent contract counts')
    if grounding['n']!=len(grounding['rows']) or grounding['passed']!=sum(row['passed'] for row in grounding['rows']):errors.append('PGA revision: inconsistent grounding counts')
    if grounding['fixture_sha256']!=hashlib.sha256((ROOT/'evidence/pga-revision/grounding-cases.json').read_bytes()).hexdigest():errors.append('PGA revision: authored fixture differs from measured input')
    if replay['n']!=len(replay['rows']) or replay['utility_successes']!=sum(row['native_utility_fixed_plan_replay'] for row in replay['rows']):errors.append('PGA revision: inconsistent replay counts')
    if any(row['native_targeted_asr'] is not None or not row['not_a_new_agent_episode'] for row in replay['rows']):errors.append('PGA revision: replay represented as a new agent/ASR result')
    calls=[call for data in [grounding,replay] for row in data['rows'] for call in row['calls']]
    usage=revision_summary['usage']
    if usage['model_calls']!=len(calls) or usage['missing_usage']!=sum(call.get('usage') is None for call in calls):errors.append('PGA revision: model-call accounting')
    for field in ['input_tokens','output_tokens']:
        if usage[field]!=sum((call.get('usage') or {}).get(field,0) for call in calls):errors.append('PGA revision: token accounting '+field)
    if usage['cached_input_tokens']!=sum(((call.get('usage') or {}).get('input_tokens_details') or {}).get('cached_tokens',0) for call in calls):errors.append('PGA revision: cached-token accounting')
    pi=json.loads((ROOT/'evidence/pi-luna/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256']:
        for path,expected in pi[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from Pi integration record')
    pi_summary=json.loads((ROOT/'evidence/pi-luna/summary.json').read_text())
    full=json.loads((ROOT/'evidence/pi-full/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256']:
        for path,expected in full[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from full-scope readiness record')
    inventory=json.loads((ROOT/'evidence/pi-full/inventory.json').read_text())
    full_summary=json.loads((ROOT/'evidence/pi-full/summary.json').read_text())
    if full_summary['inventory_sha256']!=hashlib.sha256((ROOT/'evidence/pi-full/inventory.json').read_bytes()).hexdigest():errors.append('Full-scope summary has stale inventory')
    counts=inventory['counts']
    if counts['clean']+counts['attack']+counts['goal_control']!=counts['scheduled_per_arm']:errors.append('Full-scope schedule counts')
    if counts['attack']+counts['excluded_not_injectable']+counts['preparation_errors']!=counts['cartesian_pairs']:errors.append('Full-scope pair accounting')
    if not full_summary['all_main_runs_complete'] or len(full_summary['arms'])!=2:errors.append('Full registry: both completed arms required')
    for arm in full_summary['arms']:
        with (ROOT/'evidence/pi-full'/(arm['arm']+'-episodes.csv')).open(newline='') as f:rows=list(csv.DictReader(f))
        if len(rows)!=arm['scheduled'] or len({r['case_id'] for r in rows})!=len(rows):errors.append('Full registry: case coverage/duplicates')
        for condition,expected in arm['conditions'].items():
            selected=[r for r in rows if r['condition']==condition]
            if len(selected)!=expected['observed'] or sum(r['native_utility']=='True' for r in selected)!=expected['native_success']:errors.append('Full registry: native utility counts')
            if condition=='attack' and (sum(r['native_targeted_asr']=='True' for r in selected)!=expected['asr_true'] or sum(not r['native_targeted_asr'] for r in selected)!=expected['asr_unknown']):errors.append('Full registry: ASR/unknown counts')
        if any(r['native_targeted_asr'] for r in rows if r['condition']!='attack'):errors.append('Full registry: goal control/clean row in ASR')
        for field in ['model_calls','input_tokens','cached_input_tokens','cache_write_tokens','output_tokens','missing_usage_calls','episodes_without_call_records']:
            if sum(int(r[field]) for r in rows)!=arm['usage'][field]:errors.append('Full registry: usage mismatch '+field)
    for name,expected in pi_summary['input_sha256'].items():
        if hashlib.sha256((ROOT/'evidence/pi-luna'/name).read_bytes()).hexdigest()!=expected:errors.append('Pi integration: stale result input '+name)
    generic=json.loads((ROOT/'evidence/intent-guard/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256']:
        for path,expected in generic[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from generic-guard record')
    generic_summary=json.loads((ROOT/'evidence/intent-guard/summary.json').read_text())
    for run in generic_summary['runs']:
        path=ROOT/'evidence/intent-guard'/run['pairs_csv']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=run['pairs_csv_sha256']:errors.append('Generic guard: pair CSV hash mismatch')
        with path.open(newline='') as stream:rows=list(csv.DictReader(stream))
        if len(rows)!=run['observed'] or len({x['case_id'] for x in rows})!=len(rows):errors.append('Generic guard: pair coverage or duplicates')
        if run['unobserved_scheduled']!=run['scheduled']-len(rows):errors.append('Generic guard: stopped schedule accounting')
        if run['complete'] and run['unobserved_scheduled']:errors.append('Generic guard: incomplete run marked complete')
        for condition,c in run['conditions'].items():
            subset=[r for r in rows if r['condition']==condition]
            if len(subset)!=c['n'] or sum(r['baseline_utility']=='True' for r in subset)!=c['baseline_utility'] or sum(r['guard_utility']=='True' for r in subset)!=c['guard_utility']:errors.append('Generic guard: utility totals')
            for field,key in [('utility_loss','paired_losses'),('utility_gain','paired_gains'),('comparison_unknown','unknown_comparisons')]:
                if sum(r[field]=='True' for r in subset)!=c[key]:errors.append('Generic guard: paired contrast count '+field)
            if sum(r['pair_valid']!='True' for r in subset)!=c['invalid_pairs']:errors.append('Generic guard: invalid pairs hidden')
            if condition=='goal_control':
                if sum(r['capability_control_loss']=='True' for r in subset)!=c['capability_losses'] or sum(r['capability_control_gain']=='True' for r in subset)!=c['capability_gains']:errors.append('Generic guard: capability losses/gains netted or inconsistent')
            if condition=='attack':
                if sum(r['baseline_asr']=='True' for r in subset)!=c['baseline_asr'] or sum(r['guard_asr']=='True' for r in subset)!=c['guard_asr']:errors.append('Generic guard: native ASR totals')
    for name in ['qualification.json','coupling-checks.json','measurement-checks.json']:
        data=json.loads((ROOT/'evidence/intent-guard'/name).read_text())
        if data['passed']!=data['n']:errors.append('Generic guard: failed final qualification '+name)
    if not json.loads((ROOT/'evidence/intent-guard/protocol-checks.json').read_text())['passed']:errors.append('Generic guard: protocol control failed')
    for name in ['none-results.json','pga-results.json','smoke-results.json']:
        data=json.loads((ROOT/'evidence/pi-luna'/name).read_text());rows=data['rows']
        if len(rows)!=data['scheduled'] or len({r['case_id'] for r in rows})!=len(rows):errors.append('Pi integration: missing/duplicate cases '+name)
        if any(r.get('native_targeted_asr') is not None for r in rows if r['condition']!='attack'):errors.append('Pi integration: non-attack in ASR')
        for row in rows:
            for call in row.get('pi',{}).get('calls',[])+row.get('grounding_calls',[]):
                if call['requested_model']!='gpt-6-luna' or call['reasoning_effort']!='none':errors.append('Pi integration: wrong requested model/reasoning')
    summary=json.loads((ROOT/'evidence/case-summary.json').read_text())['observations']
    if sum(summary['response_targets'].values())!=summary['response_target_total']:errors.append('case-summary: inconsistent response count')
    if summary['new_defense_experiments_run']!=0:errors.append('case-summary: update research status deliberately before claiming new results')
    pilot=json.loads((ROOT/'evidence/registry-pilot-summary.json').read_text())
    for attempt in pilot['attempts']:
        if 'results' not in attempt:continue
        result=attempt['results']
        if attempt['normal_passed']!=sum(row['passed'] for row in result['normal_cases']):errors.append('pilot: inconsistent normal count')
        if attempt['controls_detected']!=sum(row['detected'] for row in result['negative_controls']):errors.append('pilot: inconsistent control count')
    latest=pilot['attempts'][-1]
    for path,expected in latest['published_input_hashes'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from final qualified input')
    if hashlib.sha256((ROOT/'prototype/Cargo.lock').read_bytes()).hexdigest()!=latest['build']['cargo_lock_sha256']:errors.append('pilot: dependency lock differs from recorded build')
    study=json.loads((ROOT/'evidence/process-study-summary.json').read_text())
    with (ROOT/'evidence/process-study-outcomes.csv').open(newline='') as source:case_rows=list(csv.DictReader(source))
    for run in study['runs']:
        rows=[row for row in case_rows if row['run']==run['name'] and row['phase']=='normal']
        expected_keys={(arm,family,seed) for arm in ['procontract','durable_sop'] for family in run['families'] for seed in range(run['seed_start'],run['seed_start']+run['seeds'])}
        actual_keys={(row['arm'],row['family'],int(row['seed'])) for row in rows}
        if actual_keys!=expected_keys or len(actual_keys)!=len(rows):errors.append('process study: incomplete/duplicated schedule coverage')
        if len(rows)!=run['observed_cases'] or sum(int(row['passed']) for row in rows)!=run['passed']:errors.append('process study: case count mismatch')
        for metric in ['process_crashes','worker_calls']:
            if sum(int(row[metric]) for row in rows)!=run[metric]:errors.append('process study: '+metric+' mismatch')
        if sum(row['cases'] for row in run['arm_seed_rows'])!=run['observed_cases']:errors.append('process study: arm/seed count mismatch')
    for path,expected in study['runs'][-1]['input_hashes'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from process study input')
    async_study=json.loads((ROOT/'evidence/async-study-summary.json').read_text())
    with (ROOT/'evidence/async-study-outcomes.csv').open(newline='') as source:async_rows=list(csv.DictReader(source))
    for run in async_study['runs']:
        rows=[row for row in async_rows if row['run']==run['name']]
        expected_keys={(b,p,f,s) for b in ['procontract','durable_sop'] for p in ['local_snapshot','provider_fenced'] for f in run['families'] for s in range(run['seed_start'],run['seed_start']+run['seeds'])}
        actual_keys={(row['bookkeeping'],row['profile'],row['family'],int(row['seed'])) for row in rows}
        if actual_keys!=expected_keys or len(actual_keys)!=len(rows):errors.append('async study: incomplete/duplicated coverage')
        if len(rows)!=run['observed_cases'] or sum(1-int(row['expectation_met']) for row in rows)!=run['unexpected']:errors.append('async study: case count mismatch')
        for metric in ['caller_sigkills','provider_sigkills','worker_calls','fixture_rpc_calls']:
            if sum(int(row[metric]) for row in rows)!=run[metric]:errors.append('async study: '+metric+' mismatch')
        for arm in run['arm_rows']:
            subset=[row for row in rows if row['bookkeeping']==arm['bookkeeping'] and row['profile']==arm['profile']]
            if sum(int(row['provider_auth_violation']) for row in subset)!=arm['provider_auth_violations']:errors.append('async study: safety/expectation conflation')
            if sum(int(row['effect_after_local_withdraw']) for row in subset)!=arm['effects_after_local_withdraw']:errors.append('async study: local/provider boundary mismatch')
    for path,expected in async_study['runs'][-1]['input_hashes'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from async study input')
    witnesses=json.loads((ROOT/'evidence/async-counterexamples.json').read_text())
    for group in witnesses['boundary_counts']:
        subset=[row for row in async_rows if row['run']==witnesses['run'] and row['bookkeeping']==group['bookkeeping'] and row['profile']==group['profile']]
        post=sum(int(row['provider_auth_violation']) for row in subset)
        inclusive=sum(int(row['effect_after_local_withdraw']) for row in subset)
        if post!=group['post_provider_fence_violations'] or inclusive-post!=group['pre_provider_propagation_gap_effects']:errors.append('async study: overlapping boundary totals')
    ledger=(ROOT/'evidence/claim-ledger.md').read_text();paper=(ROOT/'paper/manuscript.zh-CN.md').read_text()
    for i in range(14):
        if '| E'+str(i)+' |' not in ledger:errors.append('missing evidence ID E'+str(i))
    for i in range(1,29):
        if '**[R'+str(i)+']**' not in paper:errors.append('missing reference ID R'+str(i))
    bib=(ROOT/'paper/references.bib').read_text()
    keys=re.findall(r'@\w+\s*\{\s*([^,\s]+)',bib)
    if len(keys)!=len(set(keys)):errors.append('duplicate bibliography keys')
    manifest=json.loads((ROOT/'preview/manifest.json').read_text())
    paper_build=json.loads((ROOT/'paper/latex/build-manifest.json').read_text())
    if hashlib.sha256((ROOT/paper_build['pdf']).read_bytes()).hexdigest()!=paper_build['pdf_sha256']:errors.append('English paper: PDF differs from build manifest')
    for path,expected in paper_build['source_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from compiled English paper')
    if paper_build['class']!='IEEEtran 1.8b' or paper_build['class_options']!=['conference','compsoc']:errors.append('English paper: wrong class/options')
    if paper_build['paper_size_pt']!=[612,792] or paper_build['pages']>18 or paper_build['main_text_pages']>13 or paper_build.get('references_and_appendices_pages',paper_build['reference_pages'])>5:errors.append('English paper: formatting bounds')
    reference_audit=json.loads((ROOT/'evidence/reference-audit.json').read_text())
    if reference_audit['distinct_body_citations']<80 or paper_build['printed_references']!=reference_audit['distinct_references']:errors.append('English paper: reference count mismatch')
    if reference_audit['catalog_sha256']!=hashlib.sha256((ROOT/'paper/latex/reference-catalog.json').read_bytes()).hexdigest():errors.append('English paper: stale reference catalog audit')
    if reference_audit['bibliography_sha256']!=hashlib.sha256((ROOT/'paper/latex/references.bib').read_bytes()).hexdigest():errors.append('English paper: stale bibliography audit')
    supplement=json.loads((ROOT/'paper/latex/supplement-manifest.json').read_text())
    if hashlib.sha256((ROOT/supplement['pdf']).read_bytes()).hexdigest()!=supplement['pdf_sha256']:errors.append('Supplement PDF differs from checked build')
    for path,expected in supplement['source_sha256'].items():
        if retained_publication_sha256('paper/latex/supplement-manifest.json','source_sha256',path,expected)!=expected:errors.append(path+': differs from supplement build')
    proof=json.loads((ROOT/'theory/verification.json').read_text())
    if proof['exit_code']!=0 or hashlib.sha256((ROOT/proof['source']).read_bytes()).hexdigest()!=proof['source_sha256']:errors.append('Lean proof source/result mismatch')
    if len(proof['axiom_reports'])!=proof['theorem_count'] or any('sorryAx' in line for line in proof['axiom_reports']):errors.append('Lean proof reports incomplete/contain admitted proof')
    names=re.findall(r'^theorem\s+(\w+)',(ROOT/proof['source']).read_text(),re.M)
    if names!=proof['theorems'] or len(names)!=proof['theorem_count']:errors.append('Lean theorem inventory differs from checked source')
    finite=json.loads((ROOT/'theory/finite-verification.json').read_text())
    if finite['exit_code']!=0:errors.append('Finite algorithm verification did not pass')
    for path,expected in finite['source_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from finite algorithm check')
    continuation=json.loads((ROOT/'theory/continuation-verification.json').read_text())
    if continuation['exit_code']!=0:errors.append('Continuation finite qualification did not pass')
    for path,expected in continuation['source_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from continuation check')
    continuation_record=json.loads((ROOT/'evidence/continuation-theory/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_empirical_sha256']:
        for path,expected in continuation_record[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from continuation research record')
    for current,archive in continuation_record['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:
            errors.append(current+': historical measurement fields changed')
    novelty=json.loads((ROOT/'evidence/novelty-frontier/provenance.json').read_text())
    for section in ['source_sha256','publication_sha256','unchanged_evidence_sha256']:
        for path,expected in novelty[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from novelty review record')
    for current,archive in novelty['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        old_fixed={k:v for k,v in old.items() if k!='publication_sha256'}
        for helper in novelty['publication_helper_reclassification'].get(current,[]):
            if helper not in {'scripts/build.py','scripts/build_supplement.py','scripts/validate.py'} or helper not in old_fixed['source_sha256']:
                errors.append(current+': invalid publication-helper migration')
                continue
            del old_fixed['source_sha256'][helper]
            if helper in new['source_sha256'] or helper not in new['publication_sha256']:
                errors.append(current+': publication helper not reclassified explicitly')
        if old_fixed!={k:v for k,v in new.items() if k!='publication_sha256'}:
            errors.append(current+': measured or historical fields changed during novelty review')
    contribution=json.loads((ROOT/'evidence/contribution-case/provenance.json').read_text())
    for section in ['input_sha256','publication_sha256','unchanged_evidence_sha256']:
        for path,expected in contribution[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from contribution reassessment record')
    for current,archive in contribution['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        old_fixed={k:v for k,v in old.items() if k!='publication_sha256'}
        for helper in contribution['publication_helper_reclassification'].get(current,[]):
            if helper not in {'scripts/build.py','scripts/build_supplement.py','scripts/validate.py'} or helper not in old_fixed['source_sha256']:
                errors.append(current+': invalid contribution publication-helper migration')
                continue
            del old_fixed['source_sha256'][helper]
            if helper in new['source_sha256'] or helper not in new['publication_sha256']:
                errors.append(current+': publication helper not reclassified')
        if old_fixed!={k:v for k,v in new.items() if k!='publication_sha256'}:
            errors.append(current+': measured or historical fields changed during contribution reassessment')
    claim_map=json.loads((ROOT/'evidence/contribution-case/claims.json').read_text())
    for claim in claim_map['claims']:
        for path,expected in claim['source_sha256'].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(claim['id']+': stale supporting evidence '+path)
    contract=json.loads((ROOT/'evidence/contract-study/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_evidence_sha256']:
        for path,expected in contract[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from frozen contract study record')
    for current,archive in contract['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:
            errors.append(current+': historical measurement fields changed during contract study publication')
    study=json.loads((ROOT/'evidence/contract-study/summary.json').read_text())
    if study['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_contract_study.py').read_bytes()).hexdigest():errors.append('Contract study: analysis source mismatch')
    if [r['observed'] for r in study['runs']]!=[1081,97] or not all(r['complete'] for r in study['runs']):errors.append('Contract study: declared coverage incomplete')
    for run in study['runs']:
        byarm={}
        for arm,name in run['episode_csvs'].items():
            path=ROOT/'evidence/contract-study'/name
            if hashlib.sha256(path.read_bytes()).hexdigest()!=run['episode_csv_sha256'][name]:errors.append('Contract study: CSV hash mismatch')
            with path.open(newline='') as f:rows=list(csv.DictReader(f))
            byarm[arm]={x['case_id']:x for x in rows}
            if len(rows)!=run['observed'] or len(byarm[arm])!=len(rows):errors.append('Contract study: missing/duplicate episodes')
            for condition,g in run['strata'].items():
                selected=[x for x in rows if x['condition']==condition];m=g['arms'][arm]
                if len(selected)!=m['episodes'] or sum(x['utility']=='True' for x in selected)!=m['utility']:errors.append('Contract study: native utility count mismatch')
                if condition=='attack' and sum(x['asr']=='True' for x in selected)!=m.get('asr'):errors.append('Contract study: native ASR count mismatch')
        for condition,g in run['strata'].items():
            for contrast in g['contrasts'].values():
                on=byarm[contrast['on_or_reference']];off=byarm[contrast['off_or_candidate']]
                pairs=[(x,off[k]) for k,x in on.items() if x['condition']==condition and x['audit_valid']=='True' and off[k]['audit_valid']=='True' and x['utility'] in {'True','False'} and off[k]['utility'] in {'True','False'}]
                if sum(x['utility']=='True' and y['utility']=='False' for x,y in pairs)!=contrast['on_only_success'] or sum(x['utility']=='False' and y['utility']=='True' for x,y in pairs)!=contrast['off_only_success']:errors.append('Contract study: paired factor count mismatch')
    screen=json.loads((ROOT/'evidence/fact-screen/summary.json').read_text())
    if screen['observed']!=32 or screen['episodes']!=160 or screen['audit_findings']:errors.append('Fact screen: coverage/audit mismatch')
    if screen['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_fact_screen.py').read_bytes()).hexdigest():errors.append('Fact screen: analysis mismatch')
    for filename,expected in screen['episode_csv_sha256'].items():
        path=ROOT/'evidence/fact-screen'/filename
        if hashlib.sha256(path.read_bytes()).hexdigest()!=expected:errors.append('Fact screen: CSV digest mismatch')
        with path.open(newline='') as f:rows=list(csv.DictReader(f))
        arm=rows[0]['arm']
        if len(rows)!=32 or len({r['case_id'] for r in rows})!=32:errors.append('Fact screen: incomplete episode CSV')
        for condition,g in screen['strata'].items():
            selected=[r for r in rows if r['condition']==condition];m=g['arms'][arm]
            if len(selected)!=m['episodes'] or sum(r['utility']=='True' for r in selected)!=m['utility']:errors.append('Fact screen: utility mismatch')
            if condition=='attack' and sum(r['asr']=='True' for r in selected)!=m['asr']:errors.append('Fact screen: ASR mismatch')
    screen_record=json.loads((ROOT/'evidence/fact-screen/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256']:
        for path,expected in screen_record[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from fact-screen record')
    for current,archive in screen_record['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': prior fact-screen measurement fields changed')
    intervention=json.loads((ROOT/'evidence/intervention-semantics/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256']:
        for path,expected in intervention[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': intervention record mismatch')
    for current,archive in intervention['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': prior measurement changed during intervention revision')
    negative=json.loads((ROOT/'theory/negative-constraint-verification.json').read_text())
    if negative['equivalence_checks']!=1536:errors.append('Negative constraint qualification coverage mismatch')
    for path,expected in negative['source_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': negative constraint source mismatch')
    localization=json.loads((ROOT/'evidence/intervention-semantics/localization.json').read_text())
    if localization['source_sha256']!=hashlib.sha256((ROOT/'scripts/audit_intervention_semantics.py').read_bytes()).hexdigest():errors.append('Intervention localization source mismatch')
    if len(localization['records'])!=42:errors.append('Intervention localization missing contrasts')
    for path,expected in localization['inputs'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append('Intervention audit input mismatch')
    for job,c in localization['counts'].items():
        selected=[r for r in localization['records'] if r['job']==job]
        if len(selected)!=c['pairs'] or len({r['case_id'] for r in selected})!=c['distinct_cases']:errors.append('Intervention contrast count mismatch')
        for label,total in c['classification'].items():
            if sum((r['witness'] or {}).get('classification','unlocalized')==label for r in selected)!=total:errors.append('Intervention classification count mismatch')
    multi=json.loads((ROOT/'evidence/multibench/summary.json').read_text())
    if multi['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_multibench.py').read_bytes()).hexdigest():errors.append('Multibench analysis source mismatch')
    mains=[r for r in multi['runs'] if r['job'] in {'multibench-asb-main-v1','multibench-injecagent-main-v1'}]
    if sum(r['observed'] for r in mains)!=2559 or sum(r['episodes'] for r in mains)!=7677:errors.append('Multibench main coverage mismatch')
    for run in multi['runs']:
        if not run['complete'] or run['audit_findings'] or run['metric_corrections']:errors.append('Multibench audit/coverage finding')
        rows=[]
        for name,digest in run['episode_csv_sha256'].items():
            path=ROOT/'evidence/multibench'/name
            if hashlib.sha256(path.read_bytes()).hexdigest()!=digest:errors.append('Multibench CSV identity mismatch')
            with path.open(newline='') as f:rows.extend(csv.DictReader(f))
        if len(rows)!=run['episodes'] or len({(x['case_id'],x['arm']) for x in rows})!=len(rows):errors.append('Multibench missing/duplicate episodes')
        for group,arms in run['groups'].items():
            for arm,entry in arms.items():
                selected=[x for x in rows if x['benchmark']+'_'+x['stratum']==group and x['arm']==arm]
                if len(selected)!=entry['n']:errors.append('Multibench group coverage mismatch')
                for metric,m in entry['metrics'].items():
                    if sum(x.get(metric)=='True' for x in selected)!=m['positive'] or sum(x.get(metric) in {'True','False'} for x in selected)!=m['observed']:errors.append('Multibench native/dispatch count mismatch')
        for c in run['contrasts']:
            by={a:{x['case_id']:x for x in rows if x['benchmark']+'_'+x['stratum']==c['group'] and x['arm']==a} for a in [c['reference'],c['candidate']]}
            ref,cand=by[c['reference']],by[c['candidate']]
            for metric,onkey,offkey in [('native_marker_utility','utility_gains','utility_losses'),('dispatch_asr','candidate_only_target_dispatch','reference_only_target_dispatch')]:
                pairs=[(x,cand[k]) for k,x in ref.items() if x.get(metric) in {'True','False'} and cand[k].get(metric) in {'True','False'} and x['audit_valid']=='True' and cand[k]['audit_valid']=='True' and x['status'] not in {'adapter_error','inference_error','episode_timeout','no_response'} and cand[k]['status'] not in {'adapter_error','inference_error','episode_timeout','no_response'}]
                if sum(x[metric]=='False' and y[metric]=='True' for x,y in pairs)!=len(c[onkey]) or sum(x[metric]=='True' and y[metric]=='False' for x,y in pairs)!=len(c[offkey]):errors.append('Multibench paired contrast mismatch')
    multirecord=json.loads((ROOT/'evidence/multibench/provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,digest in multirecord[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=digest:errors.append(path+': multibench record mismatch')
    for current,archive in multirecord['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': old measurements changed during multibench publication')
    grantbase=ROOT/'evidence/explicit-grants'
    grants=json.loads((grantbase/'summary.json').read_text())
    if grants['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_explicit_grants.py').read_bytes()).hexdigest():errors.append('Explicit grants: stale analysis source')
    if [r['episodes'] for r in grants['runs']]!=[3,72]:errors.append('Explicit grants: declared coverage mismatch')
    for run in grants['runs']:
        if not run['complete'] or run['audit_findings']:errors.append('Explicit grants: audit or coverage failure')
        path=grantbase/run['episode_csv']
        if hashlib.sha256(path.read_bytes()).hexdigest()!=run['episode_csv_sha256']:errors.append('Explicit grants: episode CSV hash mismatch')
        with path.open(newline='') as f:rows=list(csv.DictReader(f))
        if len(rows)!=run['episodes'] or len({(r['case_id'],r['arm']) for r in rows})!=len(rows):errors.append('Explicit grants: episode coverage/duplicates')
        for arm,expected in run['arms'].items():
            selected=[r for r in rows if r['arm']==arm]
            if len(selected)!=expected['episodes']:errors.append('Explicit grants: arm denominator')
            for metric in ['workflow_complete','scope_violation','safe_complete']:
                if sum(r[metric]=='True' for r in selected)!=expected[metric]:errors.append('Explicit grants: metric mismatch '+metric)
            for metric in ['actor_logical_calls','judge_logical_calls','actor_network_calls','judge_network_calls']:
                if sum(int(r[metric]) for r in selected)!=expected['cost'].get(metric,0):errors.append('Explicit grants: accounting mismatch '+metric)
        for decision in run['promotion'].values():
            if decision['classification']!='Bad for efficacy promotion' or decision['goal_step_gains'] or decision['semantic_veto_opportunities']:errors.append('Explicit grants: inconsistent promotion decision')
    first=json.loads((grantbase/'analysis-first.json').read_text())
    if first['runs']!=grants['runs']:errors.append('Explicit grants: undeclared score change during audit strengthening')
    for filename in ['kernel-qualification-v2.json','native-qualification-v2.json']:
        qualification=json.loads((grantbase/filename).read_text())
        if qualification['passed']!=qualification['n']:errors.append('Explicit grants: failed qualification')
        for name,expected in qualification['source_sha256'].items():
            if hashlib.sha256((ROOT/'evaluation/explicit_grants'/name).read_bytes()).hexdigest()!=expected:errors.append('Explicit grants: qualification source mismatch')
    grantrecord=json.loads((grantbase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in grantrecord[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': explicit-grant provenance mismatch')
    for current,archive in grantrecord['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': old measurement fields changed during explicit-grant publication')
    crossbase=ROOT/'evidence/diagnostic-crossover'
    cross=json.loads((crossbase/'summary.json').read_text());details=json.loads((crossbase/'case-details.json').read_text())
    if cross['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_diagnostic_crossover.py').read_bytes()).hexdigest():errors.append('Diagnostic crossover: analysis source mismatch')
    if cross['episodes']!=54 or cross['audited']!=54 or cross['audit_findings']:errors.append('Diagnostic crossover: coverage/audit failure')
    path=crossbase/'episodes.csv'
    if hashlib.sha256(path.read_bytes()).hexdigest()!=cross['episode_csv_sha256']:errors.append('Diagnostic crossover: CSV hash mismatch')
    with path.open(newline='') as f:rows=list(csv.DictReader(f))
    if len(rows)!=54 or len({(r['case_id'],r['replicate'],r['background'],r['message']) for r in rows})!=54:errors.append('Diagnostic crossover: duplicated/missing cases')
    for cell in cross['cells']:
        selected=[r for r in rows if all(r[k]==cell[k] for k in ['case_id','background','message'])]
        if len(selected)!=cell['n'] or sum(r['native_utility']=='True' for r in selected)!=cell['utility'] or sum(r['native_asr']=='True' for r in selected)!=cell['asr']:errors.append('Diagnostic crossover: cell count mismatch')
    for name,total in cross['cost'].items():
        if sum(r['cost'].get(name,0) for r in details)!=total:errors.append('Diagnostic crossover: cost mismatch')
    qualification=json.loads((crossbase/'qualification.json').read_text())
    if qualification['passed']!=qualification['n'] or qualification['n']!=19 or qualification['new_model_requests']:errors.append('Diagnostic crossover: qualification failure')
    if qualification['source_sha256']!=hashlib.sha256((ROOT/'scripts/qualify_diagnostic_crossover.py').read_bytes()).hexdigest():errors.append('Diagnostic crossover: qualification source mismatch')
    contrasts=json.loads((crossbase/'contrasts.json').read_text())
    if contrasts['source_sha256']!=hashlib.sha256((ROOT/'scripts/render_diagnostic_crossover.py').read_bytes()).hexdigest():errors.append('Diagnostic crossover: contrast renderer mismatch')
    exposure=json.loads((crossbase/'exposure-audit.json').read_text())
    if exposure['source_sha256']!=hashlib.sha256((ROOT/'scripts/audit_diagnostic_exposure.py').read_bytes()).hexdigest() or exposure['input_sha256']!=cross['input_sha256']['results.json']:errors.append('Diagnostic crossover: exposure source/input mismatch')
    for bg,expected in exposure['groups'].items():
        selected=[r for r in exposure['rows'] if r['background']==bg]
        if sum(r['later_nonempty_fact_messages'] for r in selected)!=expected['nonempty_fact_messages'] or sum(r['later_nonempty_fact_messages']>0 for r in selected)!=expected['exposed_episodes']:errors.append('Diagnostic crossover: exposure count mismatch')
    crossrecord=json.loads((crossbase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in crossrecord[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': crossover provenance mismatch')
    for current,archive in crossrecord['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': prior measured fields changed during crossover publication')
    baselinebase=ROOT/'evidence/baseline-audit'
    baseline=json.loads((baselinebase/'summary.json').read_text())
    if baseline['source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_baseline_audit.py').read_bytes()).hexdigest():errors.append('Baseline audit: stale analysis source')
    if baseline['audit_findings'] or [r['scheduled'] for r in baseline['runs']]!=[3,1,1] or not all(r['complete'] for r in baseline['runs']):errors.append('Baseline audit: coverage/findings mismatch')
    if baseline['total_cost_complete'] or not baseline['runs'][0]['rows'][-1]['policy_usage_unknown']:errors.append('Baseline audit: missing failed-run cost was hidden')
    last=baseline['runs'][-1]['rows'][0]
    if last['arm']!='progent' or last['status']!='completed' or last['native_utility'] is not True or last['mechanical_policy_checks']!=3:errors.append('Baseline audit: final integration qualification mismatch')
    qualification=json.loads((baselinebase/'qualification.json').read_text())
    if qualification['passed']!=qualification['n'] or qualification['n']!=12 or qualification['model_requests'] or qualification['network_attempts']:errors.append('Baseline audit: failed original-path controls')
    if qualification['harness_sha256']!=hashlib.sha256((ROOT/'evaluation/baseline_audit/qualify.py').read_bytes()).hexdigest():errors.append('Baseline audit: qualification harness mismatch')
    context=json.loads((baselinebase/'context-qualification.json').read_text())
    if context['passed']!=context['n'] or context['n']!=3 or context['network_requests'] or context['model_requests']:errors.append('Baseline audit: failed context qualification')
    if context['source_sha256']!=hashlib.sha256((ROOT/'evaluation/baseline_audit/check_context.mjs').read_bytes()).hexdigest():errors.append('Baseline audit: context checker mismatch')
    baselinerecord=json.loads((baselinebase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in baselinerecord[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': baseline audit provenance mismatch')
    for current,archive in baselinerecord['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': old measured fields changed during baseline audit')
    strengthsbase=ROOT/'evidence/strengths-presentation'
    strengths=json.loads((strengthsbase/'checked-evidence.json').read_text())
    if strengths['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/prepare_strengths_presentation.py').read_bytes()).hexdigest():errors.append('Strengths presentation: stale analysis source')
    for path,expected in strengths['input_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': strengths presentation input mismatch')
    expected_points={('contract-factorial-main-v1','clean'):(97,87,87,0,0),('contract-factorial-main-v1','attack'):(949,827,835,4,12),('contract-factorial-main-v1','goal_control'):(35,33,32,1,0),('contract-factorial-clean-repeat-v1','clean'):(97,86,88,0,2)}
    if len(strengths['operating_points'])!=len(expected_points):errors.append('Strengths presentation: cohort coverage')
    for point in strengths['operating_points']:
        observed=tuple(point[k] for k in ['n','reference_success','minimal_success','paired_losses','paired_gains'])
        if observed!=expected_points.get((point['job'],point['condition'])):errors.append('Strengths presentation: operating point mismatch')
    if strengths['profile_scope']['shared_actor_profiles']!=['user_task_32','user_task_6','user_task_7']:errors.append('Strengths presentation: shared profile scope changed')
    slide=json.loads((ROOT/'presentation/build-manifest.json').read_text())
    if slide['pages']!=6 or not slide['fonts_embedded'] or slide['overfull_boxes_pt']:errors.append('Strengths presentation: build qualification')
    if slide['evidence_sha256']!=hashlib.sha256((strengthsbase/'checked-evidence.json').read_bytes()).hexdigest():errors.append('Strengths presentation: compiled evidence mismatch')
    for path,expected in slide['source_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': presentation source mismatch')
    if hashlib.sha256((ROOT/slide['pdf']).read_bytes()).hexdigest()!=slide['pdf_sha256']:errors.append('Strengths presentation: PDF mismatch')
    strengthsrecord=json.loads((strengthsbase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in strengthsrecord[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': strengths provenance mismatch')
    for current,archive in strengthsrecord['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': old measured fields changed during presentation revision')
    runtimebase=ROOT/'evidence/runtime-control'
    runtime=json.loads((runtimebase/'summary.json').read_text())
    if runtime['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_registry_control.py').read_bytes()).hexdigest():errors.append('Registry control: stale analyzer')
    if [r['scheduled'] for r in runtime['runs']]!=[1,451]:errors.append('Registry control: cohort coverage')
    for run in runtime['runs']:
        if not run['complete'] or run['audit_findings']:errors.append('Registry control: incomplete audit')
        episodepath=runtimebase/(run['job']+'-episode_rows.csv');pairpath=runtimebase/(run['job']+'-pair_rows.csv')
        for key,path in [('episode_rows_sha256',episodepath),('pair_rows_sha256',pairpath)]:
            if hashlib.sha256(path.read_bytes()).hexdigest()!=run[key]:errors.append('Registry control: CSV identity mismatch')
        with episodepath.open(newline='') as f:episodes=list(csv.DictReader(f))
        with pairpath.open(newline='') as f:pairs=list(csv.DictReader(f))
        if len(episodes)!=2*run['scheduled'] or len(pairs)!=run['scheduled']:errors.append('Registry control: CSV coverage')
        for condition,arms in run['groups'].items():
            for arm,group in arms.items():
                rows=[e for e in episodes if e['condition']==condition and e['arm']==arm]
                for key,metric in group['metrics'].items():
                    if metric['n']!=len(rows) or metric['positive']!=sum(e[key]=='True' and e['audit_valid']=='True' for e in rows):errors.append('Registry control: metric count mismatch')
            rows=[e for e in pairs if e['condition']==condition]
            contrast=run['contrasts'][condition]
            for field,cases in [('utility_gain','utility_gains'),('utility_loss','utility_losses')]:
                if sorted(e['case_id'] for e in rows if e[field]=='True')!=sorted(contrast[cases]):errors.append('Registry control: paired differences mismatch')
            if sorted(e['case_id'] for e in rows if e['valid_complete']=='True' and e['actor_trace_equal']=='False')!=sorted(contrast['trace_mismatches']):errors.append('Registry control: trace differences mismatch')
    qualification=json.loads((runtimebase/'qualification.json').read_text())
    if qualification['passed']!=5 or qualification['n']!=5 or qualification['offered_interface_comparisons']!=1302 or qualification['clean_replayed_cases']!=51 or qualification['model_requests']:errors.append('Registry control: qualification coverage')
    for name,h in qualification['source_sha256'].items():
        if hashlib.sha256((ROOT/'evaluation/registry_control'/name).read_bytes()).hexdigest()!=h:errors.append('Registry control: qualification source mismatch')
    runtime_record=json.loads((runtimebase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in runtime_record[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': runtime-control provenance mismatch')
    for current,archive in runtime_record['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': prior measured fields changed during runtime-control publication')
    strongbase=ROOT/'evidence/strong-comparison'
    strong=json.loads((strongbase/'summary.json').read_text())
    if strong['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_strong_comparison.py').read_bytes()).hexdigest():errors.append('Strong comparison: stale analyzer')
    if [r['scheduled'] for r in strong['runs']]!=[3,169]:errors.append('Strong comparison: cohort coverage')
    for run in strong['runs']:
        if not run['complete'] or run['audit_findings'] or run['metrics']['invalid_or_incomplete']:errors.append('Strong comparison: incomplete or failed audit')
        for key in ['episodes','pairs']:
            path=strongbase/(run['job']+'-'+key+'.csv')
            if hashlib.sha256(path.read_bytes()).hexdigest()!=run[key+'_csv_sha256']:errors.append('Strong comparison: CSV identity')
        with (strongbase/(run['job']+'-episodes.csv')).open(newline='') as f:episodes=list(csv.DictReader(f))
        with (strongbase/(run['job']+'-pairs.csv')).open(newline='') as f:pairs=list(csv.DictReader(f))
        if len(episodes)!=3*run['scheduled'] or len(pairs)!=run['scheduled']:errors.append('Strong comparison: CSV count')
        for condition,arms in run['groups'].items():
            for arm,group in arms.items():
                rows=[e for e in episodes if e['condition']==condition and e['arm']==arm]
                for key,m in group['metrics'].items():
                    if m['n']!=len(rows) or m['positive']!=sum(e[key]=='True' and e['audit_valid']=='True' for e in rows):errors.append('Strong comparison: metric counts')
        for contrast in run['contrasts']:
            rows=[r for r in pairs if r['condition']==contrast['condition'] and r['valid_complete']=='True'];a=contrast['candidate'];b=contrast['reference']
            if sorted(r['case_id'] for r in rows if r[a+'_utility']=='True' and r[b+'_utility']=='False')!=sorted(contrast['utility_gains']):errors.append('Strong comparison: gains')
            if sorted(r['case_id'] for r in rows if r[a+'_utility']=='False' and r[b+'_utility']=='True')!=sorted(contrast['utility_losses']):errors.append('Strong comparison: losses')
    replay=json.loads((strongbase/'policy-replay.json').read_text())
    if replay['passed']!=169 or replay['scheduled']!=169 or replay['model_requests'] or replay['network_requests']:errors.append('Strong comparison: replay coverage')
    if replay['source_sha256']!=hashlib.sha256((ROOT/'scripts/replay_progent_policies.py').read_bytes()).hexdigest():errors.append('Strong comparison: replay source')
    localization=json.loads((strongbase/'localization.json').read_text())
    if localization['source_sha256']!=hashlib.sha256((ROOT/'scripts/localize_strong_comparison.py').read_bytes()).hexdigest() or len(localization['rows'])!=41:errors.append('Strong comparison: localization source/coverage')
    if strong['runs'][-1]['total_actual_cost']['calls_missing_usage']!=5:errors.append('Strong comparison: missing costs hidden')
    strongrecord=json.loads((strongbase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in strongrecord[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': strong-comparison provenance mismatch')
    for current,archive in strongrecord['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': prior measured fields changed during strong comparison')
    relbase=ROOT/'evidence/clm-relations'
    relation=json.loads((relbase/'summary.json').read_text())
    if relation['analysis_source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_relation_diagnostic.py').read_bytes()).hexdigest():errors.append('Relation diagnostic: stale analyzer')
    if [r['scheduled'] for r in relation['runs']]!=[1,12,3]:errors.append('Relation diagnostic: cohort coverage')
    for run in relation['runs']:
        if run['audit_findings'] or not run['complete']:errors.append('Relation diagnostic: incomplete/failed audit')
        path=relbase/(run['job']+'-samples.csv')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=run['samples_csv_sha256']:errors.append('Relation diagnostic: CSV identity')
        with path.open(newline='') as f:rows=list(csv.DictReader(f))
        if len(rows)!=2*run['scheduled']:errors.append('Relation diagnostic: sample count')
        for arm,g in run['groups'].items():
            es=[r for r in rows if r['arm']==arm]
            if len(es)!=g['samples'] or sum(e['exact_conformance']=='True' for e in es)!=g['exact']:errors.append('Relation diagnostic: exactness count')
            for key in ['valid_admitted','invalid_admitted','cross_recipient_body_admitted','within_body_mismatches_admitted']:
                if sum(int(e[key]) for e in es)!=g[key]:errors.append('Relation diagnostic: probe count')
    qual=json.loads((relbase/'qualification.json').read_text())
    if qual['passed']!=4 or qual['n']!=4 or qual['model_requests'] or qual['network_requests'] or qual['native_effects']:errors.append('Relation diagnostic: control qualification')
    if qual['source_sha256']!=hashlib.sha256((ROOT/'evaluation/relation_diagnostic/check.py').read_bytes()).hexdigest():errors.append('Relation diagnostic: checker identity')
    relrecord=json.loads((relbase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in relrecord[section].items():
            if retained_publication_sha256('evidence/clm-relations/provenance.json',section,path,expected)!=expected:errors.append(path+': relation narrative provenance mismatch')
    for current,archive in relrecord['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': prior measured fields changed during relation narrative revision')
    witnessbase=ROOT/'evidence/witness-construction'
    witness=json.loads((witnessbase/'summary.json').read_text())
    if witness['audit_findings']:errors.append('Witness construction/native audit findings')
    expected_studies={'construction-smoke-v1':[0,0,1], 'construction-main-v1':[15,11,10], 'fee-recovery-v2':[3,4,4]}
    for run,counts in expected_studies.items():
        for mode,count in zip(['values','refs','query'],counts):
            samples=[json.loads(p.read_text()) for p in (witnessbase/run).glob('*/replicate-*/'+mode+'.raw.json')]
            if sum(x['result']['exact_grounding'] for x in samples)!=count or witness['construction'][run][mode]['exact']!=count:errors.append('Witness construction table differs from raw rows')
    for arm,count in zip(['none','values','refs','query'],[2,2,2,0]):
        if witness['native']['native-pi-v3'][arm].get('owner_complete',0)!=count:errors.append('Witness native table mismatch')
    if witness['source_sha256']!=hashlib.sha256((ROOT/'scripts/summarize_witness.py').read_bytes()).hexdigest():errors.append('Witness summary analyzer identity')
    for row in json.loads((witnessbase/'raw-publication-index.json').read_text())['files']:
        if hashlib.sha256((ROOT/row['published']).read_bytes()).hexdigest()!=row['published_sha256']:errors.append('Witness raw publication hash')
    wr=json.loads((witnessbase/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in wr[section].items():
            if retained_publication_sha256('evidence/witness-construction/provenance.json',section,path,expected)!=expected:errors.append(path+': witness study provenance mismatch')
    for current,archive in wr['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': old measurements changed during witness study')
    cb=ROOT/'evidence/control-boundary'
    control=json.loads((cb/'control-boundary-main-v1/summary.json').read_text())
    if control['scheduled']!=144 or control['observed']!=144 or not control['complete'] or control['replay_failures']:errors.append('Control-boundary replay coverage')
    qualified=[r for r in control['rows'] if r['coverage']=='qualified_single_candidate']
    if len(qualified)!=98 or sum(r['progent']['allowed'] for r in qualified)!=1 or sum(r['progent']['native_goal'] for r in qualified)!=1:errors.append('Control-boundary result counts')
    for r in control['rows']:
        if r.get('packet_file') and hashlib.sha256((cb/'control-boundary-main-v1'/r['packet_file']).read_bytes()).hexdigest()!=r['packet_sha256']:errors.append('Control-boundary packet identity')
    checker=json.loads((cb/'packet-check.json').read_text())
    if checker['matching']!=98 or checker['qualified']!=98 or any(r['findings'] for r in checker['rows']):errors.append('Control-boundary packet re-execution')
    if checker['source_sha256']!=hashlib.sha256((ROOT/'evaluation/control_boundary/check_packets.py').read_bytes()).hexdigest():errors.append('Control-boundary verifier identity')
    for r in json.loads((cb/'artifact-index.json').read_text())['files']:
        if hashlib.sha256((ROOT/r['published_path']).read_bytes()).hexdigest()!=r['sha256']:errors.append('Control-boundary artifact identity')
    cr=json.loads((cb/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_prior_sha256']:
        for path,expected in cr[section].items():
            if retained_publication_sha256('evidence/control-boundary/provenance.json',section,path,expected)!=expected:errors.append(path+': control-boundary provenance mismatch')
    for current,archive in cr['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': old measurements changed during control-boundary study')
    cp=ROOT/'evidence/control-paper'
    snapshots=json.loads((cp/'historical-document-snapshots.json').read_text())['entries']
    if len(snapshots)!=6:errors.append('Control manuscript: historical document snapshot count')
    for item in snapshots:
        if (item['section']!='unchanged_prior_sha256' and (item['record'],item['section'],item['path'])!=('paper/latex/supplement-manifest.json','source_sha256','paper/latex/references.bib')) or item['path'] not in {'paper/paper-en.pdf','paper/latex/build-manifest.json','paper/latex/references.bib'}:errors.append('Control manuscript: non-publication archival mapping')
        if hashlib.sha256((ROOT/item['archive']).read_bytes()).hexdigest()!=item['sha256']:errors.append('Control manuscript: historical document identity')
        record=json.loads((ROOT/item['record']).read_text())
        if record[item['section']][item['path']]!=item['sha256']:errors.append('Control manuscript: historical claim modified')
    revision=json.loads((cp/'revision-summary.json').read_text())
    # This prior revision report is frozen evidence; its manuscript is archived.
    if revision['format']['pdf_sha256']!=hashlib.sha256((ROOT/'evidence/refinement/previous-paper.pdf').read_bytes()).hexdigest():errors.append('Control manuscript: archived revision PDF identity')
    review=json.loads((cp/'review-record.json').read_text())
    if review['calibration_n']!=0 or review['acceptance_agreement'] is not None:errors.append('Control manuscript: unmeasured calibration claim')
    main=(ROOT/'paper/latex/main.tex').read_text()
    abstract=re.sub(r'\s+',' ',re.search(r'\\begin\{abstract\}(.*?)\\end\{abstract\}',main,re.S)[1]).strip()
    if (ROOT/'paper/submission-abstract.txt').read_text().split('Abstract:\n',1)[1].strip()!=abstract:errors.append('Control manuscript: registration abstract mismatch')
    cpr=json.loads((cp/'provenance.json').read_text())
    for section in ['source_sha256','result_sha256','publication_sha256','unchanged_empirical_sha256']:
        for path,expected in cpr[section].items():
            if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': control manuscript provenance mismatch')
    for current,archive in cpr['historical_publication_archives'].items():
        old=json.loads((ROOT/archive).read_text());new=json.loads((ROOT/current).read_text())
        if {k:v for k,v in old.items() if k!='publication_sha256'}!={k:v for k,v in new.items() if k!='publication_sha256'}:errors.append(current+': prior measurements changed during control manuscript revision')
    initiative=json.loads((ROOT/'theory/initiative-risk-verification.json').read_text())
    if initiative['exit_code']!=0:errors.append('Initiative risk-model verification did not pass')
    for path,expected in initiative['source_sha256'].items():
        if hashlib.sha256((ROOT/path).read_bytes()).hexdigest()!=expected:errors.append(path+': differs from frozen risk-model check')
    mapping=json.loads((ROOT/'evidence/implementation-scope.json').read_text())
    for entry in mapping['case_sources']:
        if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:errors.append(entry['path']+': differs from worked-case source mapping')
    icml=json.loads((ROOT/'paper/icml2026/build-manifest.json').read_text())
    if hashlib.sha256((ROOT/icml['pdf']).read_bytes()).hexdigest()!=icml['pdf_sha256']:errors.append('ICML PDF differs from its preserved build manifest')
    for path,expected in icml['source_sha256'].items():
        if hashlib.sha256((ROOT/'paper/icml2026'/path).read_bytes()).hexdigest()!=expected:errors.append('paper/icml2026/'+path+': differs from preserved ICML build')
    approval=json.loads((ROOT/'paper/approval-identity/build-manifest.json').read_text())
    if hashlib.sha256((ROOT/approval['pdf']).read_bytes()).hexdigest()!=approval['pdf_sha256']:errors.append('Approval-case PDF differs from its preserved build')
    for path,expected in approval['source_sha256'].items():
        if hashlib.sha256((ROOT/'paper/approval-identity'/path).read_bytes()).hexdigest()!=expected:errors.append('paper/approval-identity/'+path+': differs from preserved build')
    for entry in manifest['documents']:
        for field in ['source','output']:
            digest=hashlib.sha256((ROOT/entry[field]).read_bytes()).hexdigest()
            if digest!=entry[field+'_sha256']:errors.append(entry[field]+': stale preview manifest')
    if errors:
        print('\n'.join(errors));raise SystemExit(1)
    print(json.dumps({'checked_files':len(actual),'local_links':'ok','redaction_patterns':'no findings','counts':'consistent','previews':'current','scope':'Repository checks only; original raw evidence and proposed defense efficacy are not validated here.'},indent=2))

if __name__=='__main__':main()
