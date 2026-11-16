# Authorization in LLM agents: anonymous review artifact

This snapshot accompanies **Enforcing the Wrong Permissions: An Empirical Study of Authorization in LLM Agents**.

It contains experimental source code, recorded inputs and continuations, and a portable offline analysis entry point. The artifact distinguishes proposals, installed permissions and changes recorded in the native benchmark state.

## Start here

Requirements: Python **3.11 or newer**, including its standard `lzma` module. The offline analysis needs no third-party Python packages, API keys, model downloads or network access. Allow approximately 1 GB of free memory and several minutes for all analyses; actual resources depend on the machine.

From an extracted ZIP or a clone of this snapshot:

```sh
python3 scripts/reproduce.py --study all
```

Individual studies can be run separately:

```sh
python3 scripts/reproduce.py --study faults
python3 scripts/reproduce.py --study matched
python3 scripts/reproduce.py --study models
```

The runner checks the file manifest before reading the data and writes JSON reports to `results/`. It disables network connections. It uses retained analysis-function bodies while omitting imports and launch configuration tied to the original research machine.

## What these commands reproduce

| Study | Retained evidence | Offline check |
|---|---|---|
| Fault injection | 965 raw episode records, the declared cohort and condition manifest | Re-extract selected native effects; recover 83, 54, 1, 0 and 0 wrong effects across the five refusal forms, each out of 130 faults |
| Matched information inputs | All 816 main continuations, 136 source states, labels and the registered protocol | Recompute first-response adoption, first-update admission, later selected effects and task-weighted contrasts: 47.5 percentage points and 4.0509–4.5139 points |
| Full cross-model study | The three configurations on the 83-condition panel, including updater records and recorded failures | Re-extract actor effects from recorded before/after states; check saved updater admission against the raw updater record |
| Common model panel | Eight actor configurations on the same 31 tasks and seven completed updater configurations | Recompute the strict selected-effect definition used in the comparison; preserve unknown outcomes |
| Repair-status study | 108 recorded continuations under the matched notices | Reaggregate the runtime endpoints and check them against the raw records |
| Prompt reminders | 498 recorded continuations | Reaggregate the runtime endpoints and check them against the raw records |

The main conditional wrong-effect counts on all 83 conditions are 43, 11 and 22 for GPT-6 Luna, Claude Haiku 5.5 and DeepSeek-V4.1-Flash. On the common 31-task panel, value-stating corruption counts are 20, 5, 9, 17, 21, 14, 20 and 23 in the model order documented in `docs/STUDIES.md`.

The matched-study interval represents **bounds from missing outcomes**, not a confidence interval. Its registered harmful-admission decision remains indeterminate because the predicted five-point effect was not reached.

## Scope of reproduction

These commands reanalyze **retained model outputs and state traces**. They do not resample the model APIs, execute the native benchmark tools again, or establish statistical independence from the original study. Updater admission is checked against the recorded installed-policy probe, rather than recomputed by a new SMT invocation. Repair-status and reminder endpoints are retained runtime measurements.

For the matched study, parameter validity, native defaults and coercions are supplied by `data/native-parameter-normalization.json`, exported from the pinned AgentDojo models for every operation used by the analyzer. The offline runner rejects calls outside this fixed fixture. To verify the fixture itself, install the pinned AgentDojo source in a separate environment and run `python3 scripts/verify_native_normalization.py`; that optional check needs AgentDojo and its dependencies, while the default analysis does not.

Selected effects concern the declared argument or relation. They are not a complete authorization oracle for arbitrary side effects, cumulative transfers or repeated payments. Task utility and attacker-goal predicates are reported separately from those selected effects.

The earlier lifecycle replay, banking update, four-suite reviewer, replacement-actor, construction and sealed-comparison experiments have reference source code here and selected result summaries under `supplement/`. Their complete historical raw archives and a portable fresh-sampling campaign are **not included in this compact snapshot**. The commands above do not claim to reproduce those studies.

## Repository layout

```text
scripts/reproduce.py       portable offline analysis
data/*.jsonl.xz            compressed JSON-lines records, readable with Python lzma
data/common-panel-selection.json
reference/evaluation/     retained experiment implementations
reference/scripts/        retained experiment and analysis utilities
reference/crossmodel/     actor, updater, provider and analysis implementations
reference/metric_sources/ exact function sources loaded by the offline runner
supplement/               selected earlier-study result summaries
docs/                     study map, provenance and limitations
SOURCE-MANIFEST.json       source-byte and anonymized-byte hashes
MANIFEST.json              checksums of the delivered snapshot
```

## Version and anonymization

The underlying benchmark is AgentDojo commit `089ed468cf3ed0322acc66b0211f26d9d90dbf60`; the original policy implementation is Progent commit `b02783b896d4bf01a2adf24738015e258db8d35b`. Core experiments use Pi 1.5.0. Model identifiers, configurations and conditions remain in the records.

This repository has a new anonymous Git history. Author identifiers and machine-specific paths are removed from the exported contents, including the compressed records. Anonymous path aliases in `reference/` are provenance placeholders, not expected installation locations. `SOURCE-MANIFEST.json` distinguishes the retained source-byte hashes from the anonymized-byte hashes. Original opaque request hashes may therefore refer to pre-anonymization bytes; `MANIFEST.json` verifies the actual delivered files.

All task identities, accounts, messages and file names in benchmark states are simulated benchmark data. Authentication metadata is excluded. Credentials for fresh model calls are never supplied by this artifact.

For review, use the anonymous hosting URL. Keep the published snapshot fixed after the paper deadline. See `NOTICE.md` for source and licensing scope.
