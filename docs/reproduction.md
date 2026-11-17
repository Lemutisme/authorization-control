# Reproduction

Run the entire recorded pipeline:

```sh
python3 -m pipeline setup
.venv/bin/python -m pipeline reproduce --all
```

Setup creates a Python 3.13 environment, installs the pinned benchmark and controller, and checks out the original Progent revision. The reproduction command recomputes the tables, replays native effects and permission probes, and generates figures. It makes no model requests. To recompute tables without native replay, add `--analysis-only`.

## Studies

| Study | Recorded evaluation |
|---|---|
| `reviewer` | 5,890 episodes across the four AgentDojo suites |
| `banking` | 925 banking episodes under five controllers |
| `faults` | 965 refusal-message interventions and controls |
| `approvers` | 740 optional/forced and automatic/narrowing episodes |
| `replacement` | 1,296 adversarial episodes, 48 honest controls, and the separately reported trusted-only baseline |
| `replacement-development` | 432 attack-development episodes and 12 capability-selection episodes |
| `repeated-probes` | Both the 98-state and 112-state panels under three controllers |
| `reconstruction-faults` | 756 episodes over 83 faults and one control |
| `sealed` | 2,688 replacement-actor and honest episodes |
| `sealed-natural` | 56 continuations from seven natural-error states |
| `reduced-reconstruction` | 48 constructor outputs shared across 168 evaluations |
| `construction` | 60 policies across three representations |
| `matched` | 816 continuations under six matched-input conditions |
| `models` | Three full model panels and the common eight-actor/seven-updater panel |
| `repair-status` | 108 continuations under matched permission-status notices |
| `reminders` | 498 continuations under three system-prompt conditions |
| `policy-replay` | 144 original policy lifecycles and initial/post-exposure native probes |

Preparation inputs, development panels, unknown outcomes, original model outputs, state transitions, protocol definitions and the analysis functions are included. Main estimates keep development and control populations separate. Incomplete model configurations outside the paper's reported panels are not promoted into completed results.

## Fresh experiments

Copy `.env.example` to `.env` and set the providers needed for the selected study. The original Luna studies use a Responses-compatible endpoint. Anthropic supplies Haiku; the retained DeepSeek, GLM-Flash and MiniMax configurations use Canopy Wave; the retained Qwen, GLM and Beam configurations use Lumen. Provider configuration and requested model identifiers are retained with each protocol.

```sh
.venv/bin/python -m pipeline prepare
.venv/bin/python -m pipeline run --study faults --out runs/faults-new --plan
.venv/bin/python -m pipeline run --study faults --out runs/faults-new
```

`prepare` reconstructs inputs under `.work/` and rebinds path-dependent integrity pins. It requires approximately 6 GB of disk space. `run` invokes the pinned study implementations with a fresh output and coupling directory. `--study all` selects all schedules. The fixed conditional panels reuse their released source states; fresh continuations do not turn those panels into new-task evaluations. Provider calls incur usage, and newly sampled outcomes can differ from the paper.

Frozen actor prefixes are replayed by exact request-payload and response hashes, independently of the original endpoint or credential. These replays are labeled in the output. New responses after a fork retain provider-scoped caching and are sampled using the user's configured provider.

## Outputs

- `results/*.json`: recomputed endpoint counts, task-level contrasts and missing-outcome bounds.
- `results/native-*.json`: native replay and permission-probe checks.
- `results/tables/`: CSV tables, machine-readable results and LaTeX table output.
- `results/figures/`: generated PDF and SVG figures.
- `.work/relocation.json`: the source and working-copy hash map after relocating paths.

Native replay compares full recorded states, with only calendar participant and email-recipient ordering normalized; multiplicity is preserved. It also reruns the original task-utility and attacker-goal predicates on the replayed states. Updater probes use the original Progent checker. Policy-lifecycle replay rebuilds the original requests before supplying recorded model responses. Utility, attacker-goal attainment and selected argument effects remain separate. A selected-effect metric is not a complete trajectory-authorization oracle.

## Container

```sh
docker build -t authorization-control .
docker run --rm --network none -v "$PWD/results:/app/results" authorization-control reproduce --all
```

The image pins Node.js 22.19 and Python 3.13 and installs the same source revisions as local setup. Dependency installation requires network access; recorded reproduction does not.
