# Research material

Everything the paper's results are computed from. `python -m pipeline` reads this directory; nothing here needs to be run by hand.

| Directory | Contents |
|---|---|
| `experiments/` | One directory per study with its pinned implementation, plus `catalog.json` (the launch schedules) and `SOURCES.json` (checksums of every pinned file). |
| `inputs/` | Utilities that prepared the cohorts for the matched-input study. |
| `data/` | Recorded protocols, experiment inputs and complete study records as compressed JSON lines, with their indexes. |
| `replay/` | A standalone script that replays recorded results through the pinned benchmark; it ships with the runtime package. |

Before an experiment or a replay runs, the pipeline copies `experiments/` and `inputs/` into a workspace (`.work/` by default, or `AC_WORKSPACE`) and expands the records from `data/` beside them. The pinned code addresses files relative to that workspace, which is why its layout is kept as it was when the studies ran.

Each study named by `python -m pipeline list` and in [the reproduction notes](../docs/reproduction.md) has its schedules in `experiments/catalog.json`. The schedules use these directories:

| Study | Directory under `experiments/` |
|---|---|
| `faults` | `faults/` |
| `matched` | `channels/` |
| `models`, `repair-status`, `reminders` | `models/` |
| `policy-replay` | `lifecycles/`, `shared/` |
| `repeated-probes` | `repeated/` |
| `banking`, `conditional-updates` | `banking/` |
| `approvers` | `approvers/` |
| `replacement`, `replacement-development` | `replacement/` |
| `reviewer` | `reviewer/` |
| `sealed` | `sealed/` |
| `sealed-natural` | `natural/` |
| `reconstruction-faults` | `reconstruction/` |
| `reduced-reconstruction` | `reduced/` |
| `construction` | `construction/` |
