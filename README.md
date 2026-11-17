# Authorization Control

Tool-call authorization for LLM agents, with a Pi extension, an Agent SDK adapter, and the experiment pipeline for **Enforcing the Wrong Permissions: An Empirical Study of Authorization in LLM Agents**.

The runtime enforces explicit policies, returns value-free refusals, and records admitted calls and their outcomes. The experiments measure how refusal feedback, policy updates and repair notifications affect authorization and task completion.

## Run the product

Requires Node.js 22.19+.

```sh
npm ci
npm run demo
npm test
```

The demo runs the Pi agent loop against an in-memory ledger without model requests. To use the extension in Pi:

```sh
pi install .
pi --auth-policy /path/to/policy.json
```

Use `/auth status` to inspect the active policy. See [policy format and SDK usage](docs/runtime.md) for application integration.

## Reproduce the paper

Requires Python 3.13, Git, and pip or uv. With uv installed, setup selects Python 3.13 automatically.

```sh
python3 -m pipeline setup
.venv/bin/python -m pipeline reproduce --all
```

This rebuilds the reported tables, replays recorded effects through the pinned benchmark, and writes CSV/LaTeX tables and PDF/SVG figures to `results/`. It uses the recorded model responses and makes no model requests.

To run fresh model experiments, configure the provider variables in [`.env.example`](.env.example), then choose a new output directory:

```sh
.venv/bin/python -m pipeline list
.venv/bin/python -m pipeline run --study faults --out runs/faults-new
```

Use `--study all` for all schedules or `--plan` to inspect the commands first. Fresh experiments call the configured providers and may produce different outcomes. [Reproduction details](docs/reproduction.md) describe the studies, dependencies and outputs.

## Layout

```text
src/           authorization runtime and Pi SDK adapter
extensions/    Pi coding-agent extension
examples/      policies, tools and executable demo
pipeline/      preparation, experiment launch, replay, analysis and figures
experiments/   pinned study implementations and launch schedules
inputs/        cohort preparation utilities
data/          protocols, recorded inputs and complete study records
test/          runtime and integration tests
```

MIT-licensed runtime; third-party components retain their own licenses. The runtime enforces the supplied policy; applications own policy correctness and tool-effect isolation. Paper results refer to the corresponding experiment implementations. See [architecture](docs/architecture.md) and [third-party notices](THIRD_PARTY_NOTICES.md).
