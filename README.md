# Authorization Control

Tool-call authorization for LLM agents, and the complete experiment record of the paper
**When Refusals Change Actions and Permissions: Runtime Authorization in LLM Agents**.

The repository has two parts that can be used independently.

| Part | What it is | Where | Requires |
|---|---|---|---|
| **Runtime** | Enforces an explicit policy on every tool call, answers a refused call without naming a permitted value, and records admitted calls and their outcomes. Ships a Pi extension and an Agent SDK adapter. | `src/` `extensions/` `bin/` `examples/` `test/` | Node.js 22.19+ |
| **Paper** | Recomputes every reported table and figure from the recorded model responses, replays recorded effects through the pinned benchmark, and can launch the experiments again. | `pipeline/` `research/` | Python 3.13, Git |

## Use the runtime

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

Use `/auth status` to inspect the active policy. See [policy format and SDK usage](docs/runtime.md) for application integration and [architecture](docs/architecture.md) for what the runtime does and does not mediate.

## Reproduce the paper

With uv installed, setup selects Python 3.13 automatically; pip works as well.

```sh
python3 -m pipeline setup
.venv/bin/python -m pipeline reproduce --all
```

This verifies the tracked files against `MANIFEST.json`, rebuilds the reported tables, replays recorded effects through the pinned benchmark, and writes CSV and LaTeX tables and PDF and SVG figures to `results/`. It uses the recorded model responses and makes no model request.

To run fresh model experiments, configure the provider variables in [`.env.example`](.env.example), then choose a new output directory:

```sh
.venv/bin/python -m pipeline list
.venv/bin/python -m pipeline run --study faults --out runs/faults-new
```

Use `--study all` for all schedules or `--plan` to inspect the commands first. Fresh experiments call the configured providers and may produce different outcomes. [Reproduction details](docs/reproduction.md) describe the studies, dependencies and outputs, and [verification](docs/verification.md) lists the checks.

## Layout

```text
src/            authorization runtime, Pi SDK adapter, reader for recorded results
extensions/     Pi coding-agent extension
bin/            authorization-artifact command
examples/       policy, tools and an executable demo
test/           runtime and packaging tests
docs/           runtime, architecture, reproduction, verification, release

pipeline/       python -m pipeline: setup, reproduce, replay, figures, run
  metrics/      measurements recomputed from the records
  tests/        pipeline tests
research/       what the paper's results are computed from (see research/README.md)
  experiments/  pinned study implementations and launch schedules
  inputs/       cohort preparation utilities
  data/         protocols, recorded inputs and complete study records
  replay/       standalone native replay shipped with the runtime package
scripts/        release packaging, manifest, normalization check
```

Files under `research/experiments/` and `research/inputs/` are pinned: the paper's results refer to these exact implementations, `research/experiments/SOURCES.json` records their checksums, and they are not reformatted or refactored.

## Scope

The runtime enforces the policy it is given. Applications own the correctness of that policy and the isolation of their tools' effects. The paper's results refer to the pinned experiment implementations and not to the runtime.

## License

MIT © Lemutisme. Third-party components retain their own licenses; see [third-party notices](THIRD_PARTY_NOTICES.md).
