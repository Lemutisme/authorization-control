# Studies and analysis boundaries

The paper's research questions concern wrong permissions, gate-to-actor feedback, proposal-dependent updates, and recovery after a refusal.

| Paper result | Source and data in this snapshot |
|---|---|
| Fault-injection table | `reference/evaluation/authorship/x1/`, `data/fault-injection.jsonl.xz` |
| Matched-inputs appendix | `reference/evaluation/two_channel/`, `reference/metric_sources/matched_analyze.py`, `data/matched-inputs.jsonl.xz` |
| Cross-model actor and updater comparisons | `reference/crossmodel/`, `data/model-continuations.jsonl.xz` |
| Repaired-permission announcement | `reference/crossmodel/ack_trial.py`, `ack_campaign.py`, `analyze_ack.py`, status collection in the model archive |
| Prompt reminders | `reference/crossmodel/prompt_followup.py`, `analyze_prompt.py`, reminders collection in the model archive |
| Initial/lifecycle probes and update comparisons | `reference/evaluation/control_boundary/`, `refinement/`, `refinement_initial/`, and reference replay scripts |
| Replacement actor and update strategies | `reference/evaluation/authorship/x2/`, `x2b/` |
| Sealed comparison and reduced reconstruction | `reference/evaluation/sealed_control/`, `sealed_control_natural/`, `matched_natural_repair/` |
| Four-suite reviewer study | `reference/evaluation/contract_study/` |
| Construction representations | `reference/evaluation/witness_native/`, retained construction utilities |

The common actor panel uses these configuration labels:

| Internal label | Configuration named in the paper |
|---|---|
| `luna` | GPT-6 Luna |
| `haiku` | Claude Haiku 5.5 |
| `deepseek` | DeepSeek-V4.1-Flash |
| `lumen_qwen` | Qwen3.8-Flash-Next, third-party quantized build |
| `lumen_glm` | GLM-5.3 |
| `glm` | GLM-5.3-Flash |
| `lumen_beam` | Beam 1.0 |
| `minimax` | MiniMax-M3.1-Flash, actor results only |

The three-model full protocol and the 31-task comparison use their original endpoint definitions: legacy selected effects in the former, strict committed selected-field/relation changes in the latter. Both definitions are retained in `reference/metric_sources/strict_effects.py`. The portable runner checks the appropriate definition against saved measurements; it does not silently rewrite the older protocol's endpoint.

All continuation comparisons remain conditional on the recorded source states. They do not estimate each model's spontaneous error prevalence or establish rankings at equal compute.

## Inspect the records

The archives are UTF-8 JSON Lines compressed with XZ. Stream them without extracting a directory tree:

```python
import json, lzma
with lzma.open('data/fault-injection.jsonl.xz', 'rt') as stream:
    for line in stream:
        record = json.loads(line)
        if record['kind'] == 'run':
            print(record['condition']['condition_id'])
```

The fault archive begins with cohort and manifest records, followed by 965 runs. The matched archive contains its protocol, source-state records and 816 runs. The model archive contains collection rows, source packets and deduplicated raw records; `raw_record_id` and `packet_record_id` join them without relying on original host paths.

No examples or negative outcomes are removed because of their result. Incomplete MiMo work and the unfinished MiniMax updater/unforced panels are outside the completed configurations reported here and are not included in the common-panel export.
