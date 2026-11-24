# Validation

The product and research pipeline are checked separately.

| Check | Result |
|---|---|
| Core, SDK, extension and artifact reader tests | 18 passed |
| TypeScript public API checks | Passed |
| Actual npm tarball installed in a clean consumer | Passed |
| Independent Node 22 container: tests and Pi demo | Passed |
| Source/input launch recipes | 72 recipes, 23 executable entry points qualified |
| Fixed schedule dry runs | Sealed, natural, reduced and matched schedules qualified |
| Credential-independent prefix replay | 3 scripted fault/control episodes, 7 exact source-response replays, no live model calls |
| Fault-injection native replay | 965 records passed |
| Matched-input native replay | 816 records passed |
| Earlier-study native replay | 14,027 records passed |
| Cross-model actor native replay | 2,186 trajectories passed |
| Cross-model updater permission checks | 5,440 original-checker probes passed |
| Original benchmark utility and attacker-goal scorers | 30,105 score comparisons passed |
| Post-exposure policy lifecycles | 144 histories reconstructed; 1/98 qualified targets admitted |
| Initial policy probes | 144 histories reconstructed; 7/112 qualified targets admitted |

Recorded data analysis reproduces the headline fault counts, the matched task-level contrasts, the model comparisons, the replacement-actor/approver/repair tables, and the construction and reduced-reconstruction results. All checks above use scripted responses or recorded data; they do not resample the live model campaigns.

`python -m pipeline reproduce --all` performs the full recorded pipeline. `pipeline/tests/qualify_pipeline.py` exercises a complete new continuation using an in-process Responses fixture and a different credential/endpoint identity. Native replay compares state transitions and invokes the original permission checker; it does not infer user authorization from task utility alone.
