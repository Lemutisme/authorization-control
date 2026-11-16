# Frozen contract-factorial results

F is the controller fact packet; R is the proposal-local repair suffix. All original effects remain gated. This is a within-method study on development tasks, not held-out transfer or contemporary-baseline superiority.

## contract-factorial-main-v1

Observed 1081/1081 cases; audit findings in 0 cases.

| Condition | Arm | Native utility | Targeted ASR | Utility unknown |
|---|---|---:|---:|---:|
| clean | none | 87/97 | N/A | 0 |
| clean | pga | 85/97 | N/A | 0 |
| clean | no_facts | 87/97 | N/A | 0 |
| clean | no_feedback | 86/97 | N/A | 0 |
| clean | no_facts_no_feedback | 87/97 | N/A | 0 |
| attack | none | 827/949 | 11/949 (0 unknown) | 0 |
| attack | pga | 838/949 | 0/949 (0 unknown) | 0 |
| attack | no_facts | 833/949 | 0/949 (0 unknown) | 0 |
| attack | no_feedback | 838/949 | 0/949 (0 unknown) | 0 |
| attack | no_facts_no_feedback | 835/949 | 0/949 (0 unknown) | 0 |
| goal_control | none | 33/35 | N/A | 0 |
| goal_control | pga | 32/35 | N/A | 0 |
| goal_control | no_facts | 32/35 | N/A | 0 |
| goal_control | no_feedback | 32/35 | N/A | 0 |
| goal_control | no_facts_no_feedback | 32/35 | N/A | 0 |

| Condition | Factor contrast | ON-only success | OFF-only success | Net ON − OFF | Unknown/invalid |
|---|---|---:|---:|---:|---:|
| clean | facts_with_feedback | 0 | 2 | -2 | 0 |
| clean | facts_without_feedback | 0 | 1 | -1 | 0 |
| clean | feedback_with_facts | 0 | 1 | -1 | 0 |
| clean | feedback_without_facts | 0 | 0 | 0 | 0 |
| attack | facts_with_feedback | 7 | 2 | 5 | 0 |
| attack | facts_without_feedback | 5 | 2 | 3 | 0 |
| attack | feedback_with_facts | 1 | 1 | 0 | 0 |
| attack | feedback_without_facts | 0 | 2 | -2 | 0 |
| goal_control | facts_with_feedback | 0 | 0 | 0 | 0 |
| goal_control | facts_without_feedback | 0 | 0 | 0 | 0 |
| goal_control | feedback_with_facts | 0 | 0 | 0 | 0 |
| goal_control | feedback_without_facts | 0 | 0 | 0 | 0 |

All 24 utility/ASR-discordant factor pairs (including separate capability controls) were localized; 2 contain create_calendar_event in either trace. Absence rules out only that identified participant-order operator. Presence is not proof of bias. No outcome, input or primary denominator was normalized or removed.

Operational outcomes and task-bootstrap ranges are in the JSON report. Cache-reused samples are charged as logical calls but not new network usage; experimental arm timings/costs are not standalone deployment estimates. Common initial state and clock do not establish deterministic native observation ordering.

## contract-factorial-clean-repeat-v1

Observed 97/97 cases; audit findings in 0 cases.

| Condition | Arm | Native utility | Targeted ASR | Utility unknown |
|---|---|---:|---:|---:|
| clean | none | 86/97 | N/A | 0 |
| clean | pga | 85/97 | N/A | 0 |
| clean | no_facts | 87/97 | N/A | 0 |
| clean | no_feedback | 86/97 | N/A | 0 |
| clean | no_facts_no_feedback | 88/97 | N/A | 0 |

| Condition | Factor contrast | ON-only success | OFF-only success | Net ON − OFF | Unknown/invalid |
|---|---|---:|---:|---:|---:|
| clean | facts_with_feedback | 0 | 2 | -2 | 0 |
| clean | facts_without_feedback | 0 | 2 | -2 | 0 |
| clean | feedback_with_facts | 0 | 1 | -1 | 0 |
| clean | feedback_without_facts | 0 | 1 | -1 | 0 |

All 6 utility/ASR-discordant factor pairs (including separate capability controls) were localized; 2 contain create_calendar_event in either trace. Absence rules out only that identified participant-order operator. Presence is not proof of bias. No outcome, input or primary denominator was normalized or removed.

Operational outcomes and task-bootstrap ranges are in the JSON report. Cache-reused samples are charged as logical calls but not new network usage; experimental arm timings/costs are not standalone deployment estimates. Common initial state and clock do not establish deterministic native observation ordering.
