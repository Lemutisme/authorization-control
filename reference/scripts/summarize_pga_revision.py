#!/usr/bin/env python3
"""Summarize revision qualifications without relabeling them as agent efficacy."""
import argparse,hashlib,json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--contract',type=Path,required=True);p.add_argument('--diagnostics',type=Path,required=True);p.add_argument('--replay',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
c=json.loads(a.contract.read_text());d=json.loads(a.diagnostics.read_text());r=json.loads(a.replay.read_text());a.out.mkdir(parents=True,exist_ok=True)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
selected=[x for x in d['rows'] if x['expected']['decision']=='select'];abstained=[x for x in d['rows'] if x['expected']['decision']=='abstain']
calendar=[x for x in r['rows'] if x['task_id']=='user_task_7']
calls=[x for row in d['rows'] for x in row['calls']]+[x for row in r['rows'] for x in row['calls']]
summary={'kind':'method revision component qualification and fixed-plan replay; not a new closed-loop attack-defense study',
 'input_sha256':{'contract':sha(a.contract),'diagnostics':sha(a.diagnostics),'replay':sha(a.replay)},
 'contract':{'passed':c['passed'],'n':c['n'],'wrong_grounder_counterexample_retained':any(x['name']=='explicit_wrong_grounder_counterexample' and x['passed'] for x in c['checks'])},
 'grounding':{'passed':d['passed'],'n':d['n'],'selection_correct':sum(x['passed'] for x in selected),'selection_n':len(selected),'abstention_correct':sum(x['passed'] for x in abstained),'abstention_n':len(abstained),'relations_passed':d['relations_passed'],'relation_n':d['relation_n']},
 'fixed_plan_replay':{'native_utility_successes':r['utility_successes'],'n':r['n'],'calendar_successes':sum(x['native_utility_fixed_plan_replay'] for x in calendar),'calendar_n':len(calendar),'calendar_input_hashes':sorted({x['binding']['grounding']['input_sha256'] for x in calendar if x['binding'].get('grounding')}),'structural_unknown':sum(x['structural_assessment']['unknown'] for x in r['rows']),'new_targeted_asr_measured':False},
 'usage':{'model_calls':len(calls),'input_tokens':sum((x.get('usage') or {}).get('input_tokens',0) for x in calls),'output_tokens':sum((x.get('usage') or {}).get('output_tokens',0) for x in calls),'cached_input_tokens':sum(((x.get('usage') or {}).get('input_tokens_details') or {}).get('cached_tokens',0) for x in calls),'missing_usage':sum(x.get('usage') is None for x in calls),'models':sorted({x.get('returned_model') for x in calls if x.get('returned_model')})},
 'qualification_source_limit':'Model diagnostics/replay precede the final locked-admission recheck. The final source has separate native qualification; no model rerun is claimed. See provenance for both source identities.',
 'limits':['Diagnostics are authored development fixtures, not held-out/population estimates.','Replay uses retained no-gate proposal sequences and final text, not a fresh proposer model.','The old 105-episode study is unchanged; there is no fresh ASR or SOP-superiority result.','Semantic grounding is fallible and explicitly delegated; a correct mechanical gate can enforce a wrong selection.','Native object identity/serialization do not establish a production provider guarantee.']}
(a.out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
lines=['# PGA method-revision validation','', '| Check | Observed result | Scope |','|---|---:|---|',
 f"| Native binding/authority controls | {c['passed']}/{c['n']} | Includes an explicit wrong-grounder counterexample; not end-to-end safety. |",
 f"| Benign semantic selections | {summary['grounding']['selection_correct']}/{len(selected)} | Author-labeled development references. |",
 f"| Required abstentions | {summary['grounding']['abstention_correct']}/{len(abstained)} | Missing or ambiguous visible support. |",
 f"| Renaming/order/information relations | {d['relations_passed']}/{d['relation_n']} | Related component checks, not independent tasks. |",
 f"| Fixed-plan native utility | {r['utility_successes']}/{r['n']} | Retained v1 no-gate plans; no new agent or ASR claim. |",
 '',f"Model use: {len(calls)} reference-grounding calls; {summary['usage']['input_tokens']} input and {summary['usage']['output_tokens']} output tokens. Model identity is a provider-reported alias.",
 '', 'The five calendar replays used one identical protected resolver-input hash across clean/attack/replacement-control conditions. The legacy structural rubric still leaves the calendar target unknown: the new model decision was not inserted into the evaluator as truth.',
 '', summary['qualification_source_limit'],
 '', 'Utility recovery in this controlled replay repairs the observed rejection mechanism under an added grounding assumption. A conventional SOP with the same view and resolver can make the same decision; superiority and broader owner-policy fidelity remain unestablished.']
(a.out/'results.md').write_text('\n'.join(lines)+'\n')
print(json.dumps({k:summary[k] for k in ['contract','grounding','fixed_plan_replay','usage']},indent=2))
