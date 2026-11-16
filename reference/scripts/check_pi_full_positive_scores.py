#!/usr/bin/env python3
"""Post-measurement native score interpretation on sealed positive cases."""
import argparse,gzip,hashlib,json,os
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionCall
from agentdojo.types import text_content_block_from_string

p=argparse.ArgumentParser();p.add_argument('--run',type=Path,required=True);p.add_argument('--out',type=Path);a=p.parse_args()
out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
report=json.loads((a.run/'result.json').read_text());rows=[]
def raw(path):
    with gzip.open(path,'rt') as f:return json.load(f)
for row in report['rows']:
    if row.get('native_targeted_asr') is not True:continue
    source=a.run/(row['case_id']+'.json.gz');x=raw(source)
    clean_path=a.run/(row['suite']+'__'+row['task_id']+'__clean.json.gz');clean=raw(clean_path)
    suite=get_suite('v1.2.2',row['suite']);env_type=type(suite.load_and_inject_default_environment({}))
    goal=suite.get_injection_task_by_id(row['injection_id'])
    def score(before,after,text,trace):
        return suite._check_injection_task_security(goal,[text_content_block_from_string(text)],
            env_type.model_validate(before),env_type.model_validate(after),[FunctionCall.model_validate(t) for t in trace])
    record={'case_id':row['case_id'],'attacked_raw_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
        'clean_raw_sha256':hashlib.sha256(clean_path.read_bytes()).hexdigest(),
        'initial_predicate':score(x['initial'],x['initial'],'',[]),
        'attacked_rescore':score(x['initial'],x['final'],x['final_response'],x['proposed_calls']),
        'retained_clean_predicate':score(clean['initial'],clean['final'],clean['final_response'],clean['proposed_calls'])}
    rows.append(record)
assert len(rows)==7 and all(r['attacked_rescore'] is True for r in rows)
result={'kind':'post-measurement native evaluator diagnostic; no model, task rerun or new attack',
    'rows':rows,'n':len(rows),'all_primary_positive_labels_reproduced':True,
    'limits':['Official primary labels remain unchanged.','Clean and attacked trajectories are separate stochastic executions, not a coupled causal experiment.','Native attacker-goal success is not a complete owner-policy violation oracle.']}
(out/'result.json').write_text(json.dumps(result,indent=2)+'\n');(out/'status.md').write_text('Native positive-label audit complete; no model calls.\n')
print(json.dumps(result,indent=2))
