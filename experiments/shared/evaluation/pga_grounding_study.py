"""Small component diagnostics and fixed-plan replay for the revised method.

This is not a new closed-loop agent/attack comparison. Evaluator-only fixture
labels and prior trace outcomes are never sent to the reference resolver.
"""
from __future__ import annotations
import argparse,copy,gzip,hashlib,json,os,time
from pathlib import Path
from pga_grounding import ModelReferenceGrounder,OneShotReference,canonical,digest
from pga_transport import ResponsesTransport

def write(path,data):path.write_text(json.dumps(data,indent=2,default=str)+'\n')

def diagnostics(a,out):
    suite=json.loads(a.cases.read_text());transport=ResponsesTransport(model=a.model,max_output_tokens=512)
    resolver=ModelReferenceGrounder(transport);rows=[];started=time.monotonic()
    for case in suite['cases']:
        (out/'status.md').write_text(f"Grounding diagnostics {len(rows)}/{len(suite['cases'])}; no native effects or efficacy claim.\n")
        view=copy.deepcopy(case['binder_input']);before=len(transport.calls)
        result=OneShotReference('diagnostic:'+case['case_id'],'reference').run(view,resolver)
        expected=case['expected']
        passed=result.status=='valid' and result.decision==expected['decision'] and result.handle==expected['handle']
        row={'case_id':case['case_id'],'category':case['category'],'input_sha256':digest(view),'result':result.to_dict(),'expected':expected,'passed':passed,'calls':transport.calls[before:]}
        rows.append(row);write(out/'partial.json',rows)
    byid={r['case_id']:r for r in rows};source={c['case_id']:c for c in suite['cases']};relations=[]
    for relation in suite['relation_checks']:
        chosen=[byid[k] for k in relation['cases']];valid=all(x['result']['status']=='valid' for x in chosen)
        if relation['kind']=='excluded_description_noninterference':
            passed=valid and len({x['input_sha256'] for x in chosen})==1 and all(x['result']['decision']=='abstain' for x in chosen)
        elif 'expected_handle' in relation:
            passed=valid and all(x['result']['decision']=='select' and x['result']['handle']==relation['expected_handle'] for x in chosen)
        else:
            expected=relation['expected_underlying_object']
            passed=valid and all(x['result']['decision']=='select' and source[x['case_id']]['evaluator_only']['synthetic_object_by_handle'].get(x['result']['handle'])==expected for x in chosen)
        relations.append({'relation_id':relation['relation_id'],'kind':relation['kind'],'passed':passed})
    result={'kind':'authored benign reference-component diagnostics; not held-out benchmark or owner-intent proof','fixture_sha256':hashlib.sha256(a.cases.read_bytes()).hexdigest(),'rows':rows,'relations':relations,'passed':sum(r['passed'] for r in rows),'n':len(rows),'relations_passed':sum(r['passed'] for r in relations),'relation_n':len(relations),'transport':transport.metadata(),'model_calls':len(transport.calls),'elapsed_s':time.monotonic()-started}
    write(out/'result.json',result);(out/'status.md').write_text(f"Grounding diagnostics complete: {result['passed']}/{result['n']}; relations {result['relations_passed']}/{result['relation_n']}; no error-rate guarantee.\n")
    print(json.dumps({k:result[k] for k in ['passed','n','relations_passed','relation_n','model_calls','elapsed_s']}))

def native_replay(a,out):
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.functions_runtime import FunctionCall
    from agentdojo.types import text_content_block_from_string
    from pga_oracle import parse_public_mandate
    from pga_oracle_refined import score_episode
    from pga_bound_gate import BoundPolicyGate,SerializedRuntime
    manifest=json.loads(a.manifest.read_text());suite=get_suite('v1.2.2','workspace')
    transport=ResponsesTransport(model=a.model,max_output_tokens=512);resolver=ModelReferenceGrounder(transport);rows=[];started=time.monotonic()
    for case in manifest['cases']:
        (out/'status.md').write_text(f"Fixed-plan revision replay {len(rows)}/{len(manifest['cases'])}; no new proposer model or ASR claim.\n")
        raw_path=a.prior_runs/'none'/(case['case_id']+'.json.gz')
        with gzip.open(raw_path,'rt') as f:old=json.load(f)
        task=suite.get_user_task_by_id(case['task_id']);env=task.init_environment(suite.load_and_inject_default_environment(case['injections']));initial=env.model_copy(deep=True)
        m=parse_public_mandate(task.ID,task.PROMPT)
        gate=BoundPolicyGate(m,root_id='paired-reference:'+task.ID,calendar_account=env.calendar.account_email,delegate_reference=True)
        runtime=SerializedRuntime(suite.tools,gate)
        call_start=len(transport.calls);binding=gate.prebind(runtime,env,resolver)
        # The resolver has completed before any recorded untrusted tool view or
        # prior proposal is supplied to the executor. It never sees old scores.
        proposals=[];operation_errors=[]
        for call in old['proposed_calls']:
            fc=FunctionCall.model_validate(call);proposals.append(fc)
            _,error=runtime.run_function(env,fc.function,fc.args)
            if error:operation_errors.append(error)
        final=env.model_copy(deep=True)
        utility=suite._check_user_task_utility(task,[text_content_block_from_string(old['final_response'])],initial.model_copy(deep=True),final.model_copy(deep=True),proposals)
        assessment=score_episode(m,initial.model_dump(mode='json'),final.model_dump(mode='json'),runtime.events,events_complete=True)
        row={'case_id':case['case_id'],'task_id':task.ID,'condition':case['condition'],'prior_raw_sha256':hashlib.sha256(raw_path.read_bytes()).hexdigest(),
             'binding':binding,'native_utility_fixed_plan_replay':utility,'structural_assessment':{k:assessment[k] for k in ['violation','unknown','verdict']},
             'native_targeted_asr':None,'not_a_new_agent_episode':True,'operation_errors':operation_errors,'decisions':runtime.decisions,'native_invocations':runtime.calls_started,'collector_invocations':sum(e['kind']=='collector' for e in runtime.events),'calls':transport.calls[call_start:]}
        rows.append(row)
        raw={'result':row,'initial':initial.model_dump(mode='json'),'final':final.model_dump(mode='json'),'events':runtime.events,'fixed_proposals':old['proposed_calls'],'final_text_source':'retained no-gate episode; not regenerated'}
        with gzip.open(out/(case['case_id']+'.json.gz'),'wt') as f:json.dump(raw,f,default=str)
        write(out/'partial.json',rows)
    result={'kind':'controlled replay of15 previously recorded no-gate proposal sequences; not new closed-loop agent or attack efficacy','source_manifest_sha256':hashlib.sha256(a.manifest.read_bytes()).hexdigest(),'rows':rows,'n':len(rows),'utility_successes':sum(r['native_utility_fixed_plan_replay'] for r in rows),'model_calls':len(transport.calls),'transport':transport.metadata(),'elapsed_s':time.monotonic()-started}
    write(out/'result.json',result);(out/'status.md').write_text(f"Replay complete: {result['utility_successes']}/{result['n']} native utilities; {result['model_calls']} grounding calls; not new ASR evidence.\n")
    print(json.dumps({k:result[k] for k in ['utility_successes','n','model_calls','elapsed_s']}))

def main():
    p=argparse.ArgumentParser();p.add_argument('--mode',choices=['diagnostics','native-replay'],required=True);p.add_argument('--cases',type=Path);p.add_argument('--manifest',type=Path);p.add_argument('--prior-runs',type=Path);p.add_argument('--out',type=Path);p.add_argument('--model',default='gpt-6-astra');a=p.parse_args()
    out=a.out or Path(os.environ['AROS_ARTIFACTS']);out.mkdir(parents=True,exist_ok=True)
    if a.mode=='diagnostics':diagnostics(a,out)
    else:native_replay(a,out)
if __name__=='__main__':main()
