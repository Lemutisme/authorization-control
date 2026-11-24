"""One-record source-producer diagnostic; no models or study writes."""
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import x4_native_audit as v1


def first_differences(a,b,path='$',limit=8):
    rows=[]
    if type(a) != type(b):
        return [{'path':path,'left_type':type(a).__name__,'right_type':type(b).__name__,'left':repr(a)[:120],'right':repr(b)[:120]}]
    if isinstance(a,dict):
        for key in sorted(a.keys() | b.keys()):
            if key not in a or key not in b:
                rows.append({'path':path+'.'+str(key),'left_present':key in a,'right_present':key in b})
            else:rows+=first_differences(a[key],b[key],path+'.'+str(key),limit-len(rows))
            if len(rows)>=limit:return rows[:limit]
    elif isinstance(a,list):
        if len(a)!=len(b):rows.append({'path':path,'left_length':len(a),'right_length':len(b)})
        for i,(x,y) in enumerate(zip(a,b)):
            rows+=first_differences(x,y,path+f'[{i}]',limit-len(rows))
            if len(rows)>=limit:return rows[:limit]
    elif a!=b:rows.append({'path':path,'left':repr(a)[:120],'right':repr(b)[:120]})
    return rows[:limit]


def main():
    p=argparse.ArgumentParser();p.add_argument('--raw',type=Path,required=True);p.add_argument('--frozen',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    assert not a.out.exists()
    raw=v1.load(a.raw);x4=a.frozen/'evaluation/authorship/x4';node=v1.NodeNormalizer()
    try:
        with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
            source=v1.load_source(a.frozen);source['install_clock'](raw['result']['clock_profile']['anchor'])
            suite,task,fresh=source['instantiate'](raw['result']['suite'],raw['result']['task_id'])
            restored=v1.restore_model(type(fresh),raw['initial'])
            spec=importlib.util.spec_from_file_location('x4_initial_producer',x4/'broker.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
            broker=module.Broker()
            init=broker.init({'manifest':str(x4/'dataset-v1/cohort.json'),'case_id':raw['result']['case_id'],'unit':raw['x1_unit'],'model':'gpt-6-luna','clock_anchor':'2026-11-05T00:00:00','variant':'fault','bound_projection':raw['x1_bound_projection'],'prefix_sha256':raw['result']['x1_anchor']['prefix_sha256'],'x4_arm':raw['result']['x4_arm'],'audit_plan':raw['x4_audit_plan'],'audit_ledger':str(a.out.parent/'unused-audit.json'),'repair_bank':str(a.out.parent/'unused-bank'),'constructor_journal':str(a.out.parent/'unused-constructor.jsonl')})
            actual=broker.initial.model_dump(mode='json');broker.close()
        views={'raw_initial':raw['initial'],'schema_restored_initial':restored.model_dump(mode='json'),'cohort_instantiated_initial':fresh.model_dump(mode='json'),'original_broker_initial':actual}
        result={'raw_sha256':v1.sha(a.raw),'recorded_initial_hash':raw['result']['initial_state_sha256'],'original_broker_returned_initial_hash':init['initial_state_sha256'],
                'hashes':{k:v1.digest(v) for k,v in views.items()},
                'node_readback_hashes':{k:v1.digest(node.normalize(v)) for k,v in views.items()},
                'producer_vs_saved_differences':first_differences(actual,raw['initial']),
                'producer_vs_schema_restored_differences':first_differences(actual,views['schema_restored_initial']),
                'producer_vs_cohort_differences':first_differences(actual,views['cohort_instantiated_initial']),
                'schema_vs_saved_differences':first_differences(views['schema_restored_initial'],raw['initial']),
                'default_str_changes_model_json':json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False,default=str)!=json.dumps(actual,sort_keys=True,separators=(',',':'),ensure_ascii=False),
                'network_or_model_attempts':len(v1.FORBIDDEN_CALLS),'model_requests':0}
        v1.save(a.out,result);print(json.dumps(result,indent=2))
    finally:node.close()


if __name__=='__main__':main()
