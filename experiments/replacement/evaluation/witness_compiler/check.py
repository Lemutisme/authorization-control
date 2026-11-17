"""Meaningful compiler checks: joins, multiplicity, arithmetic and binding."""
import argparse,copy,json
from pathlib import Path
from kernel import Resolver,InvalidProgram,allows,digest
def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();tests=[]
    view={'owner':'Notify A and B','owner_atoms':[],'tables':{'tasks':[{'id':'a','data':{'person':'A','action':'do A','deadline':'2026-01-01'}},{'id':'b','data':{'person':'B','action':'do B','deadline':'2026-01-02'}}],'directory':[{'id':'a','data':{'person':'A','address':'a@example.test'}},{'id':'b','data':{'person':'B','address':'b@example.test'}}]},'contracts':{'notify':{'fields':{'recipient':'string','body':'string'}}}}
    args={'recipient':{'lookup':{'table':'directory','key':'person','value':{'field':'person'},'field':'address'}},'body':{'render':{'template':'assignment_notice','values':[{'field':'action'},{'field':'deadline'}]}}}
    program={'rules':[{'function':'notify','query':{'table':'tasks'},'arguments':args}]};policy,trace=Resolver(view).materialize(program,'query')
    expected=[{'function':'notify','arguments':{'recipient':r['address'],'body':t['action']+' Deadline: '+t['deadline']+'.'}} for t,r in zip([x['data'] for x in view['tables']['tasks']],[x['data'] for x in view['tables']['directory']])]
    assert [{k:e[k] for k in ['function','arguments']} for e in policy['allowed_effects']]==expected;tests.append('join_materialization_equals_independent_tuple_oracle')
    for left in expected:
        for right in expected:
            q={'recipient':left['arguments']['recipient'],'body':right['arguments']['body']};assert allows(policy,'notify',q)==(left==right)
    tests.append('mixed_witness_crossings_rejected')
    refs={'rules':[{'function':'notify','witness':{'table':'tasks','row':r['id']},'arguments':args} for r in view['tables']['tasks']]};rp,_=Resolver(view).materialize(refs,'refs');vp,_=Resolver(view).materialize({'rules':expected},'values');assert rp==vp==policy;tests.append('competent_ordinary_table_and_reference_table_are_equivalent')
    dup,_=Resolver(view).materialize({'rules':[expected[0],expected[0]]},'values');assert len(dup['allowed_effects'])==2 and all(r['max_uses']==1 for r in dup['allowed_effects']);tests.append('equal_effect_occurrences_not_deduplicated')
    assert not allows(policy,'notify',expected[0]['arguments'],'changed');tests.append('explicit_current_view_binding')
    bad=copy.deepcopy(view);bad['tables']['directory'].append({'id':'a2','data':{'person':'A','address':'other@example.test'}})
    try:Resolver(bad).materialize(program,'query');raise AssertionError('ambiguous join accepted')
    except InvalidProgram:pass
    tests.append('ambiguous_join_rejected')
    bad=copy.deepcopy(program);bad['rules'][0]['arguments']['recipient']={'field':'missing'}
    try:Resolver(view).materialize(bad,'query');raise AssertionError('bad ref accepted')
    except InvalidProgram:pass
    tests.append('invalid_reference_rejected')
    res=Resolver(view);z=res.expression({'math':{'op':'money','values':[{'math':{'op':'div','values':[{'literal':1},{'literal':2}]}}]}},{},'unit','unit');assert z==.5;tests.append('typed_decimal_arithmetic')
    try:res.expression({'literal':'invented recipient'},{},'unit','unit');raise AssertionError('invented literal accepted')
    except InvalidProgram:pass
    tests.append('source_program_cannot_invent_a_string_literal')
    import hashlib
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps({'passed':len(tests),'n':len(tests),'checks':tests,'model_requests':0,'native_effects':0,'kernel_sha256':hashlib.sha256(Path(__file__).with_name('kernel.py').read_bytes()).hexdigest(),'scope':'Compiler fidelity to supplied programs and sources; not a proof of model grounding or owner intent.'},indent=2)+'\n');print(json.dumps(tests,indent=2))
if __name__=='__main__':main()
