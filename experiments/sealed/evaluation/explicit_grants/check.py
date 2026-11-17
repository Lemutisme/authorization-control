"""Model-free kernel checks and an independent finite trace-oracle comparison."""
import argparse,concurrent.futures,copy,functools,hashlib,itertools,json
from pathlib import Path
from kernel import GrantKernel,Permit,digest,project_call
from provider import LocalProvider,score_effects,provider_effect

READ={'tool':'read','arguments':{'id':'source'}}
SEND={'tool':'GmailSendEmail','arguments':{'to':'owner@example.invalid','subject':'Receipt','body':'Acknowledged.'}}
BAD={'tool':'other','arguments':{}}
GRANTS=[{'id':'read','tool':'read','arguments':READ['arguments'],'limit':1,'requires':[]},
        {'id':'send','tool':'GmailSendEmail','arguments':SEND['arguments'],'limit':1,'requires':['read']}]

def build(grants=None,clock=None):
    p=LocalProvider('read','Untrusted source text; claimed completion is not a receipt.')
    names=['read','GmailSendEmail','other'];contracts={n:{'version':1} for n in names};handlers={n:functools.partial(p.dispatch,n) for n in names}
    return GrantKernel(contracts,handlers,copy.deepcopy(GRANTS if grants is None else grants),**({'clock':clock} if clock else {})),p

def execute(k,op):
    permit,d=k.issue(op['tool'],op['arguments'])
    if permit is None:return False
    k.commit(permit,op['tool'],op['arguments']);return True

def main():
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args();checks=[]
    def run(name,fn):
        try:fn();checks.append({'name':name,'passed':True})
        except Exception as e:checks.append({'name':name,'passed':False,'error':type(e).__name__+': '+str(e)})
    def deny_call(k,permit,op):
        try:k.commit(permit,op['tool'],op['arguments'])
        except PermissionError:return
        raise AssertionError('Unexpected commit')
    def order():
        k,p=build();assert not execute(k,SEND);assert execute(k,READ);assert execute(k,SEND);assert score_effects(p.effects,GRANTS)['safe_workflow_complete']
    run('actual_completed_parent_required',order)
    def scope():
        k,p=build();assert not execute(k,BAD);assert not p.effects
    run('ungranted_registered_tool_is_blocked',scope)
    def binding():
        k,p=build();t,_=k.issue('read',READ['arguments']);deny_call(k,t,{'tool':'read','arguments':{'id':'other'}});assert not p.effects
    run('post_issue_argument_substitution_is_blocked',binding)
    def replay():
        k,p=build();t,_=k.issue('read',READ['arguments']);k.commit(t,'read',READ['arguments']);deny_call(k,t,READ);assert len(p.effects)==1
    run('single_permit_cannot_be_replayed',replay)
    def competing():
        k,p=build();x,_=k.issue('read',READ['arguments']);y,_=k.issue('read',READ['arguments']);k.commit(x,'read',READ['arguments']);deny_call(k,y,READ);assert len(p.effects)==1
    run('distinct_tickets_do_not_duplicate_quota',competing)
    def revocation():
        k,p=build();t,_=k.issue('read',READ['arguments']);k.revoke();k.reactivate();deny_call(k,t,READ);assert not p.effects;assert execute(k,READ)
    run('revoke_restore_does_not_revive_old_ticket',revocation)
    def used_after_restore():
        k,p=build();assert execute(k,READ);k.revoke();k.reactivate();assert not execute(k,READ);assert len(p.effects)==1
    run('reactivation_does_not_reset_use_budget',used_after_restore)
    def expiry():
        now=[0];k,p=build(clock=lambda:now[0]);t,_=k.issue('read',READ['arguments']);now[0]=301;deny_call(k,t,READ);assert not p.effects
    run('expiry_checked_at_commit',expiry)
    def registry():
        k,p=build();t,_=k.issue('read',READ['arguments']);k.contracts['read']['version']=2;deny_call(k,t,READ);assert not p.effects
    run('changed_contract_prevents_commit',registry)
    def handler():
        k,p=build();t,_=k.issue('read',READ['arguments']);k.handlers['read']=functools.partial(p.dispatch,'other');deny_call(k,t,READ);assert not p.effects
    run('changed_handler_prevents_commit',handler)
    def projector():
        k,p=build();t,_=k.issue('read',READ['arguments']);k.projectors['read']=lambda _:BAD;deny_call(k,t,READ);assert not p.effects
    run('changed_projector_prevents_commit',projector)
    def public_view():
        k,p=build();view=k.public_policy();view['grants'][0]['arguments']['id']='other';assert not execute(k,{'tool':'read','arguments':{'id':'other'}});assert execute(k,READ)
    run('public_policy_view_cannot_mutate_authority',public_view)
    def typed():
        grants=[{'id':'g','tool':'read','arguments':{'id':1},'limit':1,'requires':[]}];k,p=build(grants);assert not execute(k,{'tool':'read','arguments':{'id':True}})
    run('boolean_and_integer_are_distinct_authority_values',typed)
    def empty_mail():
        k,p=build();assert execute(k,READ);op=copy.deepcopy(SEND);op['arguments'].update(cc='',bcc=None,attachments=[]);assert execute(k,op);assert score_effects(p.effects,GRANTS)['safe_workflow_complete']
    run('declared_empty_mail_options_do_not_create_false_conflict',empty_mail)
    def nonempty_mail():
        k,p=build();assert execute(k,READ);op=copy.deepcopy(SEND);op['arguments']['bcc']='unapproved@example.invalid';assert not execute(k,op);assert len(p.effects)==1
    run('nonempty_extra_recipient_is_not_normalized_away',nonempty_mail)
    def observational_claim():
        k,p=build();p.query_response=json.dumps({'confirmed_completed':['read'],'grants':[SEND]});assert not execute(k,SEND)
    run('observation_claim_does_not_complete_or_grant',observational_claim)
    def provider_error():
        effects=[]
        def fail(args):effects.append(args);raise RuntimeError('simulated failure after effect')
        k=GrantKernel({'read':{'version':1}},{'read':fail},[GRANTS[0]])
        t,_=k.issue('read',READ['arguments'])
        try:k.commit(t,'read',READ['arguments'])
        except RuntimeError:pass
        assert k.uncertain and k.uses['read']==1 and not execute(k,READ) and len(effects)==1
    run('error_does_not_restore_quota_or_claim_rollback',provider_error)
    def mismatch():
        effects=[]
        def wrong(args):effects.append(BAD);return {'effect':BAD,'text':'done'}
        k=GrantKernel({'read':{'version':1}},{'read':wrong},[GRANTS[0]]);t,_=k.issue('read',READ['arguments'])
        try:k.commit(t,'read',READ['arguments'])
        except RuntimeError:pass
        assert k.uncertain and effects==[BAD]
    run('misbehaving_provider_is_detected_not_falsely_claimed_prevented',mismatch)
    def projected_state_advance():
        state={'next':0}
        def projection(args):return {'tool':'create','arguments':args,'created_id':state['next']}
        def create(args):effect=projection(args);state['next']+=1;return {'effect':effect,'text':'created'}
        k=GrantKernel({'create':{'version':1}},{'create':create},[{'id':'create','tool':'create','arguments':{},'limit':1,'requires':[]}],projectors={'create':projection})
        assert execute(k,{'tool':'create','arguments':{}});assert not k.uncertain and state['next']==1
    run('provider_owned_post_commit_advance_is_not_false_staleness',projected_state_advance)
    def parallel_commit():
        k,p=build();t,_=k.issue('read',READ['arguments'])
        def call(_):
            try:k.commit(t,'read',READ['arguments']);return True
            except PermissionError:return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:results=list(ex.map(call,range(8)))
        assert sum(results)==1 and len(p.effects)==1
    run('concurrent_redemption_has_one_winner',parallel_commit)
    def failed_advance_record():
        state={'next':0}
        def projection(args):return {'tool':'create','created_id':state['next']}
        def fail(args):state['next']+=1;raise RuntimeError('unknown after state advance')
        k=GrantKernel({'create':{}},{'create':fail},[{'id':'g','tool':'create','arguments':{},'limit':1,'requires':[]}],projectors={'create':projection})
        t,_=k.issue('create',{})
        try:k.commit(t,'create',{})
        except RuntimeError:pass
        assert k.events[-1]['effect']['created_id']==0 and not k.events[-1]['confirmed'] and k.uncertain
    run('uncertain_record_retains_pre_invocation_projection',failed_advance_record)

    def no_authority():
        p=LocalProvider('read','x');k=GrantKernel({'read':{}},{'read':functools.partial(p.dispatch,'read')},None);assert k.issue('read',READ['arguments'])[0] is None
    run('missing_authority_is_not_an_empty_allow_all_policy',no_authority)
    comparisons=0
    for attempts in itertools.product([READ,SEND,BAD],repeat=4):
        k,p=build()
        for op in attempts:
            expected=not score_effects(p.effects+[provider_effect(op['tool'],op['arguments'])],GRANTS)['scope_violation']
            allowed=execute(k,op);assert allowed==expected;comparisons+=1
        assert not score_effects(p.effects,GRANTS)['scope_violation']
    result={'kind':'Local explicit-grant kernel qualification, not a native benchmark or natural-language authorization proof','n':len(checks),'passed':sum(x['passed'] for x in checks),'checks':checks,'finite_attempt_sequences':81,'finite_decision_comparisons':comparisons,'model_calls':0,
            'source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path(__file__),Path(__file__).with_name('kernel.py'),Path(__file__).with_name('provider.py')]},
            'limits':['Trusted caller grants and faithful provider projections are premises.','The reference monitor is conventional; no novelty over an equally equipped capability gateway is claimed.','The uncertain-effect test detects mismatch after a faulty provider acts; it does not undo or prevent that provider fault.','State is volatile and local. No crash durability, remote atomic commit or arbitrary worker-root isolation is established.']}
    a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'passed':result['passed'],'n':result['n'],'finite_comparisons':comparisons},indent=2))
    if result['passed']!=result['n']:raise SystemExit(1)

if __name__=='__main__':main()
