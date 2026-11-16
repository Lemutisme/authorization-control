"""One new policy update using unchanged Progent generation/parser/installation.

The original Luna-specific policy instruction and parser branch are held fixed
for both providers. This is a model substitution, not a claim to reproduce
Progent's separate Claude-specific prompt configuration.
"""
import argparse, contextlib, copy, gzip, importlib.util, io, json, os, sys, time
from pathlib import Path

HERE=Path(__file__).resolve().parent
NATIVE=Path('/artifact-source/211b28dfa309/sp27-baseline-audit-20261108')
sys.path[:0]=[str(HERE/'provider'),str(HERE),str(NATIVE/'vendor'),str(NATIVE/'sources/progent')]
os.environ.update(SECAGENT_POLICY_MODEL='gpt-6-luna',SECAGENT_GENERATE='True',ENABLE_SECAGENT='True',
                  SECAGENT_IGNORE_UPDATE_ERROR='True',SECAGENT_ONLY_ALLOW_NARROW='False')
with contextlib.redirect_stderr(io.StringIO()):
    from secagent import tool as gate
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime

CHANNEL_PATH=Path('/artifact-source/7defb8251014/channels.py')
spec=importlib.util.spec_from_file_location('matched_channels',CHANNEL_PATH)
channels=importlib.util.module_from_spec(spec);sys.modules[spec.name]=channels;spec.loader.exec_module(channels)


class PolicyClient:
    def __init__(self, model, historical):
        from luna import make_client
        self.client=make_client(model,allow_network=True)
        self.calls=[];self.stage='initial';self.historical=historical

    def request(self, system, user, temperature=0.0):
        if self.historical+len(self.calls)>=64:
            self.calls.append({'ok':False,'error':{'class':'policy_budget_exhausted'},'network_requests':0})
            raise RuntimeError('policy_budget_exhausted')
        record=self.client.complete_pi({'systemPrompt':system,'messages':[{'role':'user','content':user}], 'tools':[]},
                                       max_tokens=self.client.policy_output_tokens,temperature=0.7)
        record['requested_native_retry_temperature']=temperature
        record['sampling']='Requested temperature0.7 and model-specific thinking profile; Progent retry temperature logged but not forwarded'
        self.calls.append(record)
        if not record.get('ok'):
            raise RuntimeError('model_transport_or_normalization_failure')
        if record.get('returned_model') != self.client.model:
            raise RuntimeError('model_identity_mismatch')
        return record['text']


def evaluate(packet, policy):
    suite=get_suite('v1.2.2',packet['suite'])
    fn=next(f for f in suite.tools if f.name==packet['original_proposal']['function'])
    envtype=type(suite.load_and_inject_default_environment({}))
    state=envtype.model_validate(packet['state'])
    args=fn.parameters.model_validate(packet['original_proposal']['args']).model_dump()
    enriched=copy.deepcopy(args)
    enriched.update({key:dep.extract_dep_from_env(state) for key,dep in fn.dependencies.items()})
    gate.security_policy=copy.deepcopy(policy)
    try:
        with contextlib.redirect_stderr(io.StringIO()): gate.check_tool_call(fn.name,enriched)
        allowed=True;reason=None
    except gate.ValidationError as exc: allowed=False;reason=str(exc)
    result={'allowed':allowed,'reason':reason,'native_state_changed':False,'native_error':None}
    if allowed:
        after=state.model_copy(deep=True)
        _,error=FunctionsRuntime(suite.tools).run_function(after,fn.name,args)
        result.update(native_state_changed=state.model_dump(mode='json')!=after.model_dump(mode='json'),native_error=error,
                      native_after=after.model_dump(mode='json'))
    return result


def run(packet_path, model, visible, repetition, dry=False):
    packet=json.loads(Path(packet_path).read_text());began=time.monotonic()
    gate.init_user_query=packet['owner_request'];gate.available_tools=copy.deepcopy(packet['tools'])
    gate.security_policy=copy.deepcopy(packet['policy'])
    before=evaluate(packet,gate.security_policy)
    if before['allowed']:raise ValueError('Source call was not refused')
    # evaluate restores a copy; preserve source input after probing.
    gate.security_policy=copy.deepcopy(packet['policy'])
    gate.get_SYS_PROMPT_2=lambda:packet['system_prompt']
    captures=[]
    if dry:
        class Fake:
            calls=[];stage='initial'
            def request(self,system,user,temperature=0):
                self.calls.append({'system':system,'user':user});return 'No'
        client=Fake()
    else: client=PolicyClient(model,packet['historical_constructor_calls'])
    def request(system,user,temperature=0):
        captures.append({'systemPrompt':system,'messages':[{'role':'user','content':user}]})
        return client.request(system,user,temperature)
    gate.api_request=request
    with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
        update=channels.update_after_refusal(gate,client,packet['proposal'],packet['tool_result'],visible)
    after_policy=copy.deepcopy(gate.security_policy)
    after=evaluate(packet,after_policy)
    expected=copy.deepcopy(packet['reference_hidden_context'])
    actual=captures[0]
    # Compare prompt and all parsed semantic fields after masking the sole input treatment.
    import re
    def mask(text):return re.sub(r'(?<=\nTOOL_CALL_PARAM: ).*?(?=\nTOOL_CALL_RESULT:)','[]',text,flags=re.S)
    exact=actual['systemPrompt']==expected['systemPrompt'] and mask(actual['messages'][0]['content'])==mask(expected['messages'][0]['content'])
    if not exact:raise ValueError('New request differs from retained source beyond proposal visibility')
    transport_failed=any(not c.get('ok',True) for c in client.calls)
    admission=int(after['allowed']) if after['allowed'] or not transport_failed else None
    return {'unit_id':packet['unit_id'],'panel':packet['panel'],'task_id':packet['task_id'],
            'model':model,'proposal_visible':visible,'repetition':repetition,'before':before,'after':after,
            'admission':admission,'transport_failed':transport_failed,'update':update,'policy_after':after_policy,
            'requests':client.calls,'contexts':captures,'only_input_treatment_differs':exact,
            'elapsed_s':time.monotonic()-began,'dry':dry,'packet_path':str(packet_path)}


def main():
    p=argparse.ArgumentParser();p.add_argument('--packet',required=True);p.add_argument('--model',choices=['lumen_beam'],required=True)
    p.add_argument('--visible',type=int,choices=[0,1],required=True);p.add_argument('--repetition',type=int,default=0)
    p.add_argument('--out',required=True);p.add_argument('--dry',action='store_true');a=p.parse_args()
    result=run(a.packet,a.model,bool(a.visible),a.repetition,a.dry)
    out=Path(a.out);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(gzip.compress(json.dumps(result,ensure_ascii=False,default=str).encode()))
    print(json.dumps({k:result[k] for k in ['unit_id','model','proposal_visible','admission','transport_failed','elapsed_s','dry']}))


if __name__=='__main__':main()
