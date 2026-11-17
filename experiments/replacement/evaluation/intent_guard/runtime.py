"""Exact candidate admission and native invocation under a shared local boundary."""
import copy,threading,json
from agentdojo.functions_runtime import FunctionCall
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from pga_runtime import AuditedRuntime
from pga_gate import portable
from guard import digest
from catalog import invocation_mode

class IntentRuntime(AuditedRuntime):
    def __init__(self,functions,guard,catalog,*,max_calls=64):
        super().__init__([f.model_copy(deep=True) for f in functions],None,max_calls=max_calls)
        self.authorizer=guard;self.catalog=copy.deepcopy(catalog);self.lock=guard.lock
        self.catalog_key=digest(self.catalog);self.native_functions={name:f.run for name,f in self.functions.items()}
        self.native_parameters={name:(f.parameters,f.parameters.__pydantic_validator__) for name,f in self.functions.items()}
        self.revision=0;self.receipts=[];self.receipt_keys=set();self.uncertain_effect=False
    def update_functions(self,new_functions):raise RuntimeError('Frozen tool registry; create a new reviewed runtime')
    def register_function(self,function):raise RuntimeError('Frozen tool registry; create a new reviewed runtime')
    def _receipt(self,function,args,result,error,mode=None):
        text=tool_result_to_str(result) if error is None else 'Error: '+error
        receipt={'tool':function,'arguments':copy.deepcopy(args),'result':text,'value':portable(result) if error is None else None,
                 'error':error is not None,'status':'success' if error is None else 'error','mode':mode or self.catalog[function]['mode']}
        if getattr(self,'auto_collecting',False):receipt['controller_collected']=True
        if getattr(self,'auto_collecting',False) and function=='read_channel_messages' and error is None:
            # Additional aggregation queries need sender identities/counts,
            # not message bodies. Actor-requested returns remain unchanged.
            projected=[{'sender':row['sender']} for row in receipt['value']]
            receipt.update(value=projected,result=json.dumps(projected,ensure_ascii=False),projection='controller_message_senders_only')
        key=digest(receipt)
        # Successful/failed effects are ordered occurrences, never a set: two
        # transfers can return the same value but create two distinct effects.
        if receipt['mode']=='effect' or key not in self.receipt_keys:
            self.receipt_keys.add(key);self.receipts.append(receipt)
    def _invoke_record(self,env,function,args,raise_on_error,mode=None):
        supplied=copy.deepcopy(args)
        prior_events=len(self.events)
        try:
            result,error=super()._invoke(env,function,args,raise_on_error=raise_on_error,kind='collector' if getattr(self,'auto_collecting',False) else 'agent')
            self._receipt(function,supplied,result,error,mode);return result,error
        finally:
            if len(self.events)>prior_events:self.events[-1]['classified_mode']=mode or self.catalog[function]['mode']
            self.revision+=1
            if self.events and self.events[-1].get('error') and self.events[-1].get('entry_state_changed'):self.uncertain_effect=True
    def run_function(self,env,function,args,raise_on_error=False):
        def reject(reason):
            if raise_on_error:raise ValueError(reason)
            return None,reason
        def stable():
            if function not in self.functions:return False
            f=self.functions[function];model,validator=self.native_parameters[function]
            return digest(self.catalog)==self.catalog_key and f.run is self.native_functions[function] and f.parameters is model and f.parameters.__pydantic_validator__ is validator
        with self.lock:
            if function not in self.catalog:return reject('Unregistered effect surface')
            if not stable():return reject('Registered tool contract changed')
        try:resolved=self._execute_nested_calls(env,copy.deepcopy(args))
        except Exception as exc:
            if raise_on_error:raise
            return None,type(exc).__name__+': nested operation failed'
        with self.lock:
            if not stable():return reject('Registered tool contract changed')
            try:
                # Nested references use this same mediated entry; the authorizer
                # sees the resolved, schema-normalized arguments actually used.
                normalized=self.functions[function].parameters.model_validate(resolved).model_dump()
            except Exception as exc:
                # Preserve the native validation error/count/feedback path. The
                # reviewed parameter validators reject before function execution.
                return self._invoke_record(env,function,resolved,raise_on_error)
            if invocation_mode(function,normalized)=='internal_read':return self._invoke_record(env,function,normalized,raise_on_error,mode='internal_read')
            if self.uncertain_effect:return reject('Authorization unresolved after a partial native effect')
        if not self.authorizer.prepare_scope():
            with self.lock:self.decisions.append({'operation':{'function':function,'args':copy.deepcopy(normalized)},'decision':'needs_facts','verdict':'needs_facts','reason':'Owner-only interpretation unavailable or changed.','model_call':False,'basis':'owner_scope_unavailable'})
            message='Authorization needs_facts: owner-only interpretation unavailable or changed.'
            if self.authorizer.scope_status=='unavailable':message+=' This top-level tool function has not executed; earlier completed effects are not undone. One later interpretation attempt may remain under the shared budget. This is not permission to execute.'
            return reject(message)
        with self.lock:
            if not stable() or self.uncertain_effect or not self.authorizer.scope_ready():return reject('Authorization dependencies changed during owner interpretation')
            # A previously observed resource inventory is data. Query missing
            # members by their exact native identifier; do not let language-model
            # normalization silently change the universe of an aggregate check.
            query='get_users_in_channel' if function=='send_channel_message' else 'read_channel_messages'
            if function in {'send_direct_message','add_user_to_channel','send_channel_message'} and query in self.catalog:
                inventory=None;observed=set()
                for receipt in self.receipts:
                    if receipt['error']:continue
                    if receipt['tool']=='get_channels' and isinstance(receipt.get('value'),list):inventory=receipt['value']
                    if receipt['tool']==query:observed.add(receipt['arguments']['channel'])
                if inventory is not None:
                    self.auto_collecting=True
                    try:
                        for channel in inventory:
                            if self.calls_started>=self.max_calls:break
                            if isinstance(channel,str) and channel not in observed:
                                _,error=self.run_function(env,query,{'channel':channel})
                                if error is None:observed.add(channel)
                    finally:self.auto_collecting=False
            if function in {'create_calendar_event','cancel_calendar_event','reschedule_calendar_event','add_calendar_event_participants','reserve_hotel','reserve_restaurant','reserve_car_rental'} and 'get_current_day' in self.catalog and not any(r['tool']=='get_current_day' and not r['error'] for r in self.receipts):
                self.auto_collecting=True
                try:self.run_function(env,'get_current_day',{})
                finally:self.auto_collecting=False
            revision=self.revision;authority=self.authorizer.authority_key();observations=copy.deepcopy(self.receipts)
            exact=digest({'function':function,'arguments':normalized})
        decision=self.authorizer.authorize(self.catalog[function],normalized,observations)
        with self.lock:
            if revision!=self.revision or authority!=self.authorizer.authority_key() or exact!=digest({'function':function,'arguments':normalized}) or not stable():
                decision={**decision,'decision':'needs_facts','reason':'Authority, request or native revision changed before invocation.'}
            record={'operation':{'function':function,'args':copy.deepcopy(normalized)},'verdict':decision['decision'],**decision}
            self.decisions.append(record)
            if decision['decision']!='allow':
                message='Authorization '+decision['decision']+': '+decision['reason']
                if decision.get('operational_unavailable'):
                    message+=' No applicable permission was obtained and this top-level tool function has not executed. One later reauthorization attempt may be available under the same total budget; never assume approval or repeat an earlier completed effect.'
                else:
                    message+=' This is a decision on this specific proposal. If the owner task is already fulfilled, report completion. Otherwise, a narrower or corrected proposal may be checked separately using the original request and available facts. Do not repeat completed effects, seek broader authority, or merely reword the same rejected request; obtain any genuinely missing facts.'
                if raise_on_error:raise ValueError(message)
                return None,message
            return self._invoke_record(env,function,normalized,raise_on_error)
