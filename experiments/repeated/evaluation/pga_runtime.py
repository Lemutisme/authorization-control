"""Instrument actual AgentDojo invocations, including nested and error effects."""
from __future__ import annotations
import copy
import time
from agentdojo.functions_runtime import FunctionsRuntime

class AuditedRuntime(FunctionsRuntime):
    def __init__(self, functions, gate=None, *, max_calls=64):
        super().__init__(functions)
        self.gate=gate;self.events=[];self.decisions=[];self.depth=0
        self.collecting=False;self._last_snapshot=None;self.max_calls=max_calls;self.calls_started=0

    def _invoke(self, env, function, args, *, kind='agent', raise_on_error=False):
        if self.calls_started>=self.max_calls:
            if raise_on_error:raise RuntimeError('Shared native invocation budget exhausted')
            return None,'Shared native invocation budget exhausted'
        self.calls_started+=1
        before=env.model_dump(mode='json'); original_args=copy.deepcopy(args); t=time.monotonic();depth=self.depth
        if self._last_snapshot is None:self._last_snapshot=copy.deepcopy(before)
        self.depth+=1; error=None; result=None
        try:
            result,error=super().run_function(env,function,args,raise_on_error=raise_on_error)
            return result,error
        except Exception as e:
            error=type(e).__name__;raise
        finally:
            self.depth-=1
            after=env.model_dump(mode='json')
            self.events.append({'index':len(self.events),'operation':{'function':function,'args':original_args},
                'kind':kind,'depth':depth,'before':self._last_snapshot,'after':after,'entry_state_changed':before!=after,'error':error,
                'elapsed_s':time.monotonic()-t})
            self._last_snapshot=copy.deepcopy(after)
            if self.gate is not None and error is None:
                self.gate.observe(function,original_args,result)
            elif self.gate is not None and before!=after:
                self.gate.mark_uncertain()

    def run_function(self, env, function, args, raise_on_error=False):
        if self.gate is not None and not self.collecting:
            decision=self.gate.decide(function,args,self,env)
            self.decisions.append({'operation':{'function':function,'args':copy.deepcopy(args)},**decision})
            if decision['verdict']!='allow':
                message='Policy gate '+decision['verdict']+': '+decision['reason']
                if raise_on_error:raise RuntimeError(message)
                return None,message
        return self._invoke(env,function,args,raise_on_error=raise_on_error)

    def collect(self, env, function, args):
        if self.gate is None or not self.gate.query_allowed(function,args):
            return None,'Collector query not authorized'
        old=self.collecting;self.collecting=True
        try:return self._invoke(env,function,args,kind='collector')
        finally:self.collecting=old
