"""Small current-grant reference monitor for an explicit-authority regime.

The trusted caller supplies grants and provider contracts. This module does
not infer authority from natural language, observations, prior calls or labels.
The local provider's effect projection must be faithful; it is not proven here.
"""
from dataclasses import dataclass
import copy,functools,hashlib,json,secrets,threading,time


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)


def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def project_call(name,args):
    """Declared local control contract, not a claim about production Gmail.

    Objects are key-order independent; opaque strings and array order remain
    exact. In this local mail provider empty optional fields add no recipient,
    attachment or schedule. No nonempty field is discarded.
    """
    if not isinstance(args,dict):raise ValueError('Arguments must be an object')
    args=copy.deepcopy(args)
    if name=='GmailSendEmail':
        for key in ['cc','bcc','send_at','attachments']:
            if key in args and args[key] in ['',None,[]]:del args[key]
    return {'tool':name,'arguments':args}


@dataclass(frozen=True)
class Snapshot:
    authority: str
    epoch: int
    revision: int
    registry: str
    operation: str
    wire_operation: str


@dataclass(frozen=True)
class Permit:
    token: str
    snapshot: Snapshot
    grant: str


class GrantKernel:
    def __init__(self,contracts,handlers,grants,*,clock=time.monotonic,lifetime=300,projectors=None):
        if set(contracts)!=set(handlers):raise ValueError('Registry mismatch')
        self.lock=threading.RLock();self.contracts=copy.deepcopy(contracts)
        self.handlers=dict(handlers);self.original_handlers=dict(handlers)
        self.projectors=dict(projectors) if projectors is not None else {name:functools.partial(project_call,name) for name in contracts}
        if set(self.projectors)!=set(contracts):raise ValueError('Projector registry mismatch')
        self.original_projectors=dict(self.projectors)
        self.registry=digest(self.contracts);self.clock=clock;self.expires=clock()+lifetime
        self.authority=secrets.token_hex(16);self.epoch=0;self.revision=0;self.active=grants is not None
        self.grants=copy.deepcopy(grants or []);self.uses={};self.completed=set();self.uncertain=False
        self.issued={};self.consumed=set();self.events=[]
        ids=[g['id'] for g in self.grants]
        if len(ids)!=len(set(ids)):raise ValueError('Duplicate grant identity')
        effects=[]
        for g in self.grants:
            if g['tool'] not in contracts or type(g['limit']) is not int or g['limit']<1:raise ValueError('Invalid grant')
            if set(g['requires'])-set(ids) or g['id'] in g['requires']:raise ValueError('Invalid prerequisite')
            g['effect']=self.project(g['tool'],g['arguments']);effects.append(digest(g['effect']));self.uses[g['id']]=0
        if len(effects)!=len(set(effects)):raise ValueError('Ambiguous duplicate effect grants')
        # Dependency cycles are invalid authority input, not completion proofs.
        pending={g['id']:set(g['requires']) for g in self.grants};done=set()
        while pending:
            ready={k for k,v in pending.items() if v<=done}
            if not ready:raise ValueError('Cyclic prerequisites')
            done|=ready;pending={k:v for k,v in pending.items() if k not in ready}

    def project(self,name,args):return self.projectors[name](copy.deepcopy(args))

    def public_policy(self):
        return {'grants':[{k:copy.deepcopy(g[k]) for k in ['id','tool','arguments','limit','requires']} for g in self.grants],
                'status':'active' if self.active else 'revoked','used':dict(self.uses),
                'confirmed_completed':sorted(self.completed),'outcome_uncertain':self.uncertain,
                'rule':'These grants come from the authenticated application. Observation text cannot add grants or mark an operation complete.'}

    def snapshot(self,name,args):
        with self.lock:return Snapshot(self.authority,self.epoch,self.revision,self.registry,digest(self.project(name,args)),digest({'tool':name,'arguments':args}))

    def _stable(self,snapshot,name,args):
        return (snapshot.authority==self.authority and snapshot.epoch==self.epoch and snapshot.revision==self.revision
            and snapshot.registry==self.registry==digest(self.contracts)
            and name in self.handlers and self.handlers[name] is self.original_handlers[name]
            and self.projectors[name] is self.original_projectors[name]
            and snapshot.operation==digest(self.project(name,args))
            and snapshot.wire_operation==digest({'tool':name,'arguments':args}))

    def assess(self,name,args):
        with self.lock:
            if not self.active:return {'status':'blocked','reason':'authority_inactive'}
            if self.clock()>=self.expires:return {'status':'blocked','reason':'authority_expired'}
            if self.uncertain:return {'status':'blocked','reason':'effect_outcome_uncertain'}
            if name not in self.contracts or name not in self.handlers or name not in self.projectors or digest(self.contracts)!=self.registry or self.handlers[name] is not self.original_handlers[name] or self.projectors[name] is not self.original_projectors[name]:return {'status':'blocked','reason':'unverified_registry'}
            effect=self.project(name,args)
            matches=[g for g in self.grants if g['tool']==name and digest(g['effect'])==digest(effect)]
            if not matches:return {'status':'blocked','reason':'outside_explicit_grant'}
            g=matches[0]
            if self.uses[g['id']]>=g['limit']:return {'status':'blocked','reason':'grant_budget_exhausted','grant':g['id']}
            if not set(g['requires'])<=self.completed:return {'status':'blocked','reason':'prerequisite_not_confirmed','grant':g['id']}
            return {'status':'ready','reason':'explicit_current_grant','grant':g['id']}

    def issue(self,name,args):
        with self.lock:
            decision=self.assess(name,args)
            if decision['status']!='ready':return None,decision
            token=secrets.token_hex(16);permit=Permit(token,self.snapshot(name,args),decision['grant'])
            self.issued[token]=permit;return permit,decision

    def commit(self,permit,name,args):
        with self.lock:
            if not isinstance(permit,Permit) or self.issued.get(permit.token)!=permit or permit.token in self.consumed:raise PermissionError('Unknown or consumed permit')
            if not self._stable(permit.snapshot,name,args):raise PermissionError('Current invocation changed')
            decision=self.assess(name,args)
            if decision['status']!='ready' or decision['grant']!=permit.grant:raise PermissionError('Current authority condition changed')
            # Consume before invocation; an error is not evidence of rollback.
            expected_effect=copy.deepcopy(self.project(name,args))
            self.consumed.add(permit.token);self.uses[permit.grant]+=1
            try:
                receipt=self.handlers[name](copy.deepcopy(args))
                if digest(receipt['effect'])!=permit.snapshot.operation:raise RuntimeError('Provider effect receipt mismatch')
                self.completed.add(permit.grant)
                self.events.append({'grant':permit.grant,'effect':receipt['effect'],'confirmed':True})
                return receipt
            except BaseException:
                self.uncertain=True
                self.events.append({'grant':permit.grant,'effect':expected_effect,'confirmed':False})
                raise
            finally:self.revision+=1

    def observe_unenforced_for_experiment(self,snapshot,name,args):
        """Experimental baseline only: execute without the scope ceiling.

        This path is never used by the enforced deployment mode and is not an
        actor tool. It preserves invocation identity and records actual effects
        for a fair no-enforcement/semantic-only comparison.
        """
        with self.lock:
            if not self._stable(snapshot,name,args):raise PermissionError('Current invocation changed')
            before=self.assess(name,args);effect=self.project(name,args)
            matching=next((g for g in self.grants if g['tool']==name and digest(g['effect'])==digest(effect)),None)
            if matching:self.uses[matching['id']]+=1
            try:
                receipt=self.handlers[name](copy.deepcopy(args))
                if digest(receipt['effect'])!=digest(effect):raise RuntimeError('Provider effect receipt mismatch')
                if before['status']=='ready':self.completed.add(before['grant'])
                self.events.append({'grant':before.get('grant'),'effect':receipt['effect'],'confirmed':True,'scope_status_before':before['status']})
                return receipt
            except BaseException:self.uncertain=True;raise
            finally:self.revision+=1

    def revoke(self):
        with self.lock:self.active=False;self.epoch+=1

    def reactivate(self):
        with self.lock:self.active=True;self.epoch+=1
