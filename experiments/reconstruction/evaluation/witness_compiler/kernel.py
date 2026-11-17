"""Finite source-bound policy programs; no eval, I/O or hidden task oracle."""
import copy,hashlib,json,math
from decimal import Decimal,ROUND_HALF_UP
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)
def digest(x):return hashlib.sha256(canonical(x).encode()).hexdigest()
def effect_key(effect):
    def normalize(x):
        if type(x) in (int,float):return {'numeric_value':format(Decimal(str(x)).normalize(),'f')}
        if isinstance(x,list):return [normalize(v) for v in x]
        if isinstance(x,dict):return {k:normalize(v) for k,v in x.items()}
        return x
    return canonical(normalize({'function':effect['function'],'arguments':effect['arguments']}))
class InvalidProgram(ValueError):pass
def get_path(obj,path):
    if not isinstance(path,str) or len(path)>160:raise InvalidProgram('Invalid field path')
    cur=obj
    for part in path.split('.'):
        if not part or part.startswith('_'):raise InvalidProgram('Invalid field path')
        if isinstance(cur,dict) and part in cur:cur=cur[part]
        elif isinstance(cur,list) and part.isdigit() and int(part)<len(cur):cur=cur[int(part)]
        else:raise InvalidProgram('Unknown field')
    return copy.deepcopy(cur)
def scalar(x):
    if not isinstance(x,(str,int,float,bool,type(None))):raise InvalidProgram('Expected scalar')
    if isinstance(x,float) and not math.isfinite(x):raise InvalidProgram('Nonfinite scalar')
    return x
class Resolver:
    def __init__(self,view):
        self.view=copy.deepcopy(view);self.hash=digest(view);self.tables=self.view['tables'];self.atoms={a['id']:a['value'] for a in view['owner_atoms']}
        self.reads=[];self.steps=0
        for name,rows in self.tables.items():
            ids=[r['id'] for r in rows]
            if len(set(ids))!=len(ids):raise InvalidProgram('Ambiguous source row')
    def tick(self):
        self.steps+=1
        if self.steps>20000:raise InvalidProgram('Program budget exceeded')
    def expression(self,e,row,table,row_id,depth=0):
        self.tick()
        if depth>12 or not isinstance(e,dict) or len(e)!=1:raise InvalidProgram('Invalid expression')
        kind,value=next(iter(e.items()));rec=lambda x:self.expression(x,row,table,row_id,depth+1)
        if kind=='field':
            v=get_path(row,value);self.reads.append({'table':table,'row':row_id,'field':value});return v
        if kind=='owner':
            if value not in self.atoms:raise InvalidProgram('Unknown owner literal')
            self.reads.append({'owner_atom':value});return copy.deepcopy(self.atoms[value])
        if kind=='literal':
            scalar(value)
            if isinstance(value,bool) or value is None or type(value) in (int,float) and value in {0,1,2,100}:return value
            if value in self.atoms.values() or isinstance(value,str) and value and value in self.view['owner']:return value
            raise InvalidProgram('Literal not supplied by owner')
        if kind=='list':
            if not isinstance(value,list) or len(value)>100:raise InvalidProgram('Invalid list')
            return [rec(x) for x in value]
        if kind=='lookup':
            if not isinstance(value,dict) or set(value)!={'table','key','value','field'}:raise InvalidProgram('Invalid lookup')
            target=value['table'];wanted=rec(value['value']);matches=[r for r in self.tables.get(target,[]) if get_path(r['data'],value['key'])==wanted]
            if len(matches)!=1:raise InvalidProgram('Lookup must have one witness')
            r=matches[0];self.reads.append({'table':target,'row':r['id'],'field':value['field'],'join_key':value['key']});return get_path(r['data'],value['field'])
        if kind=='render':
            if not isinstance(value,dict) or set(value)!={'template','values'}:raise InvalidProgram('Invalid renderer')
            vals=[rec(x) for x in value['values']]
            if value['template']=='assignment_notice' and len(vals)==2 and all(isinstance(v,str) for v in vals):return vals[0]+' Deadline: '+vals[1]+'.'
            raise InvalidProgram('Unsupported renderer')
        if kind=='math':
            if not isinstance(value,dict) or set(value)!={'op','values'}:raise InvalidProgram('Invalid arithmetic')
            vals=[Decimal(str(rec(x))) for x in value['values']];op=value['op']
            if len(vals)==2 and op in {'add','sub','mul','div'}:
                a,b=vals;z=a+b if op=='add' else a-b if op=='sub' else a*b if op=='mul' else a/b
            elif len(vals)==1 and op=='money':z=vals[0].quantize(Decimal('.01'),rounding=ROUND_HALF_UP)
            else:raise InvalidProgram('Unsupported arithmetic')
            if not z.is_finite():raise InvalidProgram('Nonfinite result')
            return int(z) if z==z.to_integral_value() else float(z)
        raise InvalidProgram('Unknown expression')
    def select(self,query):
        if not isinstance(query,dict) or not {'table'}<=set(query) or set(query)-{'table','where','order_by','descending','limit'}:raise InvalidProgram('Invalid source query')
        table=query['table']
        if table=='unit':rows=[{'id':'unit','data':{}}]
        elif table in self.tables:rows=copy.deepcopy(self.tables[table])
        else:raise InvalidProgram('Unknown source table')
        conditions=query.get('where',[])
        if not isinstance(conditions,list) or len(conditions)>10:raise InvalidProgram('Invalid filters')
        for c in conditions:
            if not isinstance(c,dict) or set(c)!={'field','op','value'}:raise InvalidProgram('Invalid filter')
            selected=[]
            for r in rows:
                left=get_path(r['data'],c['field']);right=self.expression(c['value'],r['data'],table,r['id']);op=c['op']
                if op=='eq':ok=type(left)==type(right) and left==right or type(left) in (int,float) and type(right) in (int,float) and left==right
                elif op=='contains':ok=isinstance(left,str) and isinstance(right,str) and right.casefold() in left.casefold()
                elif op=='ne':ok=left!=right
                else:raise InvalidProgram('Unsupported filter')
                if ok:selected.append(r)
            rows=selected
        if 'order_by' in query:rows.sort(key=lambda r:get_path(r['data'],query['order_by']),reverse=query.get('descending',False))
        if 'limit' in query:
            n=query['limit']
            if type(n)!=int or not 1<=n<=100:raise InvalidProgram('Invalid limit')
            rows=rows[:n]
        return table,rows
    def materialize(self,program,mode):
        if not isinstance(program,dict) or set(program)!={'rules'} or not isinstance(program['rules'],list) or len(program['rules'])>100:raise InvalidProgram('Invalid policy container')
        effects=[];witnesses=[]
        for rule in program['rules']:
            self.tick()
            if not isinstance(rule,dict) or 'function' not in rule:raise InvalidProgram('Invalid rule')
            fn=rule['function'];contract=self.view['contracts'].get(fn)
            if contract is None:raise InvalidProgram('Unknown effect function')
            if mode=='values':
                if set(rule)!={'function','arguments'}:raise InvalidProgram('Invalid value row')
                candidates=[(copy.deepcopy(rule['arguments']),{'kind':'copied_values'})]
            else:
                if mode=='refs':
                    if set(rule)!={'function','witness','arguments'} or set(rule['witness'])!={'table','row'}:raise InvalidProgram('Invalid reference row')
                    table=rule['witness']['table'];ident=rule['witness']['row'];rows=[{'id':'unit','data':{}}] if table=='unit' and ident=='unit' else [r for r in self.tables.get(table,[]) if r['id']==ident]
                    if len(rows)!=1:raise InvalidProgram('Unknown or ambiguous witness')
                elif mode=='query':
                    if set(rule)!={'function','query','arguments'}:raise InvalidProgram('Invalid query rule')
                    table,rows=self.select(rule['query'])
                else:raise InvalidProgram('Unknown construction mode')
                if not isinstance(rule['arguments'],dict):raise InvalidProgram('Invalid arguments')
                candidates=[]
                for r in rows:
                    begin=len(self.reads);args={k:self.expression(v,r['data'],table,r['id']) for k,v in rule['arguments'].items()};candidates.append((args,{'kind':'source_binding','table':table,'row':r['id'],'reads':self.reads[begin:]}))
            for args,witness in candidates:
                if not isinstance(args,dict) or set(args)!=set(contract['fields']):raise InvalidProgram('Missing or extra protected field')
                for k,typ in contract['fields'].items():
                    v=args[k];good=(typ=='string' and isinstance(v,str) or typ=='number' and type(v) in (int,float) and math.isfinite(v) or typ=='boolean' and type(v)==bool or typ=='strings' and isinstance(v,list) and all(isinstance(z,str) for z in v))
                    if not good:raise InvalidProgram('Wrong field type')
                effects.append({'function':fn,'arguments':args});witnesses.append(witness)
        # Equal argument tuples can represent distinct authorized occurrences.
        # Preserve multiplicity instead of turning a task relation into a set.
        policy={'schema':1,'source_view_sha256':self.hash,'allowed_effects':[{**e,'max_uses':1} for e in effects]}
        return policy,{'materialized_rows':effects,'witnesses':witnesses,'expression_steps':self.steps}
def allows(policy,function,args,current_view_sha256=None):
    if current_view_sha256 is not None and policy.get('source_view_sha256')!=current_view_sha256:return False
    return any(r['function']==function and all(k in args and type(args[k])==type(v) and args[k]==v or k in args and type(args[k]) in (int,float) and type(v) in (int,float) and args[k]==v for k,v in r['arguments'].items()) for r in policy['allowed_effects'])
