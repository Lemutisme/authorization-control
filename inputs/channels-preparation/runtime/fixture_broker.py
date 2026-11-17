"""Qualification-only connection substitution; native/policy logic is unchanged."""
import contextlib,io,json,sys,traceback
from broker import Broker,m

class FixtureBroker(Broker):
    def init(self, params):
        original = m.BudgetPolicyClient
        connection = {'base_url': 'https://channels-qualification.invalid/v1', 'api_key': None}
        m.BudgetPolicyClient = lambda _connection, *args, **kwargs: original(connection, *args, **kwargs)
        try:
            result = super().init(params)
        finally:
            m.BudgetPolicyClient = original
        result['connection'] = connection
        result['qualification_only'] = True
        return result

def main():
    broker=FixtureBroker()
    try:
        for line in sys.stdin:
            ident=None
            try:
                q=json.loads(line);ident=q['id']
                if set(q)!={'id','method','params'} or q['method'] not in {'init','invoke','finish'}:raise ValueError('Invalid fixture RPC')
                with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                    result=getattr(broker,q['method'])(q['params'])
                print(json.dumps({'id':ident,'ok':True,'result':result},default=str),flush=True)
            except Exception as exc:print(json.dumps({'id':ident,'ok':False,'error':type(exc).__name__,'diagnostic':traceback.format_exc()}),flush=True)
    finally:broker.close()

if __name__=='__main__':main()
