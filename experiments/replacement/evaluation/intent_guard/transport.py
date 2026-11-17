"""Luna-only authorizer with an explicit small reasoning budget profile."""
import hashlib,json,time,urllib.error,urllib.request
from luna_transport import LunaTransport,MODEL
from pga_transport import TransportError

class AuthorizationTransport(LunaTransport):
    def __init__(self):super().__init__(max_output_tokens=1536,timeout=90)
    def request(self,history,tools,instructions):
        payload={'model':MODEL,'input':history,'instructions':instructions,'tools':tools,
            'parallel_tool_calls':False,'max_output_tokens':self.max_output_tokens,'reasoning':{'effort':'low'},'store':False}
        headers={'Content-Type':'application/json'}
        if self.key:headers['Authorization']='Bearer '+self.key
        start=time.monotonic();record={'requested_model':MODEL,'reasoning_effort':'low','request_sha256':hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest(),
            'purpose':'owner_only_scope' if tools and tools[0].get('name')=='describe_owner_task' else 'effect_authorization'}
        try:
            req=urllib.request.Request(self.endpoint,json.dumps(payload).encode(),headers,method='POST')
            with urllib.request.urlopen(req,timeout=self.timeout) as response:data=json.load(response);record['http_status']=response.status
            record.update(returned_model=data.get('model'),response_status=data.get('status'),usage=data.get('usage'))
            if data.get('error'):raise TransportError('Provider response error')
            return data
        except urllib.error.HTTPError as exc:
            record.update(http_status=exc.code,error='HTTPError');raise TransportError('Authorization HTTP '+str(exc.code)) from None
        except (OSError,ValueError) as exc:
            record['error']=type(exc).__name__;raise TransportError('Authorization transport '+type(exc).__name__) from None
        finally:record['elapsed_s']=time.monotonic()-start;self.calls.append(record)
    def metadata(self):return {**super().metadata(),'reasoning_effort':'low','max_output_tokens':1536}
