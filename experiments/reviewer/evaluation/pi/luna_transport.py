"""Explicit Luna/none transport for the protected Python grounding component."""
import hashlib,json,time,urllib.error,urllib.request
from pga_transport import ResponsesTransport,TransportError

MODEL='gpt-6-luna'

class LunaTransport(ResponsesTransport):
    def __init__(self,*,max_output_tokens=512,timeout=90):
        super().__init__(model=MODEL,max_output_tokens=max_output_tokens,timeout=timeout)

    def request(self,history,tools,instructions):
        payload={'model':MODEL,'input':history,'instructions':instructions,'tools':tools,
                 'parallel_tool_calls':False,'max_output_tokens':self.max_output_tokens,
                 'reasoning':{'effort':'none'},'store':False}
        headers={'Content-Type':'application/json'}
        if self.key:headers['Authorization']='Bearer '+self.key
        start=time.monotonic();record={'requested_model':MODEL,'reasoning_effort':'none',
            'request_sha256':hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()}
        try:
            req=urllib.request.Request(self.endpoint,json.dumps(payload).encode(),headers,method='POST')
            with urllib.request.urlopen(req,timeout=self.timeout) as response:
                data=json.load(response);record['http_status']=response.status
            record.update(returned_model=data.get('model'),response_status=data.get('status'),usage=data.get('usage'))
            if data.get('error'):raise TransportError('Provider response error')
            return data
        except urllib.error.HTTPError as exc:
            record.update(http_status=exc.code,error='HTTPError')
            raise TransportError('Grounding inference HTTP '+str(exc.code)) from None
        except (OSError,ValueError) as exc:
            record['error']=type(exc).__name__
            raise TransportError('Grounding transport '+type(exc).__name__) from None
        finally:
            record['elapsed_s']=time.monotonic()-start;self.calls.append(record)

    def metadata(self):
        return {**super().metadata(),'reasoning_effort':'none','automatic_retries':0,
                'price_basis':'Official standard list-price estimate only; provider invoice unknown'}
