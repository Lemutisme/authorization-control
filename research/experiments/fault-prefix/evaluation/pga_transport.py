"""Small Responses transport. Never writes credentials or provider URLs to results."""
from __future__ import annotations
import hashlib
import json
import os
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path

class TransportError(RuntimeError):
    pass

class ResponsesTransport:
    def __init__(self, *, model=None, max_output_tokens=1400, timeout=90):
        self.endpoint=os.environ.get('PGA_API_BASE_URL')
        self.key=os.environ.get('PGA_API_KEY')
        self.model=model or os.environ.get('PGA_MODEL')
        self.config_hash=None
        if not self.endpoint:
            path=Path(os.environ['PGA_CODEX_CONFIG']) if os.environ.get('PGA_CODEX_CONFIG') else Path.home()/'.codex'/'config.toml'
            raw=path.read_bytes(); cfg=tomllib.loads(raw.decode())
            p=cfg['model_providers'][cfg['model_provider']]
            if p.get('wire_api')!='responses':
                raise ValueError('Configured provider is not a Responses interface')
            self.endpoint=p['base_url']; self.model=self.model or cfg['model']
            if p.get('env_key'): self.key=self.key or os.environ.get(p['env_key'])
            self.config_hash=hashlib.sha256(raw).hexdigest()
        if not self.model: raise ValueError('PGA_MODEL is required with PGA_API_BASE_URL')
        self.endpoint=self.endpoint.rstrip('/')+'/responses'
        self.max_output_tokens=max_output_tokens; self.timeout=timeout
        self.calls=[]

    def request(self, history, tools, instructions):
        data={'model':self.model,'input':history,'instructions':instructions,
              'tools':tools,'parallel_tool_calls':False,'max_output_tokens':self.max_output_tokens,
              'store':False}
        headers={'Content-Type':'application/json'}
        if self.key: headers['Authorization']='Bearer '+self.key
        t=time.monotonic(); rec={'requested_model':self.model,'request_sha256':hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()}
        try:
            req=urllib.request.Request(self.endpoint,data=json.dumps(data).encode(),headers=headers,method='POST')
            with urllib.request.urlopen(req,timeout=self.timeout) as f:
                result=json.loads(f.read()); rec['http_status']=f.status
            rec.update(returned_model=result.get('model'),response_status=result.get('status'),usage=result.get('usage'))
            if result.get('error'): raise TransportError('Provider response error')
            return result
        except urllib.error.HTTPError as e:
            rec.update(http_status=e.code,error='HTTPError')
            raise TransportError(f'Inference HTTP {e.code}') from None
        except (OSError,ValueError) as e:
            rec['error']=type(e).__name__
            raise TransportError('Inference transport '+type(e).__name__) from None
        finally:
            rec['elapsed_s']=time.monotonic()-t;self.calls.append(rec)

    def metadata(self):
        return {'requested_model':self.model,'provider_config_sha256':self.config_hash,
                'wire_api':'responses','max_output_tokens':self.max_output_tokens,
                'timeout_s':self.timeout,'temperature':'provider default','seed':'not supplied',
                'cache':'no client response cache; provider cached-token usage retained',
                'model_snapshot_limit':'provider returns a model alias; immutable weights revision not available'}
