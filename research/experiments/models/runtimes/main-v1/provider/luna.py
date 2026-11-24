"""Native Luna Responses calls with official Pi 1.5 transcript conversion.

No inference on import or conversion. The explicit network guard and credential
handling match the Haiku adapter. The same caller can use complete_pi on either.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import subprocess
import time
import tomllib
import urllib.error
import urllib.request
from pathlib import Path
try:
    from .haiku import _NoRedirect, digest
except ImportError:
    from haiku import _NoRedirect, digest

MODEL = 'gpt-6-luna'
HERE = Path(__file__).resolve().parent


def from_pi_context(context: dict, *, max_tokens: int = 1400,
                    temperature: float | None = None) -> tuple[dict, dict]:
    data = {'context': context, 'max_tokens': max_tokens, 'temperature': temperature}
    process = subprocess.run([os.environ.get('HAIKU_STUDY_NODE', 'node'), str(HERE / 'convert_luna.mjs')],
                             input=json.dumps(data), text=True, capture_output=True, check=False)
    if process.returncode:
        raise RuntimeError('Offline Pi Responses conversion failed')
    converted = json.loads(process.stdout)
    converted['conversion']['source_context_sha256'] = digest(context)
    return converted['payload'], converted['conversion']


def as_pi_message(response: dict) -> dict:
    content = []
    for item in response.get('output', []):
        if item.get('type') == 'message':
            for block in item.get('content', []):
                if block.get('type') == 'output_text':
                    content.append({'type': 'text', 'text': block['text'],
                                    'textSignature': json.dumps({'v': 1, 'id': item.get('id'), 'phase': item.get('phase')})})
                elif block.get('type') == 'refusal':
                    content.append({'type': 'text', 'text': block.get('refusal', '')})
                else:
                    raise ValueError('Unexpected Responses message block')
        elif item.get('type') == 'function_call':
            args = item['arguments']
            if isinstance(args, str):
                args = json.loads(args)
            ident = item['call_id'] + ('|' + item['id'] if item.get('id') else '')
            content.append({'type': 'toolCall', 'id': ident, 'name': item['name'], 'arguments': args})
        elif item.get('type') == 'reasoning':
            # Retain opaque provider continuity if unexpectedly returned despite
            # none reasoning; a cross-provider transfer must explicitly reject it.
            text = ''.join(b.get('text', '') for b in item.get('summary', []))
            content.append({'type': 'thinking', 'thinking': text, 'thinkingSignature': json.dumps(item)})
        else:
            raise ValueError('Unexpected Responses output item')
    usage = response.get('usage') or {}
    status = response.get('status')
    reason = 'length' if status == 'incomplete' else 'toolUse' if any(b['type'] == 'toolCall' for b in content) else 'stop'
    return {'role': 'assistant', 'content': content, 'api': 'openai-responses',
            'provider': 'openai', 'model': response.get('model'),
            'stopReason': reason, 'native_stop_reason': status, 'responseId': response.get('id'),
            'timestamp': int(time.time() * 1000),
            'usage': {'input': usage.get('input_tokens', 0), 'output': usage.get('output_tokens', 0),
                      'cacheRead': (usage.get('input_tokens_details') or {}).get('cached_tokens', 0),
                      'cacheWrite': 0, 'totalTokens': usage.get('total_tokens', usage.get('input_tokens', 0) + usage.get('output_tokens', 0))}}


class LunaClient:
    def __init__(self, *, model: str = MODEL, allow_network: bool = False, timeout: float = 120.0):
        if model != MODEL:
            raise ValueError('Luna reference has a fixed requested model')
        self.model, self.allow_network, self.timeout = model, allow_network, timeout
        endpoint, key = os.environ.get('PGA_API_BASE_URL'), os.environ.get('PGA_API_KEY')
        self.config_hash = None
        if not endpoint:
            path = Path(os.environ.get('PGA_CODEX_CONFIG', str(Path.home() / '.codex/config.toml')))
            raw = path.read_bytes()
            config = tomllib.loads(raw.decode())
            provider = config['model_providers'][config['model_provider']]
            if provider.get('wire_api') != 'responses':
                raise ValueError('Configured Luna provider is not a Responses endpoint')
            endpoint = provider['base_url']
            if provider.get('env_key'):
                key = key or os.environ.get(provider['env_key'])
            self.config_hash = hashlib.sha256(raw).hexdigest()
        self.endpoint = endpoint.rstrip('/') + '/responses'
        self._key = key
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _redact(self, value):
        if isinstance(value, str):
            return value.replace(self._key, '[REDACTED_TRANSPORT_CREDENTIAL]') if self._key else value
        if isinstance(value, list):
            return [self._redact(v) for v in value]
        if isinstance(value, dict):
            return {k: self._redact(v) for k, v in value.items()}
        return value

    def metadata(self):
        return {'requested_model': MODEL, 'api': 'openai-responses',
                'endpoint_sha256': hashlib.sha256(self.endpoint.encode()).hexdigest(),
                'provider_config_sha256': self.config_hash, 'automatic_retries': 0,
                'timeout_s': self.timeout, 'reasoning_effort': 'none',
                'identity_limit': 'Requested and returned labels, not immutable weights identity'}

    def complete(self, payload: dict, *, conversion: dict | None = None) -> dict:
        if not self.allow_network:
            raise RuntimeError('Inference disabled until registered live call')
        request = copy.deepcopy(payload)
        if request.get('model') != MODEL:
            raise ValueError('Payload model differs from fixed Luna reference')
        if request.get('stream') not in [None, False]:
            raise ValueError('This adapter records complete non-streamed responses')
        request['stream'] = False
        headers = {'Content-Type': 'application/json'}
        if self._key:
            headers['Authorization'] = 'Bearer ' + self._key
        req = urllib.request.Request(self.endpoint, data=json.dumps(request).encode(), headers=headers, method='POST')
        result = {'provider': self.metadata(), 'request': request, 'request_sha256': digest(request),
                  'conversion': conversion, 'network_requests': 1, 'attempts': 1,
                  'response': None, 'ok': False, 'error': None}
        began = time.monotonic()
        try:
            with self._opener.open(req, timeout=self.timeout) as response:
                result['http_status'] = response.status
                raw = json.loads(response.read())
            result['response'] = raw
            if raw.get('error') or raw.get('status') in {'failed', 'cancelled'}:
                result['error'] = {'class': 'provider_error', 'detail': raw.get('error')}
            else:
                normalized = as_pi_message(raw)
                result.update(returned_model=raw.get('model'), model_label_matches=raw.get('model') == MODEL,
                              usage=raw.get('usage'), stop_reason=raw.get('status'), message=normalized,
                              text=''.join(b['text'] for b in normalized['content'] if b['type'] == 'text'),
                              tool_calls=[{'id': b['id'], 'name': b['name'], 'input': b['arguments'], 'arguments': b['arguments']} for b in normalized['content'] if b['type'] == 'toolCall'],
                              ok=True)
        except urllib.error.HTTPError as exc:
            result['http_status'] = exc.code
            try:
                detail = json.loads(exc.read())
            except Exception:
                detail = {'body': 'unparsed_provider_error_not_retained'}
            result['error'] = {'class': 'HTTPError', 'detail': detail}
        except Exception as exc:
            result['error'] = {'class': type(exc).__name__}
        result['elapsed_s'] = time.monotonic() - began
        return self._redact(result)

    def complete_pi(self, context: dict, **kwargs) -> dict:
        payload, metadata = from_pi_context(context, **kwargs)
        return self.complete(payload, conversion=metadata)


def make_client(model='haiku', *, allow_network=False, timeout=120.0):
    if model in {'luna', MODEL}:
        return LunaClient(allow_network=allow_network, timeout=timeout)
    if model in {'haiku', 'claude-haiku-5-5'}:
        try:
            from .haiku import AnthropicClient, DEFAULT_MODEL
        except ImportError:
            from haiku import AnthropicClient, DEFAULT_MODEL
        return AnthropicClient(model=DEFAULT_MODEL, allow_network=allow_network, timeout=timeout)
    if model in {'deepseek', 'deepseek/deepseek-v4.1-flash'}:
        try:
            from .deepseek import DeepSeekClient
        except ImportError:
            from deepseek import DeepSeekClient
        return DeepSeekClient(allow_network=allow_network, timeout=timeout)
    raise ValueError('Unregistered model; no fallback')
