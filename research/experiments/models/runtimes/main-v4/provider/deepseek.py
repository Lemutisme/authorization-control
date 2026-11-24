"""Fixed user-authorized Canopy Wave DeepSeek Chat Completions transport.

The key is read as a literal assignment, never by sourcing ~/.bashrc. It is used
only on the endpoint below. Redirects and implicit retries are disabled.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import re
import shlex
import time
import urllib.error
import urllib.request
from pathlib import Path
try:
    from .haiku import _NoRedirect, digest
    from .throttle import SharedThrottle, safe_rate_headers
except ImportError:
    from haiku import _NoRedirect, digest
    from throttle import SharedThrottle, safe_rate_headers

MODEL = 'deepseek/deepseek-v4.1-flash'
ENDPOINT = 'https://inference.canopywave.io/v1/chat/completions'
DEFAULT_TEMPERATURE = 0.7


def _load_key() -> str:
    if os.environ.get('canopy_wave_key'):
        return os.environ['canopy_wave_key']
    values = []
    for line in (Path.home() / '.bashrc').read_text().splitlines():
        if not re.match(r'^\s*(?:export\s+)?canopy_wave_key\s*=', line):
            continue
        parts = shlex.split(line.split('=', 1)[1], comments=True, posix=True)
        if len(parts) != 1 or not parts[0] or any(c in parts[0] for c in ['$', '`', ';']):
            raise RuntimeError('Canopy credential assignment is not a single literal; no shell evaluation permitted')
        values.append(parts[0])
    if len(values) != 1:
        raise RuntimeError('Expected exactly one literal Canopy credential assignment')
    return values[0]


def _text(content):
    if isinstance(content, str):
        return content
    if content is None:
        return ''
    if not isinstance(content, list) or any(b.get('type') != 'text' for b in content):
        raise ValueError('Only text blocks supported by this frozen cross-model context')
    return '\n'.join(b.get('text', '') for b in content)


def from_pi_context(context: dict, *, max_tokens: int = 1400,
                    temperature: float | None = DEFAULT_TEMPERATURE) -> tuple[dict, dict]:
    # None from the shared caller means this provider's registered 0.7, not an
    # omitted field. This provider-specific difference is explicit in metadata.
    if temperature is None:
        temperature = DEFAULT_TEMPERATURE
    messages, ids = [], {}

    def tool_id(value):
        if value not in ids:
            plain = value.split('|', 1)[0]
            ids[value] = plain if re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', plain or '') else 'call_' + hashlib.sha256(value.encode()).hexdigest()[:32]
        return ids[value]

    if context.get('systemPrompt'):
        messages.append({'role': 'system', 'content': context['systemPrompt']})
    for message in context.get('messages', []):
        role = message['role']
        if role == 'user':
            messages.append({'role': 'user', 'content': _text(message.get('content'))})
        elif role == 'assistant':
            content = message.get('content', [])
            if isinstance(content, str):
                content = [{'type': 'text', 'text': content}]
            texts, calls = [], []
            for block in content:
                if block.get('type') == 'text':
                    texts.append(block.get('text', ''))
                elif block.get('type') == 'toolCall':
                    calls.append({'id': tool_id(block['id']), 'type': 'function',
                                  'function': {'name': block['name'], 'arguments': json.dumps(block['arguments'], ensure_ascii=False, separators=(',', ':'))}})
                else:
                    raise ValueError('Unsupported historical assistant block: ' + str(block.get('type')))
            converted = {'role': 'assistant', 'content': '\n'.join(texts) or None}
            if calls:
                converted['tool_calls'] = calls
            if '_native_deepseek_reasoning_content' in message:
                # Returned same-provider reasoning is retained for continuity;
                # it is not shown as tool evidence or user-visible actor text.
                converted['reasoning_content'] = message['_native_deepseek_reasoning_content']
            messages.append(converted)
        elif role in {'toolResult', 'tool'}:
            ident = message.get('toolCallId') or message.get('tool_call_id')
            if not ident:
                raise ValueError('Tool result missing call ID')
            messages.append({'role': 'tool', 'tool_call_id': tool_id(ident),
                             'content': _text(message.get('content'))})
        else:
            raise ValueError('Unsupported role in portable context: ' + role)
    tools = [{'type': 'function', 'function': {'name': t['name'], 'description': t.get('description', ''),
                                            'parameters': copy.deepcopy(t.get('parameters', t.get('input_schema')))}} for t in context.get('tools', [])]
    payload = {'model': MODEL, 'messages': messages, 'max_tokens': max_tokens,
               'temperature': temperature, 'stream': False,
               'thinking': {'type': 'disabled'}}
    if tools:
        payload.update(tools=tools, tool_choice='auto', parallel_tool_calls=False)
    return payload, {'conversion': 'pi-to-openai-chat-v2-thinking-disabled', 'source_context_sha256': digest(context),
                     'tool_call_id_map': {k: v for k, v in ids.items() if k != v},
                     'tool_schemas_changed': False, 'temperature': temperature,
                     'reasoning_mode': 'requested disabled via top-level thinking.type; observed usage retained',
                     'tool_error_flag': 'Chat API has no separate error bit; exact tool text retained'}


def as_pi_message(response: dict) -> dict:
    choices = response.get('choices') or []
    if len(choices) != 1:
        raise ValueError('Expected exactly one Chat Completions choice')
    choice = choices[0]
    raw = choice['message']
    content = []
    if raw.get('content'):
        if not isinstance(raw['content'], str):
            raise ValueError('Unexpected nontext assistant content')
        content.append({'type': 'text', 'text': raw['content']})
    for call in raw.get('tool_calls', []):
        function = call['function']
        args = function.get('arguments', '{}')
        if isinstance(args, str):
            args = json.loads(args)
        content.append({'type': 'toolCall', 'id': call['id'], 'name': function['name'], 'arguments': args})
    finish = choice.get('finish_reason')
    usage = response.get('usage') or {}
    message = {'role': 'assistant', 'content': content, 'api': 'openai-chat-completions',
               'provider': 'canopywave', 'model': response.get('model'),
               'stopReason': {'stop': 'stop', 'tool_calls': 'toolUse', 'length': 'length'}.get(finish, finish),
               'native_stop_reason': finish, 'responseId': response.get('id'),
               'timestamp': int(time.time() * 1000),
               'usage': {'input': usage.get('prompt_tokens', 0), 'output': usage.get('completion_tokens', 0),
                         'cacheRead': (usage.get('prompt_tokens_details') or {}).get('cached_tokens', usage.get('prompt_cache_hit_tokens', 0)),
                         'cacheWrite': 0, 'totalTokens': usage.get('total_tokens', usage.get('prompt_tokens', 0) + usage.get('completion_tokens', 0))}}
    if 'reasoning_content' in raw:
        message['_native_deepseek_reasoning_content'] = raw['reasoning_content']
    return message


class DeepSeekClient:
    def __init__(self, *, model: str = MODEL, allow_network: bool = False, timeout: float = 120.0):
        if model != MODEL:
            raise ValueError('Unregistered DeepSeek model; no fallback')
        self.model, self.allow_network, self.timeout = model, allow_network, timeout
        self._key = _load_key()
        self._opener = urllib.request.build_opener(_NoRedirect)
        self._throttle = SharedThrottle(ENDPOINT, self._key)

    def _redact(self, value):
        if isinstance(value, str):
            return value.replace(self._key, '[REDACTED_TRANSPORT_CREDENTIAL]')
        if isinstance(value, list):
            return [self._redact(v) for v in value]
        if isinstance(value, dict):
            return {k: self._redact(v) for k, v in value.items()}
        return value

    def metadata(self):
        return {'requested_model': MODEL, 'api': 'openai-chat-completions', 'provider': 'canopywave',
                'endpoint': ENDPOINT, 'automatic_retries': 0, 'timeout_s': self.timeout,
                'temperature': DEFAULT_TEMPERATURE, 'reasoning_mode': 'requested disabled via thinking.type',
                'throttle': {'serial_one_inflight': True, 'interval_after_completion_s': 21.0,
                             'minimum_429_cooldown_s': 60.0, 'scope': 'study/account/endpoint'},
                'identity_limit': 'Provider returned label, not immutable weights attestation'}

    def complete(self, payload: dict, *, conversion: dict | None = None) -> dict:
        if not self.allow_network:
            raise RuntimeError('Inference disabled until registered live call')
        request = copy.deepcopy(payload)
        if request.get('model') != MODEL:
            raise ValueError('Payload model differs from registered DeepSeek model')
        if request.get('stream') not in [None, False]:
            raise ValueError('Complete non-streamed responses required')
        request['stream'] = False
        req = urllib.request.Request(ENDPOINT, data=json.dumps(request, ensure_ascii=False).encode(),
                                     headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + self._key}, method='POST')
        result = {'provider': self.metadata(), 'request': request, 'request_sha256': digest(request),
                  'conversion': conversion, 'network_requests': 0, 'attempts': 0,
                  'response': None, 'ok': False, 'error': None}
        began = time.monotonic()
        lease = None
        try:
            lease = self._throttle.acquire()
            result['throttle'] = lease.metadata
            result['network_requests'] = 1
            result['attempts'] = 1
            with self._opener.open(req, timeout=self.timeout) as response:
                result['http_status'] = response.status
                result['rate_limit_headers'] = safe_rate_headers(response.headers)
                raw = json.loads(response.read())
            result['response'] = raw
            if raw.get('error'):
                result['error'] = {'class': 'provider_error', 'detail': raw.get('error')}
            else:
                normalized = as_pi_message(raw)
                result.update(returned_model=raw.get('model'), model_label_matches=raw.get('model') == MODEL,
                              usage=raw.get('usage'), stop_reason=normalized['native_stop_reason'], message=normalized,
                              text=''.join(b['text'] for b in normalized['content'] if b['type'] == 'text'),
                              tool_calls=[{'id': b['id'], 'name': b['name'], 'input': b['arguments'], 'arguments': b['arguments']} for b in normalized['content'] if b['type'] == 'toolCall'],
                              reasoning_metadata={'requested_mode': request.get('thinking'),
                                                  'returned_reasoning_content_present': bool(normalized.get('_native_deepseek_reasoning_content')),
                                                  'reported_reasoning_tokens': ((raw.get('usage') or {}).get('completion_tokens_details') or {}).get('reasoning_tokens')}, ok=True)
        except urllib.error.HTTPError as exc:
            result['http_status'] = exc.code
            result['rate_limit_headers'] = safe_rate_headers(exc.headers)
            try:
                detail = json.loads(exc.read())
            except Exception:
                detail = {'body': 'unparsed_provider_error_not_retained'}
            result['error'] = {'class': 'HTTPError', 'detail': detail}
        except Exception as exc:
            result['error'] = {'class': type(exc).__name__}
        finally:
            if lease is not None:
                lease.finish(result.get('http_status'), result.get('rate_limit_headers', {}))
        result['elapsed_s'] = time.monotonic() - began
        return self._redact(result)

    def complete_pi(self, context: dict, **kwargs):
        payload, conversion = from_pi_context(context, **kwargs)
        return self.complete(payload, conversion=conversion)
