"""Explicit four-model Canopy client; no model fallback or inference on import.

The shared account+endpoint limiter is identical in scope to the ongoing
DeepSeek study. Model-specific thinking controls are explicit configurations,
not an assertion that Canopy has already honored them.
"""
from __future__ import annotations
import copy
import hashlib
import json
import re
import time
import urllib.error
import urllib.request
try:
    from .common import NoRedirect, digest, load_key
    from .throttle import SharedThrottle, safe_rate_headers
except ImportError:
    from common import NoRedirect, digest, load_key
    from throttle import SharedThrottle, safe_rate_headers

ENDPOINT = 'https://inference.canopywave.io/v1/chat/completions'
MODEL_MODES = {
    'zai/glm-5.3-flash': {'default', 'low', 'high', 'max'},
    'minimax/minimax-m3.1-flash': {'default', 'low', 'medium', 'high', 'xhigh', 'max'},
    'xiaomimimo/mimo-v2.6-flash': {'default'},
    'qwen/qwen3.8-flash-next': {'default', 'low', 'medium', 'xhigh', 'off', 'off_top_level'},
}


def capture_headers(headers):
    result = safe_rate_headers(headers or {})
    for name, value in (headers or {}).items():
        if str(name).lower() == 'date':
            result['date'] = str(value)[:1024]
    return result


def reasoning_fields(model, mode):
    if model not in MODEL_MODES:
        raise ValueError('Unregistered model ID; no alias substitution or fallback')
    if mode not in MODEL_MODES[model]:
        raise ValueError('Reasoning mode not supported by the inspected model-specific evidence')
    if mode == 'default':
        return {}
    if mode == 'off':
        return {'chat_template_kwargs': {'enable_thinking': False}}
    if mode == 'off_top_level':
        # Qwen's official model card documents this interface for Qwen Cloud.
        # Canopy support is a separate, prospectively registered qualification.
        return {'enable_thinking': False}
    return {'reasoning_effort': mode}


def text_content(content):
    if content is None:
        return ''
    if isinstance(content, str):
        return content
    if not isinstance(content, list) or any(x.get('type') != 'text' for x in content):
        raise ValueError('This frozen study accepts text content only')
    return '\n'.join(x.get('text', '') for x in content)


def from_pi_context(context, *, model, reasoning_mode='default', max_tokens=1400, temperature=0.7):
    fields = reasoning_fields(model, reasoning_mode)
    if temperature is None:
        temperature = 0.7
    messages, mapping = [], {}

    def tool_id(value):
        if value not in mapping:
            plain = value.split('|', 1)[0]
            mapping[value] = plain if re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', plain or '') else 'call_'+hashlib.sha256(value.encode()).hexdigest()[:32]
        return mapping[value]

    if context.get('systemPrompt'):
        messages.append({'role': 'system', 'content': context['systemPrompt']})
    for message in context.get('messages', []):
        role = message['role']
        if role == 'user':
            messages.append({'role': 'user', 'content': text_content(message.get('content'))})
        elif role == 'assistant':
            content = message.get('content', [])
            if isinstance(content, str):
                content = [{'type': 'text', 'text': content}]
            texts, calls = [], []
            for block in content:
                if block.get('type') == 'text':
                    texts.append(block.get('text', ''))
                elif block.get('type') == 'toolCall':
                    calls.append({'id': tool_id(block['id']), 'type': 'function', 'function': {
                        'name': block['name'], 'arguments': json.dumps(block['arguments'], ensure_ascii=False, separators=(',', ':'))}})
                else:
                    raise ValueError('Unsupported historical assistant block; no silent reasoning loss')
            converted = {'role': 'assistant', 'content': '\n'.join(texts) or None}
            if calls:
                converted['tool_calls'] = calls
            native_fields = message.get('_native_canopy_reasoning_fields', {})
            if native_fields:
                if message.get('provider') != 'canopywave' or message.get('model') != model:
                    raise ValueError('Native reasoning fields cannot be replayed across model identities')
                converted.update(copy.deepcopy(native_fields))
            messages.append(converted)
        elif role in {'toolResult', 'tool'}:
            ident = message.get('toolCallId') or message.get('tool_call_id')
            if not ident:
                raise ValueError('Tool result is missing its call ID')
            messages.append({'role': 'tool', 'tool_call_id': tool_id(ident), 'content': text_content(message.get('content'))})
        else:
            raise ValueError('Unsupported portable message role: '+role)
    tools = [{'type': 'function', 'function': {'name': t['name'], 'description': t.get('description', ''),
                                             'parameters': copy.deepcopy(t.get('parameters', t.get('input_schema')))}} for t in context.get('tools', [])]
    if any(not isinstance(t['function']['parameters'], dict) for t in tools):
        raise ValueError('Every tool must retain its object JSON Schema')
    payload = {'model': model, 'messages': messages, 'max_tokens': max_tokens,
               'temperature': temperature, 'stream': False, **fields}
    if tools:
        payload.update(tools=tools, tool_choice='auto', parallel_tool_calls=False)
    return payload, {'conversion': 'pi-to-canopy-flash-v1', 'source_context_sha256': digest(context),
                     'tool_call_id_map': {k: v for k, v in mapping.items() if k != v}, 'tool_schemas_changed': False,
                     'requested_reasoning_mode': reasoning_mode, 'requested_reasoning_fields': fields,
                     'control_qualification': 'Not asserted by converter; consult registered qualification and observed reasoning fields',
                     'tool_error_bit': 'Not separately represented in Chat API; exact tool/refusal text preserved'}


def as_pi_message(response):
    choices = response.get('choices') or []
    if len(choices) != 1:
        raise ValueError('Expected one completion choice')
    choice = choices[0]
    raw = choice['message']
    content = []
    if raw.get('content'):
        if not isinstance(raw['content'], str):
            raise ValueError('Unexpected non-text assistant content')
        content.append({'type': 'text', 'text': raw['content']})
    for call in raw.get('tool_calls', []):
        f = call['function']
        args = f.get('arguments', '{}')
        args = json.loads(args) if isinstance(args, str) else args
        content.append({'type': 'toolCall', 'id': call['id'], 'name': f['name'], 'arguments': args})
    usage = response.get('usage') or {}
    finish = choice.get('finish_reason')
    msg = {'role': 'assistant', 'content': content, 'api': 'openai-chat-completions', 'provider': 'canopywave',
           'model': response.get('model'), 'stopReason': {'stop': 'stop', 'tool_calls': 'toolUse', 'length': 'length'}.get(finish, finish),
           'native_stop_reason': finish, 'responseId': response.get('id'), 'timestamp': int(time.time()*1000),
           'usage': {'input': usage.get('prompt_tokens', 0), 'output': usage.get('completion_tokens', 0),
                     'cacheRead': (usage.get('prompt_tokens_details') or {}).get('cached_tokens', usage.get('prompt_cache_hit_tokens', 0)),
                     'cacheWrite': 0, 'totalTokens': usage.get('total_tokens', usage.get('prompt_tokens', 0)+usage.get('completion_tokens', 0))}}
    native = {k: copy.deepcopy(raw[k]) for k in ['reasoning_content', 'reasoning_details', 'reasoning'] if k in raw}
    if native:
        msg['_native_canopy_reasoning_fields'] = native
    return msg


class CanopyClient:
    def __init__(self, model, *, reasoning_mode='default', allow_network=False, timeout=120.0):
        reasoning_fields(model, reasoning_mode)
        self.model, self.reasoning_mode = model, reasoning_mode
        self.allow_network, self.timeout = allow_network, timeout
        self._key = load_key()
        self._opener = urllib.request.build_opener(NoRedirect)
        self._throttle = SharedThrottle(ENDPOINT, self._key, interval_s=21, cooldown_s=60)

    def _redact(self, value):
        if isinstance(value, str):
            return value.replace(self._key, '[REDACTED_TRANSPORT_CREDENTIAL]')
        if isinstance(value, list):
            return [self._redact(x) for x in value]
        if isinstance(value, dict):
            return {k: self._redact(v) for k, v in value.items()}
        return value

    def metadata(self):
        return {'requested_model': self.model, 'endpoint': ENDPOINT, 'api': 'openai-chat-completions',
                'requested_reasoning_mode': self.reasoning_mode,
                'reasoning_fields': reasoning_fields(self.model, self.reasoning_mode),
                'automatic_retries': 0, 'timeout_s': self.timeout,
                'throttle': {'shared_across_models': True, 'serial_one_inflight': True, 'interval_after_completion_s': 21,
                             'minimum_429_cooldown_s': 60, 'scope': 'same study/account/endpoint as ongoing DeepSeek'},
                'identity_limit': 'Requested and returned alias only; no immutable weights, license, or architecture attestation'}

    def complete(self, payload, *, conversion=None):
        if not self.allow_network:
            raise RuntimeError('Inference disabled until root registers the live experiment')
        request = copy.deepcopy(payload)
        if request.get('model') != self.model:
            raise ValueError('Payload model differs from pinned client; no fallback')
        if request.get('stream') not in [None, False]:
            raise ValueError('Only non-streamed complete responses supported')
        request['stream'] = False
        req = urllib.request.Request(ENDPOINT, data=json.dumps(request, ensure_ascii=False).encode(),
                                     headers={'Content-Type': 'application/json', 'Authorization': 'Bearer '+self._key}, method='POST')
        result = {'provider': self.metadata(), 'request': request, 'request_sha256': digest(request), 'conversion': conversion,
                  'network_requests': 0, 'attempts': 0, 'response': None, 'ok': False, 'error': None}
        began, lease = time.monotonic(), None
        try:
            lease = self._throttle.acquire()
            result['throttle'] = lease.metadata
            result['throttle']['shared_attempt_sequence'] = lease.state['total_attempts']
            result.update(network_requests=1, attempts=1, request_started_epoch=time.time())
            with self._opener.open(req, timeout=self.timeout) as response:
                result['http_status'] = response.status
                result['rate_limit_headers'] = capture_headers(response.headers)
                raw = json.loads(response.read())
            result['response_received_epoch'] = time.time()
            result['response'] = raw
            if raw.get('error'):
                result['error'] = {'class': 'provider_error', 'detail': raw['error']}
            else:
                msg = as_pi_message(raw)
                usage = raw.get('usage') or {}
                result.update(returned_model=raw.get('model'), model_label_matches=raw.get('model') == self.model,
                              usage=usage, stop_reason=msg['native_stop_reason'], message=msg,
                              text=''.join(x['text'] for x in msg['content'] if x['type'] == 'text'),
                              tool_calls=[{'id': x['id'], 'name': x['name'], 'arguments': x['arguments'], 'input': x['arguments']} for x in msg['content'] if x['type'] == 'toolCall'],
                              reasoning_metadata={'requested_mode': self.reasoning_mode,
                                                  'returned_fields': list(msg.get('_native_canopy_reasoning_fields', {})),
                                                  'nonempty_native_reasoning': any(bool(v) for v in msg.get('_native_canopy_reasoning_fields', {}).values()),
                                                  'reported_reasoning_tokens': (usage.get('completion_tokens_details') or {}).get('reasoning_tokens'),
                                                  'reported_thinking_tokens': (usage.get('output_tokens_details') or {}).get('thinking_tokens')}, ok=True)
        except urllib.error.HTTPError as exc:
            result.update(http_status=exc.code, response_received_epoch=time.time(), rate_limit_headers=capture_headers(exc.headers or {}))
            try:
                detail = json.loads(exc.read())
            except Exception:
                detail = {'body': 'unparsed provider error omitted'}
            result['error'] = {'class': 'HTTPError', 'detail': detail}
        except Exception as exc:
            result['error'] = {'class': type(exc).__name__}
        finally:
            if lease:
                lease.finish(result.get('http_status'), result.get('rate_limit_headers', {}))
        result['elapsed_s'] = time.monotonic()-began
        return self._redact(result)

    def complete_pi(self, context, **kwargs):
        payload, conversion = from_pi_context(context, model=self.model, reasoning_mode=self.reasoning_mode, **kwargs)
        return self.complete(payload, conversion=conversion)
