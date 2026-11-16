"""Explicit two-model Lumen client; no model fallback or inference on import.

The Lumen account+endpoint limiter and halt marker are independent of all
Canopy jobs. Model-specific thinking controls are explicit configurations,
not an assertion that Lumen has already honored them.
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
    from .throttle import SharedThrottle, TerminalQuotaHalt, safe_rate_headers
except ImportError:
    from common import NoRedirect, digest, load_key
    from throttle import SharedThrottle, TerminalQuotaHalt, safe_rate_headers

ENDPOINT = 'https://lumen.ncsa.illinois.edu/v1/chat/completions'
MODEL_MODES = {
    'qwen3.8-flash': {'default', 'off', 'off_top_level', 'low', 'medium', 'xhigh'},
    'glm-5.3': {'default', 'low', 'high', 'max'},
}


def capture_headers(headers):
    result = safe_rate_headers(headers or {})
    for name, value in (headers or {}).items():
        if str(name).lower() == 'date':
            result['date'] = str(value)[:1024]
    return result


def provider_error_code(detail):
    if not isinstance(detail, dict):
        return None
    inner = detail.get('error', detail)
    return inner.get('code') if isinstance(inner, dict) else detail.get('code')


def reasoning_observation(response):
    """Retain reported counter locations; absence is unknown, not zero."""
    usage = response.get('usage') or {}
    paths = [
        ('usage.reasoning_tokens', usage, 'reasoning_tokens'),
        ('usage.completion_tokens_details.reasoning_tokens', usage.get('completion_tokens_details') or {}, 'reasoning_tokens'),
        ('usage.output_tokens_details.reasoning_tokens', usage.get('output_tokens_details') or {}, 'reasoning_tokens'),
        ('usage.output_tokens_details.thinking_tokens', usage.get('output_tokens_details') or {}, 'thinking_tokens'),
    ]
    sources = {path: obj[key] for path, obj, key in paths if isinstance(obj, dict) and key in obj}
    valid = {path: value for path, value in sources.items() if isinstance(value, int) and not isinstance(value, bool) and value >= 0}
    invalid = {path: value for path, value in sources.items() if value is not None and path not in valid}
    distinct = set(valid.values())
    conflict = len(distinct) > 1
    value = next(iter(distinct)) if len(distinct) == 1 and not invalid else None
    status = 'conflicting' if conflict else 'invalid' if invalid else 'reported' if valid else 'missing'
    return {'reported_reasoning_tokens': value,
            'reported_thinking_tokens': (usage.get('output_tokens_details') or {}).get('thinking_tokens'),
            'reasoning_token_sources': sources,
            'reasoning_token_conflict': conflict,
            'reasoning_counter_status': status,
            'invalid_reasoning_counter_sources': invalid}


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
        # Lumen support is a separate, prospectively registered qualification.
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
            native_fields = message.get('_native_lumen_reasoning_fields', {})
            if native_fields:
                if message.get('provider') != 'lumen' or message.get('model') != model:
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
    return payload, {'conversion': 'pi-to-lumen-v1', 'source_context_sha256': digest(context),
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
    raw_calls = raw.get('tool_calls')
    if raw_calls is None:
        raw_calls = []
    if not isinstance(raw_calls, list):
        raise ValueError('tool_calls must be a list or null')
    for call in raw_calls:
        if not isinstance(call, dict) or not isinstance(call.get('function'), dict):
            raise ValueError('Each tool call must contain a function object')
        f = call['function']
        args = f.get('arguments', '{}')
        args = json.loads(args) if isinstance(args, str) else args
        content.append({'type': 'toolCall', 'id': call['id'], 'name': f['name'], 'arguments': args})
    usage = response.get('usage') or {}
    finish = choice.get('finish_reason')
    msg = {'role': 'assistant', 'content': content, 'api': 'openai-chat-completions', 'provider': 'lumen',
           'model': response.get('model'), 'stopReason': {'stop': 'stop', 'tool_calls': 'toolUse', 'length': 'length'}.get(finish, finish),
           'native_stop_reason': finish, 'responseId': response.get('id'), 'timestamp': int(time.time()*1000),
           'usage': {'input': usage.get('prompt_tokens', 0), 'output': usage.get('completion_tokens', 0),
                     'cacheRead': (usage.get('prompt_tokens_details') or {}).get('cached_tokens', usage.get('prompt_cache_hit_tokens', 0)),
                     'cacheWrite': 0, 'totalTokens': usage.get('total_tokens', usage.get('prompt_tokens', 0)+usage.get('completion_tokens', 0))}}
    native = {k: copy.deepcopy(raw[k]) for k in ['reasoning_content', 'reasoning_details', 'reasoning'] if k in raw}
    if native:
        msg['_native_lumen_reasoning_fields'] = native
    return msg


class LumenClient:
    def __init__(self, model, *, reasoning_mode='default', allow_network=False, timeout=120.0):
        reasoning_fields(model, reasoning_mode)
        self.model, self.reasoning_mode = model, reasoning_mode
        self.allow_network, self.timeout = allow_network, timeout
        self._key = load_key()
        self._opener = urllib.request.build_opener(NoRedirect)
        self._throttle = SharedThrottle(ENDPOINT, self._key, interval_s=2.1, cooldown_s=60)

    def _redact(self, value):
        if isinstance(value, str):
            return value.replace(self._key, '[REDACTED_TRANSPORT_CREDENTIAL]')
        if isinstance(value, list):
            return [self._redact(x) for x in value]
        if isinstance(value, dict):
            return {k: self._redact(v) for k, v in value.items()}
        return value

    def _parse_failure_body(self, body):
        text = body.decode('utf-8', errors='replace').replace(self._key, '[REDACTED_TRANSPORT_CREDENTIAL]')
        # Retain diagnostic prose, but not credential-shaped transport headers
        # that a gateway error page might echo from its own upstream request.
        text = re.sub(r'(?i)(authorization[\"\s]*[:=][\"\s]*(?:bearer|basic)\s+)[^\s,\"\x27<>]+', r'\1[REDACTED]', text)
        text = re.sub(r'(?i)((?:x-api-key|api_key|access_token|auth_token)[\"\x27\s]*[:=][\"\x27\s]*)[^\s,\"\x27<>}]+', r'\1[REDACTED]', text)
        safe_bytes = text.encode('utf-8')
        retained = safe_bytes[:65536]
        return {'response_text_on_parse_failure': retained.decode('utf-8', errors='replace'),
                'response_text_truncated': len(safe_bytes) > 65536,
                'response_text_retained_bytes': len(retained),
                'response_body_bytes': len(body),
                'response_body_sha256': hashlib.sha256(body).hexdigest()}

    def metadata(self):
        return {'requested_model': self.model, 'endpoint': ENDPOINT, 'api': 'openai-chat-completions',
                'requested_reasoning_mode': self.reasoning_mode,
                'reasoning_fields': reasoning_fields(self.model, self.reasoning_mode),
                'automatic_retries': 0, 'timeout_s': self.timeout,
                'throttle': {'shared_across_models': True, 'serial_one_inflight': True, 'interval_after_completion_s': 2.1,
                             'minimum_429_cooldown_s': 60, 'scope': 'independent Lumen account+endpoint; no Canopy state or lock'},
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
                  'network_requests': 0, 'attempts': 0, 'response': None, 'ok': False, 'error': None,
                  'terminal_provider_halt': False}
        began, lease = time.monotonic(), None
        error_code = None
        try:
            lease = self._throttle.acquire()
            result['throttle'] = lease.metadata
            result['throttle']['shared_attempt_sequence'] = lease.state['total_attempts']
            result.update(network_requests=1, attempts=1, request_started_epoch=time.time())
            with self._opener.open(req, timeout=self.timeout) as response:
                result['http_status'] = response.status
                result['rate_limit_headers'] = capture_headers(response.headers)
                body = response.read()
                try:
                    raw = json.loads(body)
                except (json.JSONDecodeError, UnicodeDecodeError):
                    result.update(self._parse_failure_body(body))
                    raise
            result['response_received_epoch'] = time.time()
            result['response'] = raw
            if raw.get('error'):
                error_code = provider_error_code(raw)
                result['error'] = {'class': 'provider_error', 'code': error_code, 'detail': raw['error']}
            else:
                msg = as_pi_message(raw)
                usage = raw.get('usage') or {}
                result.update(returned_model=raw.get('model'), model_label_matches=raw.get('model') == self.model,
                              usage=usage, stop_reason=msg['native_stop_reason'], message=msg,
                              text=''.join(x['text'] for x in msg['content'] if x['type'] == 'text'),
                              tool_calls=[{'id': x['id'], 'name': x['name'], 'arguments': x['arguments'], 'input': x['arguments']} for x in msg['content'] if x['type'] == 'toolCall'],
                              reasoning_metadata={'requested_mode': self.reasoning_mode,
                                                  'returned_fields': list(msg.get('_native_lumen_reasoning_fields', {})),
                                                  'nonempty_native_reasoning': any(bool(v) for v in msg.get('_native_lumen_reasoning_fields', {}).values()),
                                                  **reasoning_observation(raw)}, ok=True)
        except TerminalQuotaHalt as exc:
            error_code = 'insufficient_quota'
            result['terminal_provider_halt'] = True
            result['error'] = {'class': 'TerminalQuotaHalt', 'code': error_code, 'detail': exc.record}
        except urllib.error.HTTPError as exc:
            result.update(http_status=exc.code, response_received_epoch=time.time(), rate_limit_headers=capture_headers(exc.headers or {}))
            body = exc.read()
            try:
                detail = json.loads(body)
            except Exception:
                result.update(self._parse_failure_body(body))
                detail = {'body': 'Non-JSON provider error retained in response_text_on_parse_failure'}
            error_code = provider_error_code(detail)
            result['error'] = {'class': 'HTTPError', 'code': error_code, 'detail': detail}
        except Exception as exc:
            result['error'] = {'class': type(exc).__name__}
        finally:
            if error_code == 'insufficient_quota':
                result['terminal_provider_halt'] = True
            if lease:
                lease.finish(result.get('http_status'), result.get('rate_limit_headers', {}), error_code=error_code)
        result['elapsed_s'] = time.monotonic()-began
        return self._redact(result)

    def complete_pi(self, context, **kwargs):
        payload, conversion = from_pi_context(context, model=self.model, reasoning_mode=self.reasoning_mode, **kwargs)
        return self.complete(payload, conversion=conversion)
