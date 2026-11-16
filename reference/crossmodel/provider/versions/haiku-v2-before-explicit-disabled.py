"""Minimal native Anthropic Messages adapter for the Haiku study.

No inference on import. Network inference requires allow_network=True (Python)
or --live (CLI), to be used only after the parent registers the experiment.
Credentials are read from the existing environment/Claude settings and never
written. Artifacts contain payloads and responses, not authentication headers.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_MODEL = 'claude-haiku-5-5'
API_VERSION = '2023-06-01'
SETTINGS_PATH = Path.home() / '.claude/settings.json'


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def _settings() -> dict:
    if not SETTINGS_PATH.exists():
        return {}
    value = json.loads(SETTINGS_PATH.read_text())
    return value.get('env', {})


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        # Do not forward credentials to a redirect target.
        return None


def _text_blocks(content: Any) -> list[dict]:
    if isinstance(content, str):
        return [{'type': 'text', 'text': content}] if content else []
    if content is None:
        return []
    blocks = []
    for block in content:
        kind = block.get('type')
        if kind == 'text':
            if block.get('text'):
                blocks.append({'type': 'text', 'text': block['text']})
        elif kind == 'image':
            raise ValueError('Image input is outside this text-only frozen study')
        else:
            raise ValueError('Unsupported text-content block: ' + str(kind))
    return blocks


def from_pi_context(context: dict, *, model: str = DEFAULT_MODEL,
                    max_tokens: int = 1400, temperature: float | None = None,
                    disable_parallel_tools: bool = True) -> tuple[dict, dict]:
    """Convert Pi messages, preserving tool semantics and recording ID changes.

    The model identity and transport differ deliberately. No actor/owner prompt,
    tool schema, tool output, or refusal text is changed. Historical tool IDs
    invalid under Anthropic's alphabet are mapped consistently to hash IDs.
    Unsupported reasoning/image blocks fail rather than disappear silently.
    """
    messages: list[dict] = []
    id_map: dict[str, str] = {}

    def tool_id(old: str) -> str:
        if old not in id_map:
            id_map[old] = old if re.fullmatch(r'[a-zA-Z0-9_-]{1,200}', old or '') else 'toolu_' + hashlib.sha256(old.encode()).hexdigest()[:32]
        return id_map[old]

    def append(role: str, blocks: list[dict]):
        if not blocks:
            raise ValueError('An empty message cannot be silently removed')
        if messages and messages[-1]['role'] == role:
            messages[-1]['content'].extend(blocks)
        else:
            messages.append({'role': role, 'content': blocks})

    for message in context.get('messages', []):
        role = message['role']
        if role == 'user':
            append('user', _text_blocks(message.get('content')))
        elif role == 'assistant':
            blocks = []
            content = message.get('content', [])
            if isinstance(content, str):
                content = [{'type': 'text', 'text': content}]
            for block in content:
                kind = block.get('type')
                if kind == 'text':
                    if block.get('text'):
                        blocks.append({'type': 'text', 'text': block['text']})
                elif kind == 'toolCall':
                    blocks.append({'type': 'tool_use', 'id': tool_id(block['id']),
                                   'name': block['name'], 'input': copy.deepcopy(block['arguments'])})
                else:
                    raise ValueError('Unsupported assistant block: ' + str(kind))
            append('assistant', blocks)
        elif role in {'toolResult', 'tool'}:
            old_id = message.get('toolCallId') or message.get('tool_call_id')
            if not old_id:
                raise ValueError('Tool result has no call ID')
            content = _text_blocks(message.get('content'))
            # Anthropic accepts an empty tool result; keep the empty result.
            append('user', [{'type': 'tool_result', 'tool_use_id': tool_id(old_id),
                             'content': content, 'is_error': bool(message.get('isError', message.get('is_error', False)))}])
        else:
            raise ValueError('Unsupported message role: ' + role)
    tools = [{'name': tool['name'], 'description': tool.get('description', ''),
              'input_schema': copy.deepcopy(tool.get('parameters', tool.get('input_schema')))}
             for tool in context.get('tools', [])]
    if any(not isinstance(tool['input_schema'], dict) for tool in tools):
        raise ValueError('Every tool needs its unchanged object JSON Schema')
    payload = {'model': model, 'max_tokens': max_tokens, 'messages': messages,
               'stream': False}
    if context.get('systemPrompt'):
        payload['system'] = context['systemPrompt']
    if temperature is not None:
        payload['temperature'] = temperature
    if tools:
        payload['tools'] = tools
        payload['tool_choice'] = {'type': 'auto', 'disable_parallel_tool_use': disable_parallel_tools}
    metadata = {'conversion': 'pi-to-anthropic-v1',
                'tool_call_id_map': {k: v for k, v in id_map.items() if k != v},
                'source_context_sha256': digest(context),
                'source_messages': len(context.get('messages', [])),
                'wire_messages': len(messages), 'tool_schemas_changed': False,
                'adjacent_same_role_messages_merged': True,
                'thinking': 'disabled by omission; no hidden-reasoning budget requested'}
    return payload, metadata


def as_pi_message(response: dict) -> dict:
    """Normalize the reply for a Pi-compatible actor continuation."""
    content = []
    for block in response.get('content', []):
        if block.get('type') == 'text':
            content.append({'type': 'text', 'text': block['text']})
        elif block.get('type') == 'tool_use':
            content.append({'type': 'toolCall', 'id': block['id'],
                            'name': block['name'], 'arguments': block['input']})
        else:
            raise ValueError('Unexpected response block: ' + str(block.get('type')))
    reason = response.get('stop_reason')
    usage = response.get('usage', {})
    return {'role': 'assistant', 'content': content, 'api': 'anthropic-messages',
            'provider': 'anthropic', 'model': response.get('model'),
            'stopReason': {'end_turn': 'stop', 'stop_sequence': 'stop',
                           'tool_use': 'toolUse', 'max_tokens': 'length'}.get(reason, reason),
            'native_stop_reason': reason, 'responseId': response.get('id'),
            'timestamp': int(time.time() * 1000),
            'usage': {'input': usage.get('input_tokens', 0),
                      'output': usage.get('output_tokens', 0),
                      'cacheRead': usage.get('cache_read_input_tokens', 0),
                      'cacheWrite': usage.get('cache_creation_input_tokens', 0),
                      'totalTokens': sum(usage.get(k, 0) for k in ['input_tokens', 'output_tokens', 'cache_read_input_tokens', 'cache_creation_input_tokens'])}}


class AnthropicClient:
    def __init__(self, *, model: str = DEFAULT_MODEL, allow_network: bool = False,
                 timeout: float = 120.0):
        settings = _settings()
        self.model = model
        self.allow_network = allow_network
        self.timeout = timeout
        self.base_url = os.environ.get('ANTHROPIC_BASE_URL') or settings.get('ANTHROPIC_BASE_URL') or 'https://api.anthropic.com'
        self.base_url = self.base_url.rstrip('/')
        self._token = os.environ.get('ANTHROPIC_AUTH_TOKEN') or settings.get('ANTHROPIC_AUTH_TOKEN')
        self._key = os.environ.get('ANTHROPIC_API_KEY') or settings.get('ANTHROPIC_API_KEY')
        if not self._token and not self._key:
            raise RuntimeError('No configured Anthropic authentication')
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _redact(self, value: Any) -> Any:
        if isinstance(value, str):
            for secret in [self._token, self._key]:
                if secret:
                    value = value.replace(secret, '[REDACTED_TRANSPORT_CREDENTIAL]')
            return value
        if isinstance(value, list):
            return [self._redact(v) for v in value]
        if isinstance(value, dict):
            return {k: self._redact(v) for k, v in value.items()}
        return value

    def metadata(self) -> dict:
        return {'requested_model': self.model, 'api': 'anthropic-messages',
                'api_version': API_VERSION, 'base_url_sha256': hashlib.sha256(self.base_url.encode()).hexdigest(),
                'auth_mode': 'configured_bearer' if self._token else 'configured_api_key',
                'automatic_retries': 0, 'timeout_s': self.timeout,
                'identity_limit': 'Requested and returned model labels are recorded; proxy labels do not attest immutable weights.'}

    def complete(self, payload: dict, *, conversion: dict | None = None) -> dict:
        if not self.allow_network:
            raise RuntimeError('Inference is disabled; require explicit allow_network=True after registration')
        request = copy.deepcopy(payload)
        if request.get('model') != self.model:
            raise ValueError('Payload model differs from explicitly pinned client model')
        if request.get('stream') not in [None, False]:
            raise ValueError('This adapter records complete non-streamed responses only')
        request['stream'] = False
        headers = {'Content-Type': 'application/json', 'anthropic-version': API_VERSION}
        if self._token:
            headers['Authorization'] = 'Bearer ' + self._token
        else:
            headers['x-api-key'] = self._key
        req = urllib.request.Request(self.base_url + '/v1/messages',
                                     data=json.dumps(request, ensure_ascii=False).encode(),
                                     headers=headers, method='POST')
        began = time.monotonic()
        result = {'provider': self.metadata(), 'request': request,
                  'request_sha256': digest(request), 'conversion': conversion,
                  'network_requests': 1, 'attempts': 1, 'response': None,
                  'ok': False, 'error': None}
        try:
            with self._opener.open(req, timeout=self.timeout) as response:
                result['http_status'] = response.status
                body = response.read()
                raw = json.loads(body)
                result['response'] = raw
                if raw.get('type') == 'error':
                    result['error'] = {'class': 'provider_error', 'detail': raw.get('error')}
                else:
                    result['returned_model'] = raw.get('model')
                    result['model_label_matches'] = raw.get('model') == self.model
                    result['usage'] = raw.get('usage')
                    result['stop_reason'] = raw.get('stop_reason')
                    result['message'] = as_pi_message(raw)
                    result['text'] = ''.join(b['text'] for b in raw.get('content', []) if b.get('type') == 'text')
                    result['tool_calls'] = [{**b, 'arguments': b['input']} for b in raw.get('content', []) if b.get('type') == 'tool_use']
                    result['ok'] = True
        except urllib.error.HTTPError as exc:
            result['http_status'] = exc.code
            try:
                detail = json.loads(exc.read())
            except Exception:
                detail = {'body': 'unparsed_provider_error_not_retained'}
            result['error'] = {'class': 'HTTPError', 'detail': detail}
        except Exception as exc:
            # Exception messages can embed URLs or transport data. Retain class.
            result['error'] = {'class': type(exc).__name__}
        result['elapsed_s'] = time.monotonic() - began
        return self._redact(result)

    def complete_pi(self, context: dict, **kwargs) -> dict:
        payload, metadata = from_pi_context(context, model=self.model, **kwargs)
        return self.complete(payload, conversion=metadata)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--model', default=DEFAULT_MODEL)
    parser.add_argument('--pi-context', action='store_true')
    parser.add_argument('--max-tokens', type=int, default=1400)
    parser.add_argument('--temperature', type=float, default=None)
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args()
    data = json.loads(args.input.read_text())
    client = AnthropicClient(model=args.model, allow_network=args.live)
    if args.pi_context:
        payload, conversion = from_pi_context(data, model=args.model,
                                              max_tokens=args.max_tokens,
                                              temperature=args.temperature)
    else:
        payload, conversion = data, None
    result = client.complete(payload, conversion=conversion) if args.live else {
        'dry_run': True, 'provider': client.metadata(), 'request': payload,
        'request_sha256': digest(payload), 'conversion': conversion,
        'network_requests': 0, 'model_calls': 0}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    print(json.dumps({k: result.get(k) for k in ['dry_run', 'ok', 'returned_model', 'stop_reason', 'error', 'elapsed_s', 'network_requests'] if k in result}))
    if args.live and not result.get('ok'):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
