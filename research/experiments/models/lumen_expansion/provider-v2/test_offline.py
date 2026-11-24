"""No-network test of exact IDs, history preservation and persistent quota halt."""
import io
import json
import tempfile
import urllib.error
from pathlib import Path
from lumen import ENDPOINT, LumenClient, as_pi_message, capture_headers, from_pi_context
from throttle import SharedThrottle, TerminalQuotaHalt


def main():
    context = {'systemPrompt': 'Perform the owner task.', 'messages': [
        {'role': 'user', 'content': 'Pay 200.29.'},
        {'role': 'assistant', 'content': [{'type': 'toolCall', 'id': 'call_a|fc_a', 'name': 'pay', 'arguments': {'amount': 200.29}}]},
        {'role': 'toolResult', 'toolName': 'pay', 'toolCallId': 'call_a|fc_a', 'isError': True, 'content': [{'type': 'text', 'text': 'Only 195.29 is permitted.'}]},
    ], 'tools': [{'name': 'pay', 'parameters': {'type': 'object', 'properties': {'amount': {'type': 'number'}}}}]}
    for model, mode, cap in [('qwen3.8-flash', 'off', 1400), ('glm-5.3', 'low', 8192)]:
        payload, _ = from_pi_context(context, model=model, reasoning_mode=mode, max_tokens=cap)
        assert payload['model'] == model and payload['max_tokens'] == cap
        assert payload['messages'][-1]['content'] == 'Only 195.29 is permitted.'
        assert payload['messages'][-1]['tool_call_id'] == payload['messages'][-2]['tool_calls'][0]['id']
        assert payload['tools'][0]['function']['parameters'] == context['tools'][0]['parameters']
    assert payload['reasoning_effort'] == 'low'
    try:
        from_pi_context(context, model='zai/glm-5.3-flash', reasoning_mode='low')
    except ValueError:
        pass
    else:
        raise AssertionError('A Canopy ID was silently accepted')
    class FakeQuota:
        calls = 0
        def open(self, request, timeout):
            self.calls += 1
            assert request.full_url == ENDPOINT
            error = {'error': {'code': 'insufficient_quota', 'message': 'synthetic account exhausted'}}
            raise urllib.error.HTTPError(ENDPOINT, 429, 'quota', {'Retry-After': '120'}, io.BytesIO(json.dumps(error).encode()))
    with tempfile.TemporaryDirectory(prefix='offline-lumen-', dir=Path(__file__).parent) as directory:
        client = object.__new__(LumenClient)
        client.model, client.reasoning_mode, client.allow_network, client.timeout = 'glm-5.3', 'low', True, 1
        client._key = 'offline-synthetic-key'
        client._opener = FakeQuota()
        client._throttle = SharedThrottle(ENDPOINT, client._key, directory=directory, interval_s=0, cooldown_s=0)
        first = client.complete_pi(context, max_tokens=8192)
        second = client.complete_pi(context, max_tokens=8192)
        assert first['terminal_provider_halt'] and first['error']['code'] == 'insufficient_quota'
        assert second['terminal_provider_halt'] and second['error']['class'] == 'TerminalQuotaHalt'
        assert second['network_requests'] == 0 and client._opener.calls == 1
        assert 'offline-synthetic-key' not in json.dumps(first)
        state = json.loads(next(Path(directory).glob('*.json')).read_text())
        assert state['terminal_halt']['code'] == 'insufficient_quota'
        # An entirely new client/process gets the same local halt before network.
        another = SharedThrottle(ENDPOINT, client._key, directory=directory, interval_s=0, cooldown_s=0)
        try:
            another.acquire()
        except TerminalQuotaHalt:
            pass
        else:
            raise AssertionError('Quota halt did not persist across instances')
    result = {'passed': True, 'exact_lumen_model_ids_only': True, 'schema_refusal_tool_ids_preserved': True,
              'insufficient_quota_persists_terminal_halt': True, 'subsequent_call_network_requests': 0,
              'credential_not_in_record': True, 'model_calls': 0, 'real_network_calls': 0,
              'mock_http_attempts': 1}
    Path(__file__).with_name('offline-check.json').write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
