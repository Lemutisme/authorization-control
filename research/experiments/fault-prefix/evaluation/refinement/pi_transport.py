"""Pi 1.5 backed Luna transport for the generic intent guard."""
from __future__ import annotations

import hashlib
import json
import subprocess
import time
from pathlib import Path

# Reuse the existing endpoint/key discovery and transport error contract.
_EVALUATION = Path(__file__).resolve().parents[1]
import sys
if str(_EVALUATION) not in sys.path:
    sys.path.insert(0, str(_EVALUATION))
from pga_transport import ResponsesTransport, TransportError

MODEL = 'gpt-6-luna'
_CLIENT = Path(__file__).with_name('pi_review_client.mjs')


class PiAuthorizationTransport(ResponsesTransport):
    """Drop-in ``request(history, tools, instructions)`` for IntentGuard.

    Each call starts one Pi client draw. The API key and endpoint cross only
    the child process stdin pipe; neither is included in records or errors.
    """

    def __init__(self, *, node='node'):
        super().__init__(model=MODEL, max_output_tokens=1536, timeout=90)
        self.node = node

    @staticmethod
    def _payload(history, tools, instructions):
        return {
            'model': MODEL,
            'input': history,
            'instructions': instructions,
            'tools': tools,
            'parallel_tool_calls': False,
            'max_output_tokens': 1536,
            'reasoning': {'effort': 'low'},
            'store': False,
        }

    def request(self, history, tools, instructions):
        payload = self._payload(history, tools, instructions)
        record = {
            'requested_model': MODEL,
            'reasoning_effort': 'low',
            'max_output_tokens': 1536,
            'automatic_retries': 0,
            'request_sha256': hashlib.sha256(
                json.dumps(payload, sort_keys=True).encode('utf-8')
            ).hexdigest(),
        }
        start = time.monotonic()
        child_input = {
            'history': history,
            'tools': tools,
            'instructions': instructions,
            'connection': {
                'base_url': self.endpoint,
                'api_key': self.key,
            },
        }
        try:
            completed = subprocess.run(
                [self.node, str(_CLIENT)],
                input=json.dumps(child_input, ensure_ascii=False) + '\n',
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=self.timeout + 5,
                check=False,
            )
            if completed.returncode != 0:
                record['error'] = 'PiProcessError'
                raise TransportError('Authorization Pi client failed')
            lines = completed.stdout.splitlines()
            if len(lines) != 1:
                record['error'] = 'InvalidPiResponse'
                raise TransportError('Authorization Pi client returned an invalid response')
            envelope = json.loads(lines[0])
            record.update(envelope.get('meta') or {})
            if not envelope.get('ok'):
                record.setdefault('error', 'InferenceError')
                raise TransportError('Authorization inference failed')
            response = envelope.get('response')
            if not isinstance(response, dict) or response.get('status') != 'completed':
                record['error'] = 'InvalidResponse'
                raise TransportError('Authorization response was incomplete')
            return {'status': 'completed', 'output': response.get('output', [])}
        except subprocess.TimeoutExpired:
            record['error'] = 'TimeoutError'
            raise TransportError('Authorization transport TimeoutError') from None
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            record['error'] = type(exc).__name__
            raise TransportError('Authorization transport ' + type(exc).__name__) from None
        finally:
            record['elapsed_s'] = time.monotonic() - start
            self.calls.append(record)

    def metadata(self):
        return {
            **super().metadata(),
            'requested_model': MODEL,
            'reasoning_effort': 'low',
            'max_output_tokens': 1536,
            'automatic_retries': 0,
            'runtime': '@earendil-works/pi-ai streamSimple 1.5.0',
            'cache': 'no client response cache',
            'credential_storage': 'none; environment/config discovery only',
        }
