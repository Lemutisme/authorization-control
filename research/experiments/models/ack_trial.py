"""Fresh actor continuations with the post-update policy fixed and status varied."""
from pipeline.paths import resolve as research_path
import argparse, copy, gzip, hashlib, json, selectors, subprocess, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'provider'))
PYTHON = research_path('python')

class Broker:

    def __init__(self):
        self.p = subprocess.Popen([PYTHON, '-B', str(HERE / 'recovery_ack/runtime.py')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.i = 0

    def call(self, method, params):
        self.i += 1
        self.p.stdin.write(json.dumps({'id': self.i, 'method': method, 'params': params}) + '\n')
        self.p.stdin.flush()
        with selectors.DefaultSelector() as s:
            s.register(self.p.stdout, selectors.EVENT_READ)
            if not s.select(60):
                raise TimeoutError('native_broker_timeout')
        row = json.loads(self.p.stdout.readline())
        if row.get('id') != self.i or not row.get('ok'):
            raise RuntimeError('native_broker_failure_' + str(row.get('error')))
        return row['result']

    def close(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(5)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()

def run(packet_path, sha, model, arm, dry=False):
    from luna import make_client
    packet = json.loads(Path(packet_path).read_text())
    broker = Broker()
    client = None if dry else make_client(model, allow_network=True)
    began = time.monotonic()
    requests = []
    context = {}
    first = None
    status = 'running'
    error = None
    final = ''
    native = None
    try:
        init = broker.call('init', {'packet': str(packet_path), 'packet_sha256': sha, 'arm': arm})
        context = copy.deepcopy(init['context'])
        budget = init['remaining_actor_budget']
        for ordinal in range(budget):
            if dry:
                response = {'ok': True, 'model_label_matches': True, 'network_requests': 0, 'message': {'role': 'assistant', 'content': [{'type': 'text', 'text': 'Dry terminal'}], 'stopReason': 'stop'}, 'text': 'Dry terminal', 'tool_calls': []}
            else:
                response = client.complete_pi(context, max_tokens=1400, temperature=None)
            requests.append(response)
            if not response.get('ok') or not response.get('model_label_matches'):
                status = 'transport_or_identity_failure'
                error = response.get('error')
                break
            if first is None:
                first = copy.deepcopy(response['message'])
            context['messages'].append(response['message'])
            final = response.get('text', '')
            calls = response.get('tool_calls', [])
            if not calls:
                status = 'output_limit' if response['message'].get('stopReason') == 'length' else 'completed'
                break
            for call in calls:
                result = broker.call('invoke', {'function': call['name'], 'args': call['arguments'], 'call_id': call['id']})
                context['messages'].append({'role': 'toolResult', 'toolName': call['name'], 'toolCallId': call['id'], 'content': [{'type': 'text', 'text': result['text']}], 'isError': result['is_error'], 'timestamp': 0})
        else:
            status = 'actor_budget_exhausted'
        native = broker.call('finish', {'final_text': final})
    except Exception as exc:
        status = 'infrastructure_failure'
        error = {'class': type(exc).__name__, 'message': str(exc)}
        try:
            native = broker.call('finish', {'final_text': final})
        except Exception:
            pass
    finally:
        broker.close()
    incomplete = status in ['transport_or_identity_failure', 'infrastructure_failure']
    metrics = {}
    for key in ['native_utility', 'native_goal', 'original_call_changed_state_normalized']:
        value = native.get(key) if native else None
        metrics[key] = int(value) if value is not None and (value or not incomplete) else None
    for key in ['correct_selected_effect', 'wrong_selected_effect']:
        value = (native.get('selected_effects') or {}).get('legacy', {}).get(key) if native else None
        metrics[key] = int(value) if value is not None and (value or not incomplete) else None
    return {'unit_id': packet['unit_id'], 'panel': packet['panel'], 'task_id': packet['task_id'], 'model': model, 'arm': arm, 'original_admitted_after_update': packet['original_admitted_after_update'], 'status': status, 'error': error, 'requests': requests, 'first_response': first, 'native': native, 'metrics': metrics, 'final_context': context, 'packet_path': str(packet_path), 'packet_sha256': sha, 'elapsed_s': time.monotonic() - began, 'dry': dry, 'scope': 'Counterfactual fixed-after-update permission; only historical refusal acknowledgement changes; no pending call replay at init.'}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--packet', required=True)
    p.add_argument('--sha', required=True)
    p.add_argument('--model', choices=['luna', 'haiku'], required=True)
    p.add_argument('--arm', required=True)
    p.add_argument('--out', required=True)
    p.add_argument('--dry', action='store_true')
    a = p.parse_args()
    r = run(a.packet, a.sha, a.model, a.arm, a.dry)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(gzip.compress(json.dumps(r, default=str).encode()))
    print(json.dumps({k: r[k] for k in ['unit_id', 'model', 'arm', 'status', 'metrics', 'elapsed_s']}))
if __name__ == '__main__':
    main()
