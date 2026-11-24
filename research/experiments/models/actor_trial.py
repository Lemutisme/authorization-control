"""Matched native actor continuation from evaluator-specified refusal histories.

No model runs on import. Identical portable histories and native tools are used
for all providers; provider encodings and native sampling settings are recorded.
"""
from pipeline.paths import resolve as research_path
import argparse, copy, gzip, hashlib, json, os, selectors, subprocess, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / 'provider'))
PYTHON = research_path('python')

class Broker:

    def __init__(self):
        self.child = subprocess.Popen([PYTHON, '-B', str(HERE / 'correctness/native.py')], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        self.n = 0

    def call(self, method, params):
        self.n += 1
        self.child.stdin.write(json.dumps({'id': self.n, 'method': method, 'params': params}) + '\n')
        self.child.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(self.child.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=60):
                raise TimeoutError('native_broker_timeout')
        line = self.child.stdout.readline()
        if not line:
            raise RuntimeError('native_broker_exited')
        row = json.loads(line)
        if row.get('id') != self.n or not row.get('ok'):
            raise RuntimeError('native_broker_failure_' + str(row.get('error')))
        return row['result']

    def close(self):
        if self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait()

def run(packet_path, model, direction, feedback, repetition=0, unforced=False, dry=False, system_addendum=None):
    from luna import make_client
    packet = json.loads(Path(packet_path).read_text())
    began = time.monotonic()
    broker = Broker()
    client = None if dry else make_client(model, allow_network=True)
    requests = []
    native_results = []
    status = 'running'
    final_text = ''
    first_action = None
    error = None
    context = {}
    original_context_sha256 = None
    budget = None
    result = None
    actor_correct = direction == 'corruption'
    gate_correct = not actor_correct
    try:
        init = broker.call('init', {'packet': str(packet_path), 'actor_correct': actor_correct, 'gate_correct': gate_correct, 'feedback': feedback, 'pending': not unforced})
        context = copy.deepcopy(init['context'])
        original_context_sha256 = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
        if 'system' in context:
            if 'systemPrompt' in context:
                raise ValueError('Ambiguous system prompt representation')
            context['systemPrompt'] = context.pop('system')
        if system_addendum:
            context['systemPrompt'] += '\n\n' + system_addendum
        if not unforced:
            pending = init['correct_proposal'] if actor_correct else init['faulty_proposal']
            context['messages'].append({'role': 'assistant', 'content': [{'type': 'toolCall', 'id': 'panel_pending', 'name': pending['function'], 'arguments': copy.deepcopy(pending['args'])}], 'api': 'study-supplied-proposal', 'provider': 'evaluator', 'model': 'evaluator', 'stopReason': 'toolUse', 'timestamp': 0})
            context['messages'].append({'role': 'toolResult', 'toolCallId': 'panel_pending', 'toolName': pending['function'], 'content': [{'type': 'text', 'text': init['pending_response']['text']}], 'isError': init['pending_response']['is_error'], 'timestamp': 0})
            if not init['pending_response']['is_error']:
                raise ValueError('Off-diagonal pending call was not refused')
        budget = 1 if unforced else init['remaining_actor_budget']
        if budget < 1:
            raise ValueError('Source has no remaining actor budget')
        for ordinal in range(budget):
            if dry:
                message = {'role': 'assistant', 'content': [{'type': 'text', 'text': 'Dry-run terminal reply.'}], 'stopReason': 'stop', 'model': 'scripted', 'api': 'scripted', 'provider': 'scripted'}
                response = {'ok': True, 'message': message, 'text': 'Dry-run terminal reply.', 'tool_calls': [], 'network_requests': 0, 'returned_model': 'scripted', 'model_label_matches': True}
            else:
                response = client.complete_pi(context, max_tokens=1400, temperature=None)
            response['ordinal'] = ordinal
            requests.append(response)
            if not response.get('ok'):
                status = 'transport_or_conversion_failure'
                error = response.get('error')
                break
            if not dry and (not response.get('model_label_matches')):
                status = 'model_identity_mismatch'
                break
            message = response['message']
            calls = response.get('tool_calls', [])
            if ordinal == 0:
                first_action = {'text': response.get('text'), 'calls': copy.deepcopy(calls), 'stop_reason': response.get('stop_reason'), 'message': copy.deepcopy(message)}
            context['messages'].append(message)
            final_text = response.get('text', '')
            if unforced:
                status = 'unforced_first_response'
                break
            if not calls:
                status = 'output_limit' if message.get('stopReason') == 'length' else 'completed'
                break
            for call in calls:
                native = broker.call('invoke', {'function': call['name'], 'args': call['arguments'], 'call_id': call['id']})
                native_results.append({'call': copy.deepcopy(call), 'result': native})
                context['messages'].append({'role': 'toolResult', 'toolCallId': call['id'], 'toolName': call['name'], 'content': [{'type': 'text', 'text': native['text']}], 'isError': native['is_error'], 'timestamp': 0})
        else:
            status = 'actor_budget_exhausted'
        result = broker.call('finish', {'final_text': final_text})
    except Exception as exc:
        status = 'infrastructure_failure'
        error = {'class': type(exc).__name__, 'message': str(exc)}
        try:
            result = broker.call('finish', {'final_text': final_text})
        except Exception:
            result = None
    finally:
        broker.close()
    incomplete = status in {'transport_or_conversion_failure', 'model_identity_mismatch', 'infrastructure_failure'}
    endpoint = {}
    for key in ['correct_selected_effect', 'wrong_selected_effect', 'fault_selected_effect']:
        endpoint[key] = int(result[key]) if result and (result[key] or not incomplete) else None
    endpoint['native_utility'] = None if incomplete or not result or result['utility_error'] else int(result['native_utility'])
    return {'packet_id': packet['packet_id'], 'unit_id': packet['unit_id'], 'cluster_id': packet['cluster_id'], 'task_id': packet['task_id'], 'suite': packet['suite'], 'fault_class': packet['fault_class'], 'model': model, 'direction': direction, 'feedback': feedback, 'repetition': repetition, 'unforced': unforced, 'status': status, 'error': error, 'remaining_actor_budget': budget, 'native': result, 'metrics': endpoint, 'first_action': first_action, 'requests': requests, 'native_results': native_results, 'source_context_sha256': original_context_sha256, 'final_context': context, 'final_text': final_text, 'system_addendum': system_addendum, 'elapsed_s': time.monotonic() - began, 'packet_path': str(packet_path), 'dry': dry, 'scope': 'Conditional continuation from a source history; pending call correctness is evaluator-assigned, not a natural model-error sample.'}

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--packet', required=True)
    p.add_argument('--model', choices=['haiku', 'luna', 'deepseek'], required=True)
    p.add_argument('--direction', choices=['corruption', 'correction'], required=True)
    p.add_argument('--feedback', choices=['value_stating', 'value_free', 'original_F0', 'original_F3'], required=True)
    p.add_argument('--repetition', type=int, default=0)
    p.add_argument('--out', required=True)
    p.add_argument('--unforced', action='store_true')
    p.add_argument('--dry', action='store_true')
    a = p.parse_args()
    r = run(a.packet, a.model, a.direction, a.feedback, a.repetition, a.unforced, a.dry)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(gzip.compress(json.dumps(r, ensure_ascii=False, default=str).encode()))
    print(json.dumps({k: r[k] for k in ['packet_id', 'model', 'direction', 'feedback', 'status', 'metrics', 'elapsed_s', 'dry']}))
if __name__ == '__main__':
    main()
