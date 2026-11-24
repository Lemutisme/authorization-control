"""Original policy RPC, with actual-payload occurrence coupling in the Pi worker."""
import json
import subprocess
from pathlib import Path

class PolicyClient:
    def __init__(self, connection, journal, cache, reasoning):
        assert reasoning in {'none', 'medium'}
        self.journal = Path(journal)
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self.calls = []
        self.stage = 'initial'
        self.child = subprocess.Popen(['node', str(Path(__file__).with_name('policy_client.mjs'))], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.rpc({'method': 'init', 'connection': connection, 'cache': cache, 'reasoning': reasoning})
    def rpc(self, query):
        self.child.stdin.write(json.dumps(query)+'\n')
        self.child.stdin.flush()
        line = self.child.stdout.readline()
        if not line:
            raise RuntimeError('Policy worker exited')
        return json.loads(line)
    def request(self, system, user, temperature=0):
        if len(self.calls) >= 64:
            raise RuntimeError('Policy request cap reached')
        query = dict(method='complete', system=system, user=user, temperature=temperature)
        response = self.rpc(query)
        response['meta'].update(ok=response['ok'], stage=self.stage)
        response['meta'].setdefault('coupling', {})['stage'] = self.stage
        self.calls.append(response['meta'])
        with self.journal.open('a') as handle:
            handle.write(json.dumps(dict(stage='policy_response', logical_stage=self.stage, request=query, response=response))+'\n')
        if not response['ok']:
            raise RuntimeError(response['error'])
        return response['text']
    def close(self):
        if self.child.poll() is None:
            self.child.stdin.close()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.terminate()
                self.child.wait(timeout=5)
