"""One fresh/coupled Pi constructor call; no inference at import or init."""
import copy
import json
from pathlib import Path
import subprocess


class ConstructorClient:
    def __init__(self, connection, bank, journal):
        self.journal = Path(journal)
        self.journal.parent.mkdir(parents=True, exist_ok=True)
        self.calls = []
        self.child = subprocess.Popen(['node', str(Path(__file__).with_name('pi_draw.mjs'))],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=subprocess.DEVNULL, text=True)
        result = self.rpc({'method': 'init', 'connection': connection, 'bank': str(bank)})
        if not result.get('ok'):
            raise RuntimeError('Constructor initialization failed')

    def rpc(self, packet):
        self.child.stdin.write(json.dumps(packet) + '\n')
        self.child.stdin.flush()
        line = self.child.stdout.readline()
        if not line:
            raise RuntimeError('Constructor child exited')
        return json.loads(line)

    def draw(self, packet):
        if self.calls:
            raise RuntimeError('One constructor draw per unit')
        result = self.rpc({'method': 'constructor', 'packet': packet})
        self.calls.append(copy.deepcopy(result.get('meta', {'actual_network_call': None})))
        with self.journal.open('a') as handle:
            handle.write(json.dumps({'packet': packet, 'response': result}) + '\n')
        if not result.get('ok'):
            raise RuntimeError('Constructor unavailable or malformed')
        return result['reply']

    def close(self):
        if self.child.poll() is None:
            self.child.stdin.close()
            try:
                self.child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.child.terminate()
                self.child.wait(timeout=5)
