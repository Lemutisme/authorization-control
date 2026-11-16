"""Offline regression checks on retained failure samples and process throttling."""
import gzip
import json
import multiprocessing
import tempfile
import time
from pathlib import Path
from haiku import DEFAULT_MODEL, as_pi_message, from_pi_context
from throttle import SharedThrottle, safe_rate_headers, retry_after_seconds


def visit(x):
    if isinstance(x, dict):
        if 'request' in x and ('response' in x or 'error' in x):
            yield x
        for value in x.values():
            yield from visit(value)
    elif isinstance(x, list):
        for value in x:
            yield from visit(value)


def worker(directory, output):
    throttle = SharedThrottle('https://offline.invalid', 'synthetic-account', directory=directory, interval_s=0.05, cooldown_s=0.1)
    lease = throttle.acquire()
    start = time.monotonic()
    time.sleep(0.08)
    end = time.monotonic()
    lease.finish(200, {'Authorization': 'must_not_persist', 'x-ratelimit-remaining-requests': '5'})
    output.put((start, end))


def main():
    rawdir = Path('/artifact-source/c945c1606a3a/raw')
    seen = set()
    for path in rawdir.glob('*.json.gz'):
        raw = json.loads(gzip.decompress(path.read_bytes()))
        for row in visit(raw):
            response = row.get('response') or {}
            if not response.get('content') or response.get('id') in seen:
                continue
            seen.add(response['id'])
            msg = as_pi_message(response)
            assert all(b['type'] in {'text', 'toolCall'} for b in msg['content'])
            wire, _ = from_pi_context({'messages': [{'role': 'user', 'content': 'Offline shape check.'}, msg], 'tools': []})
            assert wire['messages'][-1]['content'] == response['content']
            assert wire['thinking'] == {'type': 'disabled'}
            try:
                from_pi_context({'messages': [{'role': 'user', 'content': 'Offline shape check.'}, msg]}, model='other-model')
            except ValueError:
                pass
            else:
                raise AssertionError('Opaque signature could cross model identity')
    assert len(seen) == 52
    assert safe_rate_headers({'Authorization': 'secret', 'Set-Cookie': 'secret', 'Retry-After': '7', 'X-RateLimit-Limit-Requests': '12'}) == {'retry-after': '7', 'x-ratelimit-limit-requests': '12'}
    assert retry_after_seconds({'retry-after': '3.5'}) == 3.5
    with tempfile.TemporaryDirectory(prefix='throttle-test-', dir=Path(__file__).resolve().parent) as directory:
        q = multiprocessing.Queue()
        jobs = [multiprocessing.Process(target=worker, args=(directory, q)) for _ in range(3)]
        for job in jobs:
            job.start()
        for job in jobs:
            job.join(5)
            assert job.exitcode == 0
        spans = sorted(q.get() for _ in jobs)
        gaps = [spans[i+1][0] - spans[i][1] for i in range(len(spans)-1)]
        assert min(gaps) >= 0.04
        throttle = SharedThrottle('https://offline.invalid', 'synthetic-account', directory=directory, interval_s=0, cooldown_s=0.1)
        lease = throttle.acquire()
        lease.finish(429, {'retry-after': '0.15'})
        before = time.monotonic()
        lease = throttle.acquire()
        cooldown_wait = time.monotonic() - before
        lease.finish(200, {})
        assert cooldown_wait >= 0.13
        state = json.loads(next(Path(directory).glob('*.json')).read_text())
        assert state['total_attempts'] == 5 and state['rate_limit_responses'] == 1
        assert 'secret' not in json.dumps(state)
    result = {'passed': True, 'retained_haiku_responses_roundtripped': len(seen),
              'signed_blocks_not_semantic_text': True, 'cross_model_opaque_replay_rejected': True,
              'three_process_serialization': True, 'minimum_measured_completion_gap_s': min(gaps),
              'measured_cooldown_wait_s': cooldown_wait, 'safe_header_allowlist': True,
              'model_calls': 0, 'network_calls': 0}
    Path(__file__).with_name('offline-v3-check.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
