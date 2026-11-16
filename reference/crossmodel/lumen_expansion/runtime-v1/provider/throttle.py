"""Process-shared, project-scoped, serial account/endpoint pacing.

This never retries a request. Each acquisition authorizes exactly one HTTP
attempt. A 429 records a cooldown for later explicit requests from all jobs.
"""
from __future__ import annotations
import fcntl
import hashlib
import json
import os
import time
from datetime import timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

DEFAULT_DIRECTORY = Path('/artifact-source/8d8a31bc8f1a/transport-state')


class TerminalQuotaHalt(RuntimeError):
    def __init__(self, record):
        self.record = record
        super().__init__('insufficient_quota: endpoint/account halted by prior provider response')


def safe_rate_headers(headers) -> dict:
    return {str(k).lower(): str(v)[:1024] for k, v in headers.items()
            if str(k).lower() == 'retry-after' or str(k).lower().startswith('x-ratelimit-')}


def retry_after_seconds(headers, now=None):
    value = headers.get('retry-after')
    if value is None:
        return None
    now = time.time() if now is None else now
    try:
        return max(0.0, float(value))
    except (ValueError, TypeError):
        try:
            parsed = parsedate_to_datetime(value)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return max(0.0, parsed.timestamp() - now)
        except (ValueError, TypeError, OverflowError):
            return None


class SharedThrottle:
    def __init__(self, endpoint, credential, *, directory=None, interval_s=2.1, cooldown_s=60.0):
        self.directory = Path(directory) if directory is not None else Path(os.environ.get('LUMEN_STUDY_RATE_DIR', str(DEFAULT_DIRECTORY)))
        # The credential never enters state or metadata. Its one-way digest keeps
        # separate accounts apart while all jobs for this account coordinate.
        self.scope = hashlib.sha256((endpoint + '\0' + credential).encode()).hexdigest()[:32]
        self.interval_s = float(interval_s)
        self.cooldown_s = float(cooldown_s)
        if self.interval_s < 0 or self.cooldown_s < 0:
            raise ValueError('Throttle intervals must be nonnegative')

    def acquire(self):
        self.directory.mkdir(parents=True, exist_ok=True)
        lock = (self.directory / (self.scope + '.lock')).open('a+')
        began = time.monotonic()
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        acquired = time.monotonic()
        path = self.directory / (self.scope + '.json')
        try:
            state = json.loads(path.read_text()) if path.exists() else {}
            if state.get('terminal_halt'):
                raise TerminalQuotaHalt(state['terminal_halt'])
            target = max(state.get('next_allowed_epoch', 0), state.get('cooldown_until_epoch', 0),
                         state.get('last_attempt_finished_epoch',0)+self.interval_s)
            while target > time.time():
                time.sleep(min(1.0, target - time.time()))
            started = time.time()
            state.update(last_attempt_started_epoch=started,
                         next_allowed_epoch=max(state.get('next_allowed_epoch', 0), started + self.interval_s),
                         total_attempts=state.get('total_attempts', 0) + 1)
            lease = _Lease(self, lock, path, state, {'lock_wait_s': acquired - began,
                           'pace_wait_s': time.monotonic() - acquired,
                           'serial_one_inflight': True, 'interval_after_completion_s': self.interval_s,
                           'minimum_429_cooldown_s': self.cooldown_s,
                           'scope': 'project-local account+endpoint; no global host lock'})
            lease._write()
            return lease
        except BaseException:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
            raise


class _Lease:
    def __init__(self, throttle, lock, path, state, metadata):
        self.throttle, self.lock, self.path = throttle, lock, path
        self.state, self.metadata, self.closed = state, metadata, False

    def _write(self):
        temporary = self.path.with_suffix('.tmp.' + str(os.getpid()))
        temporary.write_text(json.dumps(self.state, sort_keys=True) + '\n')
        temporary.replace(self.path)

    def finish(self, status, headers, error_code=None):
        if self.closed:
            return
        try:
            now = time.time()
            self.state['last_http_status'] = status
            self.state['last_attempt_finished_epoch'] = now
            self.state['next_allowed_epoch'] = max(self.state.get('next_allowed_epoch', 0), now + self.throttle.interval_s)
            self.state['last_rate_headers'] = safe_rate_headers(headers or {})
            if error_code == 'insufficient_quota':
                self.state['terminal_halt'] = {
                    'code': 'insufficient_quota', 'observed_epoch': now,
                    'http_status': status,
                    'reason': 'Provider reports exhausted coin budget; explicit operator recovery required before further requests.',
                }
                self.metadata['terminal_provider_halt'] = True
            if status == 429:
                server_delay = retry_after_seconds(self.state['last_rate_headers'], now)
                cooldown = max(self.throttle.cooldown_s, server_delay or 0)
                self.state['cooldown_until_epoch'] = max(self.state.get('cooldown_until_epoch', 0), now + cooldown)
                self.state['rate_limit_responses'] = self.state.get('rate_limit_responses', 0) + 1
                self.metadata['cooldown_applied_s'] = cooldown
            self._write()
            self.metadata['next_allowed_epoch'] = max(self.state['next_allowed_epoch'], self.state.get('cooldown_until_epoch', 0))
        finally:
            self.closed = True
            fcntl.flock(self.lock.fileno(), fcntl.LOCK_UN)
            self.lock.close()
