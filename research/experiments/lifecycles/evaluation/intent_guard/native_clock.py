"""Optional paired-evaluation clock, not a production defense mechanism.

Only native email/file writers use it. It advances per native now() request,
preserving timestamp ordering, and never changes the API client's real clock.
One environment per broker process is required.
"""
import datetime as real
import threading
from types import SimpleNamespace

def install(anchor):
    from agentdojo.default_suites.v1.tools import email_client,cloud_drive_client
    start=real.datetime.fromisoformat(anchor)
    if start.tzinfo is not None:raise ValueError('Use a naive UTC anchor matching native timestamps')
    state={'ticks':0};lock=threading.Lock()
    class ClockDateTime(real.datetime):
        @classmethod
        def now(cls,tz=None):
            with lock:
                value=start+real.timedelta(microseconds=state['ticks']);state['ticks']+=1
            return value if tz is None else value.replace(tzinfo=real.timezone.utc).astimezone(tz)
    class Module:
        datetime=ClockDateTime
        def __getattr__(self,name):return getattr(real,name)
    for module in [email_client,cloud_drive_client]:module.datetime=Module()
    return {'kind':'controlled_native_writer_clock','anchor':anchor,'state':state,
            'limit':'Process-local evaluation control; only native email/file now() calls, no wall-clock/deadline guarantee.'}
