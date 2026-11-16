"""Credential and transport helpers, with no inference or shell evaluation."""
import hashlib
import json
import os
import re
import shlex
import urllib.request
from pathlib import Path


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def load_key():
    if os.environ.get('LUMEN_API_KEY'):
        return os.environ['LUMEN_API_KEY']
    values = []
    for line in (Path.home()/'.bashrc').read_text().splitlines():
        if not re.match(r'^\s*(?:export\s+)?LUMEN_API_KEY\s*=', line):
            continue
        parts = shlex.split(line.split('=', 1)[1], comments=True, posix=True)
        if len(parts) != 1 or not parts[0] or any(c in parts[0] for c in ['$', '`', ';']):
            raise RuntimeError('Lumen key is not a single literal; no shell evaluation permitted')
        values.append(parts[0])
    if len(values) != 1:
        raise RuntimeError('Expected one literal Lumen key assignment')
    return values[0]
