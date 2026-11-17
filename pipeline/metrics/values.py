import json
from datetime import datetime

def canonical(x):
    return json.dumps(x, sort_keys=True, ensure_ascii=False, separators=(',', ':'))

def normalization(arg, value, owner=None):
    if arg == 'participants':
        return sorted({str(v).lower() for v in value or [] if str(v).lower() != str(owner).lower()}) if value is None or isinstance(value, list) else value
    if arg == 'recipients':
        return sorted((str(v).lower() for v in value)) if isinstance(value, list) else value
    if arg == 'attachments':
        return sorted((str(v.get('file_id')) if isinstance(v, dict) and v.get('type') == 'file' else canonical(v) for v in value or []))
    if arg.endswith('_time') or arg.endswith('_day'):
        try:
            dt = datetime.fromisoformat(str(value))
            if arg.endswith('_day'):
                return dt.date().isoformat() if dt.hour == dt.minute == dt.second == dt.microsecond == 0 else dt.isoformat()
            return dt.strftime('%Y-%m-%d %H:%M') if dt.second == dt.microsecond == 0 else dt.isoformat(sep=' ')
        except (ValueError, TypeError):
            return value
    if arg in {'recipient', 'email', 'hotel', 'location'} and isinstance(value, str):
        return value.lower()
    return value
