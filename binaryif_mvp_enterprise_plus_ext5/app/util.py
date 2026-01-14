
import json, hashlib, base64, time
from datetime import datetime, timezone

def canonicalize(obj) -> bytes:
    # Canonical JSON: lexicographic keys, no whitespace, UTF-8
    s = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return s.encode('utf-8')

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def now_epoch() -> int:
    return int(time.time())

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

def utc_rfc3339(ts_epoch: int) -> str:
    return datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
