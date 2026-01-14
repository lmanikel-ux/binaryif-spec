"""
Utility functions for BinaryIF MVP.

Provides canonical JSON serialization, hashing, encoding, and time utilities.
"""

import json
import hashlib
import base64
import time
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Union


def canonicalize(obj: Any) -> bytes:
    """
    Convert object to canonical JSON bytes.
    
    Canonical JSON:
    - Lexicographically sorted keys
    - No whitespace
    - UTF-8 encoded
    """
    s = json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return s.encode('utf-8')


def sha256_hex(data: Union[bytes, str]) -> str:
    """Compute SHA-256 hash and return as hex string."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data: Union[bytes, str]) -> bytes:
    """Compute SHA-256 hash and return as bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()


def now_epoch() -> int:
    """Get current Unix timestamp as integer."""
    return int(time.time())


def b64e(b: bytes) -> str:
    """Base64 encode bytes to string."""
    return base64.b64encode(b).decode('ascii')


def b64d(s: str) -> bytes:
    """Base64 decode string to bytes."""
    return base64.b64decode(s.encode('ascii'))


def b64url_encode(b: bytes) -> str:
    """URL-safe base64 encode bytes to string (no padding)."""
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode('ascii')


def b64url_decode(s: str) -> bytes:
    """URL-safe base64 decode string to bytes (handles missing padding)."""
    # Add padding if needed
    padding = 4 - (len(s) % 4)
    if padding != 4:
        s += '=' * padding
    return base64.urlsafe_b64decode(s.encode('ascii'))


def utc_rfc3339(ts_epoch: int) -> str:
    """Convert Unix timestamp to RFC3339 UTC string."""
    return datetime.fromtimestamp(ts_epoch, tz=timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_rfc3339(s: str) -> int:
    """Parse RFC3339 UTC string to Unix timestamp."""
    dt = datetime.strptime(s, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def constant_time_compare(a: Union[str, bytes], b: Union[str, bytes]) -> bool:
    """
    Compare two strings/bytes in constant time to prevent timing attacks.
    """
    if isinstance(a, str):
        a = a.encode('utf-8')
    if isinstance(b, str):
        b = b.encode('utf-8')
    return hmac.compare_digest(a, b)


def generate_nonce(length: int = 16) -> str:
    """Generate a cryptographically secure random nonce."""
    return secrets.token_hex(length)


def generate_id(length: int = 16) -> str:
    """Generate a cryptographically secure random ID."""
    return secrets.token_hex(length)


def mask_sensitive(value: str, visible_chars: int = 4) -> str:
    """
    Mask a sensitive value, showing only the last N characters.
    Useful for logging.
    """
    if len(value) <= visible_chars:
        return '*' * len(value)
    return '*' * (len(value) - visible_chars) + value[-visible_chars:]


def validate_hex_string(s: str, expected_length: int = None) -> bool:
    """Validate that a string is valid hexadecimal."""
    try:
        if expected_length and len(s) != expected_length:
            return False
        int(s, 16)
        return True
    except (ValueError, TypeError):
        return False


def validate_base64(s: str) -> bool:
    """Validate that a string is valid base64."""
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:
        return False
