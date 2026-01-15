"""
BinaryIF Canonical JSON Encoding (CJE)

Implements Section 11 of the BinaryIF Protocol Specification.
Ensures semantically identical actions produce identical byte representations.
"""

import json
from typing import Any, Dict, List, Union


def canonicalize(obj: Any) -> bytes:
    """
    Convert an object to Canonical JSON Encoding (CJE).
    
    Rules per Section 11.2:
    - Object keys sorted lexicographically (Unicode code point order)
    - No whitespace between tokens (compact form)
    - UTF-8 encoding, no BOM
    - Minimal escaping
    - Numbers as provided (use strings for precision)
    - Double quotes only
    - Lowercase true/false
    - Arrays preserve order
    
    Returns:
        UTF-8 encoded bytes of canonical JSON
    """
    canonical = _canonicalize_value(obj)
    return json.dumps(canonical, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def canonicalize_str(obj: Any) -> str:
    """Return canonical JSON as string."""
    return canonicalize(obj).decode('utf-8')


def _canonicalize_value(value: Any) -> Any:
    """Recursively canonicalize a value."""
    if value is None:
        return None
    elif isinstance(value, bool):
        return value
    elif isinstance(value, (int, float)):
        return value
    elif isinstance(value, str):
        return value
    elif isinstance(value, dict):
        return _canonicalize_object(value)
    elif isinstance(value, (list, tuple)):
        return _canonicalize_array(value)
    else:
        raise ValueError(f"Cannot canonicalize type: {type(value)}")


def _canonicalize_object(obj: Dict[str, Any]) -> Dict[str, Any]:
    """
    Canonicalize an object by sorting keys lexicographically.
    
    Per Section 11.2: Object keys MUST be sorted lexicographically
    (Unicode code point order).
    """
    sorted_keys = sorted(obj.keys())
    return {k: _canonicalize_value(obj[k]) for k in sorted_keys}


def _canonicalize_array(arr: Union[List, tuple]) -> List:
    """
    Canonicalize an array, preserving order.
    
    Per Section 11.2: Arrays - Order preserved exactly as provided.
    """
    return [_canonicalize_value(item) for item in arr]


# Test the canonicalization with the spec example
if __name__ == "__main__":
    # From Section 11.5
    non_canonical = {
        "parameters": {"currency": "USD", "amount": "50000000"},
        "environment_id": "production",
        "tenant_id": "acme-corp",
        "action_id": "018d9e6e-6c1e-7b6a-9c0d-111111111111",
        "action_type": "wire_transfer"
    }
    
    result = canonicalize_str(non_canonical)
    print("Canonical output:")
    print(result)
