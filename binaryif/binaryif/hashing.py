"""
BinaryIF Hashing Specification

Implements Section 12 of the BinaryIF Protocol Specification.
All hashes use SHA-256 with lowercase hexadecimal output.
"""

import hashlib
from typing import Union

from .canonicalization import canonicalize


def sha256_hash(data: Union[bytes, str]) -> str:
    """
    Compute SHA-256 hash with BinaryIF format.
    
    Per Section 12.1:
    - Algorithm: SHA-256
    - Input: UTF-8 bytes
    - Output Format: Lowercase hexadecimal with prefix
    
    Returns:
        Hash string in format "sha256:abcdef..."
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    digest = hashlib.sha256(data).hexdigest().lower()
    return f"sha256:{digest}"


def action_hash(cae: dict) -> str:
    """
    Compute the action hash for a Canonical Action Envelope.
    
    Per Section 12.1:
    action_hash = SHA-256(CJE(CAE))
    """
    canonical_bytes = canonicalize(cae)
    return sha256_hash(canonical_bytes)


def ruleset_hash(ruleset: dict) -> str:
    """
    Compute the ruleset hash.
    
    Per Section 12.2:
    ruleset_hash = SHA-256(CJE(ruleset))
    """
    canonical_bytes = canonicalize(ruleset)
    return sha256_hash(canonical_bytes)


def evidence_bundle_hash(manifest: dict) -> str:
    """
    Compute the evidence bundle hash.
    
    Per Section 12.3:
    bundle_hash = SHA-256(CJE(evidence_manifest))
    """
    canonical_bytes = canonicalize(manifest)
    return sha256_hash(canonical_bytes)


def trust_store_hash(trust_store: dict) -> str:
    """
    Compute the trust store hash.
    
    Per Section 12.4:
    trust_store_hash = SHA-256(CJE(trust_store_snapshot))
    """
    canonical_bytes = canonicalize(trust_store)
    return sha256_hash(canonical_bytes)


def content_hash(data: Union[bytes, str]) -> str:
    """
    Compute content-addressed reference.
    
    Returns:
        Content reference in format "content:sha256:abcdef..."
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    digest = hashlib.sha256(data).hexdigest().lower()
    return f"content:sha256:{digest}"


def verify_hash(declared_hash: str, data: Union[bytes, str]) -> bool:
    """
    Verify that data matches a declared hash.
    
    Per Section 12.5: Verifiers MUST recompute hashes from source data.
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    if declared_hash.startswith("sha256:"):
        computed = sha256_hash(data)
        return computed == declared_hash
    elif declared_hash.startswith("content:sha256:"):
        computed = content_hash(data)
        return computed == declared_hash
    else:
        return False
