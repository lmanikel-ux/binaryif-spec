"""
Artifact builder module for BinaryIF MVP.

Provides functions to construct PERMIT and WITHHOLD artifacts
with proper structure and cryptographic bindings.
"""

from typing import Dict, Any, List, Optional

from .util import sha256_hex, generate_id, generate_nonce


def build_permit(
    action_hash: str,
    ruleset: Dict[str, Any],
    ruleset_hash: str,
    evidence_hash: str,
    context_hash: str,
    now_epoch: int
) -> Dict[str, Any]:
    """
    Build a PERMIT artifact.
    
    A PERMIT indicates that all gates passed and the action is authorized.
    
    Args:
        action_hash: SHA-256 hash of the action envelope
        ruleset: The ruleset configuration
        ruleset_hash: SHA-256 hash of the ruleset
        evidence_hash: SHA-256 hash of the evidence bundle
        context_hash: SHA-256 hash of the request context
        now_epoch: Current Unix timestamp
        
    Returns:
        Unsigned PERMIT artifact dict
    """
    issued_at = now_epoch
    expires_at = issued_at + int(ruleset["permit_ttl_seconds"])
    
    return {
        "binaryif_version": "0.1",
        "artifact_type": "PERMIT",
        "decision": "TRUE",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "action_hash": action_hash,
        "ruleset": {
            "ruleset_id": ruleset["ruleset_id"],
            "ruleset_version": ruleset["ruleset_version"],
            "ruleset_hash": ruleset_hash
        },
        "evidence": {"bundle_hash": evidence_hash},
        "context": {"context_hash": context_hash},
        "nonce": generate_nonce(16),
        "permit_id": generate_id(16)
    }


def build_withhold(
    action_hash: str,
    ruleset: Dict[str, Any],
    ruleset_hash: str,
    evidence_hash: str,
    context_hash: str,
    now_epoch: int,
    failed: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Build a WITHHOLD artifact.
    
    A WITHHOLD indicates that one or more gates failed and the action
    is not authorized. It includes details of which gates failed.
    
    Args:
        action_hash: SHA-256 hash of the action envelope
        ruleset: The ruleset configuration
        ruleset_hash: SHA-256 hash of the ruleset
        evidence_hash: SHA-256 hash of the evidence bundle
        context_hash: SHA-256 hash of the request context
        now_epoch: Current Unix timestamp
        failed: List of failed gate details
        
    Returns:
        Unsigned WITHHOLD artifact dict
    """
    issued_at = now_epoch
    expires_at = issued_at + int(ruleset["permit_ttl_seconds"])
    
    return {
        "binaryif_version": "0.1",
        "artifact_type": "WITHHOLD",
        "decision": "FALSE",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "action_hash": action_hash,
        "ruleset": {
            "ruleset_id": ruleset["ruleset_id"],
            "ruleset_version": ruleset["ruleset_version"],
            "ruleset_hash": ruleset_hash
        },
        "evidence": {"bundle_hash": evidence_hash},
        "context": {"context_hash": context_hash},
        "nonce": generate_nonce(16),
        "withhold_id": generate_id(16),
        "failed_gates": failed
    }


def artifact_body_for_signing(artifact: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract the artifact body for canonical signing.
    
    Removes the signatures field (if present) to get the body
    that should be signed.
    
    Args:
        artifact: The artifact dict
        
    Returns:
        Artifact dict without signatures field
    """
    body = dict(artifact)
    body.pop("signatures", None)
    return body


def chain_entry_hash(prev_entry_hash: Optional[str], payload_hash: str) -> str:
    """
    Compute the hash chain entry hash.
    
    Creates a hash that links to the previous entry, forming
    an immutable chain.
    
    Args:
        prev_entry_hash: Hash of the previous entry (or None for first)
        payload_hash: Hash of the current payload
        
    Returns:
        SHA-256 hash of the concatenated hashes
    """
    data = (prev_entry_hash or "").encode("utf-8") + payload_hash.encode("utf-8")
    return sha256_hex(data)
