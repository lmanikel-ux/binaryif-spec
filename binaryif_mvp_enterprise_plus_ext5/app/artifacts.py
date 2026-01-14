
import secrets
from typing import Dict, Any, List, Tuple, Optional
from .util import canonicalize, sha256_hex

def build_permit(action_hash: str, ruleset: dict, ruleset_hash: str, evidence_hash: str, context_hash: str, now_epoch: int) -> Dict[str, Any]:
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
        "nonce": secrets.token_hex(16),
        "permit_id": secrets.token_hex(16)
    }

def build_withhold(action_hash: str, ruleset: dict, ruleset_hash: str, evidence_hash: str, context_hash: str, now_epoch: int, failed: List[Dict[str, Any]]) -> Dict[str, Any]:
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
        "nonce": secrets.token_hex(16),
        "withhold_id": secrets.token_hex(16),
        "failed_gates": failed
    }

def artifact_body_for_signing(artifact: Dict[str, Any]) -> Dict[str, Any]:
    a = dict(artifact)
    a.pop("signatures", None)
    return a

def chain_entry_hash(prev_entry_hash: Optional[str], payload_hash: str) -> str:
    data = (prev_entry_hash or "").encode("utf-8") + payload_hash.encode("utf-8")
    return sha256_hex(data)
