"""
Gate evaluation module for BinaryIF MVP.

Gates are deterministic sufficiency checks that must all pass
for a PERMIT to be issued. Each gate evaluates a specific condition
and returns True (pass) or False (fail).
"""

import json
from typing import Dict, Any

from .util import canonicalize
from .keys import verify_ed25519


def gate_allowlist(destination_account_hash: str, allowlist_path: str) -> bool:
    """
    Evaluate the recipient allowlist gate.
    
    Checks if the destination account hash is in the approved allowlist.
    
    Args:
        destination_account_hash: SHA-256 hash of the destination account
        allowlist_path: Path to the allowlist JSON file
        
    Returns:
        True if destination is in allowlist, False otherwise
    """
    try:
        with open(allowlist_path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        return destination_account_hash in snap.get("items", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return False


def gate_amount_limit(amount: int, context: Dict[str, Any]) -> bool:
    """
    Evaluate the daily limit gate.
    
    Checks if the requested amount is within the remaining daily limit.
    
    Args:
        amount: The transaction amount
        context: Request context containing remaining_daily_limit
        
    Returns:
        True if amount is within limit, False otherwise
    """
    remaining = int(context.get("remaining_daily_limit", 0))
    return amount <= remaining


def gate_cfo_token(
    action_hash: str,
    context: Dict[str, Any],
    trust_store: Dict[str, Any],
    now_epoch: int,
    freshness: int,
    max_skew: int
) -> bool:
    """
    Evaluate the CFO token gate.
    
    Verifies that a valid, fresh CFO signature exists for this action.
    
    Args:
        action_hash: SHA-256 hash of the action being authorized
        context: Request context containing cfo_token
        trust_store: Trust store containing authority public keys
        now_epoch: Current Unix timestamp
        freshness: Maximum age of token in seconds
        max_skew: Maximum clock skew allowance in seconds
        
    Returns:
        True if valid CFO token exists, False otherwise
    """
    token = context.get("cfo_token")
    if not token:
        return False
    
    # Validate token structure
    kid = token.get("kid")
    if not kid:
        return False
    
    # Get public key from trust store
    pub = trust_store.get("authority_keys", {}).get(kid)
    if not pub:
        return False
    
    # Validate issued_at
    issued_at = int(token.get("issued_at", 0))
    if issued_at <= 0:
        return False
    
    # Check freshness
    if (now_epoch - issued_at) > (freshness + max_skew):
        return False
    
    # Verify action hash matches
    if token.get("signed_action_hash") != action_hash:
        return False
    
    # Verify signature
    payload = canonicalize({
        "kid": kid,
        "issued_at": issued_at,
        "signed_action_hash": action_hash
    })
    
    return verify_ed25519(token.get("sig_b64", ""), payload, pub)


def gate_external_policy(
    action: Dict[str, Any],
    evidence: Dict[str, Any],
    context: Dict[str, Any],
    policy_url: str
) -> bool:
    """
    Evaluate an external policy gate via HTTP.
    
    Calls an external policy service (e.g., OPA) to evaluate the action.
    
    Args:
        action: The action envelope
        evidence: The evidence bundle
        context: Request context
        policy_url: URL of the policy evaluation endpoint
        
    Returns:
        True if policy allows, False otherwise
    """
    try:
        import requests
        
        response = requests.post(
            policy_url,
            json={"action": action, "evidence": evidence, "context": context},
            timeout=5
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get("allow", False)
        
        return False
    except Exception:
        # Fail closed on external policy errors
        return False
