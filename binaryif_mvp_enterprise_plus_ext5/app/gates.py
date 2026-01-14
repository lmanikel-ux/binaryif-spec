
import json
from typing import Dict, Any
from .util import canonicalize
from .keys import verify_ed25519

def gate_allowlist(destination_account_hash: str, allowlist_path: str) -> bool:
    with open(allowlist_path, "r", encoding="utf-8") as f:
        snap = json.load(f)
    return destination_account_hash in snap.get("items", [])

def gate_amount_limit(amount: int, context: Dict[str, Any]) -> bool:
    remaining = int(context.get("remaining_daily_limit", 0))
    return amount <= remaining

def gate_cfo_token(action_hash: str, context: Dict[str, Any], trust_store: dict, now_epoch: int, freshness: int, max_skew: int) -> bool:
    token = context.get("cfo_token")
    if not token:
        return False
    kid = token.get("kid")
    pub = trust_store.get("authority_keys", {}).get(kid)
    if not pub:
        return False
    issued_at = int(token.get("issued_at", 0))
    if issued_at <= 0:
        return False
    if (now_epoch - issued_at) > (freshness + max_skew):
        return False
    if token.get("signed_action_hash") != action_hash:
        return False
    payload = canonicalize({"kid": kid, "issued_at": issued_at, "signed_action_hash": action_hash})
    return verify_ed25519(token.get("sig_b64",""), payload, pub)
