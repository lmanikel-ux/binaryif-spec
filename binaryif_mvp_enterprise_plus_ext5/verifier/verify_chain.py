#!/usr/bin/env python3
"""
BinaryIF Offline Chain Verifier

Verifies the complete authorization-to-execution chain without network access.
Suitable for air-gapped auditors and insurers.

Usage:
    python verify_chain.py <permit.json> <receipt.json> <action.json> <trust_store.json>

Output:
    VALID: Chain verification passed
    INVALID: <reason>
"""

import sys
import json
import hashlib
import base64
from typing import Dict, Any, Tuple, List

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignature
except ImportError:
    print("ERROR: PyNaCl not installed. Run: pip install pynacl", file=sys.stderr)
    sys.exit(1)


def canonicalize(obj: Any) -> bytes:
    """Canonical JSON serialization (sorted keys, no whitespace)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """SHA-256 hash as hex string."""
    return hashlib.sha256(data).hexdigest()


def verify_ed25519(sig_b64: str, message: bytes, pub_b64: str) -> bool:
    """Verify an Ed25519 signature."""
    try:
        sig = base64.b64decode(sig_b64)
        pub = base64.b64decode(pub_b64)
        vk = VerifyKey(pub)
        vk.verify(message, sig)
        return True
    except (BadSignature, Exception):
        return False


def load_json_file(path: str) -> Dict[str, Any]:
    """Load a JSON file."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def verify_artifact_signature(artifact: Dict[str, Any], trust_store: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Verify the signature on an artifact (PERMIT or EXECUTION_RECEIPT).
    Returns (valid, reason).
    """
    sigs = artifact.get("signatures", [])
    if not sigs:
        return False, "No signatures present"
    
    sig = sigs[0]
    kid = sig.get("kid")
    sig_b64 = sig.get("sig_b64")
    
    if not kid or not sig_b64:
        return False, "Missing kid or sig_b64"
    
    # Look up public key in trust store
    pub_b64 = trust_store.get("binaryif_artifact_keys", {}).get(kid)
    if not pub_b64:
        return False, f"Unknown key ID: {kid}"
    
    # Extract body (without signatures)
    body = dict(artifact)
    body.pop("signatures", None)
    
    # Verify signature
    if not verify_ed25519(sig_b64, canonicalize(body), pub_b64):
        return False, "Invalid signature"
    
    return True, "Valid"


def verify_chain(
    permit: Dict[str, Any],
    receipt: Dict[str, Any],
    action: Dict[str, Any],
    trust_store: Dict[str, Any]
) -> Tuple[bool, List[Dict[str, Any]]]:
    """
    Verify the complete authorization-to-execution chain.
    Returns (all_valid, checks).
    """
    checks = []
    
    # CHECK 1: Verify PERMIT signature
    permit_sig_valid, permit_sig_reason = verify_artifact_signature(permit, trust_store)
    checks.append({
        "check": "permit_signature",
        "result": permit_sig_valid,
        "reason": permit_sig_reason
    })
    
    # CHECK 2: Verify PERMIT was not expired at execution time
    try:
        permit_expires_at = int(permit.get("expires_at", 0))
        executed_at = int(receipt.get("executed_at", 0))
        permit_not_expired = permit_expires_at >= executed_at
        reason = "Valid" if permit_not_expired else f"PERMIT expired at {permit_expires_at}, execution at {executed_at}"
    except Exception as e:
        permit_not_expired = False
        reason = str(e)
    checks.append({
        "check": "permit_not_expired",
        "result": permit_not_expired,
        "reason": reason
    })
    
    # CHECK 3: Verify RECEIPT signature
    receipt_sig_valid, receipt_sig_reason = verify_artifact_signature(receipt, trust_store)
    checks.append({
        "check": "receipt_signature",
        "result": receipt_sig_valid,
        "reason": receipt_sig_reason
    })
    
    # CHECK 4: Verify RECEIPT.permit_id == PERMIT.permit_id
    permit_id_match = receipt.get("permit_id") == permit.get("permit_id")
    checks.append({
        "check": "permit_id_match",
        "result": permit_id_match,
        "reason": "Valid" if permit_id_match else f"Receipt permit_id={receipt.get('permit_id')}, Permit permit_id={permit.get('permit_id')}"
    })
    
    # CHECK 5: Verify RECEIPT.permit_hash == hash(PERMIT body)
    try:
        permit_body = dict(permit)
        permit_body.pop("signatures", None)
        expected_hash = sha256_hex(canonicalize(permit_body))
        actual_hash = receipt.get("permit_hash")
        permit_hash_match = actual_hash == expected_hash
        reason = "Valid" if permit_hash_match else f"Expected {expected_hash[:16]}..., got {actual_hash[:16] if actual_hash else 'None'}..."
    except Exception as e:
        permit_hash_match = False
        reason = str(e)
    checks.append({
        "check": "permit_hash_match",
        "result": permit_hash_match,
        "reason": reason
    })
    
    # CHECK 6: Verify action hash chain consistency
    try:
        action_hash = sha256_hex(canonicalize(action))
        permit_action_hash = permit.get("action_hash")
        receipt_action_hash = receipt.get("action_hash")
        action_hash_chain = (action_hash == permit_action_hash == receipt_action_hash)
        if action_hash_chain:
            reason = "Valid"
        else:
            reason = f"Action={action_hash[:16]}..., Permit={permit_action_hash[:16] if permit_action_hash else 'None'}..., Receipt={receipt_action_hash[:16] if receipt_action_hash else 'None'}..."
    except Exception as e:
        action_hash_chain = False
        reason = str(e)
    checks.append({
        "check": "action_hash_chain",
        "result": action_hash_chain,
        "reason": reason
    })
    
    # CHECK 7: Verify execution was successful
    try:
        execution_result = receipt.get("execution_result", {})
        execution_success = execution_result.get("status") == "SUCCESS"
        reason = "Valid" if execution_success else f"Status={execution_result.get('status')}"
    except Exception as e:
        execution_success = False
        reason = str(e)
    checks.append({
        "check": "execution_success",
        "result": execution_success,
        "reason": reason
    })
    
    all_valid = all(c["result"] for c in checks)
    return all_valid, checks


def main():
    if len(sys.argv) != 5:
        print("Usage: python verify_chain.py <permit.json> <receipt.json> <action.json> <trust_store.json>", file=sys.stderr)
        sys.exit(1)
    
    permit_path = sys.argv[1]
    receipt_path = sys.argv[2]
    action_path = sys.argv[3]
    trust_store_path = sys.argv[4]
    
    try:
        permit = load_json_file(permit_path)
        receipt = load_json_file(receipt_path)
        action = load_json_file(action_path)
        trust_store = load_json_file(trust_store_path)
    except FileNotFoundError as e:
        print(f"INVALID: File not found - {e.filename}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"INVALID: JSON parse error - {e}", file=sys.stderr)
        sys.exit(1)
    
    all_valid, checks = verify_chain(permit, receipt, action, trust_store)
    
    # Print detailed results
    print("\n" + "=" * 60)
    print("BINARYIF CHAIN VERIFICATION REPORT")
    print("=" * 60)
    
    for check in checks:
        status = "✓ PASS" if check["result"] else "✗ FAIL"
        print(f"\n{status}: {check['check']}")
        print(f"       {check['reason']}")
    
    print("\n" + "=" * 60)
    
    if all_valid:
        print("RESULT: VALID - Chain verification passed")
        print("=" * 60)
        
        # Print chain summary
        print("\nCHAIN SUMMARY:")
        print(f"  Permit ID:      {permit.get('permit_id')}")
        print(f"  Receipt ID:     {receipt.get('receipt_id')}")
        print(f"  Action Hash:    {permit.get('action_hash', '')[:32]}...")
        print(f"  Authorized At:  {permit.get('issued_at')}")
        print(f"  Executed At:    {receipt.get('executed_at')}")
        print(f"  External Ref:   {receipt.get('execution_result', {}).get('external_reference')}")
        print(f"  Environment:    {receipt.get('execution_environment', {}).get('environment_id')}")
        
        sys.exit(0)
    else:
        failed = [c for c in checks if not c["result"]]
        print(f"RESULT: INVALID - {len(failed)} check(s) failed")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
