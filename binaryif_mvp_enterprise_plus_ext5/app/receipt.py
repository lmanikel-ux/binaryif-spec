"""
Execution Receipt Builder for BinaryIF MVP.

This module generates EXECUTION_RECEIPT artifacts that cryptographically bind
a PERMIT to its actual execution outcome, completing the chain of custody.

The Execution Binding pattern ensures:
1. Every execution is tied to exactly one PERMIT
2. The PERMIT cannot be reused (single-use enforcement)
3. The execution outcome is cryptographically signed
4. The complete chain is independently verifiable
"""

from typing import Dict, Any, Optional

from .util import canonicalize, sha256_hex, now_epoch, generate_id, generate_nonce


def build_execution_receipt(
    permit: Dict[str, Any],
    execution_result: Dict[str, Any],
    execution_environment_id: str,
    environment_type: str = "interceptor",
    executed_at: Optional[int] = None
) -> Dict[str, Any]:
    """
    Build an EXECUTION_RECEIPT artifact.
    
    The receipt cryptographically binds the PERMIT to the execution outcome,
    creating an immutable record of what was authorized and what was executed.
    
    Args:
        permit: The PERMIT artifact that authorized this execution
        execution_result: Dict containing:
            - status: "SUCCESS" or "FAILURE"
            - external_reference: Optional transaction ID from execution environment
            - error_code: Optional error code if status is FAILURE
        execution_environment_id: Identifier of the execution environment
        environment_type: "interceptor" (BinaryIF-signed) or "native" (execution env-signed)
        executed_at: Epoch timestamp of execution (defaults to now)
    
    Returns:
        Unsigned EXECUTION_RECEIPT artifact dict
    """
    if executed_at is None:
        executed_at = now_epoch()
    
    # Compute the permit hash for binding
    permit_body = dict(permit)
    permit_body.pop("signatures", None)
    permit_hash = sha256_hex(canonicalize(permit_body))
    
    return {
        "binaryif_version": "0.1",
        "artifact_type": "EXECUTION_RECEIPT",
        "receipt_id": generate_id(16),
        "permit_id": permit.get("permit_id"),
        "permit_hash": permit_hash,
        "action_hash": permit.get("action_hash"),
        "executed_at": executed_at,
        "execution_environment": {
            "environment_id": execution_environment_id,
            "environment_type": environment_type
        },
        "execution_result": {
            "status": execution_result.get("status", "SUCCESS"),
            "external_reference": execution_result.get("external_reference"),
            "error_code": execution_result.get("error_code")
        },
        "nonce": generate_nonce(16)
    }


def receipt_body_for_signing(receipt: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract the receipt body for canonical signing.
    
    Removes the signatures field to get the body that should be signed.
    
    Args:
        receipt: The receipt artifact dict
        
    Returns:
        Receipt dict without signatures field
    """
    body = dict(receipt)
    body.pop("signatures", None)
    return body


def verify_receipt_permit_binding(receipt: Dict[str, Any], permit: Dict[str, Any]) -> bool:
    """
    Verify that a receipt is correctly bound to a permit.
    
    This function checks the cryptographic binding between the receipt
    and the permit to ensure they form a valid chain.
    
    Checks:
    1. receipt.permit_id == permit.permit_id
    2. receipt.permit_hash == hash(permit body)
    3. receipt.action_hash == permit.action_hash
    
    Args:
        receipt: The EXECUTION_RECEIPT artifact
        permit: The PERMIT artifact
        
    Returns:
        True if binding is valid, False otherwise
    """
    # Check permit_id match
    if receipt.get("permit_id") != permit.get("permit_id"):
        return False
    
    # Check permit_hash match
    permit_body = dict(permit)
    permit_body.pop("signatures", None)
    expected_hash = sha256_hex(canonicalize(permit_body))
    if receipt.get("permit_hash") != expected_hash:
        return False
    
    # Check action_hash match
    if receipt.get("action_hash") != permit.get("action_hash"):
        return False
    
    return True


def verify_receipt_signature(
    receipt: Dict[str, Any],
    trust_store: Dict[str, Any],
    verify_func
) -> bool:
    """
    Verify the cryptographic signature on a receipt.
    
    Args:
        receipt: The EXECUTION_RECEIPT artifact
        trust_store: Trust store containing public keys
        verify_func: Function to verify Ed25519 signatures
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        sigs = receipt.get("signatures", [])
        if not sigs:
            return False
        
        s = sigs[0]
        kid = s.get("kid")
        pub = trust_store.get("binaryif_artifact_keys", {}).get(kid)
        if not pub:
            return False
        
        body = dict(receipt)
        body.pop("signatures", None)
        
        return verify_func(s.get("sig_b64", ""), canonicalize(body), pub)
    except Exception:
        return False
