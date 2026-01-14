"""
BinaryIF MVP (Enterprise++) - Main Application

This module provides the FastAPI application for the BinaryIF protocol,
implementing deterministic action-authorization with cryptographic verification.

Endpoints:
- POST /authorize_wire: Evaluate gates and issue PERMIT or WITHHOLD
- POST /execute_wire: Execute action with Execution Binding
- GET /artifact_log: Export the complete artifact log
- GET /insurer/proof: Get artifact log proof for insurers
- GET /insurer/permit/{permit_id}: Retrieve permit by ID
- GET /insurer/receipt/{permit_id}: Retrieve receipt by permit ID
- POST /insurer/verify_chain: Verify complete authorization-to-execution chain
"""

import json
import os
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .config import (
    AUTHORIZE_RPM, EXECUTE_RPM, TRUST_STORE_PATH, REVOCATION_LIST_PATH,
    RULESET_PATH, ALLOWLIST_PATH, SIGNER_TYPE, SIGNING_KEY_PATH,
    AWS_KMS_KEY_ID, AWS_REGION, AWS_KMS_KID, EXECUTION_ENVIRONMENT_ID,
    load_json_cached, load_ruleset, load_revocation_list
)
from .db import (
    init_db, store_permit, mark_permit_used, insert_nonce,
    export_artifact_log_full, latest_entry_hash,
    is_permit_consumed, consume_permit_atomic, get_receipt_by_permit_id
)
from .keys import KeyProvider, get_key_provider, verify_ed25519
from .gates import gate_allowlist, gate_amount_limit, gate_cfo_token
from .artifacts import build_permit, build_withhold, artifact_body_for_signing, chain_entry_hash
from .receipt import build_execution_receipt, receipt_body_for_signing
from .log_backends import get_log_backend
from .policy_adapter import external_policy_allows
from .rate_limit import RateLimiter
from .models import AuthorizationRequest, ExecuteRequest
from .util import canonicalize, sha256_hex, now_epoch
from .insurer_api import get_permit_by_id, get_trust_snapshot_by_hash, artifact_log_proof
from .logging_config import audit_log, set_request_id, configure_logging


# ============================================================
# Application Setup
# ============================================================

app = FastAPI(
    title="BinaryIF MVP (Enterprise++)",
    description="Deterministic action-authorization layer for autonomous systems",
    version="0.1.0"
)

# CORS middleware for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
LOG = get_log_backend()
auth_limiter = RateLimiter(AUTHORIZE_RPM)
exec_limiter = RateLimiter(EXECUTE_RPM)
KEYS: Optional[KeyProvider] = None


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
def _startup() -> None:
    """Initialize application state on startup."""
    global KEYS
    configure_logging()
    init_db()
    KEYS = get_key_provider(
        signer_type=SIGNER_TYPE,
        signing_key_path=SIGNING_KEY_PATH,
        trust_store_path=TRUST_STORE_PATH,
        kms_key_id=AWS_KMS_KEY_ID,
        kms_region=AWS_REGION,
        kms_kid=AWS_KMS_KID
    )


# ============================================================
# Helper Functions
# ============================================================

def _trust_store_hash() -> str:
    """Compute hash of the current trust store."""
    return sha256_hex(canonicalize(load_json_cached(TRUST_STORE_PATH)))


def _revocation_list_hash() -> str:
    """Compute hash of the current revocation list."""
    return sha256_hex(canonicalize(load_revocation_list()))


def _is_revoked(kid: str, issued_at: int, revocation: Dict[str, Any]) -> bool:
    """Check if a key is revoked at the given time."""
    effective = int(revocation.get("effective_at_epoch", 0))
    revoked = set(revocation.get("revoked_kids", []))
    return issued_at >= effective and kid in revoked


def _validate_permit_signature(
    permit: Dict[str, Any],
    trust_store: Dict[str, Any],
    revocation: Dict[str, Any],
    now: int
) -> None:
    """
    Validate permit signature and check for revocation/expiry.
    
    Raises HTTPException on validation failure.
    """
    # Validate permit type
    if permit.get("artifact_type") != "PERMIT" or permit.get("decision") != "TRUE":
        raise HTTPException(403, "NO_VALID_PERMIT")
    
    # Validate signature exists
    sigs = permit.get("signatures", [])
    if not sigs:
        raise HTTPException(403, "MISSING_SIGNATURE")
    
    s = sigs[0]
    kid = s.get("kid")
    pub = trust_store.get("binaryif_artifact_keys", {}).get(kid)
    if not pub:
        raise HTTPException(403, "UNKNOWN_KID")
    
    # Validate issued_at
    issued_at = int(permit.get("issued_at", 0))
    if issued_at <= 0:
        raise HTTPException(403, "MISSING_ISSUED_AT")
    
    # Check revocation
    if _is_revoked(kid, issued_at, revocation):
        raise HTTPException(403, "KEY_REVOKED")
    
    # Verify signature
    body = dict(permit)
    body.pop("signatures", None)
    if not verify_ed25519(s.get("sig_b64", ""), canonicalize(body), pub):
        raise HTTPException(403, "INVALID_SIGNATURE")
    
    # Check expiry
    if int(permit.get("expires_at", 0)) < now:
        raise HTTPException(403, "PERMIT_EXPIRED")


def _log_artifact(
    artifact_id: str,
    artifact_type: str,
    issued_at: int,
    payload: bytes,
    artifact_json: str
) -> None:
    """Log an artifact to the WORM log."""
    prev = latest_entry_hash()
    payload_hash = sha256_hex(payload)
    entry_hash = chain_entry_hash(prev, payload_hash)
    LOG.write_entry(artifact_id, artifact_type, issued_at, payload_hash, entry_hash, artifact_json)


# ============================================================
# Endpoints
# ============================================================

@app.get("/artifact_log")
def artifact_log() -> List[Dict[str, Any]]:
    """Export the complete artifact log."""
    return export_artifact_log_full()


@app.get("/health")
def health_check() -> Dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy", "version": "0.1.0"}


@app.post("/authorize_wire")
def authorize_wire(req: AuthorizationRequest) -> Dict[str, Any]:
    """
    Evaluate authorization gates and issue PERMIT or WITHHOLD.
    
    This endpoint:
    1. Validates the action, evidence, and context
    2. Evaluates all configured gates
    3. Issues a signed PERMIT if all gates pass
    4. Issues a signed WITHHOLD if any gate fails
    5. Logs the artifact to the WORM log
    """
    request_id = set_request_id()
    
    # Rate limiting
    if not auth_limiter.allow('authorize'):
        audit_log.rate_limit_exceeded('authorize', '/authorize_wire')
        raise HTTPException(429, 'RATE_LIMIT')
    
    ruleset = load_ruleset()
    trust_store = KEYS.get_trust_store()
    revocation = load_revocation_list()
    now = now_epoch()
    
    # Compute hashes
    action_hash = sha256_hex(canonicalize(req.action.model_dump()))
    ruleset_hash = sha256_hex(canonicalize(ruleset))
    evidence_hash = sha256_hex(canonicalize(req.evidence.model_dump()))
    context_hash = sha256_hex(canonicalize(req.context))
    
    # Extract action parameters
    amount = int(req.action.parameters.get("amount", 0))
    dest = req.action.parameters.get("destination_account_hash", "")
    
    # Log authorization request
    audit_log.authorization_request(
        action_hash=action_hash,
        tenant_id=req.action.tenant_id,
        action_type=req.action.action_type,
        amount=amount
    )
    
    # Evaluate gates
    failed: List[Dict[str, str]] = []
    
    # External policy hook (OPA)
    ext = external_policy_allows(req.action.model_dump(), req.evidence.model_dump(), req.context)
    if ext is False:
        failed.append({"gate_id": "external_policy", "failure": "DENY"})
    
    # Threshold gate
    if amount < int(ruleset["threshold_amount"]):
        failed.append({"gate_id": "threshold", "failure": "BELOW_THRESHOLD"})
    
    # Allowlist gate
    if not gate_allowlist(dest, ALLOWLIST_PATH):
        failed.append({"gate_id": "recipient_allowlist", "failure": "MISSING"})
    
    # Daily limit gate
    if not gate_amount_limit(amount, req.context):
        failed.append({"gate_id": "daily_limit", "failure": "EXCEEDED"})
    
    # CFO token gate
    if not gate_cfo_token(
        action_hash, req.context, trust_store, now,
        int(ruleset["cfo_freshness_seconds"]),
        int(ruleset["max_clock_skew_seconds"])
    ):
        failed.append({"gate_id": "cfo_signature", "failure": "MISSING_OR_INVALID"})
    
    # Build artifact
    if failed:
        art = build_withhold(action_hash, ruleset, ruleset_hash, evidence_hash, context_hash, now, failed)
    else:
        art = build_permit(action_hash, ruleset, ruleset_hash, evidence_hash, context_hash, now)
        ok = insert_nonce(art["nonce"], art["expires_at"])
        if not ok:
            art = build_withhold(
                action_hash, ruleset, ruleset_hash, evidence_hash, context_hash, now,
                [{"gate_id": "nonce", "failure": "REPLAY"}]
            )
    
    # Add trust bindings
    art["trust"] = {
        "trust_store_hash": _trust_store_hash(),
        "revocation_list_hash": _revocation_list_hash()
    }
    
    # Sign artifact
    body = artifact_body_for_signing(art)
    payload = canonicalize(body)
    kid, sig_b64 = KEYS.sign_binaryif_artifact(payload)
    signed = dict(body)
    signed["signatures"] = [{"kid": kid, "alg": "ed25519", "sig_b64": sig_b64}]
    
    # Store permit if applicable
    if signed.get("artifact_type") == "PERMIT":
        store_permit(signed["permit_id"], json.dumps(signed, sort_keys=True))
    
    # Log to WORM
    artifact_id = signed.get("permit_id") or signed.get("withhold_id")
    _log_artifact(artifact_id, signed["artifact_type"], signed["issued_at"], payload, json.dumps(signed, sort_keys=True))
    
    # Audit log
    audit_log.authorization_decision(
        action_hash=action_hash,
        decision=signed.get("decision", "FALSE"),
        permit_id=signed.get("permit_id"),
        withhold_id=signed.get("withhold_id"),
        failed_gates=signed.get("failed_gates")
    )
    
    return signed


@app.post("/execute_wire")
def execute_wire(req: ExecuteRequest) -> Dict[str, Any]:
    """
    Execute a wire transfer with Execution Binding.
    
    This endpoint:
    1. Validates the PERMIT
    2. Checks if the PERMIT has already been consumed
    3. Executes the action (simulated for MVP)
    4. Generates a signed EXECUTION_RECEIPT
    5. Atomically marks the PERMIT as consumed
    6. Logs the receipt to the WORM log
    7. Returns the signed receipt
    """
    request_id = set_request_id()
    
    # Rate limiting
    if not exec_limiter.allow('execute'):
        audit_log.rate_limit_exceeded('execute', '/execute_wire')
        raise HTTPException(429, 'RATE_LIMIT')
    
    permit = req.permit
    trust_store = KEYS.get_trust_store()
    revocation = load_revocation_list()
    now = now_epoch()
    
    # Get permit ID early for logging
    pid = permit.get("permit_id", "unknown")
    
    # Log execution request
    audit_log.execution_request(
        permit_id=pid,
        action_hash=permit.get("action_hash", "unknown")
    )
    
    # Validate permit
    _validate_permit_signature(permit, trust_store, revocation, now)
    
    # Verify action hash matches
    action_hash = sha256_hex(canonicalize(req.action.model_dump()))
    if permit.get("action_hash") != action_hash:
        audit_log.execution_rejected(pid, "PERMIT_ACTION_MISMATCH")
        raise HTTPException(403, "PERMIT_ACTION_MISMATCH")
    
    # Get permit ID
    pid = permit.get("permit_id")
    if not pid:
        audit_log.execution_rejected("unknown", "MISSING_PERMIT_ID")
        raise HTTPException(403, "MISSING_PERMIT_ID")
    
    # Check if permit already consumed (idempotent return)
    if is_permit_consumed(pid):
        existing_receipt = get_receipt_by_permit_id(pid)
        if existing_receipt:
            return json.loads(existing_receipt)
        audit_log.execution_rejected(pid, "PERMIT_ALREADY_CONSUMED")
        raise HTTPException(403, "PERMIT_ALREADY_CONSUMED")
    
    # Execute the action (simulated for MVP)
    import secrets
    wire_id = secrets.token_hex(8)
    execution_result = {
        "status": "SUCCESS",
        "external_reference": wire_id,
        "error_code": None
    }
    
    # Generate Execution Receipt
    receipt = build_execution_receipt(
        permit=permit,
        execution_result=execution_result,
        execution_environment_id=EXECUTION_ENVIRONMENT_ID,
        environment_type="interceptor",
        executed_at=now
    )
    
    # Sign the receipt
    receipt_body = receipt_body_for_signing(receipt)
    receipt_payload = canonicalize(receipt_body)
    receipt_kid, receipt_sig_b64 = KEYS.sign_binaryif_artifact(receipt_payload)
    signed_receipt = dict(receipt_body)
    signed_receipt["signatures"] = [{"kid": receipt_kid, "alg": "ed25519", "sig_b64": receipt_sig_b64}]
    
    # Atomically consume the permit
    receipt_json = json.dumps(signed_receipt, sort_keys=True)
    if not consume_permit_atomic(pid, receipt["receipt_id"], now, receipt_json):
        # Race condition: another execution consumed it first
        existing_receipt = get_receipt_by_permit_id(pid)
        if existing_receipt:
            return json.loads(existing_receipt)
        audit_log.execution_rejected(pid, "PERMIT_ALREADY_CONSUMED")
        raise HTTPException(403, "PERMIT_ALREADY_CONSUMED")
    
    # Also mark in the old permits table for backward compatibility
    mark_permit_used(pid)
    
    # Log the receipt to WORM log
    _log_artifact(
        signed_receipt["receipt_id"],
        "EXECUTION_RECEIPT",
        signed_receipt["executed_at"],
        receipt_payload,
        receipt_json
    )
    
    # Audit log
    audit_log.execution_complete(
        permit_id=pid,
        receipt_id=signed_receipt["receipt_id"],
        status=execution_result["status"],
        external_reference=wire_id
    )
    
    return signed_receipt


# ============================================================
# Insurer API Endpoints
# ============================================================

@app.get("/insurer/proof")
def insurer_proof() -> Dict[str, Any]:
    """Get artifact log proof for insurers."""
    return artifact_log_proof()


@app.get("/insurer/permit/{permit_id}")
def insurer_get_permit(permit_id: str) -> Dict[str, Any]:
    """Retrieve permit by ID."""
    p = get_permit_by_id(permit_id)
    if not p:
        raise HTTPException(404, "NOT_FOUND")
    return p


@app.get("/insurer/trust/{trust_hash}")
def insurer_get_trust(trust_hash: str) -> Dict[str, Any]:
    """Retrieve trust snapshot by hash."""
    snap = get_trust_snapshot_by_hash(trust_hash)
    if not snap:
        raise HTTPException(404, "NOT_FOUND")
    return snap


@app.get("/insurer/receipt/{permit_id}")
def insurer_get_receipt(permit_id: str) -> Dict[str, Any]:
    """Retrieve the execution receipt for a consumed permit."""
    receipt_json = get_receipt_by_permit_id(permit_id)
    if not receipt_json:
        raise HTTPException(404, "RECEIPT_NOT_FOUND")
    return json.loads(receipt_json)


# ============================================================
# Chain Verification Endpoint
# ============================================================

class VerifyChainRequest(BaseModel):
    """Request to verify the complete authorization-to-execution chain."""
    permit: Dict[str, Any]
    receipt: Dict[str, Any]
    action: Dict[str, Any]


class ChainVerificationResult(BaseModel):
    """Result of chain verification."""
    valid: bool
    checks: List[Dict[str, Any]]
    chain_summary: Optional[Dict[str, Any]] = None


@app.post("/insurer/verify_chain", response_model=ChainVerificationResult)
def verify_chain(req: VerifyChainRequest) -> ChainVerificationResult:
    """
    Verify the complete authorization-to-execution chain.
    
    This endpoint allows insurers to verify:
    1. The PERMIT was validly signed
    2. The PERMIT was not expired at execution time
    3. The EXECUTION_RECEIPT was validly signed
    4. The RECEIPT is correctly bound to the PERMIT
    5. The ACTION hash is consistent across all artifacts
    
    Returns a detailed verification result with all checks.
    """
    trust_store = KEYS.get_trust_store()
    checks: List[Dict[str, Any]] = []
    
    permit = req.permit
    receipt = req.receipt
    action = req.action
    
    # CHECK 1: Verify PERMIT signature
    permit_sig_valid = False
    try:
        sigs = permit.get("signatures", [])
        if sigs:
            s = sigs[0]
            kid = s.get("kid")
            pub = trust_store.get("binaryif_artifact_keys", {}).get(kid)
            if pub:
                body = dict(permit)
                body.pop("signatures", None)
                permit_sig_valid = verify_ed25519(s.get("sig_b64", ""), canonicalize(body), pub)
    except Exception:
        pass
    checks.append({
        "check": "permit_signature",
        "result": permit_sig_valid,
        "description": "PERMIT has valid cryptographic signature"
    })
    
    # CHECK 2: Verify PERMIT was not expired at execution time
    permit_not_expired = False
    try:
        permit_expires_at = int(permit.get("expires_at", 0))
        executed_at = int(receipt.get("executed_at", 0))
        permit_not_expired = permit_expires_at >= executed_at
    except Exception:
        pass
    checks.append({
        "check": "permit_not_expired",
        "result": permit_not_expired,
        "description": "PERMIT was valid at execution time"
    })
    
    # CHECK 3: Verify RECEIPT signature
    receipt_sig_valid = False
    try:
        sigs = receipt.get("signatures", [])
        if sigs:
            s = sigs[0]
            kid = s.get("kid")
            pub = trust_store.get("binaryif_artifact_keys", {}).get(kid)
            if pub:
                body = dict(receipt)
                body.pop("signatures", None)
                receipt_sig_valid = verify_ed25519(s.get("sig_b64", ""), canonicalize(body), pub)
    except Exception:
        pass
    checks.append({
        "check": "receipt_signature",
        "result": receipt_sig_valid,
        "description": "EXECUTION_RECEIPT has valid cryptographic signature"
    })
    
    # CHECK 4: Verify RECEIPT.permit_id == PERMIT.permit_id
    permit_id_match = receipt.get("permit_id") == permit.get("permit_id")
    checks.append({
        "check": "permit_id_match",
        "result": permit_id_match,
        "description": "RECEIPT references correct PERMIT ID"
    })
    
    # CHECK 5: Verify RECEIPT.permit_hash == hash(PERMIT body)
    permit_hash_match = False
    try:
        permit_body = dict(permit)
        permit_body.pop("signatures", None)
        expected_hash = sha256_hex(canonicalize(permit_body))
        permit_hash_match = receipt.get("permit_hash") == expected_hash
    except Exception:
        pass
    checks.append({
        "check": "permit_hash_match",
        "result": permit_hash_match,
        "description": "RECEIPT contains correct PERMIT hash"
    })
    
    # CHECK 6: Verify action hash chain consistency
    action_hash_chain = False
    try:
        computed_action_hash = sha256_hex(canonicalize(action))
        permit_action_hash = permit.get("action_hash")
        receipt_action_hash = receipt.get("action_hash")
        action_hash_chain = (computed_action_hash == permit_action_hash == receipt_action_hash)
    except Exception:
        pass
    checks.append({
        "check": "action_hash_chain",
        "result": action_hash_chain,
        "description": "ACTION hash consistent across all artifacts"
    })
    
    # CHECK 7: Verify execution was successful
    execution_success = False
    try:
        execution_result = receipt.get("execution_result", {})
        execution_success = execution_result.get("status") == "SUCCESS"
    except Exception:
        pass
    checks.append({
        "check": "execution_success",
        "result": execution_success,
        "description": "Execution completed successfully"
    })
    
    # FINAL VERDICT
    all_valid = all(c["result"] for c in checks)
    
    # Build chain summary for valid chains
    chain_summary = None
    if all_valid:
        chain_summary = {
            "permit_id": permit.get("permit_id"),
            "receipt_id": receipt.get("receipt_id"),
            "action_hash": permit.get("action_hash"),
            "authorized_at": permit.get("issued_at"),
            "executed_at": receipt.get("executed_at"),
            "external_reference": receipt.get("execution_result", {}).get("external_reference"),
            "execution_environment": receipt.get("execution_environment", {}).get("environment_id")
        }
    
    return ChainVerificationResult(
        valid=all_valid,
        checks=checks,
        chain_summary=chain_summary
    )
