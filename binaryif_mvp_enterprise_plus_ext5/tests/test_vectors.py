
import json, os, time
from fastapi.testclient import TestClient
from app.main import app
from app.util import canonicalize, sha256_hex
import subprocess, sys

client = TestClient(app)

def load(p):
    return json.load(open(p,"r",encoding="utf-8"))

def make_cfo(action_hash: str):
    out = subprocess.check_output([sys.executable, "tools/make_cfo_token.py", action_hash])
    return json.loads(out.decode("utf-8"))

def authorize(action, evidence, context):
    return client.post("/authorize_wire", json={"action": action, "evidence": evidence, "context": context}).json()

def execute(action, permit):
    return client.post("/execute_wire", json={"action": action, "permit": permit})

# TV-01: Happy path -> PERMIT
def test_tv01_happy_path_permit():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["artifact_type"] == "PERMIT"
    assert art["decision"] == "TRUE"

# TV-02: Execute without permit -> blocked
def test_tv02_execute_without_permit_blocked():
    action = load("fixtures/action.json")
    r = client.post("/execute_wire", json={"action": action, "permit": {}})
    assert r.status_code == 403

# TV-03: Permit allows execution once (idempotent return on replay)
def test_tv03_single_use():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    r1 = execute(action, permit)
    assert r1.status_code == 200
    receipt1 = r1.json()
    # Second execution returns the same receipt (idempotent)
    r2 = execute(action, permit)
    assert r2.status_code == 200
    receipt2 = r2.json()
    # Both receipts should be identical (same receipt_id)
    assert receipt1.get("receipt_id") == receipt2.get("receipt_id")

# TV-04: Below threshold -> WITHHOLD
def test_tv04_below_threshold_withhold():
    action = load("fixtures/action_low.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["artifact_type"] == "WITHHOLD"

# TV-05: Bad allowlist -> WITHHOLD
def test_tv05_allowlist_miss_withhold():
    action = load("fixtures/action_bad_dest.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["artifact_type"] == "WITHHOLD"

# TV-06: Limit exceeded -> WITHHOLD
def test_tv06_limit_exceeded_withhold():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["artifact_type"] == "WITHHOLD"

# TV-07: Missing CFO -> WITHHOLD
def test_tv07_missing_cfo_withhold():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ctx = {"remaining_daily_limit": 1000000}
    art = authorize(action, evidence, ctx)
    assert art["artifact_type"] == "WITHHOLD"

# TV-08: Stale CFO token -> WITHHOLD (by manipulating issued_at)
def test_tv08_stale_cfo_withhold():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    cfo["issued_at"] = 1  # ancient
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["artifact_type"] == "WITHHOLD"

# TV-09: Action mismatch -> blocked
def test_tv09_action_mismatch_blocked():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    bad_action = load("fixtures/action_low.json")
    r = execute(bad_action, permit)
    assert r.status_code == 403

# TV-10: Tampered permit signature -> blocked
def test_tv10_tampered_signature_blocked():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    # Replace with a different valid base64 signature (wrong key)
    import base64
    fake_sig = base64.b64encode(b'X' * 64).decode('utf-8')
    permit["signatures"][0]["sig_b64"] = fake_sig
    r = execute(action, permit)
    assert r.status_code == 403

# TV-11: Permit expiry -> blocked (force expires_at in past)
def test_tv11_expired_permit_blocked():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    permit["expires_at"] = 1
    r = execute(action, permit)
    assert r.status_code == 403

# TV-12: WITHHOLD must contain failed_gates
def test_tv12_withhold_has_failed_gates():
    action = load("fixtures/action_low.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert "failed_gates" in art and len(art["failed_gates"]) >= 1

# TV-13: Ruleset hash present
def test_tv13_ruleset_hash_present():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["ruleset"]["ruleset_hash"]

# TV-14: Evidence hash present (bundle hash)
def test_tv14_bundle_hash_present():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["evidence"]["bundle_hash"]

# TV-15: Context hash present
def test_tv15_context_hash_present():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art["context"]["context_hash"]

# TV-16: Nonce present (anti-replay)
def test_tv16_nonce_present():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art.get("nonce")

# TV-17: Permit has permit_id
def test_tv17_permit_id_present():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert art.get("permit_id")

# TV-18: Permit includes TTL window (expires_at > issued_at)
def test_tv18_ttl_window():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    art = authorize(action, evidence, ctx)
    assert int(art["expires_at"]) > int(art["issued_at"])

# TV-19: Artifact log grows on authorize
def test_tv19_artifact_log_grows():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    before = client.get("/artifact_log").json()
    authorize(action, evidence, ctx)
    after = client.get("/artifact_log").json()
    assert len(after) >= len(before) + 1

# TV-20: Verifier validates a permit (offline)
def test_tv20_verifier_validates():
    from verifier.verify import load as vload
    # create a permit, then write to artifacts/permit.json and run verifier
    import os
    os.makedirs("artifacts", exist_ok=True)
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    with open("artifacts/permit.json","w",encoding="utf-8") as f:
        json.dump(permit, f, indent=2)
    # Run verifier as module
    import subprocess, sys
    out = subprocess.check_output([sys.executable, "verifier/verify.py", "artifacts/permit.json", "fixtures/action.json", "rules/wire_ruleset.json", "trust/trust_store.json"])
    assert b"VALID" in out


# ============================================================
# EXECUTION BINDING CONFORMANCE TESTS (TV-21 through TV-27)
# ============================================================

# TV-21: Execute returns EXECUTION_RECEIPT with correct structure
def test_tv21_execution_receipt_structure():
    """Verify that execute_wire returns a properly structured EXECUTION_RECEIPT."""
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    
    r = execute(action, permit)
    assert r.status_code == 200
    receipt = r.json()
    
    # Verify receipt structure
    assert receipt.get("artifact_type") == "EXECUTION_RECEIPT"
    assert receipt.get("binaryif_version") == "0.1"
    assert receipt.get("permit_id") == permit.get("permit_id")
    assert receipt.get("permit_hash")  # Must have permit hash
    assert receipt.get("action_hash") == permit.get("action_hash")
    assert receipt.get("executed_at")  # Must have execution timestamp
    assert receipt.get("receipt_id")  # Must have unique ID
    assert receipt.get("nonce")  # Must have nonce
    
    # Verify execution environment
    env = receipt.get("execution_environment", {})
    assert env.get("environment_id")
    assert env.get("environment_type") in ["interceptor", "native"]
    
    # Verify execution result
    result = receipt.get("execution_result", {})
    assert result.get("status") == "SUCCESS"
    assert result.get("external_reference")  # wire_id
    
    # Verify signature
    sigs = receipt.get("signatures", [])
    assert len(sigs) >= 1
    assert sigs[0].get("kid")
    assert sigs[0].get("sig_b64")


# TV-22: EXECUTION_RECEIPT.permit_hash matches hash(PERMIT body)
def test_tv22_receipt_permit_hash_binding():
    """Verify that the receipt's permit_hash correctly binds to the permit."""
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    
    r = execute(action, permit)
    assert r.status_code == 200
    receipt = r.json()
    
    # Calculate expected permit hash
    permit_body = dict(permit)
    permit_body.pop("signatures", None)
    expected_hash = sha256_hex(canonicalize(permit_body))
    
    assert receipt.get("permit_hash") == expected_hash


# TV-23: Single-use enforcement - second execution returns same receipt (idempotency)
def test_tv23_single_use_idempotency():
    """Verify that attempting to use a consumed permit returns the existing receipt."""
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    
    # First execution
    r1 = execute(action, permit)
    assert r1.status_code == 200
    receipt1 = r1.json()
    
    # Second execution - should return same receipt (idempotent)
    r2 = execute(action, permit)
    # Could be 200 (returning existing receipt) or 403 (blocked)
    if r2.status_code == 200:
        receipt2 = r2.json()
        assert receipt2.get("receipt_id") == receipt1.get("receipt_id")
    else:
        assert r2.status_code == 403


# TV-24: verify_chain endpoint validates correct chain
def test_tv24_verify_chain_valid():
    """Verify that the verify_chain endpoint correctly validates a valid chain."""
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    
    r = execute(action, permit)
    assert r.status_code == 200
    receipt = r.json()
    
    # Verify the chain
    verify_r = client.post("/insurer/verify_chain", json={
        "permit": permit,
        "receipt": receipt,
        "action": action
    })
    assert verify_r.status_code == 200
    result = verify_r.json()
    
    assert result.get("valid") == True
    assert len(result.get("checks", [])) >= 7
    assert result.get("chain_summary")
    assert result["chain_summary"]["permit_id"] == permit.get("permit_id")
    assert result["chain_summary"]["receipt_id"] == receipt.get("receipt_id")


# TV-25: verify_chain detects tampered receipt
def test_tv25_verify_chain_tampered_receipt():
    """Verify that the verify_chain endpoint detects a tampered receipt."""
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    
    r = execute(action, permit)
    assert r.status_code == 200
    receipt = r.json()
    
    # Tamper with the receipt
    receipt["permit_hash"] = "0" * 64  # Invalid hash
    
    # Verify the chain
    verify_r = client.post("/insurer/verify_chain", json={
        "permit": permit,
        "receipt": receipt,
        "action": action
    })
    assert verify_r.status_code == 200
    result = verify_r.json()
    
    assert result.get("valid") == False
    # At least one check should fail
    failed_checks = [c for c in result.get("checks", []) if not c.get("result")]
    assert len(failed_checks) >= 1


# TV-26: verify_chain detects action hash mismatch
def test_tv26_verify_chain_action_mismatch():
    """Verify that the verify_chain endpoint detects action hash inconsistency."""
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    
    r = execute(action, permit)
    assert r.status_code == 200
    receipt = r.json()
    
    # Use a different action
    different_action = load("fixtures/action_low.json")
    
    # Verify the chain with wrong action
    verify_r = client.post("/insurer/verify_chain", json={
        "permit": permit,
        "receipt": receipt,
        "action": different_action
    })
    assert verify_r.status_code == 200
    result = verify_r.json()
    
    assert result.get("valid") == False


# TV-27: Receipt logged to WORM log
def test_tv27_receipt_logged_to_worm():
    """Verify that execution receipts are logged to the artifact log."""
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    
    before = client.get("/artifact_log").json()
    
    r = execute(action, permit)
    assert r.status_code == 200
    receipt = r.json()
    
    after = client.get("/artifact_log").json()
    
    # Log should have grown by at least 1 (the receipt)
    assert len(after) >= len(before) + 1
    
    # Find the receipt in the log
    receipt_entries = [e for e in after if e.get("artifact_type") == "EXECUTION_RECEIPT"]
    assert len(receipt_entries) >= 1
    
    # Verify the receipt ID is in the log
    receipt_ids = [e.get("artifact_id") for e in receipt_entries]
    assert receipt.get("receipt_id") in receipt_ids
