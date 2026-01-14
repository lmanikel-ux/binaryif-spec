
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

# TV-03: Permit allows execution once
def test_tv03_single_use():
    action = load("fixtures/action.json")
    evidence = load("fixtures/evidence.json")
    ah = sha256_hex(canonicalize(action))
    cfo = make_cfo(ah)
    ctx = {"remaining_daily_limit": 1000000, "cfo_token": cfo}
    permit = authorize(action, evidence, ctx)
    r1 = execute(action, permit)
    assert r1.status_code == 200
    r2 = execute(action, permit)
    assert r2.status_code == 403

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
    permit["signatures"][0]["sig_b64"] = permit["signatures"][0]["sig_b64"][::-1]
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
