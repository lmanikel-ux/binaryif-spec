
import os, json
from fastapi import FastAPI, HTTPException
from .insurer_api import get_permit_by_id, get_trust_snapshot_by_hash, artifact_log_proof
from .models import AuthorizationRequest, ExecuteRequest
from .util import canonicalize, sha256_hex, now_epoch
from .db import init_db, store_permit, mark_permit_used, insert_nonce, export_artifact_log_full
from .keys import FileKeyProvider, AwsKmsEd25519Provider, verify_ed25519
from .gates import gate_allowlist, gate_amount_limit, gate_cfo_token
from .artifacts import build_permit, build_withhold, artifact_body_for_signing, chain_entry_hash
from .log_backends import get_log_backend
from .policy_adapter import external_policy_allows
from .rate_limit import RateLimiter
from .config import AUTHORIZE_RPM, EXECUTE_RPM

app = FastAPI(title="BinaryIF MVP (Enterprise++)")

ALLOWLIST_PATH = "evidence/payee_allowlist_snapshot.json"
RULESET_PATH = "rules/wire_ruleset.json"
TRUST_STORE_PATH = os.getenv("TRUST_STORE_PATH", "trust/trust_store.json")
REVOCATION_LIST_PATH = os.getenv("REVOCATION_LIST_PATH", "trust/revocation_list.json")

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_ruleset():
    return load_json(RULESET_PATH)

def get_key_provider():
    signer = os.getenv("BINARYIF_SIGNER", "file")
    if signer == "aws_kms":
        return AwsKmsEd25519Provider(
            kms_key_id=os.environ["AWS_KMS_KEY_ID"],
            trust_store_path=TRUST_STORE_PATH,
            region=os.getenv("AWS_REGION"),
            kid=os.getenv("AWS_KMS_KID","aws-kms-ed25519")
        )
    return FileKeyProvider(signing_key_path="secrets/binaryif_signing_key.json", trust_store_path=TRUST_STORE_PATH)

def trust_store_hash() -> str:
    return sha256_hex(canonicalize(load_json(TRUST_STORE_PATH)))

def revocation_list_hash() -> str:
    return sha256_hex(canonicalize(load_json(REVOCATION_LIST_PATH)))

def is_revoked(kid: str, issued_at: int, revocation: dict) -> bool:
    effective = int(revocation.get("effective_at_epoch", 0))
    revoked = set(revocation.get("revoked_kids", []))
    return issued_at >= effective and kid in revoked

LOG = get_log_backend()
auth_limiter = RateLimiter(AUTHORIZE_RPM)
exec_limiter = RateLimiter(EXECUTE_RPM)
KEYS = None

@app.on_event("startup")
def _startup():
    global KEYS
    init_db()
    KEYS = get_key_provider()

@app.get("/artifact_log")
def artifact_log():
    return export_artifact_log_full()

@app.post("/authorize_wire")
def authorize_wire(req: AuthorizationRequest):
    # basic rate limit (per-process) for MVP
    if not auth_limiter.allow('authorize'):
        raise HTTPException(429, 'RATE_LIMIT')
    ruleset = load_ruleset()
    trust_store = KEYS.get_trust_store()
    revocation = load_json(REVOCATION_LIST_PATH)
    now = now_epoch()

    action_hash = sha256_hex(canonicalize(req.action.model_dump()))
    ruleset_hash = sha256_hex(canonicalize(ruleset))
    evidence_hash = sha256_hex(canonicalize(req.evidence.model_dump()))
    context_hash = sha256_hex(canonicalize(req.context))

    amount = int(req.action.parameters.get("amount"))
    dest = req.action.parameters.get("destination_account_hash","")

    failed = []
    # Optional external policy hook (OPA). If configured and returns False, deny.
    ext = external_policy_allows(req.action.model_dump(), req.evidence.model_dump(), req.context)
    if ext is False:
        failed.append({"gate_id":"external_policy","failure":"DENY"})
    if amount < int(ruleset["threshold_amount"]):
        failed.append({"gate_id":"threshold","failure":"BELOW_THRESHOLD"})
    if not gate_allowlist(dest, ALLOWLIST_PATH):
        failed.append({"gate_id":"recipient_allowlist","failure":"MISSING"})
    if not gate_amount_limit(amount, req.context):
        failed.append({"gate_id":"daily_limit","failure":"EXCEEDED"})
    if not gate_cfo_token(action_hash, req.context, trust_store, now,
                          int(ruleset["cfo_freshness_seconds"]), int(ruleset["max_clock_skew_seconds"])):
        failed.append({"gate_id":"cfo_signature","failure":"MISSING_OR_INVALID"})

    if failed:
        art = build_withhold(action_hash, ruleset, ruleset_hash, evidence_hash, context_hash, now, failed)
    else:
        art = build_permit(action_hash, ruleset, ruleset_hash, evidence_hash, context_hash, now)
        ok = insert_nonce(art["nonce"], art["expires_at"])
        if not ok:
            art = build_withhold(action_hash, ruleset, ruleset_hash, evidence_hash, context_hash, now,
                                 [{"gate_id":"nonce","failure":"REPLAY"}])

    # Add trust bindings (hashes) to artifact body
    art["trust"] = {
        "trust_store_hash": trust_store_hash(),
        "revocation_list_hash": revocation_list_hash()
    }

    body = artifact_body_for_signing(art)
    payload = canonicalize(body)
    kid, sig_b64 = KEYS.sign_binaryif_artifact(payload)
    signed = dict(body)
    signed["signatures"] = [{"kid": kid, "alg": "ed25519", "sig_b64": sig_b64}]

    # Store permit if applicable
    if signed.get("artifact_type") == "PERMIT":
        store_permit(signed["permit_id"], json.dumps(signed, sort_keys=True))

    # Append to log and (optionally) WORM backend
    from .db import latest_entry_hash
    prev = latest_entry_hash()
    payload_hash = sha256_hex(payload)
    entry_hash = chain_entry_hash(prev, payload_hash)

    artifact_id = signed.get("permit_id") or signed.get("withhold_id")
    LOG.write_entry(artifact_id, signed["artifact_type"], signed["issued_at"], payload_hash, entry_hash, json.dumps(signed, sort_keys=True))

    return signed

@app.post("/execute_wire")
def execute_wire(req: ExecuteRequest):
    if not exec_limiter.allow('execute'):
        raise HTTPException(429, 'RATE_LIMIT')
    permit = req.permit
    trust_store = KEYS.get_trust_store()
    revocation = load_json(REVOCATION_LIST_PATH)
    now = now_epoch()

    if permit.get("artifact_type") != "PERMIT" or permit.get("decision") != "TRUE":
        raise HTTPException(403, "NO_VALID_PERMIT")

    sigs = permit.get("signatures", [])
    if not sigs:
        raise HTTPException(403, "MISSING_SIGNATURE")
    s = sigs[0]
    kid = s.get("kid")
    pub = trust_store.get("binaryif_artifact_keys", {}).get(kid)
    if not pub:
        raise HTTPException(403, "UNKNOWN_KID")

    issued_at = int(permit.get("issued_at", 0))
    if issued_at <= 0:
        raise HTTPException(403, "MISSING_ISSUED_AT")

    if is_revoked(kid, issued_at, revocation):
        raise HTTPException(403, "KEY_REVOKED")

    body = dict(permit); body.pop("signatures", None)
    if not verify_ed25519(s.get("sig_b64",""), canonicalize(body), pub):
        raise HTTPException(403, "INVALID_SIGNATURE")

    if int(permit.get("expires_at",0)) < now:
        raise HTTPException(403, "PERMIT_EXPIRED")

    action_hash = sha256_hex(canonicalize(req.action.model_dump()))
    if permit.get("action_hash") != action_hash:
        raise HTTPException(403, "PERMIT_ACTION_MISMATCH")

    pid = permit.get("permit_id")
    if not pid:
        raise HTTPException(403, "MISSING_PERMIT_ID")
    if not mark_permit_used(pid):
        raise HTTPException(403, "PERMIT_ALREADY_USED_OR_UNKNOWN")

    import secrets
    return {"status":"EXECUTED", "wire_id": secrets.token_hex(8)}


@app.get("/insurer/proof")
def insurer_proof():
    return artifact_log_proof()

@app.get("/insurer/permit/{permit_id}")
def insurer_get_permit(permit_id: str):
    p = get_permit_by_id(permit_id)
    if not p:
        raise HTTPException(404, "NOT_FOUND")
    return p

@app.get("/insurer/trust/{trust_hash}")
def insurer_get_trust(trust_hash: str):
    snap = get_trust_snapshot_by_hash(trust_hash)
    if not snap:
        raise HTTPException(404, "NOT_FOUND")
    return snap
