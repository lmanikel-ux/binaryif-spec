
import sys, json
from app.util import canonicalize, sha256_hex, now_epoch
from app.keys import verify_ed25519

def load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def is_revoked(kid: str, issued_at: int, revocation: dict | None) -> bool:
    if not revocation:
        return False
    effective = int(revocation.get("effective_at_epoch", 0))
    revoked = set(revocation.get("revoked_kids", []))
    return issued_at >= effective and kid in revoked

def key_valid_at(kid: str, issued_at: int, trust: dict) -> bool:
    validity = trust.get("binaryif_artifact_key_validity", {}).get(kid)
    if not validity:
        return True  # MVP default; production profile should require validity windows
    nb = int(validity.get("not_before_epoch", 0))
    na = int(validity.get("not_after_epoch", 0))
    return (issued_at >= nb) and (issued_at <= na)

def main():
    if len(sys.argv) not in (5, 6):
        print("Usage: python verifier/verify.py <artifact.json> <action.json> <ruleset.json> <trust_store.json> [revocation_list.json]")
        raise SystemExit(2)

    artifact = load(sys.argv[1])
    action = load(sys.argv[2])
    ruleset = load(sys.argv[3])
    trust = load(sys.argv[4])
    revocation = load(sys.argv[5]) if len(sys.argv) == 6 else None

    sigs = artifact.get("signatures", [])
    if not sigs:
        print("INVALID: missing signature"); return
    s = sigs[0]
    kid = s.get("kid")
    pub = trust.get("binaryif_artifact_keys", {}).get(kid)
    if not pub:
        print("INVALID: unknown kid"); return

    issued_at = int(artifact.get("issued_at", 0))
    if issued_at <= 0:
        print("INVALID: missing issued_at"); return

    if is_revoked(kid, issued_at, revocation):
        print("INVALID: key revoked"); return
    if not key_valid_at(kid, issued_at, trust):
        print("INVALID: key not valid at issued_at"); return

    body = dict(artifact); body.pop("signatures", None)
    if not verify_ed25519(s.get("sig_b64",""), canonicalize(body), pub):
        print("INVALID: bad signature"); return

    ah = sha256_hex(canonicalize(action))
    if artifact.get("action_hash") != ah:
        print("INVALID: action hash mismatch"); return

    rh = sha256_hex(canonicalize(ruleset))
    if artifact.get("ruleset", {}).get("ruleset_hash") != rh:
        print("INVALID: ruleset hash mismatch"); return

    expires_at = int(artifact.get("expires_at", 0))
    if expires_at and expires_at < now_epoch():
        print("INVALID: expired"); return

    print("VALID")

if __name__ == "__main__":
    main()
