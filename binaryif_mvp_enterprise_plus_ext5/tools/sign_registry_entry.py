
import argparse, json, time, hashlib
from pathlib import Path
from nacl.signing import SigningKey
from app.util import canonicalize, sha256_hex, b64d, b64e

def load_json(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--impl_version", required=True)
    ap.add_argument("--ruleset", required=True)
    ap.add_argument("--trust", required=True)
    ap.add_argument("--rev", required=True)
    ap.add_argument("--conformance", required=True)
    ap.add_argument("--compliance_zip", required=True)
    args = ap.parse_args()

    ts = int(time.time())
    ruleset = load_json(Path(args.ruleset))
    trust = load_json(Path(args.trust))
    rev = load_json(Path(args.rev))

    entry = {
        "product_name": "BinaryIF MVP Wire Transfer",
        "implementation_version": args.impl_version,
        "issued_at_epoch": ts,
        "ruleset": {
            "ruleset_id": ruleset.get("ruleset_id"),
            "ruleset_version": ruleset.get("ruleset_version"),
            "ruleset_hash": sha256_hex(canonicalize(ruleset))
        },
        "trust_store_hash": sha256_hex(canonicalize(trust)),
        "revocation_list_hash": sha256_hex(canonicalize(rev)),
        "conformance_result_hash": sha256_file(Path(args.conformance)),
        "compliance_pack_hash": sha256_file(Path(args.compliance_zip))
    }

    key = load_json(Path("secrets/binaryif_signing_key.json"))
    sk = SigningKey(b64d(key["private_key_b64"]))
    kid = key["kid"]
    payload = canonicalize(entry)
    sig = sk.sign(payload).signature
    entry["signatures"] = [{"kid": kid, "alg":"ed25519", "sig_b64": b64e(sig)}]

    outdir = Path("certification"); outdir.mkdir(parents=True, exist_ok=True)
    out = outdir / f"registry_entry_{ts}.json"
    out.write_text(json.dumps(entry, indent=2, sort_keys=True), encoding="utf-8")
    print(str(out))

if __name__ == "__main__":
    main()
