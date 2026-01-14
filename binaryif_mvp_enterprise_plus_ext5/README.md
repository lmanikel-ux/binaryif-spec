
# BinaryIF MVP (Enterprise+) — Wire Transfer Control Boundary

This package includes **all three requested hardening upgrades**:

A) **Insurer-grade conformance suite (20 vectors + PASS/FAIL report)**  
B) **KMS/HSM signing adapter (AWS KMS Ed25519 supported; Vault/HSM seam)**  
C) **WORM-grade artifact log export (S3 Object Lock / Legal Hold adapter + local fallback)**

This is still a *reference implementation* (single irreversible action: high-value wire), but it is now shaped
for enterprise validation and insurer demonstrations.

---

## 1) Quick start (local dev)
```bash
pip install -r requirements.txt
python tools/gen_keys.py          # local Ed25519 keys + trust store snapshot
uvicorn app.main:app --reload
python tools/demo_authorize_and_execute.py
```

## 2) Run verifier (independent)
```bash
python verifier/verify.py artifacts/permit.json fixtures/action.json rules/wire_ruleset.json trust/trust_store.json
```

## 3) Conformance suite (insurer-grade)
```bash
pytest -q
python tools/conformance_report.py
```

A successful run prints a single **PASS** line and exits 0.

---

## 4) KMS/HSM signing (AWS KMS Ed25519)
AWS KMS supports Ed25519 signing as of Nov 2025 and exposes signing algorithms such as
`ED25519_SHA_512` for `Sign` on compatible keys. See AWS KMS Sign API for supported algorithms.  
https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html

### Configure (example)
Set environment variables:
- `BINARYIF_SIGNER=aws_kms`
- `AWS_REGION=...`
- `AWS_KMS_KEY_ID=arn:aws:kms:...:key/...`
- `TRUST_STORE_PATH=trust/trust_store.json`

Then run the service as normal. The artifact signature will be produced by KMS.

**Note:** The public key for the KMS key must be placed in the trust store under `binaryif_artifact_keys` for verification.

---

## 5) WORM artifact log (S3 Object Lock)
S3 Object Lock provides retention periods and legal holds to enforce WORM semantics.  
https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html

### Configure (example)
- `ARTIFACT_LOG_BACKEND=s3_object_lock`
- `S3_BUCKET=...` (Object Lock enabled)
- `S3_PREFIX=binaryif/artifact-log/`
- `S3_RETENTION_DAYS=365`
- `S3_LEGAL_HOLD=ON` (optional)

If S3 is not configured, the system still maintains a hash-chained append-only log in SQLite
and can export the log as JSON.

---

## Design constraints (non-negotiable)
- Fail-closed (indeterminacy -> WITHHOLD)
- Deterministic replay verification
- Permit is single-use and time-bounded
- Execution is blocked absent valid PERMIT
- Public site should not disclose implementation details (keep this repo private during early insurer work)


## Enterprise+++ additions
- Key validity windows enforced by verifier
- Compliance pack generator (PDF + manifest): python tools/generate_compliance_pack.py
- Optional external policy hook (OPA): set POLICY_ENGINE=opa and OPA_URL
- Policy rider generator: python tools/generate_policy_rider.py --threshold 250000

## Insurer packet
python tools/build_insurer_packet.py

## Sign registry entry
python tools/sign_registry_entry.py --impl_version 0.3.0 --ruleset rules/wire_ruleset.json --trust trust/trust_store.json --rev trust/revocation_list.json --conformance insurer_packet_x/conformance.txt --compliance_zip compliance_pack_x.zip
