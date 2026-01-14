
"""Verify the hash-chain integrity of the artifact log exported from /artifact_log."""
import json, sys, hashlib

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def chain(prev, payload_hash):
    data = (prev or "").encode("utf-8") + payload_hash.encode("utf-8")
    return sha256_hex(data)

def main(path):
    log = json.load(open(path, "r", encoding="utf-8"))
    prev = None
    for entry in log:
        expected = chain(prev, entry["payload_hash"])
        if entry["entry_hash"] != expected:
            print("FAIL: chain mismatch at seq", entry["seq"])
            sys.exit(1)
        prev = entry["entry_hash"]
    print("PASS: artifact log chain valid")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tools/verify_artifact_log_chain.py <artifact_log_export.json>")
        raise SystemExit(2)
    main(sys.argv[1])
