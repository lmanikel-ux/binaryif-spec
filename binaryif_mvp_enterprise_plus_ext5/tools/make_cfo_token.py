
import json, time, sys
from nacl.signing import SigningKey
from app.util import canonicalize, b64d, b64e

def main(action_hash: str):
    key = json.load(open("secrets/cfo_signing_key.json","r",encoding="utf-8"))
    kid = key["kid"]
    sk = SigningKey(b64d(key["private_key_b64"]))
    issued_at = int(time.time())
    payload_obj = {"kid": kid, "issued_at": issued_at, "signed_action_hash": action_hash}
    payload = canonicalize(payload_obj)
    sig = sk.sign(payload).signature
    token = dict(payload_obj)
    token["sig_b64"] = b64e(sig)
    print(json.dumps(token, indent=2))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tools/make_cfo_token.py <action_hash>"); raise SystemExit(2)
    main(sys.argv[1])
