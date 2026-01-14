
import os, json
from nacl.signing import SigningKey
from app.util import b64e

os.makedirs("secrets", exist_ok=True)
os.makedirs("trust", exist_ok=True)

sk = SigningKey.generate()
cfo = SigningKey.generate()

with open("secrets/binaryif_signing_key.json","w",encoding="utf-8") as f:
    json.dump({"kid":"binaryif-artifact-01", "private_key_b64": b64e(bytes(sk))}, f, indent=2)

with open("secrets/cfo_signing_key.json","w",encoding="utf-8") as f:
    json.dump({"kid":"cfo-01", "private_key_b64": b64e(bytes(cfo))}, f, indent=2)

trust = {
  "trust_store_id":"binaryif-trust-store-demo",
  "trust_store_version":"0.3.0",
  "binaryif_artifact_keys": {
    "binaryif-artifact-01": b64e(bytes(sk.verify_key))
  },
  "authority_keys": {
    "cfo-01": b64e(bytes(cfo.verify_key))
  }
}

with open("trust/trust_store.json","w",encoding="utf-8") as f:
    json.dump(trust, f, indent=2)

print("Generated local keys + trust store.")

import time, json
now = int(time.time())
trust = json.load(open("trust/trust_store.json","r",encoding="utf-8"))
trust["binaryif_artifact_key_validity"] = {
  "binaryif-artifact-01": {"not_before_epoch": now - 86400, "not_after_epoch": now + 365*86400}
}
trust["authority_key_validity"] = {
  "cfo-01": {"not_before_epoch": now - 86400, "not_after_epoch": now + 365*86400}
}
with open("trust/trust_store.json","w",encoding="utf-8") as f:
    json.dump(trust, f, indent=2)
print("Added key validity windows.")
