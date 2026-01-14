
import json, requests, subprocess, sys
from app.util import canonicalize, sha256_hex

BASE = "http://127.0.0.1:8000"
action = json.load(open("fixtures/action.json","r",encoding="utf-8"))
evidence = json.load(open("fixtures/evidence.json","r",encoding="utf-8"))

action_hash = sha256_hex(canonicalize(action))
out = subprocess.check_output([sys.executable, "tools/make_cfo_token.py", action_hash])
cfo_token = json.loads(out.decode("utf-8"))
context = {"remaining_daily_limit": 1000000, "cfo_token": cfo_token}

artifact = requests.post(BASE + "/authorize_wire", json={"action": action, "evidence": evidence, "context": context}).json()
print("Artifact:", json.dumps(artifact, indent=2))

resp = requests.post(BASE + "/execute_wire", json={"action": action, "permit": artifact})
print("Execute:", resp.status_code, resp.text)

print("Artifact log entries:", requests.get(BASE + "/artifact_log").status_code)
