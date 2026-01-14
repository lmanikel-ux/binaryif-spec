
import os
from typing import Optional, Dict, Any

def external_policy_allows(action: dict, evidence: dict, context: dict) -> Optional[bool]:
    engine = os.getenv("POLICY_ENGINE", "none")
    if engine != "opa":
        return None
    url = os.getenv("OPA_URL")
    if not url:
        return None
    try:
        import requests
        r = requests.post(url, json={"input": {"action": action, "evidence": evidence, "context": context}}, timeout=3)
        r.raise_for_status()
        return bool(r.json().get("result"))
    except Exception:
        return None
