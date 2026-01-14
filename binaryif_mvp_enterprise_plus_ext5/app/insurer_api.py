
import json
from pathlib import Path
from typing import Optional
from .db import get_permit_json, export_artifact_log_full
from .util import canonicalize, sha256_hex

def load_json(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))

def get_permit_by_id(permit_id: str) -> Optional[dict]:
    s = get_permit_json(permit_id)
    if not s:
        return None
    return json.loads(s)

def get_trust_snapshot_by_hash(trust_hash: str) -> Optional[dict]:
    p = Path("trust/snapshots") / f"{trust_hash}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))

def artifact_log_proof() -> dict:
    log = export_artifact_log_full()
    head = log[-1]["entry_hash"] if log else None
    return {"entries": len(log), "head_entry_hash": head}
