
import sqlite3
from typing import Optional
from pathlib import Path

DB_PATH = Path("data/binaryif.db")

def _connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    conn = _connect()
    conn.execute("""
    CREATE TABLE IF NOT EXISTS permits (
      permit_id TEXT PRIMARY KEY,
      artifact_json TEXT NOT NULL,
      used INTEGER NOT NULL DEFAULT 0
    );""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS nonces (
      nonce TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );""")
    conn.execute("""
    CREATE TABLE IF NOT EXISTS artifact_log (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      artifact_id TEXT NOT NULL,
      artifact_type TEXT NOT NULL,
      issued_at INTEGER NOT NULL,
      payload_hash TEXT NOT NULL,
      prev_entry_hash TEXT,
      entry_hash TEXT NOT NULL,
      artifact_json TEXT NOT NULL
    );""")
    conn.commit()
    conn.close()

def store_permit(permit_id: str, artifact_json: str):
    conn = _connect()
    conn.execute("INSERT OR REPLACE INTO permits(permit_id, artifact_json, used) VALUES(?,?,0)", (permit_id, artifact_json))
    conn.commit()
    conn.close()

def mark_permit_used(permit_id: str) -> bool:
    conn = _connect()
    cur = conn.execute("SELECT used FROM permits WHERE permit_id=?", (permit_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return False
    if row[0] == 1:
        conn.close()
        return False
    conn.execute("UPDATE permits SET used=1 WHERE permit_id=?", (permit_id,))
    conn.commit()
    conn.close()
    return True

def insert_nonce(nonce: str, expires_at: int) -> bool:
    conn = _connect()
    conn.execute("DELETE FROM nonces WHERE expires_at < strftime('%s','now')")
    try:
        conn.execute("INSERT INTO nonces(nonce, expires_at) VALUES(?,?)", (nonce, expires_at))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def export_artifact_log_full() -> list:
    conn = _connect()
    cur = conn.execute("SELECT seq, artifact_id, artifact_type, issued_at, payload_hash, prev_entry_hash, entry_hash, artifact_json FROM artifact_log ORDER BY seq ASC")
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "seq": r[0],
            "artifact_id": r[1],
            "artifact_type": r[2],
            "issued_at": r[3],
            "payload_hash": r[4],
            "prev_entry_hash": r[5],
            "entry_hash": r[6],
            "artifact_json": r[7],
        })
    return out

def latest_entry_hash() -> Optional[str]:
    conn = _connect()
    cur = conn.execute("SELECT entry_hash FROM artifact_log ORDER BY seq DESC LIMIT 1")
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def append_artifact_log(artifact_id: str, artifact_type: str, issued_at: int, payload_hash: str, entry_hash: str, artifact_json: str):
    conn = _connect()
    prev = latest_entry_hash()
    conn.execute(
        "INSERT INTO artifact_log(artifact_id, artifact_type, issued_at, payload_hash, prev_entry_hash, entry_hash, artifact_json) VALUES(?,?,?,?,?,?,?)",
        (artifact_id, artifact_type, issued_at, payload_hash, prev, entry_hash, artifact_json)
    )
    conn.commit()
    conn.close()


def get_permit_json(permit_id: str):
    conn = _connect()
    cur = conn.execute('SELECT artifact_json FROM permits WHERE permit_id=?', (permit_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None
