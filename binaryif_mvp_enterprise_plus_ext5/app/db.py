"""
Database module for BinaryIF MVP.

Provides SQLite-based storage for permits, nonces, artifact logs, and consumed permits.
Uses connection pooling and proper indexing for performance.
"""

import sqlite3
import threading
from typing import Optional, List, Dict, Any
from pathlib import Path
from contextlib import contextmanager

DB_PATH = Path("data/binaryif.db")

# Thread-local storage for connection pooling
_local = threading.local()


def _get_connection() -> sqlite3.Connection:
    """
    Get a thread-local database connection.
    Connections are reused within the same thread for performance.
    """
    if not hasattr(_local, 'conn') or _local.conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA cache_size=10000;")  # ~10MB cache
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.row_factory = sqlite3.Row
        _local.conn = conn
    return _local.conn


@contextmanager
def _transaction():
    """
    Context manager for database transactions.
    Automatically commits on success, rolls back on failure.
    """
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db() -> None:
    """
    Initialize database schema with proper indexes.
    Safe to call multiple times (uses IF NOT EXISTS).
    """
    with _transaction() as conn:
        # Permits table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS permits (
            permit_id TEXT PRIMARY KEY,
            artifact_json TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER DEFAULT (strftime('%s', 'now'))
        );""")
        
        # Nonces table with index for cleanup
        conn.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            expires_at INTEGER NOT NULL
        );""")
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_nonces_expires 
        ON nonces(expires_at);""")
        
        # Artifact log with indexes for common queries
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
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_artifact_log_type 
        ON artifact_log(artifact_type);""")
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_artifact_log_issued 
        ON artifact_log(issued_at);""")
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_artifact_log_artifact_id 
        ON artifact_log(artifact_id);""")
        
        # Consumed permits table for single-use enforcement
        conn.execute("""
        CREATE TABLE IF NOT EXISTS consumed_permits (
            permit_id TEXT PRIMARY KEY,
            receipt_id TEXT NOT NULL,
            consumed_at INTEGER NOT NULL,
            receipt_json TEXT NOT NULL
        );""")
        conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_consumed_permits_receipt 
        ON consumed_permits(receipt_id);""")


def store_permit(permit_id: str, artifact_json: str) -> None:
    """Store a permit artifact."""
    with _transaction() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO permits(permit_id, artifact_json, used) VALUES(?,?,0)",
            (permit_id, artifact_json)
        )


def mark_permit_used(permit_id: str) -> bool:
    """
    Mark a permit as used. Returns True if successful, False if already used or not found.
    Uses atomic UPDATE with WHERE clause for thread safety.
    """
    with _transaction() as conn:
        cur = conn.execute(
            "UPDATE permits SET used=1 WHERE permit_id=? AND used=0",
            (permit_id,)
        )
        return cur.rowcount == 1


def insert_nonce(nonce: str, expires_at: int) -> bool:
    """
    Insert a nonce for replay protection.
    Returns True if successful, False if nonce already exists.
    Also cleans up expired nonces.
    """
    conn = _get_connection()
    try:
        # Cleanup expired nonces (batch operation)
        conn.execute("DELETE FROM nonces WHERE expires_at < strftime('%s','now')")
        conn.execute("INSERT INTO nonces(nonce, expires_at) VALUES(?,?)", (nonce, expires_at))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        conn.rollback()
        return False


def export_artifact_log_full() -> List[Dict[str, Any]]:
    """Export the complete artifact log."""
    conn = _get_connection()
    cur = conn.execute(
        "SELECT seq, artifact_id, artifact_type, issued_at, payload_hash, "
        "prev_entry_hash, entry_hash, artifact_json FROM artifact_log ORDER BY seq ASC"
    )
    return [dict(row) for row in cur.fetchall()]


def latest_entry_hash() -> Optional[str]:
    """Get the hash of the most recent log entry for chain linking."""
    conn = _get_connection()
    cur = conn.execute("SELECT entry_hash FROM artifact_log ORDER BY seq DESC LIMIT 1")
    row = cur.fetchone()
    return row['entry_hash'] if row else None


def append_artifact_log(
    artifact_id: str,
    artifact_type: str,
    issued_at: int,
    payload_hash: str,
    entry_hash: str,
    artifact_json: str
) -> None:
    """Append an entry to the artifact log with hash chain linking."""
    with _transaction() as conn:
        prev = latest_entry_hash()
        conn.execute(
            "INSERT INTO artifact_log(artifact_id, artifact_type, issued_at, "
            "payload_hash, prev_entry_hash, entry_hash, artifact_json) VALUES(?,?,?,?,?,?,?)",
            (artifact_id, artifact_type, issued_at, payload_hash, prev, entry_hash, artifact_json)
        )


def get_permit_json(permit_id: str) -> Optional[str]:
    """Retrieve permit JSON by ID."""
    conn = _get_connection()
    cur = conn.execute('SELECT artifact_json FROM permits WHERE permit_id=?', (permit_id,))
    row = cur.fetchone()
    return row['artifact_json'] if row else None


# ============================================================
# Execution Binding: Single-Use Permit Consumption
# ============================================================

def is_permit_consumed(permit_id: str) -> bool:
    """Check if a permit has already been consumed (executed)."""
    conn = _get_connection()
    cur = conn.execute("SELECT 1 FROM consumed_permits WHERE permit_id=?", (permit_id,))
    return cur.fetchone() is not None


def consume_permit_atomic(permit_id: str, receipt_id: str, consumed_at: int, receipt_json: str) -> bool:
    """
    Atomically mark a permit as consumed.
    
    Returns True if successful, False if already consumed (race condition safe).
    Uses INSERT OR IGNORE for atomic operation.
    """
    conn = _get_connection()
    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO consumed_permits(permit_id, receipt_id, consumed_at, receipt_json) "
            "VALUES(?,?,?,?)",
            (permit_id, receipt_id, consumed_at, receipt_json)
        )
        conn.commit()
        return cur.rowcount == 1
    except Exception:
        conn.rollback()
        return False


def get_receipt_by_permit_id(permit_id: str) -> Optional[str]:
    """Retrieve the execution receipt JSON for a consumed permit."""
    conn = _get_connection()
    cur = conn.execute("SELECT receipt_json FROM consumed_permits WHERE permit_id=?", (permit_id,))
    row = cur.fetchone()
    return row['receipt_json'] if row else None


def get_receipt_by_receipt_id(receipt_id: str) -> Optional[str]:
    """Retrieve the execution receipt JSON by receipt_id."""
    conn = _get_connection()
    cur = conn.execute("SELECT receipt_json FROM consumed_permits WHERE receipt_id=?", (receipt_id,))
    row = cur.fetchone()
    return row['receipt_json'] if row else None


# ============================================================
# Metrics and Health
# ============================================================

def get_db_stats() -> Dict[str, int]:
    """Get database statistics for monitoring."""
    conn = _get_connection()
    stats = {}
    for table in ['permits', 'nonces', 'artifact_log', 'consumed_permits']:
        cur = conn.execute(f"SELECT COUNT(*) as cnt FROM {table}")
        stats[f"{table}_count"] = cur.fetchone()['cnt']
    return stats


# ============================================================
# Test Support: Database Reset
# ============================================================

def reset_db() -> None:
    """
    Reset the database for test isolation.
    Clears all tables but preserves schema.
    """
    with _transaction() as conn:
        conn.execute("DELETE FROM permits")
        conn.execute("DELETE FROM nonces")
        conn.execute("DELETE FROM artifact_log")
        conn.execute("DELETE FROM consumed_permits")


def close_connection() -> None:
    """Close the thread-local connection (for cleanup)."""
    if hasattr(_local, 'conn') and _local.conn is not None:
        _local.conn.close()
        _local.conn = None
