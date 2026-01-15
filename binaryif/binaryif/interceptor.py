"""
BinaryIF Execution Interceptor

Implements Level 3 Conformance - the execution gating layer.

The Interceptor sits between the BinaryIF Evaluator and the Execution Environment.
It enforces the critical invariant:

    NO IRREVERSIBLE ACTION EXECUTES WITHOUT VALID PERMIT

This is the final enforcement point. If an action reaches the execution
environment without passing through the interceptor, the system is bypassed.

Architecture:
    Agent (Untrusted) 
        ↓
    BinaryIF Evaluator (Level 2)
        ↓ PERMIT/WITHHOLD
    Execution Interceptor (Level 3) ← YOU ARE HERE
        ↓ Verified PERMIT only
    Execution Environment (Trusted)

The interceptor:
1. Receives an action and claimed PERMIT
2. Verifies the PERMIT is valid and matches the action
3. Checks the PERMIT has not expired
4. Checks the PERMIT has not been used before
5. Only then allows the action to proceed
6. Records the execution for audit

CRITICAL: This module MUST be the only path to the execution environment.
         Any bypass is a complete security failure.
"""

import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import hashlib
import json

from .hashing import action_hash, sha256_hash
from .canonicalization import canonicalize


class InterceptionResult(str, Enum):
    """Result of interceptor decision."""
    ALLOWED = "ALLOWED"     # Execution may proceed
    BLOCKED = "BLOCKED"     # Execution denied
    ERROR = "ERROR"         # Interceptor error (fail-closed)


class BlockReason(str, Enum):
    """Reason for blocking execution."""
    NO_PERMIT = "NO_PERMIT"
    INVALID_PERMIT = "INVALID_PERMIT"
    PERMIT_EXPIRED = "PERMIT_EXPIRED"
    PERMIT_USED = "PERMIT_USED"
    ACTION_MISMATCH = "ACTION_MISMATCH"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    INTERCEPTOR_ERROR = "INTERCEPTOR_ERROR"


@dataclass
class InterceptionDecision:
    """Decision from the execution interceptor."""
    result: InterceptionResult
    reason: Optional[BlockReason] = None
    details: Optional[str] = None
    permit_id: Optional[str] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def allowed(self) -> bool:
        return self.result == InterceptionResult.ALLOWED
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.result.value,
            "reason": self.reason.value if self.reason else None,
            "details": self.details,
            "permit_id": self.permit_id,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z")
        }


@dataclass
class ExecutionRecord:
    """Immutable record of an execution attempt."""
    record_id: str
    action_hash: str
    permit_id: Optional[str]
    decision: InterceptionDecision
    action_type: str
    tenant_id: str
    timestamp: datetime
    execution_duration_ms: Optional[int] = None
    execution_result: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "action_hash": self.action_hash,
            "permit_id": self.permit_id,
            "decision": self.decision.to_dict(),
            "action_type": self.action_type,
            "tenant_id": self.tenant_id,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "execution_duration_ms": self.execution_duration_ms,
            "execution_result": self.execution_result
        }


class PermitStore(ABC):
    """
    Abstract interface for tracking used permits.
    
    Implementations must be:
    - Persistent (survives restarts)
    - Consistent (no double-use)
    - Fast (low latency on hot path)
    """
    
    @abstractmethod
    def mark_used(self, permit_id: str, action_hash: str, expires_at: datetime) -> bool:
        """
        Mark a permit as used.
        
        Returns:
            True if permit was successfully marked (first use)
            False if permit was already used
        """
        pass
    
    @abstractmethod
    def is_used(self, permit_id: str) -> bool:
        """Check if a permit has been used."""
        pass
    
    @abstractmethod
    def cleanup_expired(self) -> int:
        """Remove expired permits from store. Returns count removed."""
        pass


class InMemoryPermitStore(PermitStore):
    """
    In-memory permit store for development/testing.
    
    WARNING: Not suitable for production.
    - Not persistent across restarts
    - Not distributed/clustered
    
    Use RedisPermitStore or DatabasePermitStore for production.
    """
    
    def __init__(self):
        self._used: Dict[str, Tuple[str, datetime]] = {}
        self._lock = threading.Lock()
    
    def mark_used(self, permit_id: str, action_hash: str, expires_at: datetime) -> bool:
        with self._lock:
            if permit_id in self._used:
                return False
            self._used[permit_id] = (action_hash, expires_at)
            return True
    
    def is_used(self, permit_id: str) -> bool:
        with self._lock:
            return permit_id in self._used
    
    def cleanup_expired(self) -> int:
        now = datetime.now(timezone.utc)
        with self._lock:
            expired = [k for k, (_, exp) in self._used.items() if exp < now]
            for k in expired:
                del self._used[k]
            return len(expired)


class AuditLog(ABC):
    """
    Abstract interface for audit logging.
    
    All execution attempts (allowed and blocked) must be logged.
    """
    
    @abstractmethod
    def record(self, execution_record: ExecutionRecord):
        """Record an execution attempt."""
        pass
    
    @abstractmethod
    def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        action_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
        result: Optional[InterceptionResult] = None
    ) -> List[ExecutionRecord]:
        """Query execution records."""
        pass


class InMemoryAuditLog(AuditLog):
    """
    In-memory audit log for development/testing.
    
    WARNING: Not suitable for production.
    - Not persistent
    - Not tamper-evident
    
    Use ImmutableAuditLog or BlockchainAuditLog for production.
    """
    
    def __init__(self, max_records: int = 10000):
        self._records: List[ExecutionRecord] = []
        self._lock = threading.Lock()
        self._max_records = max_records
    
    def record(self, execution_record: ExecutionRecord):
        with self._lock:
            self._records.append(execution_record)
            # Trim if needed
            if len(self._records) > self._max_records:
                self._records = self._records[-self._max_records:]
    
    def query(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        action_type: Optional[str] = None,
        tenant_id: Optional[str] = None,
        result: Optional[InterceptionResult] = None
    ) -> List[ExecutionRecord]:
        with self._lock:
            records = self._records[:]
        
        if start_time:
            records = [r for r in records if r.timestamp >= start_time]
        if end_time:
            records = [r for r in records if r.timestamp <= end_time]
        if action_type:
            records = [r for r in records if r.action_type == action_type]
        if tenant_id:
            records = [r for r in records if r.tenant_id == tenant_id]
        if result:
            records = [r for r in records if r.decision.result == result]
        
        return records


class ExecutionInterceptor:
    """
    The BinaryIF Execution Interceptor (Level 3 Conformance).
    
    This is the enforcement point that ensures:
    - No action executes without a valid PERMIT
    - Each PERMIT is used exactly once
    - All execution attempts are audited
    
    Usage:
        interceptor = ExecutionInterceptor()
        
        # Wrap your execution function
        @interceptor.protect("wire_transfer")
        def execute_wire(action_params):
            # This only runs if PERMIT is valid
            bank_api.transfer(...)
        
        # Or use explicitly
        decision = interceptor.intercept(action, permit)
        if decision.allowed():
            execute_action(action)
    """
    
    def __init__(
        self,
        permit_store: Optional[PermitStore] = None,
        audit_log: Optional[AuditLog] = None,
        trust_store: Optional[Dict[str, Any]] = None,
        max_clock_skew_seconds: int = 30
    ):
        self.permit_store = permit_store or InMemoryPermitStore()
        self.audit_log = audit_log or InMemoryAuditLog()
        self.trust_store = trust_store or {}
        self.max_clock_skew_seconds = max_clock_skew_seconds
        self._record_counter = 0
        self._lock = threading.Lock()
    
    def intercept(
        self,
        action: Dict[str, Any],
        permit: Optional[Dict[str, Any]]
    ) -> InterceptionDecision:
        """
        Intercept an action and decide whether to allow execution.
        
        This is the critical enforcement point.
        
        Args:
            action: The Canonical Action Envelope
            permit: The claimed PERMIT artifact (may be None)
        
        Returns:
            InterceptionDecision indicating whether to allow execution
        """
        now = datetime.now(timezone.utc)
        computed_action_hash = action_hash(action)
        
        # Generate record ID
        record_id = self._generate_record_id()
        
        try:
            # Check 1: PERMIT exists
            if permit is None:
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.NO_PERMIT,
                    details="No PERMIT provided"
                )
                self._audit(record_id, action, computed_action_hash, None, decision)
                return decision
            
            # Check 2: PERMIT is actually a PERMIT (not WITHHOLD)
            if permit.get("artifact_type") != "PERMIT":
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.INVALID_PERMIT,
                    details=f"Artifact is {permit.get('artifact_type')}, not PERMIT"
                )
                self._audit(record_id, action, computed_action_hash, None, decision)
                return decision
            
            # Check 3: Decision is TRUE
            if permit.get("decision") != "TRUE":
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.INVALID_PERMIT,
                    details=f"Decision is {permit.get('decision')}, not TRUE"
                )
                self._audit(record_id, action, computed_action_hash, None, decision)
                return decision
            
            # Check 4: PERMIT has not expired
            expires_at_str = permit.get("expires_at")
            if not expires_at_str:
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.INVALID_PERMIT,
                    details="PERMIT has no expiration"
                )
                self._audit(record_id, action, computed_action_hash, None, decision)
                return decision
            
            try:
                expires_at = datetime.fromisoformat(expires_at_str.replace("Z", "+00:00"))
            except Exception as e:
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.INVALID_PERMIT,
                    details=f"Invalid expires_at: {e}"
                )
                self._audit(record_id, action, computed_action_hash, None, decision)
                return decision
            
            # Allow clock skew
            effective_now = now - timedelta(seconds=self.max_clock_skew_seconds)
            if effective_now > expires_at:
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.PERMIT_EXPIRED,
                    details=f"PERMIT expired at {expires_at_str}"
                )
                self._audit(record_id, action, computed_action_hash, permit.get("nonce"), decision)
                return decision
            
            # Check 5: Action hash matches
            declared_action_hash = permit.get("action_hash")
            if declared_action_hash != computed_action_hash:
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.ACTION_MISMATCH,
                    details=f"Action hash mismatch: computed={computed_action_hash}, declared={declared_action_hash}"
                )
                self._audit(record_id, action, computed_action_hash, permit.get("nonce"), decision)
                return decision
            
            # Check 6: PERMIT has not been used
            permit_id = permit.get("nonce")  # Using nonce as permit_id
            if not permit_id:
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.INVALID_PERMIT,
                    details="PERMIT has no nonce/ID"
                )
                self._audit(record_id, action, computed_action_hash, None, decision)
                return decision
            
            # Atomic check-and-mark
            if not self.permit_store.mark_used(permit_id, computed_action_hash, expires_at):
                decision = InterceptionDecision(
                    result=InterceptionResult.BLOCKED,
                    reason=BlockReason.PERMIT_USED,
                    details=f"PERMIT {permit_id} has already been used"
                )
                self._audit(record_id, action, computed_action_hash, permit_id, decision)
                return decision
            
            # All checks passed - ALLOW execution
            decision = InterceptionDecision(
                result=InterceptionResult.ALLOWED,
                permit_id=permit_id
            )
            self._audit(record_id, action, computed_action_hash, permit_id, decision)
            return decision
            
        except Exception as e:
            # Any error = fail closed
            decision = InterceptionDecision(
                result=InterceptionResult.BLOCKED,
                reason=BlockReason.INTERCEPTOR_ERROR,
                details=str(e)
            )
            self._audit(record_id, action, computed_action_hash, None, decision)
            return decision
    
    def protect(self, action_type: str):
        """
        Decorator to protect a function with BinaryIF enforcement.
        
        Usage:
            @interceptor.protect("wire_transfer")
            def execute_wire(action, permit):
                # Only executes if PERMIT is valid
                bank.transfer(...)
        """
        def decorator(func: Callable):
            def wrapper(action: Dict[str, Any], permit: Dict[str, Any], *args, **kwargs):
                decision = self.intercept(action, permit)
                if not decision.allowed():
                    raise PermitDeniedError(decision)
                return func(action, permit, *args, **kwargs)
            return wrapper
        return decorator
    
    def _generate_record_id(self) -> str:
        """Generate unique record ID."""
        with self._lock:
            self._record_counter += 1
            counter = self._record_counter
        
        timestamp = datetime.now(timezone.utc).isoformat()
        data = f"{timestamp}:{counter}"
        return f"exec-{sha256_hash(data.encode())[:16]}"
    
    def _audit(
        self,
        record_id: str,
        action: Dict[str, Any],
        computed_hash: str,
        permit_id: Optional[str],
        decision: InterceptionDecision
    ):
        """Record execution attempt in audit log."""
        record = ExecutionRecord(
            record_id=record_id,
            action_hash=computed_hash,
            permit_id=permit_id,
            decision=decision,
            action_type=action.get("action_type", "unknown"),
            tenant_id=action.get("tenant_id", "unknown"),
            timestamp=datetime.now(timezone.utc)
        )
        self.audit_log.record(record)
    
    def get_audit_log(self) -> AuditLog:
        """Get the audit log for querying."""
        return self.audit_log
    
    def cleanup(self) -> int:
        """Clean up expired permits. Returns count removed."""
        return self.permit_store.cleanup_expired()


class PermitDeniedError(Exception):
    """Raised when execution is blocked by the interceptor."""
    
    def __init__(self, decision: InterceptionDecision):
        self.decision = decision
        super().__init__(f"Execution blocked: {decision.reason.value if decision.reason else 'unknown'}")


# =============================================================================
# PRODUCTION PERMIT STORES (Interfaces)
# =============================================================================

class RedisPermitStore(PermitStore):
    """
    Redis-backed permit store for production.
    
    Features:
    - Persistent across restarts
    - Distributed/clustered
    - Atomic operations via SETNX
    - Automatic TTL expiration
    
    Requires: redis-py
    """
    
    def __init__(self, redis_client, key_prefix: str = "binaryif:permit:"):
        # Import redis at runtime
        self.redis = redis_client
        self.key_prefix = key_prefix
    
    def mark_used(self, permit_id: str, action_hash: str, expires_at: datetime) -> bool:
        key = f"{self.key_prefix}{permit_id}"
        value = json.dumps({"action_hash": action_hash, "used_at": datetime.now(timezone.utc).isoformat()})
        
        # Calculate TTL
        now = datetime.now(timezone.utc)
        ttl_seconds = max(1, int((expires_at - now).total_seconds()) + 3600)  # Add 1 hour buffer
        
        # SETNX = atomic set-if-not-exists
        result = self.redis.set(key, value, nx=True, ex=ttl_seconds)
        return result is not None
    
    def is_used(self, permit_id: str) -> bool:
        key = f"{self.key_prefix}{permit_id}"
        return self.redis.exists(key) > 0
    
    def cleanup_expired(self) -> int:
        # Redis handles expiration automatically via TTL
        return 0


class DatabasePermitStore(PermitStore):
    """
    Database-backed permit store for production.
    
    Features:
    - ACID compliance
    - Full audit trail
    - Works with existing DB infrastructure
    
    Schema:
        CREATE TABLE binaryif_permits (
            permit_id VARCHAR(64) PRIMARY KEY,
            action_hash VARCHAR(128) NOT NULL,
            used_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL,
            INDEX idx_expires_at (expires_at)
        );
    """
    
    def __init__(self, db_connection, table_name: str = "binaryif_permits"):
        self.db = db_connection
        self.table = table_name
    
    def mark_used(self, permit_id: str, action_hash: str, expires_at: datetime) -> bool:
        try:
            # Use INSERT with conflict handling for atomicity
            cursor = self.db.cursor()
            cursor.execute(
                f"""
                INSERT INTO {self.table} (permit_id, action_hash, used_at, expires_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (permit_id) DO NOTHING
                """,
                (permit_id, action_hash, datetime.now(timezone.utc), expires_at)
            )
            self.db.commit()
            return cursor.rowcount > 0
        except Exception:
            self.db.rollback()
            return False
    
    def is_used(self, permit_id: str) -> bool:
        cursor = self.db.cursor()
        cursor.execute(
            f"SELECT 1 FROM {self.table} WHERE permit_id = %s",
            (permit_id,)
        )
        return cursor.fetchone() is not None
    
    def cleanup_expired(self) -> int:
        cursor = self.db.cursor()
        cursor.execute(
            f"DELETE FROM {self.table} WHERE expires_at < %s",
            (datetime.now(timezone.utc),)
        )
        count = cursor.rowcount
        self.db.commit()
        return count


# Import timedelta for the interceptor
from datetime import timedelta
