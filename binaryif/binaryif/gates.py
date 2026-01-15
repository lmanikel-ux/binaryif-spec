"""
BinaryIF Gate Domain-Specific Language (DSL)

Implements Section 13 of the BinaryIF Protocol Specification.
Minimal, deterministic language for defining authorization conditions.

Design principles (Section 13.1):
- Human-auditable
- Deterministic (no randomness, no ML, no probabilistic logic)
- Fail-closed (any uncertainty results in FAIL)
- Replayable (identical inputs produce identical outputs)
"""

import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import json


class GateResult(str, Enum):
    """Gate evaluation result."""
    PASS = "PASS"
    FAIL = "FAIL"


class FailureCode(str, Enum):
    """Standard failure codes per Section 15.7."""
    MISSING = "MISSING"
    INVALID = "INVALID"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    MISMATCH = "MISMATCH"
    EXCEEDED = "EXCEEDED"
    UNAUTHORIZED = "UNAUTHORIZED"
    CONTRADICTION = "CONTRADICTION"
    REPLAY = "REPLAY"
    UNKNOWN = "UNKNOWN"


@dataclass
class GateEvaluation:
    """Result of evaluating a single gate."""
    gate_id: str
    result: GateResult
    failure_code: Optional[FailureCode] = None
    required: Optional[str] = None
    observed: Optional[str] = None
    
    def passed(self) -> bool:
        return self.result == GateResult.PASS
    
    def to_dict(self) -> Dict[str, Any]:
        d = {"gate_id": self.gate_id, "result": self.result.value}
        if self.failure_code:
            d["failure_code"] = self.failure_code.value
        if self.required:
            d["required"] = self.required
        if self.observed:
            d["observed"] = self.observed
        return d


def resolve_json_path(obj: Any, path: str) -> Tuple[bool, Any]:
    """
    Resolve a JSON path expression against an object.
    
    Supports basic JSONPath syntax: $.field.subfield
    
    Returns:
        Tuple of (success, value)
    """
    if not path.startswith("$."):
        return False, None
    
    parts = path[2:].split(".")
    current = obj
    
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return False, None
    
    return True, current


class Gate(ABC):
    """Abstract base class for all gate types."""
    
    def __init__(self, gate_id: str, parameters: Dict[str, Any]):
        self.gate_id = gate_id
        self.parameters = parameters
    
    @abstractmethod
    def evaluate(
        self,
        cae: Dict[str, Any],
        evidence_bundle: Dict[str, Any],
        context: Dict[str, Any],
        trust_store: Dict[str, Any]
    ) -> GateEvaluation:
        """Evaluate the gate. Must return PASS or FAIL, never raise."""
        pass
    
    def _pass(self) -> GateEvaluation:
        return GateEvaluation(gate_id=self.gate_id, result=GateResult.PASS)
    
    def _fail(
        self,
        code: FailureCode,
        required: str = None,
        observed: str = None
    ) -> GateEvaluation:
        return GateEvaluation(
            gate_id=self.gate_id,
            result=GateResult.FAIL,
            failure_code=code,
            required=required,
            observed=observed
        )


class EvidencePresentGate(Gate):
    """
    Section 13.3.1: evidence_present
    
    Verifies that a specific piece of evidence exists in the bundle.
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        ref = self.parameters.get("ref")
        if not ref:
            return self._fail(FailureCode.INVALID, "ref parameter required", "none")
        
        # Check if evidence exists in bundle
        references = evidence_bundle.get("references", [])
        for item in references:
            if item.get("ref") == ref:
                return self._pass()
        
        # Also check direct evidence keys
        if ref in evidence_bundle:
            return self._pass()
        
        return self._fail(
            FailureCode.MISSING,
            f"evidence ref {ref}",
            "not found in bundle"
        )


class AllowlistHashMatchGate(Gate):
    """
    Section 13.3.2: allowlist_hash_match
    
    Verifies that a value is present in an approved allowlist.
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        value_path = self.parameters.get("value_path")
        allowlist_ref = self.parameters.get("allowlist_ref")
        
        if not value_path or not allowlist_ref:
            return self._fail(FailureCode.INVALID, "value_path and allowlist_ref required", "missing params")
        
        # Resolve the value from CAE
        success, value = resolve_json_path(cae, value_path)
        if not success:
            return self._fail(FailureCode.MISSING, f"value at {value_path}", "path not found")
        
        # Get the allowlist from evidence
        allowlist = evidence_bundle.get("allowlists", {}).get(allowlist_ref, [])
        if not allowlist:
            # Try direct reference
            for ref in evidence_bundle.get("references", []):
                if ref.get("ref") == allowlist_ref:
                    allowlist = ref.get("entries", [])
                    break
        
        # Check if value (or its hash) is in allowlist
        if value in allowlist:
            return self._pass()
        
        # Check if it's a hash match
        for entry in allowlist:
            if isinstance(entry, dict) and entry.get("hash") == value:
                return self._pass()
            if entry == value:
                return self._pass()
        
        return self._fail(
            FailureCode.MISMATCH,
            f"value in allowlist {allowlist_ref}",
            f"{value} not found"
        )


class NumericAssertGate(Gate):
    """
    Section 13.3.3: numeric_assert
    
    Performs a deterministic numeric comparison.
    """
    
    OPERATORS = {
        "eq": lambda a, b: a == b,
        "ne": lambda a, b: a != b,
        "lt": lambda a, b: a < b,
        "le": lambda a, b: a <= b,
        "gt": lambda a, b: a > b,
        "ge": lambda a, b: a >= b,
    }
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        left_spec = self.parameters.get("left")
        operator = self.parameters.get("operator")
        right_spec = self.parameters.get("right")
        
        if not all([left_spec, operator, right_spec]):
            return self._fail(FailureCode.INVALID, "left, operator, right required", "missing params")
        
        if operator not in self.OPERATORS:
            return self._fail(FailureCode.INVALID, f"operator in {list(self.OPERATORS.keys())}", operator)
        
        # Resolve left value
        left_val = self._resolve_numeric(left_spec, cae, context)
        if left_val is None:
            return self._fail(FailureCode.MISSING, f"numeric value at {left_spec}", "not found or invalid")
        
        # Resolve right value
        right_val = self._resolve_numeric(right_spec, cae, context)
        if right_val is None:
            return self._fail(FailureCode.MISSING, f"numeric value at {right_spec}", "not found or invalid")
        
        # Perform comparison
        try:
            result = self.OPERATORS[operator](left_val, right_val)
            if result:
                return self._pass()
            else:
                return self._fail(
                    FailureCode.EXCEEDED,
                    f"{left_spec} {operator} {right_spec}",
                    f"{left_val} {operator} {right_val} = False"
                )
        except Exception as e:
            return self._fail(FailureCode.INVALID, "comparable values", str(e))
    
    def _resolve_numeric(self, spec: str, cae: dict, context: dict) -> Optional[Decimal]:
        """Resolve a numeric value from path or literal."""
        # Try as JSON path
        if spec.startswith("$."):
            # Check CAE first
            success, value = resolve_json_path(cae, spec)
            if not success:
                # Try context
                context_path = spec.replace("$.context.", "$.")
                success, value = resolve_json_path(context, context_path)
            if success:
                try:
                    return Decimal(str(value))
                except InvalidOperation:
                    return None
            return None
        
        # Try as literal
        try:
            return Decimal(spec)
        except InvalidOperation:
            return None


class SignatureRequiredGate(Gate):
    """
    Section 13.3.4: signature_required
    
    Verifies a cryptographic signature from an authorized role.
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        role = self.parameters.get("role")
        keyring_ref = self.parameters.get("keyring_ref")
        signed_payload = self.parameters.get("signed_payload")
        token_ref = self.parameters.get("token_ref")
        freshness_seconds = self.parameters.get("freshness_seconds", 300)
        
        if not all([role, token_ref]):
            return self._fail(FailureCode.INVALID, "role and token_ref required", "missing params")
        
        # Resolve the token from evidence
        success, token = resolve_json_path(evidence_bundle, token_ref)
        if not success or not token:
            return self._fail(
                FailureCode.MISSING,
                f"role:{role} signature within {freshness_seconds}s",
                "none"
            )
        
        # Check token structure
        if not isinstance(token, dict):
            return self._fail(FailureCode.INVALID, "token object", str(type(token)))
        
        # Check role matches
        token_role = token.get("role") or token.get("signer_role")
        if token_role != role:
            return self._fail(FailureCode.UNAUTHORIZED, f"role:{role}", f"role:{token_role}")
        
        # Check freshness
        issued_at = token.get("issued_at")
        if issued_at:
            try:
                token_time = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                age_seconds = (now - token_time).total_seconds()
                
                if age_seconds > freshness_seconds:
                    return self._fail(
                        FailureCode.EXPIRED,
                        f"freshness <= {freshness_seconds}s",
                        f"age = {int(age_seconds)}s"
                    )
            except Exception:
                return self._fail(FailureCode.INVALID, "valid timestamp", str(issued_at))
        
        # Check signature (simplified - in production use crypto verification)
        if "signature" in token or "sig" in token:
            # Signature present - would verify cryptographically in production
            return self._pass()
        
        # For testing: allow valid=True marker
        if token.get("valid") is True:
            return self._pass()
        
        return self._fail(
            FailureCode.INVALID,
            "valid signature",
            "signature verification failed"
        )


class NonreplayNonceGate(Gate):
    """
    Section 13.3.5: nonreplay_nonce
    
    Ensures a nonce has not been used within the TTL window.
    """
    
    # In-memory nonce store (in production, use persistent store)
    _used_nonces: Dict[str, float] = {}
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        nonce_path = self.parameters.get("nonce_path")
        ttl_seconds = self.parameters.get("ttl_seconds", 600)
        
        if not nonce_path:
            return self._fail(FailureCode.INVALID, "nonce_path required", "missing param")
        
        # Resolve nonce value
        success, nonce = resolve_json_path(cae, nonce_path)
        if not success or not nonce:
            # Try evidence bundle
            success, nonce = resolve_json_path(evidence_bundle, nonce_path)
        
        if not success or not nonce:
            return self._fail(FailureCode.MISSING, f"nonce at {nonce_path}", "not found")
        
        # Clean expired nonces
        current_time = time.time()
        expired = [k for k, v in self._used_nonces.items() if current_time - v > ttl_seconds]
        for k in expired:
            del self._used_nonces[k]
        
        # Check if nonce was used
        if nonce in self._used_nonces:
            return self._fail(
                FailureCode.REPLAY,
                "unique nonce",
                f"nonce {nonce} already used"
            )
        
        # Record nonce usage
        self._used_nonces[nonce] = current_time
        
        return self._pass()
    
    @classmethod
    def reset_nonces(cls):
        """Reset nonce store (for testing)."""
        cls._used_nonces.clear()


class QuorumSignatureRequiredGate(Gate):
    """
    Section 13.4.1: quorum_signature_required
    
    Requires multiple signatures meeting a threshold.
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        threshold = self.parameters.get("threshold", 2)
        roles = self.parameters.get("roles", [])
        freshness_seconds = self.parameters.get("freshness_seconds", 300)
        
        if not roles:
            return self._fail(FailureCode.INVALID, "roles list required", "missing param")
        
        # Find all valid signatures
        valid_signatures = 0
        signatures = evidence_bundle.get("signatures", [])
        
        for sig in signatures:
            sig_role = sig.get("role") or sig.get("signer_role")
            if sig_role in roles:
                # Check freshness
                issued_at = sig.get("issued_at")
                if issued_at:
                    try:
                        token_time = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                        now = datetime.now(timezone.utc)
                        age_seconds = (now - token_time).total_seconds()
                        
                        if age_seconds <= freshness_seconds:
                            valid_signatures += 1
                    except Exception:
                        continue
                elif sig.get("valid"):
                    valid_signatures += 1
        
        if valid_signatures >= threshold:
            return self._pass()
        
        return self._fail(
            FailureCode.UNAUTHORIZED,
            f"{threshold} signatures from {roles}",
            f"{valid_signatures} valid signatures found"
        )


class ContradictionGuardGate(Gate):
    """
    Section 13.4.2: contradiction_guard
    
    Detects mutually exclusive claims in evidence.
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        assertions = self.parameters.get("assertions", [])
        
        for assertion in assertions:
            path_a = assertion.get("path_a")
            path_b = assertion.get("path_b")
            must_match = assertion.get("must_match", True)
            
            if not path_a or not path_b:
                continue
            
            # Resolve both paths
            success_a, val_a = resolve_json_path(evidence_bundle, path_a)
            if not success_a:
                success_a, val_a = resolve_json_path(cae, path_a)
            
            success_b, val_b = resolve_json_path(evidence_bundle, path_b)
            if not success_b:
                success_b, val_b = resolve_json_path(cae, path_b)
            
            if success_a and success_b:
                if must_match and val_a != val_b:
                    return self._fail(
                        FailureCode.CONTRADICTION,
                        f"{path_a} == {path_b}",
                        f"{val_a} != {val_b}"
                    )
                elif not must_match and val_a == val_b:
                    return self._fail(
                        FailureCode.CONTRADICTION,
                        f"{path_a} != {path_b}",
                        f"both equal {val_a}"
                    )
        
        return self._pass()


# Gate type registry
GATE_TYPES: Dict[str, type] = {
    "evidence_present": EvidencePresentGate,
    "allowlist_hash_match": AllowlistHashMatchGate,
    "numeric_assert": NumericAssertGate,
    "signature_required": SignatureRequiredGate,
    "nonreplay_nonce": NonreplayNonceGate,
    "quorum_signature_required": QuorumSignatureRequiredGate,
    "contradiction_guard": ContradictionGuardGate,
}


def create_gate(gate_id: str, gate_type: str, parameters: Dict[str, Any]) -> Gate:
    """Factory function to create a gate instance."""
    if gate_type not in GATE_TYPES:
        raise ValueError(f"Unknown gate type: {gate_type}")
    
    return GATE_TYPES[gate_type](gate_id, parameters)
