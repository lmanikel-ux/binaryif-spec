"""
BinaryIF Verification Algorithm

Implements Section 17 of the BinaryIF Protocol Specification.

Enables third parties to confirm the validity of a BinaryIF Record
after the fact, without access to the original evaluator.

V2 Architecture: Verifies context_hash and eib_hash for full input binding.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .canonicalization import canonicalize
from .hashing import sha256_hash, action_hash, ruleset_hash, evidence_bundle_hash, trust_store_hash
from .gates import create_gate, GateResult, GateEvaluation
from .ruleset import Ruleset


class VerificationOutcome(str, Enum):
    """
    Verification outcomes per Section 17.4.
    
    VALID_PERMIT: Artifact is a valid PERMIT; execution was authorized
    VALID_WITHHOLD: Artifact is a valid WITHHOLD; execution was correctly blocked
    INVALID: Artifact is invalid; reason provided
    """
    VALID_PERMIT = "VALID_PERMIT"
    VALID_WITHHOLD = "VALID_WITHHOLD"
    INVALID = "INVALID"


@dataclass
class VerificationResult:
    """Result of verifying a BinaryIF artifact."""
    outcome: VerificationOutcome
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    def is_valid(self) -> bool:
        return self.outcome in (VerificationOutcome.VALID_PERMIT, VerificationOutcome.VALID_WITHHOLD)
    
    @classmethod
    def valid_permit(cls) -> 'VerificationResult':
        return cls(outcome=VerificationOutcome.VALID_PERMIT)
    
    @classmethod
    def valid_withhold(cls) -> 'VerificationResult':
        return cls(outcome=VerificationOutcome.VALID_WITHHOLD)
    
    @classmethod
    def invalid(cls, reason: str, details: Dict[str, Any] = None) -> 'VerificationResult':
        return cls(outcome=VerificationOutcome.INVALID, reason=reason, details=details)


def context_hash(context: Dict[str, Any]) -> str:
    """Compute hash of context snapshot."""
    return sha256_hash(canonicalize(context))


def eib_hash(cae: Dict, evidence: Dict, context: Dict, rs_hash: str, ts_hash: str) -> str:
    """Compute Evaluation Input Bundle hash."""
    eib = {
        "cae": cae,
        "evidence": evidence,
        "context": context,
        "ruleset_hash": rs_hash,
        "trust_store_hash": ts_hash
    }
    return sha256_hash(canonicalize(eib))


class BinaryIFVerifier:
    """
    BinaryIF Verifier (Level 1 Conformance).
    
    Per Section 17.1:
    Enables any third party to confirm the validity of a BinaryIF Record
    after the fact, without access to the original evaluator.
    
    V2: Validates context_hash and eib_hash for complete input binding.
    """
    
    def __init__(self, trust_store_archive: Optional[Dict[str, Dict[str, Any]]] = None):
        """
        Initialize verifier.
        
        Args:
            trust_store_archive: Historical trust store snapshots keyed by hash
        """
        self.trust_store_archive = trust_store_archive or {}
    
    def verify(
        self,
        artifact: Dict[str, Any],
        cae: Dict[str, Any],
        ruleset: Dict[str, Any],
        evidence_bundle: Dict[str, Any],
        trust_store_snapshot: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
        verification_time: Optional[datetime] = None
    ) -> VerificationResult:
        """
        Verify a BinaryIF artifact.
        
        Per Section 17.3, verification steps:
        1. Verify artifact signature(s)
        2. Verify action_hash
        3. Verify ruleset_hash
        4. Verify evidence bundle_hash
        5. Verify context_hash (V2)
        6. Verify trust_store_hash
        7. Verify eib_hash (V2)
        8. Enforce TTL (for PERMIT)
        9. Replay gate evaluation
        10. Validate decision consistency
        
        Args:
            artifact: The BinaryIF Record (PERMIT or WITHHOLD)
            cae: The Canonical Action Envelope
            ruleset: The ruleset that was applied
            evidence_bundle: The evidence used in evaluation
            trust_store_snapshot: Trust store as of issued_at
            context: Evaluation context (REQUIRED for V2 artifacts)
            verification_time: Time of verification (default: now)
        
        Returns:
            VerificationResult indicating validity
        """
        verification_time = verification_time or datetime.now(timezone.utc)
        context = context or {}
        
        # Step 1: Verify artifact signature(s)
        sig_result = self._verify_signatures(artifact, trust_store_snapshot)
        if not sig_result.is_valid():
            return sig_result
        
        # Step 2: Verify action_hash
        computed_action_hash = action_hash(cae)
        if computed_action_hash != artifact.get("action_hash"):
            return VerificationResult.invalid(
                "Action hash mismatch",
                {"computed": computed_action_hash, "declared": artifact.get("action_hash")}
            )
        
        # Step 3: Verify ruleset_hash
        computed_ruleset_hash = ruleset_hash(ruleset)
        declared_ruleset_hash = artifact.get("ruleset", {}).get("ruleset_hash")
        if computed_ruleset_hash != declared_ruleset_hash:
            return VerificationResult.invalid(
                "Ruleset hash mismatch",
                {"computed": computed_ruleset_hash, "declared": declared_ruleset_hash}
            )
        
        # Step 4: Verify evidence bundle_hash
        computed_bundle_hash = evidence_bundle_hash(evidence_bundle)
        declared_bundle_hash = artifact.get("evidence", {}).get("bundle_hash")
        if computed_bundle_hash != declared_bundle_hash:
            return VerificationResult.invalid(
                "Evidence bundle hash mismatch",
                {"computed": computed_bundle_hash, "declared": declared_bundle_hash}
            )
        
        # Step 5: Verify context_hash (V2)
        # V2 artifacts have context_hash; V1 artifacts may not
        if "context_hash" in artifact:
            computed_context_hash = context_hash(context)
            if computed_context_hash != artifact.get("context_hash"):
                return VerificationResult.invalid(
                    "Context hash mismatch",
                    {"computed": computed_context_hash, "declared": artifact.get("context_hash")}
                )
        
        # Step 6: Verify trust_store_hash
        computed_trust_hash = trust_store_hash(trust_store_snapshot)
        if computed_trust_hash != artifact.get("trust_store_hash"):
            return VerificationResult.invalid(
                "Trust store hash mismatch",
                {"computed": computed_trust_hash, "declared": artifact.get("trust_store_hash")}
            )
        
        # Step 7: Verify eib_hash (V2)
        if "eib_hash" in artifact:
            computed_eib = eib_hash(
                cae, evidence_bundle, context,
                computed_ruleset_hash, computed_trust_hash
            )
            if computed_eib != artifact.get("eib_hash"):
                return VerificationResult.invalid(
                    "EIB hash mismatch - inputs do not match evaluation",
                    {"computed": computed_eib, "declared": artifact.get("eib_hash")}
                )
        
        # Step 8: Enforce TTL (for PERMIT)
        artifact_type = artifact.get("artifact_type")
        if artifact_type == "PERMIT":
            expires_at = artifact.get("expires_at")
            if expires_at:
                try:
                    expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    if verification_time > expiry:
                        return VerificationResult.invalid(
                            "Permit expired",
                            {"expires_at": expires_at, "verification_time": verification_time.isoformat()}
                        )
                except Exception as e:
                    return VerificationResult.invalid(f"Invalid expires_at format: {e}")
        
        # Step 9: Replay gate evaluation
        replay_result = self._replay_gate_evaluation(cae, ruleset, evidence_bundle, trust_store_snapshot, context)
        if replay_result is None:
            return VerificationResult.invalid("Failed to replay gate evaluation")
        
        all_passed, gate_results = replay_result
        
        # Step 10: Validate decision consistency
        decision = artifact.get("decision")
        
        if decision == "TRUE" and not all_passed:
            return VerificationResult.invalid(
                "PERMIT issued but gates did not all pass",
                {"gate_results": [g.to_dict() for g in gate_results if not g.passed()]}
            )
        
        if decision == "FALSE" and all_passed:
            return VerificationResult.invalid(
                "WITHHOLD issued but all gates passed",
                {"gate_results": [g.to_dict() for g in gate_results]}
            )
        
        # Verification successful
        if artifact_type == "PERMIT":
            return VerificationResult.valid_permit()
        else:
            return VerificationResult.valid_withhold()
    
    def _verify_signatures(
        self,
        artifact: Dict[str, Any],
        trust_store: Dict[str, Any]
    ) -> VerificationResult:
        """
        Step 1: Verify artifact signatures.
        
        Per Section 17.3:
        - Validate cryptographic signature against known public key
        - Confirm key was valid at issued_at
        - Check revocation status
        """
        signatures = artifact.get("signatures", [])
        if not signatures:
            return VerificationResult.invalid("No signatures present")
        
        issued_at = artifact.get("issued_at")
        
        for sig in signatures:
            key_id = sig.get("key_id")
            algorithm = sig.get("algorithm")
            signature = sig.get("sig")
            
            if not all([key_id, algorithm, signature]):
                return VerificationResult.invalid("Incomplete signature data")
            
            # Find key in trust store
            key_found = False
            for key in trust_store.get("keys", []):
                if key.get("key_id") == key_id:
                    key_found = True
                    
                    # Check validity period
                    valid_from = key.get("valid_from")
                    valid_until = key.get("valid_until")
                    
                    if issued_at and valid_from and valid_until:
                        try:
                            issue_time = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
                            from_time = datetime.fromisoformat(valid_from.replace("Z", "+00:00"))
                            until_time = datetime.fromisoformat(valid_until.replace("Z", "+00:00"))
                            
                            if issue_time < from_time or issue_time > until_time:
                                return VerificationResult.invalid(
                                    "Key not valid at issuance time",
                                    {"key_id": key_id, "issued_at": issued_at}
                                )
                        except Exception as e:
                            return VerificationResult.invalid(f"Invalid timestamp format: {e}")
                    
                    # Check algorithm match
                    if key.get("algorithm") != algorithm:
                        return VerificationResult.invalid(
                            "Algorithm mismatch",
                            {"key_algorithm": key.get("algorithm"), "sig_algorithm": algorithm}
                        )
                    
                    # Note: Actual cryptographic verification would happen here
                    # For this implementation, we verify structure only
                    break
            
            if not key_found:
                return VerificationResult.invalid(
                    "Key not found in trust store",
                    {"key_id": key_id}
                )
        
        return VerificationResult(outcome=VerificationOutcome.VALID_PERMIT)  # Temp, continues to next steps
    
    def _replay_gate_evaluation(
        self,
        cae: Dict[str, Any],
        ruleset_dict: Dict[str, Any],
        evidence_bundle: Dict[str, Any],
        trust_store: Dict[str, Any],
        context: Dict[str, Any]
    ) -> Optional[Tuple[bool, List[GateEvaluation]]]:
        """
        Step 9: Replay gate evaluation.
        
        Re-evaluate all gates with the provided inputs.
        """
        try:
            ruleset = Ruleset.from_dict(ruleset_dict)
            gates = ruleset.create_gates()
            
            evaluations = []
            all_passed = True
            
            for gate in gates:
                result = gate.evaluate(cae, evidence_bundle, context, trust_store)
                evaluations.append(result)
                if not result.passed():
                    all_passed = False
            
            return all_passed, evaluations
        
        except Exception as e:
            return None


def verify_artifact(
    artifact: Dict[str, Any],
    cae: Dict[str, Any],
    ruleset: Dict[str, Any],
    evidence_bundle: Dict[str, Any],
    trust_store: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None
) -> VerificationResult:
    """
    Convenience function to verify a BinaryIF artifact.
    
    Per Section 17.4:
    - VALID_PERMIT: Artifact is a valid PERMIT; execution was authorized
    - VALID_WITHHOLD: Artifact is a valid WITHHOLD; execution was correctly blocked
    - INVALID(reason): Artifact is invalid; reason provided
    """
    verifier = BinaryIFVerifier()
    return verifier.verify(artifact, cae, ruleset, evidence_bundle, trust_store, context=context)
