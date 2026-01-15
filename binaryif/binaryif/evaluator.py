"""
BinaryIF Evaluator

Implements Sections 7, 9, 14 of the BinaryIF Protocol Specification.

This is the core authorization engine that:
- Evaluates the Boolean Authorization Predicate
- Manages the state machine
- Produces PERMIT and WITHHOLD artifacts

V2 Architecture: All evaluation inputs are hashed and bound to artifact.
"""

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .cae import CanonicalActionEnvelope
from .gates import Gate, GateResult, GateEvaluation, FailureCode
from .hashing import action_hash, evidence_bundle_hash, trust_store_hash, sha256_hash
from .canonicalization import canonicalize
from .ruleset import Ruleset, RulesetRegistry, EvaluationMode


class EvaluatorState(str, Enum):
    """
    State machine states per Section 14.1.
    
    PRE-AUTH: Action received; no permit exists
    EVALUATING: Evidence and authority being verified
    PERMIT: Permit minted; execution may proceed (terminal)
    WITHHOLD: Execution blocked; refusal artifact minted (terminal)
    """
    PRE_AUTH = "PRE_AUTH"
    EVALUATING = "EVALUATING"
    PERMIT = "PERMIT"
    WITHHOLD = "WITHHOLD"


class Decision(str, Enum):
    """Binary decision per Section 9.2."""
    TRUE = "TRUE"
    FALSE = "FALSE"


class ArtifactType(str, Enum):
    """Artifact types per Section 15."""
    PERMIT = "PERMIT"
    WITHHOLD = "WITHHOLD"


@dataclass
class EvaluationContext:
    """
    Context for authorization evaluation.
    
    Per Section 9.1, context includes:
    - Time
    - Environment
    - Tenant-specific limits and constraints
    
    V2: Context is hashed and bound to artifact for full replayability.
    """
    evaluation_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    remaining_daily_limit: Optional[str] = None
    environment: str = "production"
    tenant_id: Optional[str] = None
    additional: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        d = {
            "evaluation_time": self.evaluation_time.isoformat().replace("+00:00", "Z"),
            "environment": self.environment,
        }
        if self.remaining_daily_limit:
            d["remaining_daily_limit"] = self.remaining_daily_limit
        if self.tenant_id:
            d["tenant_id"] = self.tenant_id
        d.update(self.additional)
        return d


def context_hash(context: Dict[str, Any]) -> str:
    """Compute hash of context snapshot."""
    return sha256_hash(canonicalize(context))


def eib_hash(cae: Dict, evidence: Dict, context: Dict, ruleset_hash: str, trust_store_hash: str) -> str:
    """
    Compute Evaluation Input Bundle hash.
    
    V2 Architecture: Single hash capturing ALL inputs to evaluation.
    This ensures verification requires exact reproduction of inputs.
    """
    eib = {
        "cae": cae,
        "evidence": evidence,
        "context": context,
        "ruleset_hash": ruleset_hash,
        "trust_store_hash": trust_store_hash
    }
    return sha256_hash(canonicalize(eib))


@dataclass
class BinaryIFArtifact:
    """
    BinaryIF Record artifact.
    
    Per Section 15, contains:
    - Protocol version
    - Artifact type (PERMIT or WITHHOLD)
    - Decision (TRUE or FALSE)
    - Timestamps
    - Hashes binding action, evidence, ruleset, context, and trust store
    - Gate results
    - Cryptographic signatures
    
    V2: Includes context_hash and eib_hash for full input binding.
    """
    binaryif_version: str
    artifact_type: ArtifactType
    decision: Decision
    issued_at: str
    action_hash: str
    ruleset_id: str
    ruleset_version: str
    ruleset_hash: str
    bundle_id: str
    bundle_hash: str
    context_hash: str  # V2: Explicit context binding
    trust_store_hash: str
    eib_hash: str  # V2: Complete input binding
    nonce: str
    signatures: List[Dict[str, Any]]
    
    # PERMIT-specific
    expires_at: Optional[str] = None
    gate_results: Optional[List[Dict[str, Any]]] = None
    
    # WITHHOLD-specific
    failed_gates: Optional[List[Dict[str, Any]]] = None
    remediation: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        d = {
            "binaryif_version": self.binaryif_version,
            "artifact_type": self.artifact_type.value,
            "decision": self.decision.value,
            "issued_at": self.issued_at,
            "action_hash": self.action_hash,
            "ruleset": {
                "ruleset_id": self.ruleset_id,
                "ruleset_version": self.ruleset_version,
                "ruleset_hash": self.ruleset_hash
            },
            "evidence": {
                "bundle_id": self.bundle_id,
                "bundle_hash": self.bundle_hash
            },
            "context_hash": self.context_hash,  # V2
            "trust_store_hash": self.trust_store_hash,
            "eib_hash": self.eib_hash,  # V2
            "nonce": self.nonce,
            "signatures": self.signatures
        }
        
        if self.artifact_type == ArtifactType.PERMIT:
            if self.expires_at:
                d["expires_at"] = self.expires_at
            if self.gate_results:
                d["gates"] = self.gate_results
        else:
            if self.failed_gates:
                d["failed_gates"] = self.failed_gates
            if self.remediation:
                d["remediation"] = self.remediation
        
        return d
    
    def is_permit(self) -> bool:
        return self.artifact_type == ArtifactType.PERMIT
    
    def is_withhold(self) -> bool:
        return self.artifact_type == ArtifactType.WITHHOLD


@dataclass
class EvaluationResult:
    """Result of a BinaryIF evaluation."""
    state: EvaluatorState
    artifact: BinaryIFArtifact
    gate_evaluations: List[GateEvaluation]
    context_snapshot: Dict[str, Any]  # V2: Preserve for verification
    
    def authorized(self) -> bool:
        return self.state == EvaluatorState.PERMIT


class BinaryIFEvaluator:
    """
    The BinaryIF Evaluator (Level 2 Authorizer).
    
    Per Section 6.2:
    - Evaluates authorization predicate
    - Emits PERMIT or WITHHOLD artifacts
    
    Implements the invariant:
    AUTHORIZED(action, evidence, ruleset, context) ∈ { TRUE, FALSE }
    
    V2: All inputs hashed and bound to artifact.
    """
    
    BINARYIF_VERSION = "2.0"  # V2 for context binding
    DEFAULT_TTL_SECONDS = 300  # 5 minutes per Section 15.4
    
    def __init__(
        self,
        ruleset_registry: Optional[RulesetRegistry] = None,
        trust_store: Optional[Dict[str, Any]] = None,
        signing_key_id: str = "kid:binaryif-artifact-signing-001"
    ):
        self.ruleset_registry = ruleset_registry or RulesetRegistry()
        self.trust_store = trust_store or self._default_trust_store()
        self.signing_key_id = signing_key_id
    
    def _default_trust_store(self) -> Dict[str, Any]:
        """Create a default trust store for testing."""
        return {
            "trust_store_version": "2026-01-14-001",
            "effective_from": "2026-01-14T00:00:00Z",
            "keys": [
                {
                    "key_id": "kid:binaryif-artifact-signing-001",
                    "key_type": "ARTIFACT_SIGNING",
                    "algorithm": "Ed25519",
                    "public_key": "base64_placeholder",
                    "valid_from": "2026-01-01T00:00:00Z",
                    "valid_until": "2027-01-01T00:00:00Z"
                }
            ]
        }
    
    def evaluate(
        self,
        cae: CanonicalActionEnvelope,
        evidence_bundle: Dict[str, Any],
        ruleset: Optional[Ruleset] = None,
        context: Optional[EvaluationContext] = None
    ) -> EvaluationResult:
        """
        Evaluate the Boolean Authorization Predicate.
        
        Per Section 9.1:
        AUTHORIZED(action, evidence, ruleset, context) ∈ { TRUE, FALSE }
        
        V2: All inputs are hashed and bound to the resulting artifact.
        
        Args:
            cae: The Canonical Action Envelope
            evidence_bundle: Evidence supporting the authorization request
            ruleset: The ruleset to apply (looked up if not provided)
            context: Evaluation context
        
        Returns:
            EvaluationResult with PERMIT or WITHHOLD artifact
        """
        context = context or EvaluationContext()
        context_dict = context.to_dict()
        
        # State: PRE-AUTH -> EVALUATING
        state = EvaluatorState.EVALUATING
        
        # Resolve ruleset
        if ruleset is None:
            ruleset = self.ruleset_registry.get_for_action(cae.action_type)
            if ruleset is None:
                # Unknown action type -> WITHHOLD
                return self._emit_withhold_unknown_action(cae, evidence_bundle, context_dict)
        
        # Compute hashes (V2: including context)
        cae_dict = cae.to_dict()
        computed_action_hash = action_hash(cae_dict)
        computed_ruleset_hash = ruleset.get_hash()
        computed_bundle_hash = evidence_bundle_hash(evidence_bundle)
        computed_context_hash = context_hash(context_dict)
        computed_trust_hash = trust_store_hash(self.trust_store)
        
        # V2: Compute EIB hash (all inputs)
        computed_eib_hash = eib_hash(
            cae_dict, 
            evidence_bundle, 
            context_dict,
            computed_ruleset_hash,
            computed_trust_hash
        )
        
        # Create gate instances
        gates = ruleset.create_gates()
        
        # Evaluate all gates
        gate_evaluations: List[GateEvaluation] = []
        all_passed = True
        
        for gate in gates:
            evaluation = gate.evaluate(
                cae=cae_dict,
                evidence_bundle=evidence_bundle,
                context=context_dict,
                trust_store=self.trust_store
            )
            gate_evaluations.append(evaluation)
            
            if not evaluation.passed():
                all_passed = False
                
                # ANY_FAIL_STOPS mode - stop at first failure
                if ruleset.evaluation_mode == EvaluationMode.ANY_FAIL_STOPS:
                    break
        
        # Emit artifact
        now = datetime.now(timezone.utc)
        issued_at = now.isoformat().replace("+00:00", "Z")
        nonce = secrets.token_hex(16)
        bundle_id = evidence_bundle.get("bundle_id", f"bundle-{secrets.token_hex(8)}")
        
        if all_passed:
            # PERMIT
            expires_at = (now + timedelta(seconds=self.DEFAULT_TTL_SECONDS)).isoformat().replace("+00:00", "Z")
            
            artifact = BinaryIFArtifact(
                binaryif_version=self.BINARYIF_VERSION,
                artifact_type=ArtifactType.PERMIT,
                decision=Decision.TRUE,
                issued_at=issued_at,
                expires_at=expires_at,
                action_hash=computed_action_hash,
                ruleset_id=ruleset.id,
                ruleset_version=ruleset.version,
                ruleset_hash=computed_ruleset_hash,
                bundle_id=bundle_id,
                bundle_hash=computed_bundle_hash,
                context_hash=computed_context_hash,  # V2
                trust_store_hash=computed_trust_hash,
                eib_hash=computed_eib_hash,  # V2
                nonce=nonce,
                gate_results=[{"gate_id": e.gate_id, "result": "PASS"} for e in gate_evaluations],
                signatures=[self._sign_artifact(nonce)]
            )
            
            return EvaluationResult(
                state=EvaluatorState.PERMIT,
                artifact=artifact,
                gate_evaluations=gate_evaluations,
                context_snapshot=context_dict  # V2
            )
        else:
            # WITHHOLD
            failed = [e for e in gate_evaluations if not e.passed()]
            
            artifact = BinaryIFArtifact(
                binaryif_version=self.BINARYIF_VERSION,
                artifact_type=ArtifactType.WITHHOLD,
                decision=Decision.FALSE,
                issued_at=issued_at,
                action_hash=computed_action_hash,
                ruleset_id=ruleset.id,
                ruleset_version=ruleset.version,
                ruleset_hash=computed_ruleset_hash,
                bundle_id=bundle_id,
                bundle_hash=computed_bundle_hash,
                context_hash=computed_context_hash,  # V2
                trust_store_hash=computed_trust_hash,
                eib_hash=computed_eib_hash,  # V2
                nonce=nonce,
                failed_gates=[e.to_dict() for e in failed],
                remediation=self._generate_remediation(failed),
                signatures=[self._sign_artifact(nonce)]
            )
            
            return EvaluationResult(
                state=EvaluatorState.WITHHOLD,
                artifact=artifact,
                gate_evaluations=gate_evaluations,
                context_snapshot=context_dict  # V2
            )
    
    def _emit_withhold_unknown_action(
        self,
        cae: CanonicalActionEnvelope,
        evidence_bundle: Dict[str, Any],
        context_dict: Dict[str, Any]
    ) -> EvaluationResult:
        """Emit WITHHOLD for unknown action type."""
        now = datetime.now(timezone.utc)
        issued_at = now.isoformat().replace("+00:00", "Z")
        nonce = secrets.token_hex(16)
        
        cae_dict = cae.to_dict()
        computed_action_hash = action_hash(cae_dict)
        computed_bundle_hash = evidence_bundle_hash(evidence_bundle)
        computed_context_hash = context_hash(context_dict)
        computed_trust_hash = trust_store_hash(self.trust_store)
        bundle_id = evidence_bundle.get("bundle_id", f"bundle-{secrets.token_hex(8)}")
        
        # V2: EIB hash even for unknown action
        computed_eib_hash = eib_hash(
            cae_dict,
            evidence_bundle,
            context_dict,
            "sha256:" + "0" * 64,  # Unknown ruleset
            computed_trust_hash
        )
        
        failed_gate = GateEvaluation(
            gate_id="ruleset_lookup",
            result=GateResult.FAIL,
            failure_code=FailureCode.UNKNOWN,
            required="recognized action_type",
            observed=cae.action_type
        )
        
        artifact = BinaryIFArtifact(
            binaryif_version=self.BINARYIF_VERSION,
            artifact_type=ArtifactType.WITHHOLD,
            decision=Decision.FALSE,
            issued_at=issued_at,
            action_hash=computed_action_hash,
            ruleset_id="unknown",
            ruleset_version="0.0.0",
            ruleset_hash="sha256:" + "0" * 64,
            bundle_id=bundle_id,
            bundle_hash=computed_bundle_hash,
            context_hash=computed_context_hash,  # V2
            trust_store_hash=computed_trust_hash,
            eib_hash=computed_eib_hash,  # V2
            nonce=nonce,
            failed_gates=[failed_gate.to_dict()],
            remediation=["Register ruleset for action type: " + cae.action_type],
            signatures=[self._sign_artifact(nonce)]
        )
        
        return EvaluationResult(
            state=EvaluatorState.WITHHOLD,
            artifact=artifact,
            gate_evaluations=[failed_gate],
            context_snapshot=context_dict  # V2
        )
    
    def _sign_artifact(self, nonce: str) -> Dict[str, Any]:
        """
        Sign the artifact.
        
        Note: In production, this would use actual Ed25519 signing.
        This implementation provides the structure for integration.
        """
        return {
            "signer_role": "BinaryIF",
            "key_id": self.signing_key_id,
            "algorithm": "Ed25519",
            "sig": f"placeholder_signature_{nonce[:16]}"
        }
    
    def _generate_remediation(self, failed_gates: List[GateEvaluation]) -> List[str]:
        """Generate remediation hints for failed gates."""
        hints = []
        for gate in failed_gates:
            if gate.failure_code == FailureCode.MISSING:
                hints.append(f"Provide required evidence: {gate.required}")
            elif gate.failure_code == FailureCode.EXPIRED:
                hints.append(f"Obtain fresh credential: {gate.required}")
            elif gate.failure_code == FailureCode.EXCEEDED:
                hints.append(f"Reduce amount or request limit increase")
            elif gate.failure_code == FailureCode.MISMATCH:
                hints.append(f"Verify destination is in approved allowlist")
            elif gate.failure_code == FailureCode.UNAUTHORIZED:
                hints.append(f"Obtain authorization from required role")
            else:
                hints.append(f"Resolve issue with gate: {gate.gate_id}")
        
        hints.append("Retry evaluation with updated evidence bundle")
        return hints
