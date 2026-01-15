"""
BinaryIF Protocol Reference Implementation

Version: 2.0.0
License: Apache 2.0

The Deterministic Authorization Layer for Irreversible Actions.

BinaryIF is a protocol that evaluates a single Boolean predicate:
    AUTHORIZED(action, evidence, ruleset, context) ∈ { TRUE, FALSE }

There is no third state. If the predicate cannot be evaluated deterministically,
it resolves to FALSE.

V2 Architecture:
- All evaluation inputs (CAE, evidence, context, ruleset, trust store) are
  hashed and bound to the artifact
- context_hash and eib_hash ensure full replayability
- Verification requires exact reproduction of all inputs

Usage:
    from binaryif import (
        BinaryIFEvaluator,
        CanonicalActionEnvelope,
        create_cae,
        Ruleset,
        RulesetRegistry,
        verify_artifact
    )
    
    # Create an evaluator
    evaluator = BinaryIFEvaluator()
    
    # Register a ruleset
    ruleset = Ruleset.from_dict({...})
    evaluator.ruleset_registry.register(ruleset)
    
    # Create a Canonical Action Envelope
    cae = create_cae(
        action_type="wire_transfer",
        tenant_id="acme-corp",
        parameters={"amount": "50000000", "currency": "USD", ...}
    )
    
    # Evaluate authorization
    result = evaluator.evaluate(cae, evidence_bundle)
    
    if result.authorized():
        # PERMIT issued - execution may proceed
        permit = result.artifact.to_dict()
        # V2: context_snapshot preserved for verification
        context = result.context_snapshot
    else:
        # WITHHOLD issued - execution blocked
        failed_gates = result.artifact.failed_gates

For more information, see: https://binaryif.org
"""

__version__ = "2.0.0"
__author__ = "BinaryIF Working Group"
__license__ = "Apache-2.0"

# Core types
from .cae import (
    CanonicalActionEnvelope,
    create_cae,
    Environment,
    FinanceActionTypes,
    HealthcareActionTypes,
    InfrastructureActionTypes,
)

# Canonicalization and hashing
from .canonicalization import canonicalize, canonicalize_str
from .hashing import (
    sha256_hash,
    action_hash,
    ruleset_hash,
    evidence_bundle_hash,
    trust_store_hash,
    content_hash,
    verify_hash,
)

# Gates
from .gates import (
    Gate,
    GateResult,
    GateEvaluation,
    FailureCode,
    create_gate,
    GATE_TYPES,
    EvidencePresentGate,
    AllowlistHashMatchGate,
    NumericAssertGate,
    SignatureRequiredGate,
    NonreplayNonceGate,
    QuorumSignatureRequiredGate,
    ContradictionGuardGate,
)

# US Regulatory Gates
from .gates_us_regulatory import (
    OFACScreeningGate,
    BSAThresholdGate,
    DualControlGate,
    NPIValidationGate,
    DEAAuthorizationGate,
    HIPAAConsentGate,
    NERCCIPAuthorizationGate,
    TwoPersonIntegrityGate,
    US_REGULATORY_GATES,
)

# Rulesets
from .ruleset import (
    Ruleset,
    RulesetRegistry,
    GateDefinition,
    EvaluationMode,
    create_wire_transfer_ruleset,
    create_healthcare_procedure_ruleset,
)

# Evaluator (V2 with context binding)
from .evaluator import (
    BinaryIFEvaluator,
    EvaluationContext,
    EvaluationResult,
    BinaryIFArtifact,
    ArtifactType,
    Decision,
    EvaluatorState,
    context_hash,
    eib_hash,
)

# Verifier (V2 with context verification)
from .verifier import (
    BinaryIFVerifier,
    VerificationResult,
    VerificationOutcome,
    verify_artifact,
)

# Signing
from .signing import (
    SigningService,
    KeyPair,
    generate_signing_key,
    sign_data,
    verify_signature,
)


__all__ = [
    # Version
    "__version__",
    
    # CAE
    "CanonicalActionEnvelope",
    "create_cae",
    "Environment",
    "FinanceActionTypes",
    "HealthcareActionTypes",
    "InfrastructureActionTypes",
    
    # Canonicalization
    "canonicalize",
    "canonicalize_str",
    
    # Hashing
    "sha256_hash",
    "action_hash",
    "ruleset_hash",
    "evidence_bundle_hash",
    "trust_store_hash",
    "content_hash",
    "verify_hash",
    "context_hash",
    "eib_hash",
    
    # Gates
    "Gate",
    "GateResult",
    "GateEvaluation",
    "FailureCode",
    "create_gate",
    "GATE_TYPES",
    "EvidencePresentGate",
    "AllowlistHashMatchGate",
    "NumericAssertGate",
    "SignatureRequiredGate",
    "NonreplayNonceGate",
    "QuorumSignatureRequiredGate",
    "ContradictionGuardGate",
    
    # US Regulatory Gates
    "OFACScreeningGate",
    "BSAThresholdGate",
    "DualControlGate",
    "NPIValidationGate",
    "DEAAuthorizationGate",
    "HIPAAConsentGate",
    "NERCCIPAuthorizationGate",
    "TwoPersonIntegrityGate",
    "US_REGULATORY_GATES",
    
    # Rulesets
    "Ruleset",
    "RulesetRegistry",
    "GateDefinition",
    "EvaluationMode",
    "create_wire_transfer_ruleset",
    "create_healthcare_procedure_ruleset",
    
    # Evaluator
    "BinaryIFEvaluator",
    "EvaluationContext",
    "EvaluationResult",
    "BinaryIFArtifact",
    "ArtifactType",
    "Decision",
    "EvaluatorState",
    
    # Verifier
    "BinaryIFVerifier",
    "VerificationResult",
    "VerificationOutcome",
    "verify_artifact",
    
    # Signing
    "SigningService",
    "KeyPair",
    "generate_signing_key",
    "sign_data",
    "verify_signature",
]
