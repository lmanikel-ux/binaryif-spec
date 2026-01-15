# BinaryIF Protocol Reference Implementation

**The Deterministic Authorization Layer for Irreversible Actions**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![Conformance](https://img.shields.io/badge/BinaryIF-Level%202%20Authorizer-green.svg)](https://binaryif.org)

## Overview

BinaryIF is a protocol that governs whether an irreversible action may execute. It introduces a non-AI, fail-closed control layer between an agent's intent to act and the execution of that action.

**The core insight:** Intelligence cannot authorize itself.

The protocol evaluates a single Boolean predicate:

```
AUTHORIZED(action, evidence, ruleset, context) ∈ { TRUE, FALSE }
```

There is no third state. If the predicate cannot be evaluated deterministically, it resolves to `FALSE`.

## Installation

```bash
# Core package (no crypto)
pip install binaryif

# With Ed25519 cryptographic signing
pip install binaryif[crypto]

# Development dependencies
pip install binaryif[dev]
```

## Quick Start

```python
from binaryif import (
    BinaryIFEvaluator,
    create_cae,
    create_wire_transfer_ruleset,
    EvaluationContext,
)

# Create evaluator and register ruleset
evaluator = BinaryIFEvaluator()
ruleset = create_wire_transfer_ruleset()
evaluator.ruleset_registry.register(ruleset)

# Create a Canonical Action Envelope
cae = create_cae(
    action_type="wire_transfer",
    tenant_id="acme-corp",
    parameters={
        "amount": "50000000",
        "currency": "USD",
        "destination_account_hash": "sha256:approved_vendor_123"
    }
)

# Prepare evidence bundle
evidence = {
    "bundle_id": "evidence-001",
    "nonce": "unique-nonce-xyz",
    "allowlists": {
        "content:sha256:approved_payees": ["sha256:approved_vendor_123"]
    },
    "cfo_approval_token": {
        "role": "CFO",
        "issued_at": "2026-01-14T12:00:00Z",
        "signature": "..."
    }
}

# Set context
context = EvaluationContext(remaining_daily_limit="100000000")

# Evaluate authorization
result = evaluator.evaluate(cae, evidence, context=context)

if result.authorized():
    print("PERMIT issued - execution may proceed")
    permit = result.artifact.to_dict()
else:
    print("WITHHOLD issued - execution blocked")
    for gate in result.artifact.failed_gates:
        print(f"  Failed: {gate['gate_id']} - {gate['failure_code']}")
```

## CLI Usage

```bash
# Run demonstration
binaryif demo

# Evaluate authorization
binaryif evaluate -a action.json -e evidence.json -r ruleset.json

# Verify an artifact
binaryif verify -A permit.json -a action.json -e evidence.json -r ruleset.json

# Generate signing keys
binaryif keygen -o trust_store.json

# Compute hashes
binaryif hash -f action.json
```

## Architecture

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────────┐
│   AGENT     │────▶│    BinaryIF     │────▶│    EXECUTION        │
│ (Untrusted) │     │    EVALUATOR    │     │    ENVIRONMENT      │
└─────────────┘     └─────────────────┘     └─────────────────────┘
                            │
                            │ Emits exactly one:
                            ▼
                    ┌─────────────┐
                    │   PERMIT    │  (TRUE)
                    │     or      │
                    │  WITHHOLD   │  (FALSE)
                    └─────────────┘
```

## Key Concepts

### Canonical Action Envelope (CAE)

The normalized representation of a proposed action:

```python
from binaryif import create_cae

cae = create_cae(
    action_type="wire_transfer",      # Action class (snake_case)
    tenant_id="acme-corp",            # Entity identifier
    environment_id="production",       # Environment
    parameters={                       # Action-specific data
        "amount": "50000000",
        "currency": "USD",
        "destination_account_hash": "sha256:abc123"
    }
)
```

### Gates

Deterministic authorization conditions:

| Gate Type | Purpose |
|-----------|---------|
| `evidence_present` | Verify evidence exists |
| `allowlist_hash_match` | Verify value in approved list |
| `numeric_assert` | Numeric comparisons |
| `signature_required` | Cryptographic signature from role |
| `nonreplay_nonce` | Prevent replay attacks |
| `quorum_signature_required` | Multi-party approval |
| `contradiction_guard` | Detect conflicting claims |

### Rulesets

Versioned collections of gates:

```python
from binaryif import Ruleset, GateDefinition

ruleset = Ruleset(
    id="wire_transfer.high_value",
    version="1.0.0",
    action_type="wire_transfer",
    gates=[
        GateDefinition(
            id="cfo_approval",
            type="signature_required",
            parameters={
                "role": "CFO",
                "token_ref": "$.evidence.cfo_token",
                "freshness_seconds": 300
            }
        ),
        # ... more gates
    ]
)
```

### Artifacts

Cryptographically signed authorization records:

- **PERMIT**: All gates passed; execution authorized
- **WITHHOLD**: One or more gates failed; execution blocked

Both are immutable, replayable, and non-repudiable.

## Domain Profiles

### Finance Profile (FIP v1.0)

Covered actions: `wire_transfer`, `payee_create`, `settlement_release`

```python
from binaryif import create_wire_transfer_ruleset

ruleset = create_wire_transfer_ruleset(
    allowlist_ref="content:sha256:approved_payees",
    keyring_ref="content:sha256:executive_keyring"
)
```

### Healthcare Profile (HIP v1.0)

Covered actions: `procedure_incision_start`, `implant_selection_commit`, `medication_order_submit`

```python
from binaryif import create_healthcare_procedure_ruleset

ruleset = create_healthcare_procedure_ruleset()
```

## Verification

Third-party verification of artifacts:

```python
from binaryif import verify_artifact

result = verify_artifact(
    artifact=permit_dict,
    cae=action_dict,
    ruleset=ruleset_dict,
    evidence_bundle=evidence_dict,
    trust_store=trust_store_dict
)

if result.is_valid():
    print(f"✓ {result.outcome.value}")
else:
    print(f"✗ INVALID: {result.reason}")
```

## Conformance Levels

| Level | Name | Capability |
|-------|------|------------|
| 1 | Verifier | Validate BinaryIF Records |
| 2 | Authorizer | Evaluate rulesets, emit Records |
| 3 | Interceptor | Block execution without PERMIT |

This implementation is a **Level 2 Authorizer**.

## Protocol Invariants

1. **Execution Gating**: No irreversible action executes without valid PERMIT
2. **Fail-Closed**: Any uncertainty resolves to FALSE
3. **Replayability**: Artifacts verifiable independent of agent internals
4. **Non-Repudiation**: Cryptographically bound to inputs and rules
5. **Determinism**: Identical inputs produce identical outputs

## Security Model

### What BinaryIF Guarantees

- Fail-closed execution control
- Deterministic evaluation
- Replayable authorization
- Non-repudiation

### What BinaryIF Does NOT Guarantee

- Correctness of the action
- Safety of the action
- Absence of fraud
- Optimality of decisions

## Testing

```bash
# Run conformance test suite
python -m pytest tests/ -v

# Run specific test vector
python -m pytest tests/test_conformance.py::TestGates::test_allowlist_match_fail -v
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache 2.0. See [LICENSE](LICENSE).

## References

- [BinaryIF Protocol Specification v1.0](https://binaryif.org/spec)
- [RFC 2119](https://www.ietf.org/rfc/rfc2119.txt) - Requirement Levels
- [RFC 8032](https://www.ietf.org/rfc/rfc8032.txt) - Ed25519
- [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) - SHA-256

---

**The Final Invariant:** Execution may occur only if authority has already resolved to TRUE.
