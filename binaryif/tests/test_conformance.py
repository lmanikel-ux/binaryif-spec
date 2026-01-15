"""
BinaryIF Conformance Test Suite

Implements Section 23 of the BinaryIF Protocol Specification.

Test vectors from Appendix B ensure:
- Canonicalization correctness
- Hashing correctness
- Gate evaluation correctness
- Artifact verification correctness
- Fail-closed behavior
"""

import unittest
from datetime import datetime, timezone, timedelta
from decimal import Decimal

# Import BinaryIF modules
from binaryif import (
    # Canonicalization
    canonicalize,
    canonicalize_str,
    
    # Hashing
    sha256_hash,
    action_hash,
    ruleset_hash,
    evidence_bundle_hash,
    
    # CAE
    CanonicalActionEnvelope,
    create_cae,
    
    # Gates
    GateResult,
    FailureCode,
    EvidencePresentGate,
    AllowlistHashMatchGate,
    NumericAssertGate,
    SignatureRequiredGate,
    NonreplayNonceGate,
    ContradictionGuardGate,
    
    # Ruleset
    Ruleset,
    RulesetRegistry,
    GateDefinition,
    create_wire_transfer_ruleset,
    
    # Evaluator
    BinaryIFEvaluator,
    EvaluationContext,
    ArtifactType,
    Decision,
    
    # Verifier
    BinaryIFVerifier,
    VerificationOutcome,
    verify_artifact,
)


class TestCanonicalization(unittest.TestCase):
    """TV-01: Canonicalization Ordering"""
    
    def test_key_ordering(self):
        """Verify that key ordering produces stable hash."""
        # From Section 11.5 - non-canonical input
        non_canonical = {
            "parameters": {"currency": "USD", "amount": "50000000"},
            "environment_id": "production",
            "tenant_id": "acme-corp",
            "action_id": "018d9e6e-6c1e-7b6a-9c0d-111111111111",
            "action_type": "wire_transfer"
        }
        
        # Different key order, same data
        also_non_canonical = {
            "action_type": "wire_transfer",
            "tenant_id": "acme-corp",
            "action_id": "018d9e6e-6c1e-7b6a-9c0d-111111111111",
            "environment_id": "production",
            "parameters": {"amount": "50000000", "currency": "USD"}
        }
        
        # Both should produce identical canonical output
        canonical1 = canonicalize_str(non_canonical)
        canonical2 = canonicalize_str(also_non_canonical)
        
        self.assertEqual(canonical1, canonical2)
        
        # Verify keys are sorted
        self.assertTrue(canonical1.startswith('{"action_id":'))
    
    def test_nested_key_ordering(self):
        """Verify nested objects are also sorted."""
        data = {
            "z": {"b": 1, "a": 2},
            "a": {"y": 3, "x": 4}
        }
        
        canonical = canonicalize_str(data)
        
        # 'a' should come before 'z', and nested keys should be sorted
        self.assertEqual(canonical, '{"a":{"x":4,"y":3},"z":{"a":2,"b":1}}')
    
    def test_no_whitespace(self):
        """Verify compact form with no whitespace."""
        data = {"key": "value", "nested": {"inner": 1}}
        canonical = canonicalize_str(data)
        
        self.assertNotIn(" ", canonical)
        self.assertNotIn("\n", canonical)
        self.assertNotIn("\t", canonical)


class TestHashing(unittest.TestCase):
    """Test hashing functions."""
    
    def test_action_hash_format(self):
        """Verify action hash format."""
        cae = {
            "action_type": "wire_transfer",
            "action_id": "018d9e6e-6c1e-7b6a-9c0d-111111111111",
            "tenant_id": "acme-corp",
            "environment_id": "production",
            "parameters": {"amount": "50000000", "currency": "USD"}
        }
        
        h = action_hash(cae)
        
        self.assertTrue(h.startswith("sha256:"))
        self.assertEqual(len(h), 7 + 64)  # "sha256:" + 64 hex chars
    
    def test_hash_determinism(self):
        """Verify identical inputs produce identical hashes."""
        data = {"test": "data", "number": 123}
        
        h1 = sha256_hash(canonicalize(data))
        h2 = sha256_hash(canonicalize(data))
        
        self.assertEqual(h1, h2)


class TestCAE(unittest.TestCase):
    """Test Canonical Action Envelope."""
    
    def test_valid_cae(self):
        """Test creating a valid CAE."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={"amount": "50000000"},
            environment_id="production"
        )
        
        self.assertEqual(cae.action_type, "wire_transfer")
        self.assertEqual(cae.tenant_id, "acme-corp")
        self.assertIsNotNone(cae.action_id)
    
    def test_invalid_action_type(self):
        """Test that invalid action_type is rejected."""
        with self.assertRaises(ValueError):
            create_cae(
                action_type="Invalid-Type",  # Must be snake_case
                tenant_id="test",
                parameters={}
            )
    
    def test_invalid_environment(self):
        """Test that invalid environment is rejected."""
        with self.assertRaises(ValueError):
            create_cae(
                action_type="test_action",
                tenant_id="test",
                parameters={},
                environment_id="invalid_env"
            )


class TestGates(unittest.TestCase):
    """Test individual gate implementations."""
    
    def setUp(self):
        """Reset nonce tracking between tests."""
        NonreplayNonceGate.reset_nonces()
    
    def test_evidence_present_pass(self):
        """Test evidence_present gate passes when evidence exists."""
        gate = EvidencePresentGate("test_gate", {"ref": "content:sha256:abc123"})
        
        evidence = {
            "references": [
                {"type": "invoice", "ref": "content:sha256:abc123"}
            ]
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_evidence_present_fail(self):
        """TV-03: Missing evidence results in WITHHOLD."""
        gate = EvidencePresentGate("test_gate", {"ref": "content:sha256:missing"})
        
        evidence = {"references": []}
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISSING)
    
    def test_allowlist_match_pass(self):
        """Test allowlist gate passes for approved destination."""
        gate = AllowlistHashMatchGate("test_gate", {
            "value_path": "$.parameters.destination",
            "allowlist_ref": "approved_list"
        })
        
        cae = {"parameters": {"destination": "sha256:approved123"}}
        evidence = {
            "allowlists": {
                "approved_list": ["sha256:approved123", "sha256:approved456"]
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_allowlist_match_fail(self):
        """TV-05: Allowlist mismatch results in WITHHOLD."""
        gate = AllowlistHashMatchGate("test_gate", {
            "value_path": "$.parameters.destination",
            "allowlist_ref": "approved_list"
        })
        
        cae = {"parameters": {"destination": "sha256:unknown"}}
        evidence = {
            "allowlists": {
                "approved_list": ["sha256:approved123"]
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISMATCH)
    
    def test_numeric_assert_pass(self):
        """Test numeric assertion passes when within limit."""
        gate = NumericAssertGate("test_gate", {
            "left": "$.parameters.amount",
            "operator": "le",
            "right": "100000000"
        })
        
        cae = {"parameters": {"amount": "50000000"}}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_numeric_assert_fail(self):
        """TV-06: Limit exceeded results in WITHHOLD."""
        gate = NumericAssertGate("test_gate", {
            "left": "$.parameters.amount",
            "operator": "le",
            "right": "50000000"
        })
        
        cae = {"parameters": {"amount": "75000000"}}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.EXCEEDED)
    
    def test_signature_required_pass(self):
        """Test signature gate passes with valid token."""
        gate = SignatureRequiredGate("test_gate", {
            "role": "CFO",
            "token_ref": "$.cfo_token",
            "freshness_seconds": 300
        })
        
        evidence = {
            "cfo_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_signature_required_missing(self):
        """TV-03: Missing signature results in WITHHOLD."""
        gate = SignatureRequiredGate("test_gate", {
            "role": "CFO",
            "token_ref": "$.cfo_token",
            "freshness_seconds": 300
        })
        
        evidence = {}  # No token
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISSING)
    
    def test_signature_required_expired(self):
        """TV-04: Expired signature results in WITHHOLD."""
        gate = SignatureRequiredGate("test_gate", {
            "role": "CFO",
            "token_ref": "$.cfo_token",
            "freshness_seconds": 300
        })
        
        # Token issued 600 seconds ago (beyond 300s freshness)
        old_time = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat().replace("+00:00", "Z")
        
        evidence = {
            "cfo_token": {
                "role": "CFO",
                "issued_at": old_time,
                "valid": True
            }
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.EXPIRED)
    
    def test_nonreplay_nonce_pass(self):
        """Test nonce gate passes for unique nonce."""
        gate = NonreplayNonceGate("test_gate", {
            "nonce_path": "$.nonce",
            "ttl_seconds": 600
        })
        
        cae = {"nonce": "unique-nonce-12345"}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_nonreplay_nonce_fail(self):
        """Test nonce gate fails for reused nonce."""
        gate = NonreplayNonceGate("test_gate", {
            "nonce_path": "$.nonce",
            "ttl_seconds": 600
        })
        
        cae = {"nonce": "reused-nonce"}
        
        # First use should pass
        result1 = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result1.result, GateResult.PASS)
        
        # Second use should fail
        result2 = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result2.result, GateResult.FAIL)
        self.assertEqual(result2.failure_code, FailureCode.REPLAY)
    
    def test_contradiction_guard_pass(self):
        """Test contradiction guard passes when values match."""
        gate = ContradictionGuardGate("test_gate", {
            "assertions": [
                {
                    "path_a": "$.invoice.destination",
                    "path_b": "$.parameters.destination",
                    "must_match": True
                }
            ]
        })
        
        cae = {"parameters": {"destination": "sha256:abc123"}}
        evidence = {"invoice": {"destination": "sha256:abc123"}}
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_contradiction_guard_fail(self):
        """TV-07: Contradictory evidence results in WITHHOLD."""
        gate = ContradictionGuardGate("test_gate", {
            "assertions": [
                {
                    "path_a": "$.invoice.destination",
                    "path_b": "$.parameters.destination",
                    "must_match": True
                }
            ]
        })
        
        cae = {"parameters": {"destination": "sha256:def456"}}
        evidence = {"invoice": {"destination": "sha256:abc123"}}
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.CONTRADICTION)


class TestEvaluator(unittest.TestCase):
    """Test BinaryIF Evaluator."""
    
    def setUp(self):
        """Set up evaluator with standard ruleset."""
        NonreplayNonceGate.reset_nonces()
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
    
    def test_permit_happy_path(self):
        """TV-02: Successful authorization returns PERMIT."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000000",
                "currency": "USD",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "bundle-test",
            "nonce": "unique-test-nonce",
            "allowlists": {
                "content:sha256:approved_payees": ["sha256:approved123"]
            },
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        self.assertTrue(result.authorized())
        self.assertEqual(result.artifact.artifact_type, ArtifactType.PERMIT)
        self.assertEqual(result.artifact.decision, Decision.TRUE)
    
    def test_withhold_missing_signature(self):
        """TV-03: Missing CFO token returns WITHHOLD."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "bundle-test",
            "nonce": "unique-test-nonce-2",
            "allowlists": {
                "content:sha256:approved_payees": ["sha256:approved123"]
            }
            # No cfo_approval_token
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        self.assertFalse(result.authorized())
        self.assertEqual(result.artifact.artifact_type, ArtifactType.WITHHOLD)
        self.assertEqual(result.artifact.decision, Decision.FALSE)
        
        # Check failed gate
        failed_ids = [g["gate_id"] for g in result.artifact.failed_gates]
        self.assertIn("cfo_signature", failed_ids)
    
    def test_withhold_unknown_action(self):
        """TV-08: Unknown action type returns WITHHOLD."""
        cae = create_cae(
            action_type="unknown_action_xyz",
            tenant_id="acme-corp",
            parameters={}
        )
        
        result = self.evaluator.evaluate(cae, {})
        
        self.assertFalse(result.authorized())
        self.assertEqual(result.artifact.artifact_type, ArtifactType.WITHHOLD)
        
        failed_ids = [g["gate_id"] for g in result.artifact.failed_gates]
        self.assertIn("ruleset_lookup", failed_ids)


class TestVerifier(unittest.TestCase):
    """Test BinaryIF Verifier."""
    
    def setUp(self):
        """Set up test fixtures."""
        NonreplayNonceGate.reset_nonces()
    
    def test_valid_permit_verification(self):
        """Test verification of valid PERMIT."""
        # Create a valid permit through the evaluator
        evaluator = BinaryIFEvaluator()
        ruleset = create_wire_transfer_ruleset()
        evaluator.ruleset_registry.register(ruleset)
        
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "bundle-verify",
            "nonce": "verify-nonce-1",
            "allowlists": {
                "content:sha256:approved_payees": ["sha256:approved123"]
            },
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        eval_result = evaluator.evaluate(cae, evidence, context=context)
        
        self.assertTrue(eval_result.authorized())
        
        # Now verify the artifact - must pass same context for replay
        NonreplayNonceGate.reset_nonces()  # Reset for replay
        
        result = verify_artifact(
            artifact=eval_result.artifact.to_dict(),
            cae=cae.to_dict(),
            ruleset=ruleset.to_dict(),
            evidence_bundle=evidence,
            trust_store=evaluator.trust_store,
            context=context.to_dict()  # Pass context for replay
        )
        
        self.assertTrue(result.is_valid())
        self.assertEqual(result.outcome, VerificationOutcome.VALID_PERMIT)
    
    def test_hash_mismatch_detection(self):
        """TV-09/10: Hash mismatch is detected - action hash mismatch."""
        from binaryif import action_hash
        
        # Create matching trust store
        trust_store = {
            "trust_store_version": "2026-01-14-001",
            "effective_from": "2026-01-01T00:00:00Z",
            "keys": [{
                "key_id": "kid:test-key",
                "key_type": "ARTIFACT_SIGNING",
                "algorithm": "Ed25519",
                "public_key": "placeholder",
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z"
            }]
        }
        
        cae = {
            "action_type": "test_action",
            "action_id": "018d9e6e-6c1e-7b6a-9c0d-111111111111",
            "tenant_id": "test-tenant",
            "environment_id": "test",
            "parameters": {"key": "value"}
        }
        
        # Artifact with WRONG action hash
        artifact = {
            "binaryif_version": "1.0",
            "artifact_type": "PERMIT",
            "decision": "TRUE",
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "action_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",  # Wrong!
            "ruleset": {
                "ruleset_id": "test",
                "ruleset_version": "1.0.0",
                "ruleset_hash": "sha256:placeholder"
            },
            "evidence": {
                "bundle_id": "test",
                "bundle_hash": "sha256:placeholder"
            },
            "trust_store_hash": "sha256:placeholder",
            "nonce": "test-nonce",
            "signatures": [{
                "key_id": "kid:test-key",
                "algorithm": "Ed25519",
                "sig": "placeholder"
            }]
        }
        
        ruleset = {
            "id": "test",
            "version": "1.0.0",
            "action_type": "test_action",
            "gates": [{"id": "g", "type": "evidence_present", "parameters": {"ref": "x"}}],
            "evaluation_mode": "ALL_MUST_PASS"
        }
        
        result = verify_artifact(
            artifact=artifact,
            cae=cae,
            ruleset=ruleset,
            evidence_bundle={},
            trust_store=trust_store
        )
        
        self.assertFalse(result.is_valid())
        self.assertIn("mismatch", result.reason.lower())


class TestFailClosedBehavior(unittest.TestCase):
    """Test fail-closed behavior per Section 16."""
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
    
    def test_missing_evidence_fails_closed(self):
        """Missing evidence results in WITHHOLD."""
        evaluator = BinaryIFEvaluator()
        ruleset = create_wire_transfer_ruleset()
        evaluator.ruleset_registry.register(ruleset)
        
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={"amount": "50000000", "destination_account_hash": "sha256:test"}
        )
        
        # Empty evidence bundle
        result = evaluator.evaluate(cae, {}, context=EvaluationContext(remaining_daily_limit="100000000"))
        
        self.assertFalse(result.authorized())
        self.assertEqual(result.artifact.decision, Decision.FALSE)
    
    def test_invalid_signature_fails_closed(self):
        """Invalid signature results in WITHHOLD."""
        evaluator = BinaryIFEvaluator()
        ruleset = create_wire_transfer_ruleset()
        evaluator.ruleset_registry.register(ruleset)
        
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={"amount": "50000000", "destination_account_hash": "sha256:approved123"}
        )
        
        evidence = {
            "bundle_id": "bundle-invalid",
            "nonce": "invalid-sig-nonce",
            "allowlists": {
                "content:sha256:approved_payees": ["sha256:approved123"]
            },
            "cfo_approval_token": {
                "role": "WRONG_ROLE",  # Wrong role
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        result = evaluator.evaluate(cae, evidence, context=EvaluationContext(remaining_daily_limit="100000000"))
        
        self.assertFalse(result.authorized())


if __name__ == "__main__":
    unittest.main(verbosity=2)
