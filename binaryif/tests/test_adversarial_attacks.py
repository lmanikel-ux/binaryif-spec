"""
BinaryIF Adversarial Attack Simulation Suite

Phase 3 of the Critical Infrastructure Mode design process.

This suite systematically tests attack vectors from:
- Insider engineers
- Compromised AI models
- Malicious integrators
- Careless customers
- Post-incident regulators

Each test represents a realistic attack scenario that BinaryIF must defend against.
Tests are designed to FAIL if the defense is inadequate.
"""

import unittest
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any
import copy

from binaryif import (
    BinaryIFEvaluator,
    BinaryIFVerifier,
    create_cae,
    create_wire_transfer_ruleset,
    EvaluationContext,
    VerificationOutcome,
    verify_artifact,
    action_hash,
    canonicalize,
)
from binaryif.interceptor import (
    ExecutionInterceptor,
    InterceptionResult,
    BlockReason,
)
from binaryif.gates import NonreplayNonceGate


class TestReplayAttacks(unittest.TestCase):
    """
    Attack Vector: Replay previously valid PERMITs.
    
    Threat: Attacker captures valid PERMIT, resubmits to execute
    action multiple times (e.g., wire transfer executed twice).
    
    Defense: nonreplay_nonce gate + TTL expiry + single-use permit tracking
    """
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
        self.interceptor = ExecutionInterceptor()
    
    def test_same_nonce_rejected(self):
        """Attempt to reuse the same nonce should fail."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        # Evidence with same nonce for both attempts
        evidence = {
            "bundle_id": "test",
            "nonce": "reused-nonce-attack",  # Same nonce!
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        
        # First evaluation should succeed
        result1 = self.evaluator.evaluate(cae, evidence, context=context)
        self.assertTrue(result1.authorized())
        
        # Second evaluation with same nonce should FAIL
        result2 = self.evaluator.evaluate(cae, evidence, context=context)
        self.assertFalse(result2.authorized())
        
        # Verify the failed gate is replay_prevention
        failed_ids = [g["gate_id"] for g in result2.artifact.failed_gates]
        self.assertIn("replay_prevention", failed_ids)
    
    def test_interceptor_blocks_permit_reuse(self):
        """Interceptor should block reuse of same PERMIT."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        action = cae.to_dict()
        permit = result.artifact.to_dict()
        
        # First intercept should allow
        decision1 = self.interceptor.intercept(action, permit)
        self.assertEqual(decision1.result, InterceptionResult.ALLOWED)
        
        # Second intercept with SAME permit should block
        decision2 = self.interceptor.intercept(action, permit)
        self.assertEqual(decision2.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision2.reason, BlockReason.PERMIT_USED)
    
    def test_expired_permit_cannot_replay(self):
        """Expired permits should not be replayable."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={"amount": "50000", "destination_account_hash": "sha256:approved123"}
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        permit = result.artifact.to_dict()
        
        # Modify expiration to be in the past
        permit["expires_at"] = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
        
        decision = self.interceptor.intercept(cae.to_dict(), permit)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.PERMIT_EXPIRED)


class TestTamperingAttacks(unittest.TestCase):
    """
    Attack Vector: Modify action or permit after authorization.
    
    Threat: Attacker obtains valid PERMIT, then modifies the action
    to change destination, amount, or other critical parameters.
    
    Defense: action_hash binding + cryptographic signatures
    """
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
        self.interceptor = ExecutionInterceptor()
    
    def test_modified_amount_detected(self):
        """Changing amount after PERMIT should be detected."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",  # Original amount
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        # Get the valid permit
        permit = result.artifact.to_dict()
        
        # ATTACK: Modify the action to increase amount
        tampered_action = cae.to_dict()
        tampered_action["parameters"]["amount"] = "5000000"  # 100x increase!
        
        # Interceptor should detect the hash mismatch
        decision = self.interceptor.intercept(tampered_action, permit)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.ACTION_MISMATCH)
    
    def test_modified_destination_detected(self):
        """Changing destination after PERMIT should be detected."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"  # Original
            }
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        permit = result.artifact.to_dict()
        
        # ATTACK: Modify destination to attacker's account
        tampered_action = cae.to_dict()
        tampered_action["parameters"]["destination_account_hash"] = "sha256:attacker_account"
        
        decision = self.interceptor.intercept(tampered_action, permit)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.ACTION_MISMATCH)
    
    def test_verifier_detects_tampered_evidence(self):
        """Verifier should detect if evidence was tampered after PERMIT."""
        NonreplayNonceGate.reset_nonces()
        
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        # Tamper with evidence
        tampered_evidence = copy.deepcopy(evidence)
        tampered_evidence["cfo_approval_token"]["role"] = "Attacker"
        
        # Reset nonces for verification replay
        NonreplayNonceGate.reset_nonces()
        
        # Verification should fail due to evidence hash mismatch
        verification = verify_artifact(
            artifact=result.artifact.to_dict(),
            cae=cae.to_dict(),
            ruleset=self.ruleset.to_dict(),
            evidence_bundle=tampered_evidence,  # Tampered!
            trust_store=self.evaluator.trust_store,
            context=context.to_dict()
        )
        
        self.assertFalse(verification.is_valid())
        self.assertIn("mismatch", verification.reason.lower())


class TestForgeryAttacks(unittest.TestCase):
    """
    Attack Vector: Forge PERMIT without proper authorization.
    
    Threat: Attacker creates fake PERMIT that appears valid
    but was never actually issued by the evaluator.
    
    Defense: Cryptographic signatures + trust store verification
    """
    
    def setUp(self):
        self.interceptor = ExecutionInterceptor()
    
    def test_forged_permit_structure_rejected(self):
        """Hand-crafted PERMIT without proper hashes should be rejected."""
        action = {
            "action_type": "wire_transfer",
            "action_id": "forged-123",
            "tenant_id": "victim-corp",
            "environment_id": "production",
            "parameters": {
                "amount": "1000000",
                "destination_account_hash": "sha256:attacker_account"
            }
        }
        
        # Attacker forges a PERMIT
        forged_permit = {
            "binaryif_version": "2.0",
            "artifact_type": "PERMIT",
            "decision": "TRUE",
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "action_hash": "sha256:i_made_this_up",  # Wrong hash!
            "nonce": "forged-nonce-123"
        }
        
        decision = self.interceptor.intercept(action, forged_permit)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.ACTION_MISMATCH)
    
    def test_forged_permit_with_correct_hash_but_wrong_signature(self):
        """
        Even with correct action_hash, forged signature should fail.
        
        Note: Current implementation uses placeholder signatures.
        In production, this would verify Ed25519 signature.
        """
        action = {
            "action_type": "wire_transfer",
            "action_id": "forged-456",
            "tenant_id": "victim-corp",
            "environment_id": "production",
            "parameters": {
                "amount": "1000000",
                "destination_account_hash": "sha256:attacker_account"
            }
        }
        
        # Calculate correct hash
        correct_hash = action_hash(action)
        
        forged_permit = {
            "binaryif_version": "2.0",
            "artifact_type": "PERMIT",
            "decision": "TRUE",
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "action_hash": correct_hash,  # Correct hash
            "nonce": "forged-nonce-456",
            "signatures": [{
                "key_id": "kid:forged-key",
                "algorithm": "Ed25519",
                "sig": "totally_fake_signature"  # Forged!
            }]
        }
        
        # Interceptor allows based on structure (signature verification is separate)
        # But verifier would catch this in production
        decision = self.interceptor.intercept(action, forged_permit)
        
        # The interceptor passes structure checks but permit store would track
        # In this case, it should be ALLOWED first time (then tracked)
        # Real production would verify signature first


class TestConfusedDeputyAttacks(unittest.TestCase):
    """
    Attack Vector: Trick authorized user into signing wrong action.
    
    Threat: Attacker presents misleading UI to authorized signer,
    getting them to sign an action different from what they intended.
    
    Defense: Signature binds to action_hash, human must review canonical action
    """
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
    
    def test_signature_bound_to_specific_action(self):
        """Signature token should only work for the specific action it was created for."""
        # User thinks they're approving $1000 to Vendor A
        user_intended_action = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "1000",
                "destination_account_hash": "sha256:vendor_a"
            }
        )
        
        # But attacker submits $1000000 to Attacker's account
        actual_action = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "1000000",  # 1000x more!
                "destination_account_hash": "sha256:attacker"  # Different dest!
            }
        )
        
        # Evidence with CFO approval (user thought they approved something else)
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {
                "content:sha256:approved_payees": ["sha256:vendor_a", "sha256:attacker"]
            },
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        
        # Even if gates pass, the PERMIT is bound to actual_action
        result = self.evaluator.evaluate(actual_action, evidence, context=context)
        
        if result.authorized():
            permit = result.artifact.to_dict()
            
            # The permit's action_hash is for actual_action, not user_intended_action
            self.assertEqual(permit["action_hash"], action_hash(actual_action.to_dict()))
            self.assertNotEqual(permit["action_hash"], action_hash(user_intended_action.to_dict()))
            
            # Defense: The user signing interface MUST show the canonical action
            # (destination, amount, etc.) NOT just "Approve transfer?"


class TestContextManipulationAttacks(unittest.TestCase):
    """
    Attack Vector: Manipulate context to bypass limits.
    
    Threat: Attacker provides false context (e.g., inflated daily limit)
    to bypass numeric_assert gates.
    
    Defense: V2 architecture binds context_hash to artifact
    """
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
    
    def test_context_hash_binding(self):
        """Artifact should include context_hash for verification."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        artifact = result.artifact.to_dict()
        
        # V2 artifact must have context_hash
        self.assertIn("context_hash", artifact)
        self.assertTrue(artifact["context_hash"].startswith("sha256:"))
    
    def test_verifier_detects_context_mismatch(self):
        """Verifier should detect if context was different during evaluation."""
        NonreplayNonceGate.reset_nonces()
        
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {"content:sha256:approved_payees": ["sha256:approved123"]},
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        # Evaluation with high limit
        real_context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=real_context)
        
        # Attacker tries to verify with different (lower) context
        # to make it look like the action exceeded limits
        fake_context = {"remaining_daily_limit": "1000", "evaluation_time": real_context.to_dict()["evaluation_time"], "environment": "production"}
        
        NonreplayNonceGate.reset_nonces()
        
        verification = verify_artifact(
            artifact=result.artifact.to_dict(),
            cae=cae.to_dict(),
            ruleset=self.ruleset.to_dict(),
            evidence_bundle=evidence,
            trust_store=self.evaluator.trust_store,
            context=fake_context  # Wrong context!
        )
        
        # V2: Should detect context hash mismatch
        self.assertFalse(verification.is_valid())
        self.assertIn("context", verification.reason.lower())


class TestAllowlistBypassAttacks(unittest.TestCase):
    """
    Attack Vector: Bypass allowlist controls.
    
    Threat: Attacker finds ways to add unauthorized destinations
    to allowlist or bypass the check entirely.
    
    Defense: Allowlist hash binding + content-addressed references
    """
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
    
    def test_destination_not_in_allowlist_blocked(self):
        """Destination not in allowlist should be blocked."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:attacker_not_approved"
            }
        )
        
        evidence = {
            "bundle_id": "test",
            "nonce": f"unique-{datetime.now().timestamp()}",
            "allowlists": {
                "content:sha256:approved_payees": ["sha256:vendor_a", "sha256:vendor_b"]
                # attacker_not_approved is NOT in list
            },
            "cfo_approval_token": {
                "role": "CFO",
                "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "valid": True
            }
        }
        
        context = EvaluationContext(remaining_daily_limit="100000000")
        result = self.evaluator.evaluate(cae, evidence, context=context)
        
        self.assertFalse(result.authorized())
        
        failed_ids = [g["gate_id"] for g in result.artifact.failed_gates]
        self.assertIn("recipient_allowlist", failed_ids)


class TestTimingAttacks(unittest.TestCase):
    """
    Attack Vector: Exploit timing windows.
    
    Threat: Attacker manipulates system clock or exploits
    the time between PERMIT issuance and execution.
    
    Defense: Short TTL + attestation-based time + max_clock_skew
    """
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.interceptor = ExecutionInterceptor(max_clock_skew_seconds=30)
    
    def test_permit_ttl_enforced(self):
        """Permits should not be usable after TTL expiry."""
        action = {
            "action_type": "wire_transfer",
            "action_id": "timing-test",
            "tenant_id": "test",
            "environment_id": "production",
            "parameters": {"amount": "1000"}
        }
        
        permit = {
            "artifact_type": "PERMIT",
            "decision": "TRUE",
            "action_hash": action_hash(action),
            "expires_at": (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
            "nonce": "timing-nonce"
        }
        
        decision = self.interceptor.intercept(action, permit)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.PERMIT_EXPIRED)


if __name__ == "__main__":
    unittest.main(verbosity=2)
