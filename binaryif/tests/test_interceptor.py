"""
BinaryIF Execution Interceptor Test Suite

Tests for Level 3 conformance - execution gating.

Critical invariant tested:
    NO IRREVERSIBLE ACTION EXECUTES WITHOUT VALID PERMIT
"""

import unittest
from datetime import datetime, timezone, timedelta

from binaryif import (
    BinaryIFEvaluator,
    create_cae,
    create_wire_transfer_ruleset,
    EvaluationContext,
)
from binaryif.interceptor import (
    ExecutionInterceptor,
    InterceptionResult,
    BlockReason,
    InterceptionDecision,
    InMemoryPermitStore,
    InMemoryAuditLog,
    PermitDeniedError,
)
from binaryif.gates import NonreplayNonceGate


class TestExecutionInterceptor(unittest.TestCase):
    """Test execution interceptor."""
    
    def setUp(self):
        """Set up test fixtures."""
        NonreplayNonceGate.reset_nonces()
        self.interceptor = ExecutionInterceptor()
        
        # Create evaluator for generating permits
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
    
    def _create_valid_permit(self):
        """Helper to create a valid permit."""
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "test-bundle",
            "nonce": f"nonce-{datetime.now().timestamp()}",
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
        
        return cae.to_dict(), result.artifact.to_dict()
    
    def test_valid_permit_allowed(self):
        """Valid permit should allow execution."""
        action, permit = self._create_valid_permit()
        
        decision = self.interceptor.intercept(action, permit)
        
        self.assertEqual(decision.result, InterceptionResult.ALLOWED)
        self.assertIsNotNone(decision.permit_id)
    
    def test_no_permit_blocked(self):
        """Missing permit should block execution."""
        action, _ = self._create_valid_permit()
        
        decision = self.interceptor.intercept(action, None)
        
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.NO_PERMIT)
    
    def test_withhold_artifact_blocked(self):
        """WITHHOLD artifact should block execution."""
        action, permit = self._create_valid_permit()
        
        # Modify to be a WITHHOLD
        permit["artifact_type"] = "WITHHOLD"
        permit["decision"] = "FALSE"
        
        decision = self.interceptor.intercept(action, permit)
        
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.INVALID_PERMIT)
    
    def test_expired_permit_blocked(self):
        """Expired permit should block execution."""
        action, permit = self._create_valid_permit()
        
        # Set expiration to past
        permit["expires_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        
        decision = self.interceptor.intercept(action, permit)
        
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.PERMIT_EXPIRED)
    
    def test_action_mismatch_blocked(self):
        """Action hash mismatch should block execution."""
        action, permit = self._create_valid_permit()
        
        # Modify the action (different from what was permitted)
        action["parameters"]["amount"] = "999999"
        
        decision = self.interceptor.intercept(action, permit)
        
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.ACTION_MISMATCH)
    
    def test_permit_single_use(self):
        """Permit should only be usable once."""
        action, permit = self._create_valid_permit()
        
        # First use should succeed
        decision1 = self.interceptor.intercept(action, permit)
        self.assertEqual(decision1.result, InterceptionResult.ALLOWED)
        
        # Second use should fail
        decision2 = self.interceptor.intercept(action, permit)
        self.assertEqual(decision2.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision2.reason, BlockReason.PERMIT_USED)
    
    def test_audit_log_records_all_attempts(self):
        """Audit log should record all execution attempts."""
        action, permit = self._create_valid_permit()
        
        # Make some attempts
        self.interceptor.intercept(action, permit)  # Allowed
        self.interceptor.intercept(action, None)    # Blocked - no permit
        self.interceptor.intercept(action, permit)  # Blocked - already used
        
        # Query audit log
        log = self.interceptor.get_audit_log()
        records = log.query()
        
        self.assertEqual(len(records), 3)
        
        # Check results
        results = [r.decision.result for r in records]
        self.assertIn(InterceptionResult.ALLOWED, results)
        self.assertIn(InterceptionResult.BLOCKED, results)
    
    def test_audit_log_query_by_result(self):
        """Audit log should support filtering by result."""
        action, permit = self._create_valid_permit()
        
        self.interceptor.intercept(action, permit)  # Allowed
        self.interceptor.intercept(action, None)    # Blocked
        
        log = self.interceptor.get_audit_log()
        
        # Query only blocked
        blocked = log.query(result=InterceptionResult.BLOCKED)
        self.assertEqual(len(blocked), 1)
        
        # Query only allowed
        allowed = log.query(result=InterceptionResult.ALLOWED)
        self.assertEqual(len(allowed), 1)


class TestInterceptorDecorator(unittest.TestCase):
    """Test the @protect decorator."""
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.interceptor = ExecutionInterceptor()
        self.evaluator = BinaryIFEvaluator()
        self.ruleset = create_wire_transfer_ruleset()
        self.evaluator.ruleset_registry.register(self.ruleset)
        
        self.execution_count = 0
    
    def test_decorator_allows_valid_permit(self):
        """Decorator should allow execution with valid permit."""
        @self.interceptor.protect("wire_transfer")
        def execute_transfer(action, permit):
            self.execution_count += 1
            return "SUCCESS"
        
        cae = create_cae(
            action_type="wire_transfer",
            tenant_id="acme-corp",
            parameters={
                "amount": "50000",
                "destination_account_hash": "sha256:approved123"
            }
        )
        
        evidence = {
            "bundle_id": "test-bundle",
            "nonce": f"nonce-{datetime.now().timestamp()}",
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
        
        # Call decorated function
        output = execute_transfer(cae.to_dict(), result.artifact.to_dict())
        
        self.assertEqual(output, "SUCCESS")
        self.assertEqual(self.execution_count, 1)
    
    def test_decorator_blocks_no_permit(self):
        """Decorator should raise exception without permit."""
        @self.interceptor.protect("wire_transfer")
        def execute_transfer(action, permit):
            self.execution_count += 1
            return "SUCCESS"
        
        action = {"action_type": "wire_transfer", "parameters": {}}
        
        with self.assertRaises(PermitDeniedError) as cm:
            execute_transfer(action, None)
        
        self.assertEqual(cm.exception.decision.reason, BlockReason.NO_PERMIT)
        self.assertEqual(self.execution_count, 0)  # Never executed


class TestPermitStoreAtomicity(unittest.TestCase):
    """Test permit store atomic operations."""
    
    def test_concurrent_mark_used(self):
        """Only one concurrent mark_used should succeed."""
        store = InMemoryPermitStore()
        
        permit_id = "permit-concurrent-test"
        action_hash = "sha256:test"
        expires = datetime.now(timezone.utc) + timedelta(hours=1)
        
        # First mark should succeed
        result1 = store.mark_used(permit_id, action_hash, expires)
        self.assertTrue(result1)
        
        # Second mark should fail
        result2 = store.mark_used(permit_id, action_hash, expires)
        self.assertFalse(result2)
    
    def test_is_used_check(self):
        """is_used should reflect current state."""
        store = InMemoryPermitStore()
        
        permit_id = "permit-check-test"
        
        # Before marking
        self.assertFalse(store.is_used(permit_id))
        
        # After marking
        store.mark_used(permit_id, "hash", datetime.now(timezone.utc) + timedelta(hours=1))
        self.assertTrue(store.is_used(permit_id))


class TestInvariantEnforcement(unittest.TestCase):
    """
    Test that the critical invariant is enforced:
    
    NO IRREVERSIBLE ACTION EXECUTES WITHOUT VALID PERMIT
    
    These tests attempt to bypass the interceptor.
    """
    
    def setUp(self):
        NonreplayNonceGate.reset_nonces()
        self.interceptor = ExecutionInterceptor()
    
    def test_null_permit_blocked(self):
        """None permit is always blocked."""
        decision = self.interceptor.intercept({"action_type": "test"}, None)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
    
    def test_empty_permit_blocked(self):
        """Empty dict permit is blocked."""
        decision = self.interceptor.intercept({"action_type": "test"}, {})
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
    
    def test_malformed_permit_blocked(self):
        """Malformed permit structure is blocked."""
        malformed = {
            "not": "a",
            "real": "permit"
        }
        decision = self.interceptor.intercept({"action_type": "test"}, malformed)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
    
    def test_forged_permit_blocked(self):
        """Forged permit (right structure, wrong hash) is blocked."""
        action = {
            "action_type": "wire_transfer",
            "action_id": "123",
            "tenant_id": "test",
            "environment_id": "production",
            "parameters": {"amount": "1000000"}
        }
        
        forged_permit = {
            "artifact_type": "PERMIT",
            "decision": "TRUE",
            "action_hash": "sha256:totally_wrong_hash",
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "nonce": "forged-nonce"
        }
        
        decision = self.interceptor.intercept(action, forged_permit)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.ACTION_MISMATCH)
    
    def test_permit_for_different_action_blocked(self):
        """Permit for a different action is blocked."""
        # Create two different actions
        action1 = {
            "action_type": "wire_transfer",
            "action_id": "action-1",
            "tenant_id": "test",
            "environment_id": "production",
            "parameters": {"amount": "100"}
        }
        
        action2 = {
            "action_type": "wire_transfer",
            "action_id": "action-2",
            "tenant_id": "test",
            "environment_id": "production",
            "parameters": {"amount": "999999"}  # Different!
        }
        
        # Permit for action1
        from binaryif.hashing import action_hash
        permit = {
            "artifact_type": "PERMIT",
            "decision": "TRUE",
            "action_hash": action_hash(action1),  # Hash of action1
            "expires_at": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "nonce": "permit-1"
        }
        
        # Try to use permit1 for action2
        decision = self.interceptor.intercept(action2, permit)
        self.assertEqual(decision.result, InterceptionResult.BLOCKED)
        self.assertEqual(decision.reason, BlockReason.ACTION_MISMATCH)


if __name__ == "__main__":
    unittest.main(verbosity=2)
