#!/usr/bin/env python3
"""
BinaryIF Production Example - Complete End-to-End Flow

This example demonstrates a complete wire transfer authorization flow
with US regulatory compliance (OFAC, BSA, dual control, CFO approval).

Run with: python -m binaryif.examples.wire_transfer_example
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any

# BinaryIF imports
from binaryif import (
    BinaryIFEvaluator,
    create_cae,
    EvaluationContext,
    RulesetRegistry,
    verify_artifact,
)
from binaryif.rulesets_us import create_us_wire_transfer_ruleset
from binaryif.interceptor import (
    ExecutionInterceptor,
    InterceptionResult,
    PermitDeniedError,
)
from binaryif.gates import NonreplayNonceGate


def simulate_ofac_screening(beneficiary_id: str) -> Dict[str, Any]:
    """
    Simulate OFAC SDN screening.
    
    In production, this would call:
    - Treasury OFAC API
    - Third-party screening service (Dow Jones, LexisNexis, etc.)
    """
    # Simulate: Most entities clear, some blocked
    blocked_entities = ["SANCTIONED-CORP", "BLOCKED-PERSON"]
    
    result = "MATCH" if beneficiary_id in blocked_entities else "CLEAR"
    
    return {
        "entity_id": beneficiary_id,
        "result": result,
        "screened_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "screening_provider": "OFAC-API-SIMULATION"
    }


def simulate_cfo_approval(action_summary: str) -> Dict[str, Any]:
    """
    Simulate CFO approval flow.
    
    In production, this would:
    1. Send notification to CFO
    2. CFO reviews action details in secure UI
    3. CFO signs with hardware token / HSM
    4. Return signed token
    """
    return {
        "role": "CFO",
        "signer_id": "cfo@acme-corp.com",
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "action_summary": action_summary,
        "valid": True,
        "signature": "simulated_ed25519_signature"
    }


def get_approved_payees() -> list:
    """
    Get list of pre-approved payees.
    
    In production, this comes from:
    - Vendor management system
    - Treasury workstation
    - ERP approved vendor list
    """
    return [
        "sha256:vendor_acme_001",
        "sha256:vendor_globex_002",
        "sha256:vendor_initech_003",
    ]


def execute_wire_transfer(action: Dict, permit: Dict) -> Dict[str, Any]:
    """
    Execute the actual wire transfer.
    
    In production, this calls:
    - SWIFT API
    - Core banking system
    - Payment processor
    """
    return {
        "status": "COMPLETED",
        "reference": f"WIRE-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        "amount": action["parameters"]["amount"],
        "currency": action["parameters"].get("currency", "USD"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def main():
    print("=" * 70)
    print("BinaryIF Wire Transfer Authorization - Production Example")
    print("=" * 70)
    
    # Reset nonce tracking for demo
    NonreplayNonceGate.reset_nonces()
    
    # =========================================================================
    # SETUP: Initialize BinaryIF components
    # =========================================================================
    
    print("\n[SETUP] Initializing BinaryIF components...")
    
    # Create evaluator with US regulatory ruleset
    evaluator = BinaryIFEvaluator()
    ruleset = create_us_wire_transfer_ruleset()
    evaluator.ruleset_registry.register(ruleset)
    
    print(f"  Registered ruleset: {ruleset.id} v{ruleset.version}")
    print(f"  Gates: {[g.id for g in ruleset.gates]}")
    
    # Create execution interceptor
    interceptor = ExecutionInterceptor()
    
    # =========================================================================
    # SCENARIO 1: Successful Wire Transfer
    # =========================================================================
    
    print("\n" + "-" * 70)
    print("SCENARIO 1: Authorized Wire Transfer to Approved Vendor")
    print("-" * 70)
    
    # Step 1: Create the action
    print("\n[STEP 1] Creating wire transfer action...")
    
    wire_action = create_cae(
        action_type="wire_transfer",
        tenant_id="acme-corp",
        parameters={
            "amount": "250000",
            "currency": "USD",
            "destination_account_hash": "sha256:vendor_acme_001",
            "beneficiary_id": "ACME-VENDOR-001",
            "beneficiary_name": "Acme Supply Co.",
            "purpose": "Invoice INV-2026-001 payment"
        },
        environment_id="production"
    )
    
    print(f"  Action ID: {wire_action.action_id}")
    print(f"  Amount: ${wire_action.parameters['amount']} {wire_action.parameters['currency']}")
    print(f"  Beneficiary: {wire_action.parameters['beneficiary_name']}")
    
    # Step 2: Gather evidence
    print("\n[STEP 2] Gathering authorization evidence...")
    
    # OFAC screening
    ofac_result = simulate_ofac_screening(wire_action.parameters["beneficiary_id"])
    print(f"  OFAC Screening: {ofac_result['result']}")
    
    # CFO approval
    cfo_token = simulate_cfo_approval(
        f"Wire ${wire_action.parameters['amount']} to {wire_action.parameters['beneficiary_name']}"
    )
    print(f"  CFO Approval: Obtained from {cfo_token['signer_id']}")
    
    # Build evidence bundle
    evidence = {
        "bundle_id": f"evidence-{wire_action.action_id}",
        "nonce": f"nonce-{datetime.now().timestamp()}",
        
        # OFAC screening result
        "ofac_screening": ofac_result,
        
        # CTR filing (required for amounts over $10k)
        "ctr_filing": {"status": "FILED", "filing_id": "CTR-2026-00123"},
        
        # Approved payees allowlist
        "allowlists": {
            "content:sha256:approved_payees": get_approved_payees()
        },
        
        # Dual control evidence
        "initiator_id": "treasury-analyst@acme-corp.com",
        "approver_id": "cfo@acme-corp.com",
        
        # CFO signature
        "cfo_approval_token": cfo_token,
    }
    
    # Step 3: Evaluate authorization
    print("\n[STEP 3] Evaluating authorization...")
    
    context = EvaluationContext(
        remaining_daily_limit="10000000",  # $10M daily limit
        tenant_id="acme-corp"
    )
    
    result = evaluator.evaluate(wire_action, evidence, context=context)
    
    print(f"  Decision: {result.artifact.decision.value}")
    print(f"  Artifact Type: {result.artifact.artifact_type.value}")
    
    if result.authorized():
        print(f"  Expires At: {result.artifact.expires_at}")
        print(f"  Action Hash: {result.artifact.action_hash[:50]}...")
        
        # Step 4: Execute via interceptor
        print("\n[STEP 4] Executing via interceptor...")
        
        decision = interceptor.intercept(wire_action.to_dict(), result.artifact.to_dict())
        
        if decision.allowed():
            print(f"  Interceptor: ALLOWED (permit_id: {decision.permit_id[:20]}...)")
            
            # Execute the actual transfer
            transfer_result = execute_wire_transfer(
                wire_action.to_dict(),
                result.artifact.to_dict()
            )
            
            print(f"\n  ✓ WIRE TRANSFER COMPLETED")
            print(f"    Reference: {transfer_result['reference']}")
            print(f"    Amount: ${transfer_result['amount']} {transfer_result['currency']}")
        else:
            print(f"  Interceptor: BLOCKED - {decision.reason}")
    else:
        print(f"\n  ✗ AUTHORIZATION DENIED")
        for gate in result.artifact.failed_gates:
            print(f"    Failed: {gate['gate_id']} - {gate.get('failure_code')}")
    
    # =========================================================================
    # SCENARIO 2: Blocked - OFAC Match
    # =========================================================================
    
    print("\n" + "-" * 70)
    print("SCENARIO 2: Wire Transfer to Sanctioned Entity (BLOCKED)")
    print("-" * 70)
    
    NonreplayNonceGate.reset_nonces()
    
    blocked_action = create_cae(
        action_type="wire_transfer",
        tenant_id="acme-corp",
        parameters={
            "amount": "50000",
            "currency": "USD",
            "destination_account_hash": "sha256:sanctioned_entity",
            "beneficiary_id": "SANCTIONED-CORP",
            "beneficiary_name": "Sanctioned Corporation Ltd."
        }
    )
    
    print(f"\n[STEP 1] Wire to: {blocked_action.parameters['beneficiary_name']}")
    
    # OFAC screening returns MATCH
    ofac_result = simulate_ofac_screening("SANCTIONED-CORP")
    print(f"[STEP 2] OFAC Screening: {ofac_result['result']} ⚠️")
    
    evidence = {
        "bundle_id": f"evidence-{blocked_action.action_id}",
        "nonce": f"nonce-{datetime.now().timestamp()}",
        "ofac_screening": ofac_result,
        "ctr_filing": {"status": "FILED", "filing_id": "CTR-2026-00124"},
        "allowlists": {"content:sha256:approved_payees": get_approved_payees()},
        "initiator_id": "treasury@acme-corp.com",
        "approver_id": "cfo@acme-corp.com",
        "cfo_approval_token": simulate_cfo_approval("Transfer to sanctioned entity"),
    }
    
    result = evaluator.evaluate(blocked_action, evidence, context=context)
    
    print(f"\n[STEP 3] Authorization Result:")
    print(f"  Decision: {result.artifact.decision.value}")
    
    if not result.authorized():
        print(f"\n  ✗ WIRE TRANSFER BLOCKED")
        for gate in result.artifact.failed_gates:
            print(f"    Gate: {gate['gate_id']}")
            print(f"    Code: {gate.get('failure_code')}")
            print(f"    Required: {gate.get('required')}")
            print(f"    Observed: {gate.get('observed')}")
    
    # =========================================================================
    # SCENARIO 3: Verification by Third Party
    # =========================================================================
    
    print("\n" + "-" * 70)
    print("SCENARIO 3: Third-Party Verification (Auditor/Regulator)")
    print("-" * 70)
    
    NonreplayNonceGate.reset_nonces()
    
    # Re-create the successful scenario
    wire_action = create_cae(
        action_type="wire_transfer",
        tenant_id="acme-corp",
        parameters={
            "amount": "250000",
            "destination_account_hash": "sha256:vendor_acme_001",
            "beneficiary_id": "ACME-VENDOR-001"
        }
    )
    
    evidence = {
        "bundle_id": f"evidence-{wire_action.action_id}",
        "nonce": f"nonce-{datetime.now().timestamp()}",
        "ofac_screening": simulate_ofac_screening("ACME-VENDOR-001"),
        "ctr_filing": {"status": "FILED", "filing_id": "CTR-2026-00125"},
        "allowlists": {"content:sha256:approved_payees": get_approved_payees()},
        "initiator_id": "treasury@acme-corp.com",
        "approver_id": "cfo@acme-corp.com",
        "cfo_approval_token": simulate_cfo_approval("Wire to vendor"),
    }
    
    result = evaluator.evaluate(wire_action, evidence, context=context)
    
    print("\n[AUDITOR] Received artifacts for verification:")
    print(f"  PERMIT artifact hash: {result.artifact.action_hash[:30]}...")
    
    # Auditor verifies the permit
    NonreplayNonceGate.reset_nonces()
    
    verification = verify_artifact(
        artifact=result.artifact.to_dict(),
        cae=wire_action.to_dict(),
        ruleset=ruleset.to_dict(),
        evidence_bundle=evidence,
        trust_store=evaluator.trust_store,
        context=context.to_dict()
    )
    
    print(f"\n[VERIFICATION RESULT]")
    print(f"  Outcome: {verification.outcome.value}")
    
    if verification.is_valid():
        print(f"\n  ✓ PERMIT VERIFIED")
        print(f"    Action was properly authorized")
        print(f"    All gates passed at evaluation time")
        print(f"    Artifact is cryptographically bound to inputs")
    else:
        print(f"\n  ✗ VERIFICATION FAILED: {verification.reason}")
    
    # =========================================================================
    # AUDIT LOG
    # =========================================================================
    
    print("\n" + "-" * 70)
    print("AUDIT LOG")
    print("-" * 70)
    
    log = interceptor.get_audit_log()
    records = log.query()
    
    print(f"\nTotal execution attempts: {len(records)}")
    for record in records:
        print(f"\n  Record: {record.record_id}")
        print(f"    Action: {record.action_type}")
        print(f"    Result: {record.decision.result.value}")
        if record.decision.reason:
            print(f"    Reason: {record.decision.reason.value}")
        print(f"    Time: {record.timestamp}")
    
    print("\n" + "=" * 70)
    print("Example Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
