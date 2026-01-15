#!/usr/bin/env python3
"""
BinaryIF Command Line Interface

Usage:
    binaryif evaluate --action <file> --evidence <file> --ruleset <file>
    binaryif verify --artifact <file> --action <file> --evidence <file> --ruleset <file>
    binaryif hash --file <file>
    binaryif keygen --output <file>
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def load_json(path: str) -> dict:
    """Load JSON from file."""
    with open(path, 'r') as f:
        return json.load(f)


def save_json(data: dict, path: str):
    """Save JSON to file."""
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def cmd_evaluate(args):
    """Evaluate authorization for an action."""
    from binaryif import (
        BinaryIFEvaluator,
        CanonicalActionEnvelope,
        Ruleset,
        EvaluationContext,
    )
    
    # Load inputs
    action_data = load_json(args.action)
    evidence_data = load_json(args.evidence)
    ruleset_data = load_json(args.ruleset)
    
    # Create objects
    cae = CanonicalActionEnvelope.from_dict(action_data)
    ruleset = Ruleset.from_dict(ruleset_data)
    
    # Create context
    context = EvaluationContext()
    if args.context:
        ctx_data = load_json(args.context)
        context.remaining_daily_limit = ctx_data.get("remaining_daily_limit")
        context.additional = ctx_data
    
    # Evaluate
    evaluator = BinaryIFEvaluator()
    result = evaluator.evaluate(cae, evidence_data, ruleset, context)
    
    # Output
    artifact = result.artifact.to_dict()
    
    if args.output:
        save_json(artifact, args.output)
        print(f"Artifact saved to: {args.output}")
    else:
        print(json.dumps(artifact, indent=2))
    
    # Exit code based on result
    if result.authorized():
        print(f"\n✓ PERMIT issued", file=sys.stderr)
        return 0
    else:
        print(f"\n✗ WITHHOLD issued", file=sys.stderr)
        for gate in result.artifact.failed_gates or []:
            print(f"  - {gate['gate_id']}: {gate.get('failure_code', 'FAIL')}", file=sys.stderr)
        return 1


def cmd_verify(args):
    """Verify a BinaryIF artifact."""
    from binaryif import verify_artifact
    
    # Load inputs
    artifact = load_json(args.artifact)
    cae = load_json(args.action)
    evidence = load_json(args.evidence)
    ruleset = load_json(args.ruleset)
    
    # Load trust store
    if args.trust_store:
        trust_store = load_json(args.trust_store)
    else:
        # Default trust store
        trust_store = {
            "trust_store_version": "2026-01-14-001",
            "effective_from": "2026-01-01T00:00:00Z",
            "keys": [{
                "key_id": artifact.get("signatures", [{}])[0].get("key_id", "kid:unknown"),
                "key_type": "ARTIFACT_SIGNING",
                "algorithm": "Ed25519",
                "public_key": "placeholder",
                "valid_from": "2025-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z"
            }]
        }
    
    # Verify
    result = verify_artifact(artifact, cae, ruleset, evidence, trust_store)
    
    if result.is_valid():
        print(f"✓ {result.outcome.value}")
        return 0
    else:
        print(f"✗ INVALID: {result.reason}")
        if result.details:
            print(json.dumps(result.details, indent=2))
        return 1


def cmd_hash(args):
    """Compute BinaryIF hashes."""
    from binaryif import action_hash, ruleset_hash, evidence_bundle_hash, sha256_hash
    
    data = load_json(args.file)
    
    # Determine type and compute appropriate hash
    if "action_type" in data and "action_id" in data:
        h = action_hash(data)
        print(f"action_hash: {h}")
    elif "gates" in data and "version" in data:
        h = ruleset_hash(data)
        print(f"ruleset_hash: {h}")
    elif "bundle_id" in data or "references" in data:
        h = evidence_bundle_hash(data)
        print(f"bundle_hash: {h}")
    else:
        # Generic hash
        from binaryif.canonicalization import canonicalize
        h = sha256_hash(canonicalize(data))
        print(f"sha256: {h}")


def cmd_keygen(args):
    """Generate Ed25519 signing key pair."""
    from binaryif import SigningService
    
    service = SigningService()
    key_id = args.key_id or f"kid:binaryif-{datetime.now().strftime('%Y%m%d')}-001"
    
    key_pair = service.generate_key_pair(
        key_id=key_id,
        validity_days=args.validity_days or 90
    )
    
    trust_store = service.get_trust_store()
    
    if args.output:
        save_json(trust_store, args.output)
        print(f"Trust store saved to: {args.output}")
    else:
        print(json.dumps(trust_store, indent=2))
    
    print(f"\nGenerated key: {key_id}", file=sys.stderr)
    print(f"Valid until: {key_pair.valid_until.isoformat()}", file=sys.stderr)


def cmd_demo(args):
    """Run a demonstration of BinaryIF."""
    from binaryif import (
        BinaryIFEvaluator,
        create_cae,
        create_wire_transfer_ruleset,
        EvaluationContext,
    )
    from binaryif.gates import NonreplayNonceGate
    
    print("=" * 60)
    print("BinaryIF Protocol Demonstration")
    print("=" * 60)
    
    # Reset nonce tracking for demo
    NonreplayNonceGate.reset_nonces()
    
    # Create evaluator with standard wire transfer ruleset
    evaluator = BinaryIFEvaluator()
    ruleset = create_wire_transfer_ruleset()
    evaluator.ruleset_registry.register(ruleset)
    
    print(f"\nRegistered ruleset: {ruleset.id} v{ruleset.version}")
    print(f"Gates: {[g.id for g in ruleset.gates]}")
    
    # Scenario 1: Missing CFO signature
    print("\n" + "-" * 60)
    print("Scenario 1: Wire transfer WITHOUT CFO signature")
    print("-" * 60)
    
    cae1 = create_cae(
        action_type="wire_transfer",
        tenant_id="acme-corp",
        parameters={
            "amount": "50000000",
            "currency": "USD",
            "destination_account_hash": "sha256:approved123",
            "beneficiary_id": "vendor-001"
        }
    )
    
    evidence1 = {
        "bundle_id": "bundle-001",
        "nonce": "unique-nonce-001",
        "allowlists": {
            "content:sha256:approved_payees": ["sha256:approved123"]
        }
        # Note: NO cfo_approval_token
    }
    
    context1 = EvaluationContext(remaining_daily_limit="100000000")
    
    result1 = evaluator.evaluate(cae1, evidence1, context=context1)
    
    print(f"Decision: {result1.artifact.decision.value}")
    print(f"Artifact: {result1.artifact.artifact_type.value}")
    if result1.artifact.failed_gates:
        for fg in result1.artifact.failed_gates:
            print(f"  Failed: {fg['gate_id']} - {fg.get('failure_code')}")
    
    # Scenario 2: Complete evidence with CFO signature
    print("\n" + "-" * 60)
    print("Scenario 2: Wire transfer WITH valid CFO signature")
    print("-" * 60)
    
    cae2 = create_cae(
        action_type="wire_transfer",
        tenant_id="acme-corp",
        parameters={
            "amount": "50000000",
            "currency": "USD",
            "destination_account_hash": "sha256:approved123",
            "beneficiary_id": "vendor-001"
        }
    )
    
    evidence2 = {
        "bundle_id": "bundle-002",
        "nonce": "unique-nonce-002",
        "allowlists": {
            "content:sha256:approved_payees": ["sha256:approved123"]
        },
        "cfo_approval_token": {
            "role": "CFO",
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "valid": True,
            "signature": "placeholder"
        }
    }
    
    context2 = EvaluationContext(remaining_daily_limit="100000000")
    
    result2 = evaluator.evaluate(cae2, evidence2, context=context2)
    
    print(f"Decision: {result2.artifact.decision.value}")
    print(f"Artifact: {result2.artifact.artifact_type.value}")
    if result2.authorized():
        print(f"  Expires: {result2.artifact.expires_at}")
        print(f"  Action Hash: {result2.artifact.action_hash[:40]}...")
    
    # Scenario 3: Limit exceeded
    print("\n" + "-" * 60)
    print("Scenario 3: Wire transfer EXCEEDS daily limit")
    print("-" * 60)
    
    cae3 = create_cae(
        action_type="wire_transfer",
        tenant_id="acme-corp",
        parameters={
            "amount": "150000000",  # Exceeds limit
            "currency": "USD",
            "destination_account_hash": "sha256:approved123",
            "beneficiary_id": "vendor-001"
        }
    )
    
    evidence3 = {
        "bundle_id": "bundle-003",
        "nonce": "unique-nonce-003",
        "allowlists": {
            "content:sha256:approved_payees": ["sha256:approved123"]
        },
        "cfo_approval_token": {
            "role": "CFO",
            "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "valid": True,
            "signature": "placeholder"
        }
    }
    
    context3 = EvaluationContext(remaining_daily_limit="100000000")  # Only 100M allowed
    
    result3 = evaluator.evaluate(cae3, evidence3, context=context3)
    
    print(f"Decision: {result3.artifact.decision.value}")
    print(f"Artifact: {result3.artifact.artifact_type.value}")
    if result3.artifact.failed_gates:
        for fg in result3.artifact.failed_gates:
            print(f"  Failed: {fg['gate_id']} - {fg.get('failure_code')}")
            print(f"    Required: {fg.get('required')}")
            print(f"    Observed: {fg.get('observed')}")
    
    print("\n" + "=" * 60)
    print("Demonstration complete.")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="BinaryIF Protocol CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  binaryif demo                           Run demonstration
  binaryif evaluate -a action.json -e evidence.json -r ruleset.json
  binaryif verify -A permit.json -a action.json -e evidence.json -r ruleset.json
  binaryif hash -f action.json
  binaryif keygen -o trust_store.json
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # evaluate
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate authorization")
    eval_parser.add_argument("-a", "--action", required=True, help="Action envelope JSON file")
    eval_parser.add_argument("-e", "--evidence", required=True, help="Evidence bundle JSON file")
    eval_parser.add_argument("-r", "--ruleset", required=True, help="Ruleset JSON file")
    eval_parser.add_argument("-c", "--context", help="Context JSON file")
    eval_parser.add_argument("-o", "--output", help="Output file for artifact")
    
    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify BinaryIF artifact")
    verify_parser.add_argument("-A", "--artifact", required=True, help="Artifact JSON file")
    verify_parser.add_argument("-a", "--action", required=True, help="Action envelope JSON file")
    verify_parser.add_argument("-e", "--evidence", required=True, help="Evidence bundle JSON file")
    verify_parser.add_argument("-r", "--ruleset", required=True, help="Ruleset JSON file")
    verify_parser.add_argument("-t", "--trust-store", help="Trust store JSON file")
    
    # hash
    hash_parser = subparsers.add_parser("hash", help="Compute BinaryIF hash")
    hash_parser.add_argument("-f", "--file", required=True, help="JSON file to hash")
    
    # keygen
    keygen_parser = subparsers.add_parser("keygen", help="Generate signing key pair")
    keygen_parser.add_argument("-o", "--output", help="Output file for trust store")
    keygen_parser.add_argument("-k", "--key-id", help="Key identifier")
    keygen_parser.add_argument("-v", "--validity-days", type=int, help="Validity in days")
    
    # demo
    demo_parser = subparsers.add_parser("demo", help="Run demonstration")
    
    args = parser.parse_args()
    
    if args.command == "evaluate":
        sys.exit(cmd_evaluate(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "hash":
        cmd_hash(args)
    elif args.command == "keygen":
        cmd_keygen(args)
    elif args.command == "demo":
        cmd_demo(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
