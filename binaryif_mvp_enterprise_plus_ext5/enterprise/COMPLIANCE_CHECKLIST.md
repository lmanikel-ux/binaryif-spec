
# BinaryIF — Enterprise Compliance Checklist (Wire Transfers)

## Control objective
Prevent execution of high-value wires unless a valid BinaryIF Permit exists at execution time.

## Required components
- Execution interceptor in front of wire execution call
- BinaryIF authorizer issuing signed PERMIT/WITHHOLD
- Trust store snapshot distribution and verification
- Replay verifier capability for audit/insurer use

## Minimum evidence for compliance
- Allowlist snapshot for destinations
- CFO approval token (fresh) for the specific wire action
- Deterministic daily limit context snapshot

## Required operational controls
- Permit TTL ≤ 5 minutes (recommended)
- Permit single-use enforcement
- Nonce replay protection within TTL
- Append-only artifact log (hash chained)
- Retention policy for artifacts and logs

## Audit outputs
- Permit/Withhold artifacts (JSON) for each attempted transfer
- Artifact log export (hash chain)
- Conformance report PASS/FAIL output

## Common failure conditions (expected behavior)
- Missing approval → WITHHOLD
- Destination not in allowlist → WITHHOLD
- Limit exceeded → WITHHOLD
- Permit expired → execution blocked
- Permit reused → execution blocked
