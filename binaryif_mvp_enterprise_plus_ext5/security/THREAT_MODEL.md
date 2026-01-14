
# BinaryIF Threat Model (MVP: High-Value Wire Transfers)

## Scope
This threat model covers:
- Authorization issuance (PERMIT/WITHHOLD)
- Execution enforcement (Interceptor)
- Replay verification (Verifier)
- Trust store and revocation

Out of scope:
- Fraud detection and AML/KYC
- Business correctness of invoices
- Banking rail settlement mechanics

## Primary assets
- Integrity of Permit artifacts
- Enforceability of execution boundary
- Verifiability of historical authorization truth
- Key material and trust store integrity
- Append-only artifact log integrity (hash chain + WORM storage where configured)

## Adversaries
- Compromised proposing agent
- Malicious insider attempting unauthorized wire
- Attacker replaying old permits/tokens
- Attacker tampering with artifacts/logs
- Attacker attempting key substitution / drift

## Core security properties
1) Fail-closed: indeterminacy => WITHHOLD
2) Non-repudiation: signed artifacts bound to action/ruleset/evidence/time
3) Replay resistance: nonce + TTL + single-use permits
4) Verifier independence: third party can validate without trusting runtime
5) Tamper evidence: hash-chained artifact log; optional WORM persistence

## Key threats and mitigations (summary)
- Permit forgery -> Ed25519 signature verification against trust store
- Permit replay -> single-use + nonce store within TTL
- Key compromise -> revocation list + trust store snapshot binding
- Log tampering -> hash chain + optional WORM Object Lock retention
- Confused deputy -> action hash binding + ruleset hash binding
