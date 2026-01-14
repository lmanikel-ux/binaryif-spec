
# BinaryIF — Insurer Brief (Wire Transfers MVP)

## What BinaryIF is
BinaryIF is a deterministic authorization control that blocks irreversible actions unless authority is proven **before** execution.

For this MVP, the irreversible action class is: **high‑value wire transfers above a defined threshold**.

## The underwriting object
BinaryIF produces a signed authorization artifact:

- **PERMIT (TRUE)**: cryptographically verifiable authorization issued prior to execution
- **WITHHOLD (FALSE)**: signed refusal record identifying failed authorization gates

## The underwriting boundary
- If a wire executes, there must exist a valid PERMIT for that action instance.
- If no valid PERMIT exists, execution is unauthorized under the control model.

This converts ambiguous “process evidence” into a binary, verifiable control event.

## What BinaryIF does NOT do
- Does not determine fraud probability
- Does not validate invoice truth
- Does not assess business correctness
- Does not replace AML/KYC controls

BinaryIF enforces authority, not intent.

## What you can verify independently
A third party can verify (offline):
- artifact signature validity (trusted key)
- artifact time window validity (TTL)
- binding to the specific wire action (action hash)
- binding to the ruleset in force (ruleset hash)

## Why it matters for claims
Claims and investigations often hinge on whether a transfer was authorized.
BinaryIF eliminates narrative reconstruction by producing a replayable authorization record.

## Suggested policy rider clause (draft)
Coverage for automated funds transfers exceeding $X applies only where such transfer was executed pursuant to a valid BinaryIF Authorization Permit issued prior to execution. Absence of a valid Permit constitutes unauthorized execution for coverage determination.
