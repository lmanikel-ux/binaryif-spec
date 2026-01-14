# BinaryIF

BinaryIF is a deterministic authorization protocol for irreversible actions.

BinaryIF enforces a single invariant:

Execution may occur only if authority has already resolved to TRUE.

The protocol defines:
- a canonical action envelope
- a deterministic authorization predicate
- cryptographically verifiable authorization records
- replayable verification independent of agent internals

BinaryIF governs authorization, not correctness.
