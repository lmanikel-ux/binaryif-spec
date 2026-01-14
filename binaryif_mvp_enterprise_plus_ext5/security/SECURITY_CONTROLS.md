
# BinaryIF Security Controls (MVP)
This document enumerates controls expected for insurer and audit review.

## Control 1: Execution boundary enforcement
- Interceptor MUST refuse execution absent a valid Permit.

## Control 2: Artifact integrity and non-repudiation
- Permits and Withholds MUST be signed.
- Verifier MUST validate signature and bindings.

## Control 3: Replay protection
- Permits MUST be time-bounded (TTL).
- Permits MUST be single-use.
- Nonces MUST be unique within TTL.

## Control 4: Trust store snapshot binding
- Artifacts SHOULD include trust_store_hash and revocation_list_hash.

## Control 5: Key lifecycle
- Keys SHOULD be rotated.
- Revocation MUST be supported and enforced by verifier.

## Control 6: Audit immutability
- Artifact log MUST be append-only with tamper evidence.
- WORM backend (S3 Object Lock) SHOULD be used for production retention.
