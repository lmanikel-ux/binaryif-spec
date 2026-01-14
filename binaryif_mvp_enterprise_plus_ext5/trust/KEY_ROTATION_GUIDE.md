
# Key Rotation Guide (MVP -> Production)

## Principle
Rotation must not break replay verification.

## Minimum requirements
- Trust store snapshots MUST be versioned and retained.
- Artifacts MUST reference the trust_store_hash used at issuance.
- Verifiers MUST validate using the trust store snapshot in force at issued_at.

## Procedure (recommended)
1) Generate new artifact signing key (kid=...)
2) Publish updated trust_store.json including new public key, keep old key active
3) Deploy authorizer to sign with new kid
4) After overlap window, revoke old kid (soft revoke) in revocation_list.json with effective_at_epoch
5) Retain trust store snapshots indefinitely (or per policy) for historical verification
