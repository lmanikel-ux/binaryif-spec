
# Trust Store Format (Enterprise+++)
Supports time-bounded key validity for replay-safe verification.

## Fields
- binaryif_artifact_keys: { kid: public_key_b64 }
- binaryif_artifact_key_validity: { kid: { not_before_epoch, not_after_epoch } }
- authority_keys: { kid: public_key_b64 }
- authority_key_validity: { kid: { not_before_epoch, not_after_epoch } }

## Verifier rule
Key MUST be valid at artifact.issued_at, otherwise INVALID.
