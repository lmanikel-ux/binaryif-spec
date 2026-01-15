"""
BinaryIF Cryptographic Signing

Implements Section 18 Trust and Key Management.

Uses Ed25519 (RFC 8032) for artifact signing.
"""

import base64
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.exceptions import BadSignature
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


@dataclass
class KeyPair:
    """Ed25519 key pair."""
    key_id: str
    signing_key: bytes
    verify_key: bytes
    valid_from: datetime
    valid_until: datetime
    key_type: str = "ARTIFACT_SIGNING"
    algorithm: str = "Ed25519"
    
    def to_trust_store_entry(self) -> Dict[str, Any]:
        """Convert to trust store entry format."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type,
            "algorithm": self.algorithm,
            "public_key": base64.b64encode(self.verify_key).decode('utf-8'),
            "valid_from": self.valid_from.isoformat().replace("+00:00", "Z"),
            "valid_until": self.valid_until.isoformat().replace("+00:00", "Z"),
            "key_usage": ["sign_artifacts"]
        }


class SigningService:
    """
    BinaryIF artifact signing service.
    
    Per Section 18.4, supports:
    - Root keys (offline, 5+ years validity)
    - Intermediate keys (HSM, 1 year validity)
    - Artifact signing keys (online, 30-90 days validity)
    """
    
    def __init__(self):
        if not NACL_AVAILABLE:
            raise RuntimeError("PyNaCl required for cryptographic operations. Install with: pip install pynacl")
        
        self._keys: Dict[str, KeyPair] = {}
        self._active_key_id: Optional[str] = None
    
    def generate_key_pair(
        self,
        key_id: str,
        key_type: str = "ARTIFACT_SIGNING",
        validity_days: int = 90
    ) -> KeyPair:
        """
        Generate a new Ed25519 key pair.
        
        Args:
            key_id: Unique key identifier (e.g., "kid:binaryif-artifact-001")
            key_type: Key type (ROOT, INTERMEDIATE, ARTIFACT_SIGNING)
            validity_days: Validity period in days
        
        Returns:
            KeyPair with signing and verification keys
        """
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key
        
        now = datetime.now(timezone.utc)
        
        key_pair = KeyPair(
            key_id=key_id,
            signing_key=bytes(signing_key),
            verify_key=bytes(verify_key),
            valid_from=now,
            valid_until=now + timedelta(days=validity_days),
            key_type=key_type
        )
        
        self._keys[key_id] = key_pair
        
        if self._active_key_id is None:
            self._active_key_id = key_id
        
        return key_pair
    
    def set_active_key(self, key_id: str):
        """Set the active signing key."""
        if key_id not in self._keys:
            raise ValueError(f"Key not found: {key_id}")
        self._active_key_id = key_id
    
    def sign(self, data: bytes, key_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Sign data with Ed25519.
        
        Args:
            data: Data to sign
            key_id: Key to use (default: active key)
        
        Returns:
            Signature dict with key_id, algorithm, and base64 signature
        """
        key_id = key_id or self._active_key_id
        if not key_id:
            raise ValueError("No signing key available")
        
        key_pair = self._keys.get(key_id)
        if not key_pair:
            raise ValueError(f"Key not found: {key_id}")
        
        # Check validity
        now = datetime.now(timezone.utc)
        if now < key_pair.valid_from or now > key_pair.valid_until:
            raise ValueError(f"Key {key_id} is not currently valid")
        
        # Sign
        signing_key = SigningKey(key_pair.signing_key)
        signed = signing_key.sign(data)
        signature = signed.signature
        
        return {
            "signer_role": "BinaryIF",
            "key_id": key_id,
            "algorithm": "Ed25519",
            "sig": base64.b64encode(signature).decode('utf-8')
        }
    
    def verify(
        self,
        data: bytes,
        signature_b64: str,
        verify_key_b64: str
    ) -> bool:
        """
        Verify an Ed25519 signature.
        
        Args:
            data: Original data
            signature_b64: Base64-encoded signature
            verify_key_b64: Base64-encoded public key
        
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            signature = base64.b64decode(signature_b64)
            verify_key_bytes = base64.b64decode(verify_key_b64)
            verify_key = VerifyKey(verify_key_bytes)
            
            verify_key.verify(data, signature)
            return True
        except (BadSignature, Exception):
            return False
    
    def get_trust_store(self) -> Dict[str, Any]:
        """
        Generate a trust store from registered keys.
        
        Per Section 18.2.3, includes:
        - Version
        - Hash
        - Effective date
        - Keys with validity periods
        """
        from .hashing import trust_store_hash
        
        now = datetime.now(timezone.utc)
        
        store = {
            "trust_store_version": now.strftime("%Y-%m-%d-001"),
            "effective_from": now.isoformat().replace("+00:00", "Z"),
            "keys": [kp.to_trust_store_entry() for kp in self._keys.values()]
        }
        
        store["trust_store_hash"] = trust_store_hash(store)
        
        return store


class ProductionSigningService(SigningService):
    """
    Production-grade signing service with HSM integration placeholder.
    
    In production, this would integrate with:
    - AWS CloudHSM
    - Azure Dedicated HSM
    - Google Cloud HSM
    - Thales Luna HSM
    """
    
    def __init__(self, hsm_config: Optional[Dict[str, Any]] = None):
        super().__init__()
        self.hsm_config = hsm_config
        # In production: Initialize HSM connection
    
    def sign_with_hsm(self, data: bytes, key_label: str) -> Dict[str, Any]:
        """
        Sign using HSM-protected key.
        
        In production, this would:
        1. Open PKCS#11 session
        2. Find key by label
        3. Sign data
        4. Return signature
        """
        # Placeholder - in production, integrate with HSM
        raise NotImplementedError("HSM integration required for production")


# Convenience functions

def generate_signing_key(key_id: str = None) -> Tuple[bytes, bytes]:
    """
    Generate an Ed25519 key pair.
    
    Returns:
        Tuple of (signing_key_bytes, verify_key_bytes)
    """
    if not NACL_AVAILABLE:
        raise RuntimeError("PyNaCl required")
    
    signing_key = SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def sign_data(data: bytes, signing_key: bytes) -> bytes:
    """Sign data with Ed25519 signing key."""
    if not NACL_AVAILABLE:
        raise RuntimeError("PyNaCl required")
    
    key = SigningKey(signing_key)
    return key.sign(data).signature


def verify_signature(data: bytes, signature: bytes, verify_key: bytes) -> bool:
    """Verify Ed25519 signature."""
    if not NACL_AVAILABLE:
        raise RuntimeError("PyNaCl required")
    
    try:
        key = VerifyKey(verify_key)
        key.verify(data, signature)
        return True
    except BadSignature:
        return False
