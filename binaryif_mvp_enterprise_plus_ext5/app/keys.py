"""
Key management module for BinaryIF MVP.

Provides cryptographic key providers for signing artifacts,
with support for file-based keys and AWS KMS.
"""

import json
import os
import threading
from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any, Optional

from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from .util import b64d, b64e


class KeyProvider(ABC):
    """Abstract interface for BinaryIF artifact signing and trust store retrieval."""
    
    @abstractmethod
    def sign_binaryif_artifact(self, payload: bytes) -> Tuple[str, str]:
        """
        Sign a payload and return (kid, signature_b64).
        
        Args:
            payload: The canonical JSON bytes to sign
            
        Returns:
            Tuple of (key_id, base64_encoded_signature)
        """
        pass
    
    @abstractmethod
    def get_trust_store(self) -> Dict[str, Any]:
        """
        Get the trust store containing public keys.
        
        Returns:
            Dict containing authority_keys and binaryif_artifact_keys
        """
        pass
    
    @abstractmethod
    def get_kid(self) -> str:
        """Get the key ID used for signing."""
        pass


class FileKeyProvider(KeyProvider):
    """
    File-based key provider using Ed25519 keys stored in JSON files.
    
    Thread-safe with cached trust store loading.
    """
    
    def __init__(self, signing_key_path: str, trust_store_path: str):
        self._signing_key_path = signing_key_path
        self._trust_store_path = trust_store_path
        self._lock = threading.RLock()
        self._trust_store_cache: Optional[Dict[str, Any]] = None
        self._trust_store_mtime: float = 0
        
        # Load signing key once at initialization
        with open(self._signing_key_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        
        self._kid = raw["kid"]
        self._sk = SigningKey(b64d(raw["private_key_b64"]))
    
    def sign_binaryif_artifact(self, payload: bytes) -> Tuple[str, str]:
        """Sign payload with Ed25519 key."""
        sig = self._sk.sign(payload).signature
        return self._kid, b64e(sig)
    
    def get_trust_store(self) -> Dict[str, Any]:
        """
        Get trust store with file modification time caching.
        Reloads if file has been modified.
        """
        with self._lock:
            try:
                mtime = os.path.getmtime(self._trust_store_path)
                if self._trust_store_cache is None or mtime > self._trust_store_mtime:
                    with open(self._trust_store_path, "r", encoding="utf-8") as f:
                        self._trust_store_cache = json.load(f)
                    self._trust_store_mtime = mtime
            except FileNotFoundError:
                if self._trust_store_cache is None:
                    raise
            
            return self._trust_store_cache
    
    def get_kid(self) -> str:
        return self._kid


class AwsKmsEd25519Provider(KeyProvider):
    """
    AWS KMS signing provider using Ed25519 keys.
    
    Requires a SIGN_VERIFY KMS key with ED25519 support.
    Uses KMS Sign API with SigningAlgorithm ED25519_SHA_512 and MessageType RAW.
    
    Docs: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
    """
    
    def __init__(
        self,
        kms_key_id: str,
        trust_store_path: str,
        region: Optional[str] = None,
        kid: Optional[str] = None
    ):
        self._kms_key_id = kms_key_id
        self._trust_store_path = trust_store_path
        self._region = region
        self._kid = kid or "aws-kms-ed25519"
        self._client = None
        self._lock = threading.RLock()
        self._trust_store_cache: Optional[Dict[str, Any]] = None
        self._trust_store_mtime: float = 0
    
    def _get_client(self):
        """Lazy-load boto3 client."""
        if self._client is None:
            try:
                import boto3
            except ImportError as e:
                raise RuntimeError(
                    "boto3 required for AWS KMS signing. Install with: pip install boto3"
                ) from e
            self._client = boto3.client("kms", region_name=self._region)
        return self._client
    
    def sign_binaryif_artifact(self, payload: bytes) -> Tuple[str, str]:
        """Sign payload using AWS KMS."""
        client = self._get_client()
        resp = client.sign(
            KeyId=self._kms_key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm="ED25519_SHA_512"
        )
        sig = resp["Signature"]
        return self._kid, b64e(sig)
    
    def get_trust_store(self) -> Dict[str, Any]:
        """Get trust store with file modification time caching."""
        with self._lock:
            try:
                mtime = os.path.getmtime(self._trust_store_path)
                if self._trust_store_cache is None or mtime > self._trust_store_mtime:
                    with open(self._trust_store_path, "r", encoding="utf-8") as f:
                        self._trust_store_cache = json.load(f)
                    self._trust_store_mtime = mtime
            except FileNotFoundError:
                if self._trust_store_cache is None:
                    raise
            
            return self._trust_store_cache
    
    def get_kid(self) -> str:
        return self._kid


def verify_ed25519(signature_b64: str, payload: bytes, public_key_b64: str) -> bool:
    """
    Verify an Ed25519 signature.
    
    Args:
        signature_b64: Base64-encoded signature
        payload: The signed data
        public_key_b64: Base64-encoded public key
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        vk = VerifyKey(b64d(public_key_b64))
        vk.verify(payload, b64d(signature_b64))
        return True
    except (BadSignatureError, Exception):
        return False


def get_key_provider(
    signer_type: str = "file",
    signing_key_path: str = "secrets/binaryif_signing_key.json",
    trust_store_path: str = "trust/trust_store.json",
    kms_key_id: Optional[str] = None,
    kms_region: Optional[str] = None,
    kms_kid: Optional[str] = None
) -> KeyProvider:
    """
    Factory function to create the appropriate key provider.
    
    Args:
        signer_type: "file" or "aws_kms"
        signing_key_path: Path to signing key JSON (for file provider)
        trust_store_path: Path to trust store JSON
        kms_key_id: AWS KMS key ID (for KMS provider)
        kms_region: AWS region (for KMS provider)
        kms_kid: Key ID to use in signatures (for KMS provider)
        
    Returns:
        Configured KeyProvider instance
    """
    if signer_type == "aws_kms":
        if not kms_key_id:
            raise ValueError("AWS_KMS_KEY_ID required for aws_kms signer")
        return AwsKmsEd25519Provider(
            kms_key_id=kms_key_id,
            trust_store_path=trust_store_path,
            region=kms_region,
            kid=kms_kid
        )
    
    return FileKeyProvider(
        signing_key_path=signing_key_path,
        trust_store_path=trust_store_path
    )
