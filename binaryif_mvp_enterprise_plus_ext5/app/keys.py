
import json, os
from typing import Optional
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from .util import b64d, b64e, canonicalize

class KeyProvider:
    """Interface for BinaryIF artifact signing + trust store retrieval."""
    def sign_binaryif_artifact(self, payload: bytes) -> tuple[str, str]:
        """Returns (kid, signature_b64)."""
        raise NotImplementedError

    def get_trust_store(self) -> dict:
        raise NotImplementedError

class FileKeyProvider(KeyProvider):
    def __init__(self, signing_key_path: str, trust_store_path: str):
        self.signing_key_path = signing_key_path
        self.trust_store_path = trust_store_path
        with open(self.signing_key_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        self.kid = raw["kid"]
        self.sk = SigningKey(b64d(raw["private_key_b64"]))

    def sign_binaryif_artifact(self, payload: bytes) -> tuple[str, str]:
        sig = self.sk.sign(payload).signature
        return self.kid, b64e(sig)

    def get_trust_store(self) -> dict:
        with open(self.trust_store_path, "r", encoding="utf-8") as f:
            return json.load(f)

class AwsKmsEd25519Provider(KeyProvider):
    """AWS KMS signing provider. Requires a SIGN_VERIFY KMS key with ED25519 support.
    Uses KMS Sign API with SigningAlgorithm ED25519_SHA_512 and MessageType RAW.
    Docs: https://docs.aws.amazon.com/kms/latest/APIReference/API_Sign.html
    """
    def __init__(self, kms_key_id: str, trust_store_path: str, region: Optional[str]=None, kid: Optional[str]=None):
        self.kms_key_id = kms_key_id
        self.trust_store_path = trust_store_path
        self.region = region
        self.kid = kid or "aws-kms-ed25519"

    def sign_binaryif_artifact(self, payload: bytes) -> tuple[str, str]:
        try:
            import boto3
        except Exception as e:
            raise RuntimeError("boto3 required for AWS KMS signing. Install requirements.txt") from e

        client = boto3.client("kms", region_name=self.region)
        resp = client.sign(
            KeyId=self.kms_key_id,
            Message=payload,
            MessageType="RAW",
            SigningAlgorithm="ED25519_SHA_512"
        )
        sig = resp["Signature"]
        from .util import b64e
        return self.kid, b64e(sig)

    def get_trust_store(self) -> dict:
        with open(self.trust_store_path, "r", encoding="utf-8") as f:
            return json.load(f)

def verify_ed25519(signature_b64: str, payload: bytes, public_key_b64: str) -> bool:
    try:
        vk = VerifyKey(b64d(public_key_b64))
        vk.verify(payload, b64d(signature_b64))
        return True
    except BadSignatureError:
        return False
