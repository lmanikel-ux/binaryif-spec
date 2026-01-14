
import os, json
from typing import Optional
from .util import canonicalize, sha256_hex
from .db import append_artifact_log, latest_entry_hash

class ArtifactLogBackend:
    def write_entry(self, artifact_id: str, artifact_type: str, issued_at: int, payload_hash: str, entry_hash: str, artifact_json: str) -> None:
        raise NotImplementedError

class SqliteHashChainLog(ArtifactLogBackend):
    def write_entry(self, artifact_id: str, artifact_type: str, issued_at: int, payload_hash: str, entry_hash: str, artifact_json: str) -> None:
        append_artifact_log(artifact_id, artifact_type, issued_at, payload_hash, entry_hash, artifact_json)

class S3ObjectLockLog(ArtifactLogBackend):
    """Writes each artifact JSON as a separate immutable object to an S3 bucket with Object Lock.
    Requires bucket with Object Lock enabled.
    Docs: https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html
    """
    def __init__(self, bucket: str, prefix: str, retention_days: int, legal_hold: str = "OFF"):
        self.bucket = bucket
        self.prefix = prefix.rstrip("/") + "/"
        self.retention_days = retention_days
        self.legal_hold = legal_hold

    def write_entry(self, artifact_id: str, artifact_type: str, issued_at: int, payload_hash: str, entry_hash: str, artifact_json: str) -> None:
        try:
            import boto3
            from datetime import datetime, timedelta, timezone
        except Exception as e:
            raise RuntimeError("boto3 required for S3 Object Lock logging. Install requirements.txt") from e

        s3 = boto3.client("s3")
        key = f"{self.prefix}{issued_at}-{artifact_type}-{artifact_id}.json"
        # Retain until now + retention_days
        retain_until = datetime.now(timezone.utc) + timedelta(days=int(self.retention_days))
        s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=artifact_json.encode("utf-8"),
            ContentType="application/json",
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until,
            ObjectLockLegalHoldStatus=self.legal_hold
        )

def get_log_backend() -> ArtifactLogBackend:
    backend = os.getenv("ARTIFACT_LOG_BACKEND", "sqlite_hash_chain")
    if backend == "s3_object_lock":
        bucket = os.environ["S3_BUCKET"]
        prefix = os.getenv("S3_PREFIX", "binaryif/artifact-log/")
        retention_days = int(os.getenv("S3_RETENTION_DAYS", "365"))
        legal_hold = os.getenv("S3_LEGAL_HOLD", "OFF")
        return S3ObjectLockLog(bucket=bucket, prefix=prefix, retention_days=retention_days, legal_hold=legal_hold)
    return SqliteHashChainLog()
