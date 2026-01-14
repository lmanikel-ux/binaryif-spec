"""
Configuration module for BinaryIF MVP.

Centralizes all configuration with environment variable support,
validation, and caching for performance.
"""

import os
import json
import threading
from typing import Dict, Any, Optional
from functools import lru_cache
from pathlib import Path

# ============================================================
# Environment Configuration
# ============================================================

ENV = os.getenv("BINARYIF_ENV", "dev")  # dev|stage|prod

# Rate limits (requests per minute)
AUTHORIZE_RPM = int(os.getenv("AUTHORIZE_RPM", "120"))
EXECUTE_RPM = int(os.getenv("EXECUTE_RPM", "120"))

# Paths
ALLOWLIST_PATH = os.getenv("ALLOWLIST_PATH", "evidence/payee_allowlist_snapshot.json")
RULESET_PATH = os.getenv("RULESET_PATH", "rules/wire_ruleset.json")
TRUST_STORE_PATH = os.getenv("TRUST_STORE_PATH", "trust/trust_store.json")
REVOCATION_LIST_PATH = os.getenv("REVOCATION_LIST_PATH", "trust/revocation_list.json")

# Signing configuration
SIGNER_TYPE = os.getenv("BINARYIF_SIGNER", "file")
SIGNING_KEY_PATH = os.getenv("SIGNING_KEY_PATH", "secrets/binaryif_signing_key.json")
AWS_KMS_KEY_ID = os.getenv("AWS_KMS_KEY_ID", "")
AWS_REGION = os.getenv("AWS_REGION", "")
AWS_KMS_KID = os.getenv("AWS_KMS_KID", "aws-kms-ed25519")

# Execution environment
EXECUTION_ENVIRONMENT_ID = os.getenv("BINARYIF_ENVIRONMENT_ID", "binaryif-interceptor-001")

# Cache TTL (seconds)
CONFIG_CACHE_TTL = int(os.getenv("CONFIG_CACHE_TTL", "60"))


# ============================================================
# Cached Configuration Loaders
# ============================================================

class CachedConfig:
    """
    Thread-safe cached configuration loader.
    Reloads configuration files periodically based on TTL.
    """
    
    def __init__(self, ttl_seconds: int = 60):
        self._cache: Dict[str, Any] = {}
        self._timestamps: Dict[str, float] = {}
        self._lock = threading.RLock()
        self._ttl = ttl_seconds
    
    def _is_stale(self, key: str) -> bool:
        import time
        if key not in self._timestamps:
            return True
        return (time.time() - self._timestamps[key]) > self._ttl
    
    def get_json(self, path: str, force_reload: bool = False) -> Dict[str, Any]:
        """
        Load JSON file with caching.
        Returns cached version if within TTL, otherwise reloads.
        """
        import time
        
        with self._lock:
            if not force_reload and path in self._cache and not self._is_stale(path):
                return self._cache[path]
            
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            self._cache[path] = data
            self._timestamps[path] = time.time()
            return data
    
    def invalidate(self, path: Optional[str] = None) -> None:
        """Invalidate cache for a specific path or all paths."""
        with self._lock:
            if path:
                self._cache.pop(path, None)
                self._timestamps.pop(path, None)
            else:
                self._cache.clear()
                self._timestamps.clear()


# Global cached config instance
_config_cache = CachedConfig(ttl_seconds=CONFIG_CACHE_TTL)


def load_json_cached(path: str) -> Dict[str, Any]:
    """Load JSON file with caching."""
    return _config_cache.get_json(path)


def load_ruleset() -> Dict[str, Any]:
    """Load the wire ruleset with caching."""
    return load_json_cached(RULESET_PATH)


def load_trust_store() -> Dict[str, Any]:
    """Load the trust store with caching."""
    return load_json_cached(TRUST_STORE_PATH)


def load_revocation_list() -> Dict[str, Any]:
    """Load the revocation list with caching."""
    return load_json_cached(REVOCATION_LIST_PATH)


def load_allowlist() -> Dict[str, Any]:
    """Load the payee allowlist with caching."""
    return load_json_cached(ALLOWLIST_PATH)


def invalidate_config_cache() -> None:
    """Invalidate all cached configuration."""
    _config_cache.invalidate()


# ============================================================
# Validation
# ============================================================

def validate_config() -> Dict[str, bool]:
    """
    Validate that all required configuration files exist.
    Returns dict of path -> exists.
    """
    paths = {
        "ruleset": RULESET_PATH,
        "trust_store": TRUST_STORE_PATH,
        "revocation_list": REVOCATION_LIST_PATH,
        "allowlist": ALLOWLIST_PATH,
    }
    
    if SIGNER_TYPE == "file":
        paths["signing_key"] = SIGNING_KEY_PATH
    
    return {name: Path(path).exists() for name, path in paths.items()}


# ============================================================
# Feature Flags
# ============================================================

def is_production() -> bool:
    """Check if running in production mode."""
    return ENV == "prod"


def is_debug() -> bool:
    """Check if debug mode is enabled."""
    return os.getenv("BINARYIF_DEBUG", "").lower() in ("1", "true", "yes")
