"""
Security module for BinaryIF MVP.

Provides input validation, sanitization, and security utilities.
"""

import re
import uuid
import secrets
from typing import Any, Dict, Optional, List
from functools import wraps


# ============================================================
# Input Validation
# ============================================================

# Regex patterns for validation
HEX_PATTERN = re.compile(r'^[a-fA-F0-9]+$')
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]*={0,2}$')
PERMIT_ID_PATTERN = re.compile(r'^[a-f0-9]{32}$')
ACTION_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
TENANT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')
ENVIRONMENT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,64}$')


class ValidationError(Exception):
    """Raised when input validation fails."""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


def validate_hex(value: str, field_name: str, expected_length: Optional[int] = None) -> str:
    """
    Validate that a string is valid hexadecimal.
    
    Args:
        value: The string to validate
        field_name: Name of the field (for error messages)
        expected_length: Expected length of the hex string (optional)
        
    Returns:
        The validated (lowercased) hex string
        
    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(value, str):
        raise ValidationError(field_name, "must be a string")
    
    value = value.lower().strip()
    
    if not value:
        raise ValidationError(field_name, "cannot be empty")
    
    if not HEX_PATTERN.match(value):
        raise ValidationError(field_name, "must be valid hexadecimal")
    
    if expected_length and len(value) != expected_length:
        raise ValidationError(field_name, f"must be {expected_length} characters")
    
    return value


def validate_base64(value: str, field_name: str) -> str:
    """
    Validate that a string is valid base64.
    
    Args:
        value: The string to validate
        field_name: Name of the field (for error messages)
        
    Returns:
        The validated base64 string
        
    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(value, str):
        raise ValidationError(field_name, "must be a string")
    
    value = value.strip()
    
    if not value:
        raise ValidationError(field_name, "cannot be empty")
    
    if not BASE64_PATTERN.match(value):
        raise ValidationError(field_name, "must be valid base64")
    
    # Verify it can actually be decoded
    try:
        import base64
        base64.b64decode(value, validate=True)
    except Exception:
        raise ValidationError(field_name, "must be valid base64")
    
    return value


def validate_permit_id(value: str) -> str:
    """Validate a permit ID (32 hex characters)."""
    return validate_hex(value, "permit_id", expected_length=32)


def validate_action_hash(value: str) -> str:
    """Validate an action hash (64 hex characters)."""
    return validate_hex(value, "action_hash", expected_length=64)


def validate_positive_int(value: Any, field_name: str, max_value: Optional[int] = None) -> int:
    """
    Validate that a value is a positive integer.
    
    Args:
        value: The value to validate
        field_name: Name of the field (for error messages)
        max_value: Maximum allowed value (optional)
        
    Returns:
        The validated integer
        
    Raises:
        ValidationError: If validation fails
    """
    try:
        int_value = int(value)
    except (TypeError, ValueError):
        raise ValidationError(field_name, "must be an integer")
    
    if int_value <= 0:
        raise ValidationError(field_name, "must be positive")
    
    if max_value and int_value > max_value:
        raise ValidationError(field_name, f"must not exceed {max_value}")
    
    return int_value


def validate_epoch_timestamp(value: Any, field_name: str) -> int:
    """
    Validate that a value is a valid Unix epoch timestamp.
    
    Args:
        value: The value to validate
        field_name: Name of the field (for error messages)
        
    Returns:
        The validated timestamp
        
    Raises:
        ValidationError: If validation fails
    """
    try:
        ts = int(value)
    except (TypeError, ValueError):
        raise ValidationError(field_name, "must be an integer timestamp")
    
    # Reasonable range: 2020 to 2100
    if ts < 1577836800 or ts > 4102444800:
        raise ValidationError(field_name, "must be a valid Unix timestamp")
    
    return ts


def validate_string_length(
    value: str,
    field_name: str,
    min_length: int = 1,
    max_length: int = 1000
) -> str:
    """
    Validate string length.
    
    Args:
        value: The string to validate
        field_name: Name of the field (for error messages)
        min_length: Minimum allowed length
        max_length: Maximum allowed length
        
    Returns:
        The validated string
        
    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(value, str):
        raise ValidationError(field_name, "must be a string")
    
    if len(value) < min_length:
        raise ValidationError(field_name, f"must be at least {min_length} characters")
    
    if len(value) > max_length:
        raise ValidationError(field_name, f"must not exceed {max_length} characters")
    
    return value


def validate_action_envelope(action: Dict[str, Any]) -> None:
    """
    Validate an action envelope structure.
    
    Args:
        action: The action envelope dict
        
    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(action, dict):
        raise ValidationError("action", "must be an object")
    
    required_fields = ["action_type", "action_id", "tenant_id", "environment_id", "parameters"]
    for field in required_fields:
        if field not in action:
            raise ValidationError(f"action.{field}", "is required")
    
    validate_string_length(action["action_type"], "action.action_type", max_length=64)
    
    if not ACTION_ID_PATTERN.match(action["action_id"]):
        raise ValidationError("action.action_id", "invalid format")
    
    if not TENANT_ID_PATTERN.match(action["tenant_id"]):
        raise ValidationError("action.tenant_id", "invalid format")
    
    if not ENVIRONMENT_ID_PATTERN.match(action["environment_id"]):
        raise ValidationError("action.environment_id", "invalid format")
    
    if not isinstance(action["parameters"], dict):
        raise ValidationError("action.parameters", "must be an object")


def validate_permit(permit: Dict[str, Any]) -> None:
    """
    Validate a permit structure.
    
    Args:
        permit: The permit dict
        
    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(permit, dict):
        raise ValidationError("permit", "must be an object")
    
    if permit.get("artifact_type") != "PERMIT":
        raise ValidationError("permit.artifact_type", "must be PERMIT")
    
    if permit.get("decision") != "TRUE":
        raise ValidationError("permit.decision", "must be TRUE")
    
    required_fields = ["permit_id", "action_hash", "issued_at", "expires_at", "signatures"]
    for field in required_fields:
        if field not in permit:
            raise ValidationError(f"permit.{field}", "is required")
    
    validate_permit_id(permit["permit_id"])
    validate_action_hash(permit["action_hash"])
    validate_epoch_timestamp(permit["issued_at"], "permit.issued_at")
    validate_epoch_timestamp(permit["expires_at"], "permit.expires_at")
    
    if not isinstance(permit["signatures"], list) or len(permit["signatures"]) == 0:
        raise ValidationError("permit.signatures", "must be a non-empty array")


# ============================================================
# Request ID Generation
# ============================================================

def generate_request_id() -> str:
    """Generate a unique request ID for audit trail correlation."""
    return str(uuid.uuid4())


# ============================================================
# Rate Limiting Helpers
# ============================================================

def extract_client_id(headers: Dict[str, str]) -> str:
    """
    Extract a client identifier from request headers for rate limiting.
    Falls back to a default if no identifier is found.
    """
    # Check for API key
    api_key = headers.get("x-api-key", "")
    if api_key:
        return f"api:{api_key[:8]}"
    
    # Check for tenant ID
    tenant_id = headers.get("x-tenant-id", "")
    if tenant_id:
        return f"tenant:{tenant_id}"
    
    # Check for forwarded IP
    forwarded = headers.get("x-forwarded-for", "")
    if forwarded:
        return f"ip:{forwarded.split(',')[0].strip()}"
    
    return "anonymous"


# ============================================================
# Audit Logging Helpers
# ============================================================

def sanitize_for_logging(data: Dict[str, Any], sensitive_fields: List[str] = None) -> Dict[str, Any]:
    """
    Sanitize data for logging by masking sensitive fields.
    
    Args:
        data: The data to sanitize
        sensitive_fields: List of field names to mask
        
    Returns:
        Sanitized copy of the data
    """
    if sensitive_fields is None:
        sensitive_fields = ["sig_b64", "private_key_b64", "secret", "password", "token"]
    
    result = {}
    for key, value in data.items():
        if key in sensitive_fields:
            if isinstance(value, str) and len(value) > 8:
                result[key] = value[:4] + "..." + value[-4:]
            else:
                result[key] = "[REDACTED]"
        elif isinstance(value, dict):
            result[key] = sanitize_for_logging(value, sensitive_fields)
        elif isinstance(value, list):
            result[key] = [
                sanitize_for_logging(item, sensitive_fields) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            result[key] = value
    
    return result
