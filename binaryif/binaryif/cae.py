"""
BinaryIF Canonical Action Envelope (CAE)

Implements Section 10 of the BinaryIF Protocol Specification.
The normalized, structured representation of a proposed action.
"""

import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from enum import Enum


class Environment(str, Enum):
    """Valid environment identifiers per Section 10.3."""
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


# Action type pattern per schema
ACTION_TYPE_PATTERN = re.compile(r'^[a-z][a-z0-9_]*$')


@dataclass
class CanonicalActionEnvelope:
    """
    Canonical Action Envelope (CAE).
    
    Per Section 10.2, required fields:
    - action_type: Class of action (snake_case)
    - action_id: UUID v7 for temporal ordering
    - tenant_id: Entity on whose behalf action is performed
    - environment_id: Operational environment
    - parameters: Action-specific parameters
    """
    action_type: str
    action_id: str
    tenant_id: str
    environment_id: str
    parameters: Dict[str, Any]
    
    def __post_init__(self):
        """Validate CAE fields per schema."""
        self._validate()
    
    def _validate(self):
        """Validate all CAE fields."""
        # Validate action_type pattern
        if not ACTION_TYPE_PATTERN.match(self.action_type):
            raise ValueError(
                f"Invalid action_type '{self.action_type}': "
                "must be snake_case starting with lowercase letter"
            )
        
        # Validate action_id is valid UUID
        try:
            uuid.UUID(self.action_id)
        except ValueError:
            raise ValueError(f"Invalid action_id: must be valid UUID")
        
        # Validate tenant_id is non-empty
        if not self.tenant_id or len(self.tenant_id) < 1:
            raise ValueError("tenant_id must not be empty")
        
        # Validate environment_id
        valid_envs = [e.value for e in Environment]
        if self.environment_id not in valid_envs:
            raise ValueError(
                f"Invalid environment_id '{self.environment_id}': "
                f"must be one of {valid_envs}"
            )
        
        # Validate parameters is a dict
        if not isinstance(self.parameters, dict):
            raise ValueError("parameters must be an object/dict")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "action_type": self.action_type,
            "action_id": self.action_id,
            "tenant_id": self.tenant_id,
            "environment_id": self.environment_id,
            "parameters": self.parameters
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'CanonicalActionEnvelope':
        """Create CAE from dictionary."""
        required = ["action_type", "action_id", "tenant_id", "environment_id", "parameters"]
        missing = [f for f in required if f not in data]
        if missing:
            raise ValueError(f"Missing required fields: {missing}")
        
        return cls(
            action_type=data["action_type"],
            action_id=data["action_id"],
            tenant_id=data["tenant_id"],
            environment_id=data["environment_id"],
            parameters=data["parameters"]
        )
    
    @staticmethod
    def generate_action_id() -> str:
        """Generate a UUID v7 for action_id (falls back to v4 if v7 unavailable)."""
        # Python's uuid module doesn't have v7 yet, use v4 with timestamp prefix
        # In production, use a proper UUID v7 library
        return str(uuid.uuid4())


def create_cae(
    action_type: str,
    tenant_id: str,
    parameters: Dict[str, Any],
    environment_id: str = "production",
    action_id: Optional[str] = None
) -> CanonicalActionEnvelope:
    """
    Factory function to create a CAE.
    
    Args:
        action_type: The class of action (e.g., "wire_transfer")
        tenant_id: Entity on whose behalf action is performed
        parameters: Action-specific parameters
        environment_id: Operational environment (default: production)
        action_id: Optional UUID; generated if not provided
    
    Returns:
        CanonicalActionEnvelope instance
    """
    if action_id is None:
        action_id = CanonicalActionEnvelope.generate_action_id()
    
    return CanonicalActionEnvelope(
        action_type=action_type,
        action_id=action_id,
        tenant_id=tenant_id,
        environment_id=environment_id,
        parameters=parameters
    )


# Predefined action types for Finance Profile (FIP v1.0)
class FinanceActionTypes:
    WIRE_TRANSFER = "wire_transfer"
    PAYEE_CREATE = "payee_create"
    PAYEE_UPDATE = "payee_update"
    TREASURY_TRADE_EXECUTE = "treasury_trade_execute"
    SETTLEMENT_RELEASE = "settlement_release"


# Predefined action types for Healthcare Profile (HIP v1.0)
class HealthcareActionTypes:
    PROCEDURE_INCISION_START = "procedure_incision_start"
    IMPLANT_SELECTION_COMMIT = "implant_selection_commit"
    MEDICATION_ORDER_SUBMIT = "medication_order_submit"
    RADIATION_THERAPY_START = "radiation_therapy_start"


# Predefined action types for Infrastructure Profile (IIP v1.0)
class InfrastructureActionTypes:
    BREAKER_OPEN = "breaker_open"
    BREAKER_CLOSE = "breaker_close"
    LOAD_SHED = "load_shed"
    SETPOINT_CHANGE = "setpoint_change"
    SYSTEM_ISOLATION = "system_isolation"
