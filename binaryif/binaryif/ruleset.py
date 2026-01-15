"""
BinaryIF Ruleset Management

Implements ruleset loading, validation, and versioning per Section 13.5-13.6.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum

from .gates import Gate, create_gate, GATE_TYPES
from .hashing import ruleset_hash


class EvaluationMode(str, Enum):
    """Ruleset evaluation modes per Section 13.6."""
    ALL_MUST_PASS = "ALL_MUST_PASS"
    ANY_FAIL_STOPS = "ANY_FAIL_STOPS"  # Optimization


VERSION_PATTERN = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+$')
RULESET_ID_PATTERN = re.compile(r'^[a-z][a-z0-9_.]*$')


@dataclass
class GateDefinition:
    """Definition of a gate within a ruleset."""
    id: str
    type: str
    parameters: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "parameters": self.parameters
        }


@dataclass
class Ruleset:
    """
    A versioned, deterministic grammar defining authorization conditions.
    
    Per Section 13.5, a ruleset contains:
    - id: Unique ruleset identifier
    - version: Semantic version
    - action_type: Action type this ruleset applies to
    - gates: List of gate definitions
    - evaluation_mode: How gates are evaluated (default: ALL_MUST_PASS)
    """
    id: str
    version: str
    action_type: str
    gates: List[GateDefinition]
    evaluation_mode: EvaluationMode = EvaluationMode.ALL_MUST_PASS
    
    _hash: Optional[str] = field(default=None, repr=False)
    
    def __post_init__(self):
        self._validate()
        self._hash = None  # Clear cached hash
    
    def _validate(self):
        """Validate ruleset structure."""
        if not RULESET_ID_PATTERN.match(self.id):
            raise ValueError(f"Invalid ruleset id '{self.id}': must match pattern")
        
        if not VERSION_PATTERN.match(self.version):
            raise ValueError(f"Invalid version '{self.version}': must be semantic version")
        
        if not self.gates:
            raise ValueError("Ruleset must have at least one gate")
        
        gate_ids = set()
        for gate in self.gates:
            if gate.id in gate_ids:
                raise ValueError(f"Duplicate gate id: {gate.id}")
            gate_ids.add(gate.id)
            
            if gate.type not in GATE_TYPES:
                raise ValueError(f"Unknown gate type: {gate.type}")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "version": self.version,
            "action_type": self.action_type,
            "gates": [g.to_dict() for g in self.gates],
            "evaluation_mode": self.evaluation_mode.value
        }
    
    def get_hash(self) -> str:
        """Compute and cache the ruleset hash."""
        if self._hash is None:
            self._hash = ruleset_hash(self.to_dict())
        return self._hash
    
    def create_gates(self) -> List[Gate]:
        """Instantiate gate objects from definitions."""
        return [
            create_gate(g.id, g.type, g.parameters)
            for g in self.gates
        ]
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Ruleset':
        """Create Ruleset from dictionary."""
        gates = [
            GateDefinition(
                id=g["id"],
                type=g["type"],
                parameters=g.get("parameters", {})
            )
            for g in data.get("gates", [])
        ]
        
        mode = data.get("evaluation_mode", "ALL_MUST_PASS")
        if isinstance(mode, str):
            mode = EvaluationMode(mode)
        
        return cls(
            id=data["id"],
            version=data["version"],
            action_type=data["action_type"],
            gates=gates,
            evaluation_mode=mode
        )


class RulesetRegistry:
    """
    Registry for managing multiple rulesets.
    
    Supports versioning and action type mapping.
    """
    
    def __init__(self):
        self._rulesets: Dict[str, Dict[str, Ruleset]] = {}  # id -> version -> Ruleset
        self._action_map: Dict[str, str] = {}  # action_type -> ruleset_id
    
    def register(self, ruleset: Ruleset, set_as_default: bool = True):
        """Register a ruleset."""
        if ruleset.id not in self._rulesets:
            self._rulesets[ruleset.id] = {}
        
        self._rulesets[ruleset.id][ruleset.version] = ruleset
        
        if set_as_default:
            self._action_map[ruleset.action_type] = ruleset.id
    
    def get(self, ruleset_id: str, version: Optional[str] = None) -> Optional[Ruleset]:
        """Get a ruleset by id and optionally version."""
        if ruleset_id not in self._rulesets:
            return None
        
        versions = self._rulesets[ruleset_id]
        
        if version:
            return versions.get(version)
        
        # Return latest version
        if not versions:
            return None
        
        latest = max(versions.keys(), key=lambda v: [int(x) for x in v.split(".")])
        return versions[latest]
    
    def get_for_action(self, action_type: str) -> Optional[Ruleset]:
        """Get the default ruleset for an action type."""
        ruleset_id = self._action_map.get(action_type)
        if ruleset_id:
            return self.get(ruleset_id)
        return None
    
    def list_rulesets(self) -> List[str]:
        """List all registered ruleset ids."""
        return list(self._rulesets.keys())


# Finance Profile (FIP v1.0) standard rulesets

def create_wire_transfer_ruleset(
    allowlist_ref: str = "content:sha256:approved_payees",
    keyring_ref: str = "content:sha256:executive_keyring"
) -> Ruleset:
    """
    Create the standard wire_transfer.high_value ruleset per FIP v1.0.
    
    Per Section 20.2.6, required gates:
    - recipient_allowlist
    - amount_limit
    - executive_signature
    - evidence_present
    - nonreplay_nonce
    """
    return Ruleset(
        id="wire_transfer.high_value",
        version="1.0.0",
        action_type="wire_transfer",
        gates=[
            GateDefinition(
                id="recipient_allowlist",
                type="allowlist_hash_match",
                parameters={
                    "value_path": "$.parameters.destination_account_hash",
                    "allowlist_ref": allowlist_ref
                }
            ),
            GateDefinition(
                id="daily_limit",
                type="numeric_assert",
                parameters={
                    "left": "$.parameters.amount",
                    "operator": "le",
                    "right": "$.context.remaining_daily_limit"
                }
            ),
            GateDefinition(
                id="cfo_signature",
                type="signature_required",
                parameters={
                    "role": "CFO",
                    "keyring_ref": keyring_ref,
                    "signed_payload": "action_hash",
                    "token_ref": "$.cfo_approval_token",
                    "freshness_seconds": 300
                }
            ),
            GateDefinition(
                id="replay_prevention",
                type="nonreplay_nonce",
                parameters={
                    "nonce_path": "$.nonce",
                    "ttl_seconds": 600
                }
            )
        ],
        evaluation_mode=EvaluationMode.ALL_MUST_PASS
    )


def create_healthcare_procedure_ruleset() -> Ruleset:
    """
    Create the standard procedure ruleset per HIP v1.0.
    """
    return Ruleset(
        id="procedure.incision_start",
        version="1.0.0",
        action_type="procedure_incision_start",
        gates=[
            GateDefinition(
                id="patient_identity_lock",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:patient_identity"
                }
            ),
            GateDefinition(
                id="consent_present",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:procedure_consent"
                }
            ),
            GateDefinition(
                id="clinician_attestation",
                type="signature_required",
                parameters={
                    "role": "Clinician",
                    "keyring_ref": "content:sha256:clinical_keyring",
                    "signed_payload": "action_hash",
                    "token_ref": "$.evidence.clinician_token",
                    "freshness_seconds": 600
                }
            ),
            GateDefinition(
                id="replay_prevention",
                type="nonreplay_nonce",
                parameters={
                    "nonce_path": "$.nonce",
                    "ttl_seconds": 600
                }
            )
        ],
        evaluation_mode=EvaluationMode.ALL_MUST_PASS
    )
