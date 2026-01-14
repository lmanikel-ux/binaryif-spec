
from pydantic import BaseModel, Field
from typing import Dict, Any, List

class ActionEnvelope(BaseModel):
    action_type: str
    action_id: str
    tenant_id: str
    environment_id: str
    parameters: Dict[str, Any]

class EvidenceRef(BaseModel):
    type: str
    ref: str

class EvidenceBundle(BaseModel):
    bundle_id: str
    references: List[EvidenceRef] = Field(default_factory=list)

class AuthorizationRequest(BaseModel):
    action: ActionEnvelope
    evidence: EvidenceBundle
    context: Dict[str, Any]

class ExecuteRequest(BaseModel):
    action: ActionEnvelope
    permit: Dict[str, Any]
