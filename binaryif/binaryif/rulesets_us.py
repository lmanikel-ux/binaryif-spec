"""
BinaryIF US Regulatory Ruleset Profiles

Production-ready ruleset configurations for US regulatory compliance.

Finance: SEC, FinCEN, OCC, OFAC requirements
Healthcare: HHS, FDA, DEA, HIPAA requirements  
Infrastructure: NERC, DOE, NRC requirements

These profiles implement the minimum required gates for regulatory compliance
in their respective domains.
"""

from typing import Dict, List, Optional
from .ruleset import Ruleset, GateDefinition, EvaluationMode


# =============================================================================
# FINANCE PROFILES (US)
# =============================================================================

def create_us_wire_transfer_ruleset(
    threshold_amount: str = "10000",
    high_value_threshold: str = "1000000",
    cfo_required_threshold: str = "100000"
) -> Ruleset:
    """
    US-compliant wire transfer ruleset.
    
    Regulatory Coverage:
    - OFAC SDN screening (31 CFR Part 501)
    - BSA/CTR reporting (31 CFR 1010.311)
    - OCC dual control (12 CFR 30)
    - SOX segregation of duties (Section 404)
    
    Gate Sequence:
    1. OFAC screening - always required
    2. BSA threshold check - CTR if over $10k
    3. Allowlist match - payee must be pre-approved
    4. Dual control - different initiator/approver
    5. Signature - CFO for high value
    6. Amount limit - within daily limit
    7. Replay prevention - unique nonce
    """
    return Ruleset(
        id="us.finance.wire_transfer.v1",
        version="1.0.0",
        action_type="wire_transfer",
        gates=[
            # OFAC screening - ALWAYS first
            GateDefinition(
                id="ofac_screening",
                type="ofac_screening",
                parameters={
                    "beneficiary_path": "$.parameters.beneficiary_id",
                    "screening_result_ref": "$.ofac_screening",
                    "freshness_hours": 24
                }
            ),
            # BSA threshold check
            GateDefinition(
                id="bsa_ctr_check",
                type="bsa_threshold",
                parameters={
                    "amount_path": "$.parameters.amount",
                    "ctr_filed_ref": "$.ctr_filing",
                    "threshold": threshold_amount
                }
            ),
            # Payee allowlist
            GateDefinition(
                id="payee_allowlist",
                type="allowlist_hash_match",
                parameters={
                    "value_path": "$.parameters.destination_account_hash",
                    "allowlist_ref": "content:sha256:approved_payees"
                }
            ),
            # Dual control (initiator != approver)
            GateDefinition(
                id="dual_control",
                type="dual_control",
                parameters={
                    "initiator_path": "$.initiator_id",
                    "approver_path": "$.approver_id"
                }
            ),
            # CFO signature for high value
            GateDefinition(
                id="cfo_signature",
                type="signature_required",
                parameters={
                    "role": "CFO",
                    "token_ref": "$.cfo_approval_token",
                    "freshness_seconds": 300
                }
            ),
            # Daily limit check
            GateDefinition(
                id="daily_limit",
                type="numeric_assert",
                parameters={
                    "left": "$.parameters.amount",
                    "operator": "le",
                    "right": "$.context.remaining_daily_limit"
                }
            ),
            # Replay prevention
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


def create_us_ach_transfer_ruleset() -> Ruleset:
    """
    US ACH transfer ruleset (Nacha rules + federal requirements).
    
    ACH has different requirements than wire:
    - Lower urgency (batch processing)
    - Different OFAC timing requirements
    - Nacha return handling
    """
    return Ruleset(
        id="us.finance.ach_transfer.v1",
        version="1.0.0",
        action_type="ach_transfer",
        gates=[
            GateDefinition(
                id="ofac_screening",
                type="ofac_screening",
                parameters={
                    "beneficiary_path": "$.parameters.receiver_id",
                    "screening_result_ref": "$.ofac_screening",
                    "freshness_hours": 48  # Longer window for batch
                }
            ),
            GateDefinition(
                id="bsa_ctr_check",
                type="bsa_threshold",
                parameters={
                    "amount_path": "$.parameters.amount",
                    "ctr_filed_ref": "$.ctr_filing",
                    "threshold": "10000"
                }
            ),
            GateDefinition(
                id="receiver_allowlist",
                type="allowlist_hash_match",
                parameters={
                    "value_path": "$.parameters.receiver_routing_hash",
                    "allowlist_ref": "content:sha256:approved_ach_receivers"
                }
            ),
            GateDefinition(
                id="authorization_signature",
                type="signature_required",
                parameters={
                    "role": "Treasury",
                    "token_ref": "$.treasury_approval",
                    "freshness_seconds": 3600  # 1 hour for batch
                }
            ),
            GateDefinition(
                id="replay_prevention",
                type="nonreplay_nonce",
                parameters={
                    "nonce_path": "$.nonce",
                    "ttl_seconds": 86400  # 24 hours for ACH
                }
            )
        ],
        evaluation_mode=EvaluationMode.ALL_MUST_PASS
    )


def create_us_securities_trade_ruleset() -> Ruleset:
    """
    US securities trade execution ruleset.
    
    Regulatory Coverage:
    - SEC Rule 15c3-5 (market access rule)
    - FINRA Rule 3110 (supervision)
    - Reg SHO (short sale)
    """
    return Ruleset(
        id="us.finance.securities_trade.v1",
        version="1.0.0",
        action_type="securities_trade",
        gates=[
            # Pre-trade risk check
            GateDefinition(
                id="pretrade_risk",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:pretrade_risk_approval"
                }
            ),
            # Position limit check
            GateDefinition(
                id="position_limit",
                type="numeric_assert",
                parameters={
                    "left": "$.parameters.notional_value",
                    "operator": "le",
                    "right": "$.context.position_limit"
                }
            ),
            # Trader authorization
            GateDefinition(
                id="trader_authorization",
                type="signature_required",
                parameters={
                    "role": "RegisteredRep",
                    "token_ref": "$.trader_token",
                    "freshness_seconds": 60  # Very short for trading
                }
            ),
            # Compliance approval for large trades
            GateDefinition(
                id="compliance_approval",
                type="signature_required",
                parameters={
                    "role": "Compliance",
                    "token_ref": "$.compliance_token",
                    "freshness_seconds": 300
                }
            ),
            GateDefinition(
                id="replay_prevention",
                type="nonreplay_nonce",
                parameters={
                    "nonce_path": "$.nonce",
                    "ttl_seconds": 60
                }
            )
        ],
        evaluation_mode=EvaluationMode.ALL_MUST_PASS
    )


# =============================================================================
# HEALTHCARE PROFILES (US)
# =============================================================================

def create_us_medication_order_ruleset() -> Ruleset:
    """
    US medication order ruleset.
    
    Regulatory Coverage:
    - HIPAA consent (45 CFR 164.508)
    - DEA controlled substances (21 CFR 1301)
    - State pharmacy practice acts
    - Joint Commission medication safety
    """
    return Ruleset(
        id="us.healthcare.medication_order.v1",
        version="1.0.0",
        action_type="medication_order",
        gates=[
            # Patient identity verification
            GateDefinition(
                id="patient_identity",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:patient_identity"
                }
            ),
            # HIPAA consent/authorization
            GateDefinition(
                id="hipaa_consent",
                type="hipaa_consent",
                parameters={
                    "patient_id_path": "$.parameters.patient_id",
                    "consent_ref": "$.hipaa_consent",
                    "purpose_path": "$.parameters.purpose"
                }
            ),
            # Prescriber NPI validation
            GateDefinition(
                id="npi_validation",
                type="npi_validation",
                parameters={
                    "npi_path": "$.parameters.prescriber_npi",
                    "npi_validation_ref": "$.npi_validation"
                }
            ),
            # DEA authorization (if controlled)
            GateDefinition(
                id="dea_authorization",
                type="dea_authorization",
                parameters={
                    "dea_number_path": "$.parameters.prescriber_dea",
                    "drug_schedule_path": "$.parameters.drug_schedule",
                    "dea_validation_ref": "$.dea_validation"
                }
            ),
            # Contraindication check
            GateDefinition(
                id="contraindication_clear",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:contraindication_check"
                }
            ),
            # Prescriber signature
            GateDefinition(
                id="prescriber_signature",
                type="signature_required",
                parameters={
                    "role": "Prescriber",
                    "token_ref": "$.prescriber_token",
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


def create_us_surgical_procedure_ruleset() -> Ruleset:
    """
    US surgical procedure authorization ruleset.
    
    Regulatory Coverage:
    - Joint Commission Universal Protocol
    - CMS Conditions of Participation
    - State medical practice acts
    - Informed consent requirements
    """
    return Ruleset(
        id="us.healthcare.surgical_procedure.v1",
        version="1.0.0",
        action_type="surgical_procedure",
        gates=[
            # Patient identity - Universal Protocol
            GateDefinition(
                id="patient_identity",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:patient_identity_wristband"
                }
            ),
            # Informed consent
            GateDefinition(
                id="informed_consent",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:surgical_consent"
                }
            ),
            # Site marking verification
            GateDefinition(
                id="site_marking",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:site_marking_verification"
                }
            ),
            # Timeout checklist complete
            GateDefinition(
                id="timeout_complete",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:surgical_timeout"
                }
            ),
            # Surgeon NPI validation
            GateDefinition(
                id="surgeon_npi",
                type="npi_validation",
                parameters={
                    "npi_path": "$.parameters.surgeon_npi",
                    "npi_validation_ref": "$.surgeon_validation"
                }
            ),
            # Surgeon attestation
            GateDefinition(
                id="surgeon_attestation",
                type="signature_required",
                parameters={
                    "role": "Surgeon",
                    "token_ref": "$.surgeon_attestation",
                    "freshness_seconds": 300
                }
            ),
            # Anesthesiologist attestation
            GateDefinition(
                id="anesthesia_attestation",
                type="signature_required",
                parameters={
                    "role": "Anesthesiologist",
                    "token_ref": "$.anesthesia_attestation",
                    "freshness_seconds": 300
                }
            ),
            # Circulating nurse attestation
            GateDefinition(
                id="nurse_attestation",
                type="signature_required",
                parameters={
                    "role": "CirculatingNurse",
                    "token_ref": "$.nurse_attestation",
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


def create_us_phi_disclosure_ruleset() -> Ruleset:
    """
    US PHI disclosure authorization ruleset.
    
    Regulatory Coverage:
    - HIPAA Privacy Rule (45 CFR 164)
    - State health information privacy laws
    - 42 CFR Part 2 (substance abuse records)
    """
    return Ruleset(
        id="us.healthcare.phi_disclosure.v1",
        version="1.0.0",
        action_type="phi_disclosure",
        gates=[
            # HIPAA authorization
            GateDefinition(
                id="hipaa_authorization",
                type="hipaa_consent",
                parameters={
                    "patient_id_path": "$.parameters.patient_id",
                    "consent_ref": "$.hipaa_authorization",
                    "purpose_path": "$.parameters.disclosure_purpose"
                }
            ),
            # Minimum necessary check
            GateDefinition(
                id="minimum_necessary",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:minimum_necessary_determination"
                }
            ),
            # Recipient verification
            GateDefinition(
                id="recipient_verified",
                type="allowlist_hash_match",
                parameters={
                    "value_path": "$.parameters.recipient_id",
                    "allowlist_ref": "content:sha256:authorized_recipients"
                }
            ),
            # Privacy officer approval (for sensitive)
            GateDefinition(
                id="privacy_officer_approval",
                type="signature_required",
                parameters={
                    "role": "PrivacyOfficer",
                    "token_ref": "$.privacy_officer_token",
                    "freshness_seconds": 3600
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


# =============================================================================
# INFRASTRUCTURE PROFILES (US)
# =============================================================================

def create_us_grid_switching_ruleset() -> Ruleset:
    """
    US bulk electric system switching ruleset.
    
    Regulatory Coverage:
    - NERC CIP-004-6 (personnel & training)
    - NERC CIP-006-6 (physical security)
    - NERC CIP-007-6 (system security)
    - NERC TOP standards (transmission operations)
    """
    return Ruleset(
        id="us.infrastructure.grid_switching.v1",
        version="1.0.0",
        action_type="grid_switching",
        gates=[
            # NERC CIP authorization
            GateDefinition(
                id="cip_authorization",
                type="nerc_cip_authorization",
                parameters={
                    "operator_id_path": "$.parameters.operator_id",
                    "asset_id_path": "$.parameters.asset_id",
                    "authorization_ref": "$.cip_authorization"
                }
            ),
            # Two-person integrity (TPI)
            GateDefinition(
                id="two_person_integrity",
                type="two_person_integrity",
                parameters={
                    "primary_operator_path": "$.primary_operator",
                    "secondary_operator_path": "$.secondary_operator"
                }
            ),
            # Switching order authorization
            GateDefinition(
                id="switching_order",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:switching_order"
                }
            ),
            # Real-time contingency analysis
            GateDefinition(
                id="contingency_analysis",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:rtca_result"
                }
            ),
            # Primary operator signature
            GateDefinition(
                id="primary_operator_sig",
                type="signature_required",
                parameters={
                    "role": "ControlRoomOperator",
                    "token_ref": "$.primary_operator.attestation",
                    "freshness_seconds": 120
                }
            ),
            # Secondary operator (witness) signature
            GateDefinition(
                id="secondary_operator_sig",
                type="signature_required",
                parameters={
                    "role": "ControlRoomOperator",
                    "token_ref": "$.secondary_operator.attestation",
                    "freshness_seconds": 120
                }
            ),
            # Supervisor approval for critical operations
            GateDefinition(
                id="supervisor_approval",
                type="signature_required",
                parameters={
                    "role": "ShiftSupervisor",
                    "token_ref": "$.supervisor_approval",
                    "freshness_seconds": 300
                }
            ),
            GateDefinition(
                id="replay_prevention",
                type="nonreplay_nonce",
                parameters={
                    "nonce_path": "$.nonce",
                    "ttl_seconds": 120
                }
            )
        ],
        evaluation_mode=EvaluationMode.ALL_MUST_PASS
    )


def create_us_nuclear_operation_ruleset() -> Ruleset:
    """
    US nuclear facility operation ruleset.
    
    Regulatory Coverage:
    - 10 CFR 50 (domestic licensing)
    - 10 CFR 73 (physical protection)
    - NRC Technical Specifications
    """
    return Ruleset(
        id="us.infrastructure.nuclear_operation.v1",
        version="1.0.0",
        action_type="nuclear_operation",
        gates=[
            # Two-person integrity (NRC required)
            GateDefinition(
                id="two_person_integrity",
                type="two_person_integrity",
                parameters={
                    "primary_operator_path": "$.primary_operator",
                    "secondary_operator_path": "$.secondary_operator"
                }
            ),
            # Licensed operator verification
            GateDefinition(
                id="licensed_operator",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:nrc_operator_license"
                }
            ),
            # Technical specification compliance
            GateDefinition(
                id="tech_spec_compliance",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:tech_spec_evaluation"
                }
            ),
            # Reactivity management review
            GateDefinition(
                id="reactivity_review",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:reactivity_review"
                }
            ),
            # Primary operator signature
            GateDefinition(
                id="primary_operator_sig",
                type="signature_required",
                parameters={
                    "role": "ReactorOperator",
                    "token_ref": "$.primary_operator.attestation",
                    "freshness_seconds": 60
                }
            ),
            # Secondary operator signature
            GateDefinition(
                id="secondary_operator_sig",
                type="signature_required",
                parameters={
                    "role": "ReactorOperator",
                    "token_ref": "$.secondary_operator.attestation",
                    "freshness_seconds": 60
                }
            ),
            # Shift supervisor authorization
            GateDefinition(
                id="shift_supervisor",
                type="signature_required",
                parameters={
                    "role": "SeniorReactorOperator",
                    "token_ref": "$.supervisor_authorization",
                    "freshness_seconds": 120
                }
            ),
            GateDefinition(
                id="replay_prevention",
                type="nonreplay_nonce",
                parameters={
                    "nonce_path": "$.nonce",
                    "ttl_seconds": 60
                }
            )
        ],
        evaluation_mode=EvaluationMode.ALL_MUST_PASS
    )


def create_us_pipeline_operation_ruleset() -> Ruleset:
    """
    US pipeline operation ruleset.
    
    Regulatory Coverage:
    - 49 CFR 192 (natural gas pipelines)
    - 49 CFR 195 (hazardous liquids pipelines)
    - PHMSA requirements
    - TSA Pipeline Security Directives
    """
    return Ruleset(
        id="us.infrastructure.pipeline_operation.v1",
        version="1.0.0",
        action_type="pipeline_operation",
        gates=[
            # Operator qualification verification
            GateDefinition(
                id="operator_qualified",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:oq_verification"
                }
            ),
            # Control room management compliance
            GateDefinition(
                id="crm_compliance",
                type="evidence_present",
                parameters={
                    "ref": "content:sha256:crm_checklist"
                }
            ),
            # SCADA authentication
            GateDefinition(
                id="scada_auth",
                type="signature_required",
                parameters={
                    "role": "PipelineController",
                    "token_ref": "$.controller_token",
                    "freshness_seconds": 300
                }
            ),
            # Supervisor approval for high-consequence operations
            GateDefinition(
                id="supervisor_approval",
                type="signature_required",
                parameters={
                    "role": "OperationsSupervisor",
                    "token_ref": "$.supervisor_token",
                    "freshness_seconds": 600
                }
            ),
            GateDefinition(
                id="replay_prevention",
                type="nonreplay_nonce",
                parameters={
                    "nonce_path": "$.nonce",
                    "ttl_seconds": 300
                }
            )
        ],
        evaluation_mode=EvaluationMode.ALL_MUST_PASS
    )


# =============================================================================
# RULESET REGISTRY FACTORY
# =============================================================================

def create_us_regulatory_registry() -> 'RulesetRegistry':
    """
    Create a registry pre-loaded with all US regulatory rulesets.
    
    Returns:
        RulesetRegistry with all US profiles registered
    """
    from .ruleset import RulesetRegistry
    
    registry = RulesetRegistry()
    
    # Finance
    registry.register(create_us_wire_transfer_ruleset())
    registry.register(create_us_ach_transfer_ruleset())
    registry.register(create_us_securities_trade_ruleset())
    
    # Healthcare
    registry.register(create_us_medication_order_ruleset())
    registry.register(create_us_surgical_procedure_ruleset())
    registry.register(create_us_phi_disclosure_ruleset())
    
    # Infrastructure
    registry.register(create_us_grid_switching_ruleset())
    registry.register(create_us_nuclear_operation_ruleset())
    registry.register(create_us_pipeline_operation_ruleset())
    
    return registry
