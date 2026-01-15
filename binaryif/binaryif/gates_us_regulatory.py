"""
BinaryIF US Regulatory Gates

Implements gates specific to US regulatory requirements.

Finance: OFAC SDN screening, Bank Secrecy Act compliance
Healthcare: NPI validation, DEA authorization, HIPAA consent
Infrastructure: NERC CIP authorization, operator certification

These gates interface with external regulatory systems and require
appropriate API credentials and compliance frameworks.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import re

from .gates import (
    Gate,
    GateEvaluation,
    GateResult,
    FailureCode,
    resolve_json_path,
    GATE_TYPES
)


# =============================================================================
# FINANCE REGULATORY GATES (SEC, FinCEN, OCC, OFAC)
# =============================================================================

class OFACScreeningGate(Gate):
    """
    OFAC SDN (Specially Designated Nationals) Screening Gate.
    
    US Requirement: Financial institutions must screen transactions against
    OFAC's SDN list to prevent prohibited transactions.
    
    Authority: 31 CFR Part 501, Executive Order 13224
    
    Parameters:
        beneficiary_path: JSON path to beneficiary identifier
        screening_result_ref: Reference to pre-computed screening result
        
    Evidence Required:
        - OFAC screening result with timestamp
        - Screening must be fresh (default: within 24 hours)
    """
    
    DEFAULT_FRESHNESS_HOURS = 24
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        beneficiary_path = self.parameters.get("beneficiary_path", "$.parameters.beneficiary_id")
        screening_ref = self.parameters.get("screening_result_ref", "$.ofac_screening")
        freshness_hours = self.parameters.get("freshness_hours", self.DEFAULT_FRESHNESS_HOURS)
        
        # Get beneficiary
        success, beneficiary = resolve_json_path(cae, beneficiary_path)
        if not success or not beneficiary:
            return self._fail(FailureCode.MISSING, "beneficiary identifier", "not found")
        
        # Get screening result
        success, screening = resolve_json_path(evidence_bundle, screening_ref)
        if not success or not screening:
            return self._fail(
                FailureCode.MISSING,
                f"OFAC screening result for {beneficiary}",
                "screening not found in evidence"
            )
        
        # Verify screening is for correct beneficiary
        screened_entity = screening.get("entity_id") or screening.get("beneficiary_id")
        if screened_entity != beneficiary:
            return self._fail(
                FailureCode.MISMATCH,
                f"screening for {beneficiary}",
                f"screening is for {screened_entity}"
            )
        
        # Check screening result
        result = screening.get("result", "").upper()
        if result == "MATCH" or result == "POTENTIAL_MATCH":
            return self._fail(
                FailureCode.UNAUTHORIZED,
                "OFAC SDN clear",
                f"OFAC screening result: {result}"
            )
        
        if result != "CLEAR" and result != "NO_MATCH":
            return self._fail(
                FailureCode.INVALID,
                "valid OFAC screening result",
                f"unknown result: {result}"
            )
        
        # Check freshness
        screened_at = screening.get("screened_at")
        if screened_at:
            try:
                screen_time = datetime.fromisoformat(screened_at.replace("Z", "+00:00"))
                now = datetime.now(timezone.utc)
                age_hours = (now - screen_time).total_seconds() / 3600
                
                if age_hours > freshness_hours:
                    return self._fail(
                        FailureCode.EXPIRED,
                        f"screening within {freshness_hours} hours",
                        f"screening is {int(age_hours)} hours old"
                    )
            except Exception:
                return self._fail(FailureCode.INVALID, "valid timestamp", str(screened_at))
        
        return self._pass()


class BSAThresholdGate(Gate):
    """
    Bank Secrecy Act CTR Threshold Gate.
    
    US Requirement: Currency Transaction Reports (CTRs) required for
    transactions over $10,000. Structuring to avoid threshold is illegal.
    
    Authority: 31 CFR 1010.311, 31 USC 5313
    
    Parameters:
        amount_path: JSON path to transaction amount
        ctr_filed_ref: Reference to CTR filing evidence (if applicable)
        threshold: CTR threshold (default: 10000)
    """
    
    DEFAULT_THRESHOLD = 10000
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        from decimal import Decimal, InvalidOperation
        
        amount_path = self.parameters.get("amount_path", "$.parameters.amount")
        ctr_ref = self.parameters.get("ctr_filed_ref", "$.ctr_filing")
        threshold = Decimal(str(self.parameters.get("threshold", self.DEFAULT_THRESHOLD)))
        
        # Get amount
        success, amount_str = resolve_json_path(cae, amount_path)
        if not success:
            return self._fail(FailureCode.MISSING, "transaction amount", "not found")
        
        try:
            amount = Decimal(str(amount_str))
        except InvalidOperation:
            return self._fail(FailureCode.INVALID, "valid amount", str(amount_str))
        
        # If under threshold, pass without CTR
        if amount <= threshold:
            return self._pass()
        
        # Over threshold - require CTR evidence
        success, ctr = resolve_json_path(evidence_bundle, ctr_ref)
        if not success or not ctr:
            return self._fail(
                FailureCode.MISSING,
                f"CTR filing for amount ${amount} (threshold ${threshold})",
                "CTR filing evidence not found"
            )
        
        # Verify CTR filed or exemption present
        status = ctr.get("status", "").upper()
        if status in ["FILED", "EXEMPT", "PENDING_FILING", "NOT_REQUIRED"]:
            return self._pass()
        
        return self._fail(
            FailureCode.UNAUTHORIZED,
            "CTR filed or exemption",
            f"CTR status: {status}"
        )


class DualControlGate(Gate):
    """
    Dual Control / Segregation of Duties Gate.
    
    US Requirement: OCC Heightened Standards and SOX require separation
    between initiator and approver for high-value transactions.
    
    Authority: OCC 12 CFR 30, SOX Section 404
    
    Parameters:
        initiator_path: JSON path to initiator identity
        approver_path: JSON path to approver identity
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        initiator_path = self.parameters.get("initiator_path", "$.initiator_id")
        approver_path = self.parameters.get("approver_path", "$.approver_id")
        
        # Get initiator
        success, initiator = resolve_json_path(evidence_bundle, initiator_path)
        if not success:
            success, initiator = resolve_json_path(cae, initiator_path)
        
        if not success or not initiator:
            return self._fail(FailureCode.MISSING, "initiator identity", "not found")
        
        # Get approver
        success, approver = resolve_json_path(evidence_bundle, approver_path)
        if not success or not approver:
            return self._fail(FailureCode.MISSING, "approver identity", "not found")
        
        # Verify different identities
        if initiator == approver:
            return self._fail(
                FailureCode.UNAUTHORIZED,
                "different initiator and approver",
                f"same identity: {initiator}"
            )
        
        return self._pass()


# =============================================================================
# HEALTHCARE REGULATORY GATES (HHS, FDA, DEA)
# =============================================================================

class NPIValidationGate(Gate):
    """
    National Provider Identifier (NPI) Validation Gate.
    
    US Requirement: HIPAA requires use of NPIs for healthcare transactions.
    
    Authority: 45 CFR 162.406, HIPAA Administrative Simplification
    
    Parameters:
        npi_path: JSON path to NPI number
        npi_validation_ref: Reference to NPI validation result
    """
    
    NPI_PATTERN = re.compile(r'^\d{10}$')
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        npi_path = self.parameters.get("npi_path", "$.parameters.provider_npi")
        validation_ref = self.parameters.get("npi_validation_ref", "$.npi_validation")
        
        # Get NPI
        success, npi = resolve_json_path(cae, npi_path)
        if not success:
            success, npi = resolve_json_path(evidence_bundle, npi_path)
        
        if not success or not npi:
            return self._fail(FailureCode.MISSING, "NPI number", "not found")
        
        # Validate format (10 digits, Luhn check)
        if not self.NPI_PATTERN.match(str(npi)):
            return self._fail(
                FailureCode.INVALID,
                "valid NPI format (10 digits)",
                str(npi)
            )
        
        # Luhn check (NPI uses Luhn with prefix 80840)
        if not self._luhn_check(f"80840{npi}"):
            return self._fail(
                FailureCode.INVALID,
                "valid NPI checksum",
                "Luhn check failed"
            )
        
        # If validation result provided, verify it
        success, validation = resolve_json_path(evidence_bundle, validation_ref)
        if success and validation:
            status = validation.get("status", "").upper()
            if status == "DEACTIVATED" or status == "INVALID":
                return self._fail(
                    FailureCode.UNAUTHORIZED,
                    "active NPI",
                    f"NPI status: {status}"
                )
        
        return self._pass()
    
    def _luhn_check(self, number: str) -> bool:
        """Verify Luhn checksum."""
        digits = [int(d) for d in str(number)]
        odd_digits = digits[-1::-2]
        even_digits = digits[-2::-2]
        total = sum(odd_digits)
        for d in even_digits:
            total += sum(divmod(d * 2, 10))
        return total % 10 == 0


class DEAAuthorizationGate(Gate):
    """
    DEA Controlled Substance Authorization Gate.
    
    US Requirement: Prescribers must have valid DEA registration for
    controlled substance orders.
    
    Authority: 21 CFR 1301, Controlled Substances Act
    
    Parameters:
        dea_number_path: JSON path to DEA number
        drug_schedule_path: JSON path to drug schedule (I-V)
        dea_validation_ref: Reference to DEA validation result
    """
    
    DEA_PATTERN = re.compile(r'^[A-Z][A-Z9]\d{7}$')
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        dea_path = self.parameters.get("dea_number_path", "$.parameters.prescriber_dea")
        schedule_path = self.parameters.get("drug_schedule_path", "$.parameters.drug_schedule")
        validation_ref = self.parameters.get("dea_validation_ref", "$.dea_validation")
        
        # Get drug schedule
        success, schedule = resolve_json_path(cae, schedule_path)
        if not success:
            # If no schedule specified, assume non-controlled
            return self._pass()
        
        schedule = str(schedule).upper()
        if schedule not in ["I", "II", "III", "IV", "V", "1", "2", "3", "4", "5"]:
            return self._fail(FailureCode.INVALID, "valid drug schedule", schedule)
        
        # Controlled substance - require DEA number
        success, dea = resolve_json_path(cae, dea_path)
        if not success:
            success, dea = resolve_json_path(evidence_bundle, dea_path)
        
        if not success or not dea:
            return self._fail(
                FailureCode.MISSING,
                f"DEA number for Schedule {schedule} substance",
                "DEA number not found"
            )
        
        # Validate format
        if not self.DEA_PATTERN.match(str(dea)):
            return self._fail(
                FailureCode.INVALID,
                "valid DEA number format",
                str(dea)
            )
        
        # DEA checksum validation
        if not self._dea_checksum(str(dea)):
            return self._fail(
                FailureCode.INVALID,
                "valid DEA checksum",
                "checksum failed"
            )
        
        # If validation result provided, verify
        success, validation = resolve_json_path(evidence_bundle, validation_ref)
        if success and validation:
            status = validation.get("status", "").upper()
            if status in ["EXPIRED", "REVOKED", "SUSPENDED"]:
                return self._fail(
                    FailureCode.UNAUTHORIZED,
                    "active DEA registration",
                    f"DEA status: {status}"
                )
            
            # Check schedule authorization
            authorized_schedules = validation.get("authorized_schedules", [])
            if authorized_schedules and schedule not in authorized_schedules:
                return self._fail(
                    FailureCode.UNAUTHORIZED,
                    f"DEA authorization for Schedule {schedule}",
                    f"authorized for: {authorized_schedules}"
                )
        
        return self._pass()
    
    def _dea_checksum(self, dea: str) -> bool:
        """Verify DEA number checksum."""
        try:
            digits = dea[2:]
            odd_sum = int(digits[0]) + int(digits[2]) + int(digits[4])
            even_sum = int(digits[1]) + int(digits[3]) + int(digits[5])
            total = odd_sum + (even_sum * 2)
            return total % 10 == int(digits[6])
        except (IndexError, ValueError):
            return False


class HIPAAConsentGate(Gate):
    """
    HIPAA Authorization/Consent Gate.
    
    US Requirement: Use or disclosure of PHI requires patient authorization
    unless an exception applies.
    
    Authority: 45 CFR 164.508, HIPAA Privacy Rule
    
    Parameters:
        patient_id_path: JSON path to patient identifier
        consent_ref: Reference to consent/authorization evidence
        purpose_path: JSON path to purpose of use
    """
    
    # HIPAA exceptions that don't require authorization
    TREATMENT_PAYMENT_OPERATIONS = ["TREATMENT", "PAYMENT", "HEALTHCARE_OPERATIONS"]
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        patient_path = self.parameters.get("patient_id_path", "$.parameters.patient_id")
        consent_ref = self.parameters.get("consent_ref", "$.hipaa_consent")
        purpose_path = self.parameters.get("purpose_path", "$.parameters.purpose")
        
        # Get patient
        success, patient = resolve_json_path(cae, patient_path)
        if not success or not patient:
            return self._fail(FailureCode.MISSING, "patient identifier", "not found")
        
        # Get purpose
        success, purpose = resolve_json_path(cae, purpose_path)
        if success and purpose:
            purpose = str(purpose).upper()
            # TPO exception
            if purpose in self.TREATMENT_PAYMENT_OPERATIONS:
                return self._pass()
        
        # Not TPO - require explicit consent
        success, consent = resolve_json_path(evidence_bundle, consent_ref)
        if not success or not consent:
            return self._fail(
                FailureCode.MISSING,
                f"HIPAA authorization for patient {patient}",
                "consent not found"
            )
        
        # Verify consent matches patient
        consent_patient = consent.get("patient_id")
        if consent_patient != patient:
            return self._fail(
                FailureCode.MISMATCH,
                f"consent for patient {patient}",
                f"consent is for {consent_patient}"
            )
        
        # Check consent status
        status = consent.get("status", "").upper()
        if status == "REVOKED" or status == "EXPIRED":
            return self._fail(
                FailureCode.UNAUTHORIZED,
                "valid HIPAA authorization",
                f"consent status: {status}"
            )
        
        return self._pass()


# =============================================================================
# INFRASTRUCTURE REGULATORY GATES (NERC, DOE, NRC)
# =============================================================================

class NERCCIPAuthorizationGate(Gate):
    """
    NERC CIP (Critical Infrastructure Protection) Authorization Gate.
    
    US Requirement: Access to Bulk Electric System cyber assets requires
    personnel risk assessment and authorization.
    
    Authority: NERC CIP-004-6, CIP-006-6, CIP-007-6
    
    Parameters:
        operator_id_path: JSON path to operator identifier
        asset_id_path: JSON path to BES asset identifier
        authorization_ref: Reference to CIP authorization evidence
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        operator_path = self.parameters.get("operator_id_path", "$.parameters.operator_id")
        asset_path = self.parameters.get("asset_id_path", "$.parameters.asset_id")
        auth_ref = self.parameters.get("authorization_ref", "$.cip_authorization")
        
        # Get operator
        success, operator = resolve_json_path(cae, operator_path)
        if not success:
            success, operator = resolve_json_path(evidence_bundle, operator_path)
        
        if not success or not operator:
            return self._fail(FailureCode.MISSING, "operator identifier", "not found")
        
        # Get asset
        success, asset = resolve_json_path(cae, asset_path)
        if not success or not asset:
            return self._fail(FailureCode.MISSING, "BES asset identifier", "not found")
        
        # Get CIP authorization
        success, auth = resolve_json_path(evidence_bundle, auth_ref)
        if not success or not auth:
            return self._fail(
                FailureCode.MISSING,
                f"NERC CIP authorization for operator {operator}",
                "CIP authorization not found"
            )
        
        # Verify operator matches
        auth_operator = auth.get("operator_id")
        if auth_operator != operator:
            return self._fail(
                FailureCode.MISMATCH,
                f"authorization for operator {operator}",
                f"authorization is for {auth_operator}"
            )
        
        # Verify asset in authorized list
        authorized_assets = auth.get("authorized_assets", [])
        if asset not in authorized_assets and "*" not in authorized_assets:
            return self._fail(
                FailureCode.UNAUTHORIZED,
                f"authorization for asset {asset}",
                f"authorized assets: {authorized_assets}"
            )
        
        # Check PRA (Personnel Risk Assessment) status
        pra_status = auth.get("pra_status", "").upper()
        if pra_status not in ["CURRENT", "VALID", "APPROVED"]:
            return self._fail(
                FailureCode.UNAUTHORIZED,
                "current Personnel Risk Assessment",
                f"PRA status: {pra_status}"
            )
        
        # Check training status
        training_current = auth.get("training_current", False)
        if not training_current:
            return self._fail(
                FailureCode.UNAUTHORIZED,
                "current CIP training",
                "training not current"
            )
        
        return self._pass()


class TwoPersonIntegrityGate(Gate):
    """
    Two-Person Integrity (TPI) Gate.
    
    US Requirement: Nuclear and certain NERC CIP operations require
    two authorized individuals to be present.
    
    Authority: 10 CFR 73.55 (NRC), NERC CIP-006-6
    
    Parameters:
        primary_operator_path: JSON path to primary operator
        secondary_operator_path: JSON path to secondary operator (witness)
    """
    
    def evaluate(self, cae, evidence_bundle, context, trust_store) -> GateEvaluation:
        primary_path = self.parameters.get("primary_operator_path", "$.primary_operator")
        secondary_path = self.parameters.get("secondary_operator_path", "$.secondary_operator")
        
        # Get primary operator
        success, primary = resolve_json_path(evidence_bundle, primary_path)
        if not success or not primary:
            return self._fail(FailureCode.MISSING, "primary operator", "not found")
        
        # Get secondary operator (witness)
        success, secondary = resolve_json_path(evidence_bundle, secondary_path)
        if not success or not secondary:
            return self._fail(
                FailureCode.MISSING,
                "secondary operator (TPI witness)",
                "witness not found"
            )
        
        # Verify different individuals
        primary_id = primary.get("operator_id") if isinstance(primary, dict) else primary
        secondary_id = secondary.get("operator_id") if isinstance(secondary, dict) else secondary
        
        if primary_id == secondary_id:
            return self._fail(
                FailureCode.UNAUTHORIZED,
                "two different operators for TPI",
                f"same operator: {primary_id}"
            )
        
        return self._pass()


# =============================================================================
# REGISTER US REGULATORY GATES
# =============================================================================

US_REGULATORY_GATES = {
    # Finance
    "ofac_screening": OFACScreeningGate,
    "bsa_threshold": BSAThresholdGate,
    "dual_control": DualControlGate,
    
    # Healthcare
    "npi_validation": NPIValidationGate,
    "dea_authorization": DEAAuthorizationGate,
    "hipaa_consent": HIPAAConsentGate,
    
    # Infrastructure
    "nerc_cip_authorization": NERCCIPAuthorizationGate,
    "two_person_integrity": TwoPersonIntegrityGate,
}

# Add to main gate registry
GATE_TYPES.update(US_REGULATORY_GATES)
