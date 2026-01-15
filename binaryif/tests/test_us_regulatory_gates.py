"""
BinaryIF US Regulatory Gates Test Suite

Tests for US-specific regulatory compliance gates:
- OFAC SDN screening
- BSA/CTR thresholds
- Dual control / segregation of duties
- NPI validation
- DEA authorization
- HIPAA consent
- NERC CIP authorization
- Two-person integrity
"""

import unittest
from datetime import datetime, timezone, timedelta

from binaryif import (
    GateResult,
    FailureCode,
)
from binaryif.gates_us_regulatory import (
    OFACScreeningGate,
    BSAThresholdGate,
    DualControlGate,
    NPIValidationGate,
    DEAAuthorizationGate,
    HIPAAConsentGate,
    NERCCIPAuthorizationGate,
    TwoPersonIntegrityGate,
)


class TestOFACScreeningGate(unittest.TestCase):
    """Test OFAC SDN screening gate."""
    
    def test_clear_screening_passes(self):
        """OFAC clear result should pass."""
        gate = OFACScreeningGate("ofac_check", {
            "beneficiary_path": "$.parameters.beneficiary_id",
            "screening_result_ref": "$.ofac_screening",
            "freshness_hours": 24
        })
        
        cae = {"parameters": {"beneficiary_id": "VENDOR-001"}}
        evidence = {
            "ofac_screening": {
                "entity_id": "VENDOR-001",
                "result": "CLEAR",
                "screened_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_match_screening_fails(self):
        """OFAC match result should fail."""
        gate = OFACScreeningGate("ofac_check", {
            "beneficiary_path": "$.parameters.beneficiary_id",
            "screening_result_ref": "$.ofac_screening"
        })
        
        cae = {"parameters": {"beneficiary_id": "SANCTIONED-ENTITY"}}
        evidence = {
            "ofac_screening": {
                "entity_id": "SANCTIONED-ENTITY",
                "result": "MATCH",
                "screened_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.UNAUTHORIZED)
    
    def test_stale_screening_fails(self):
        """Stale OFAC screening should fail."""
        gate = OFACScreeningGate("ofac_check", {
            "beneficiary_path": "$.parameters.beneficiary_id",
            "screening_result_ref": "$.ofac_screening",
            "freshness_hours": 24
        })
        
        cae = {"parameters": {"beneficiary_id": "VENDOR-001"}}
        
        # Screening from 48 hours ago
        old_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat().replace("+00:00", "Z")
        evidence = {
            "ofac_screening": {
                "entity_id": "VENDOR-001",
                "result": "CLEAR",
                "screened_at": old_time
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.EXPIRED)
    
    def test_missing_screening_fails(self):
        """Missing OFAC screening should fail."""
        gate = OFACScreeningGate("ofac_check", {
            "beneficiary_path": "$.parameters.beneficiary_id",
            "screening_result_ref": "$.ofac_screening"
        })
        
        cae = {"parameters": {"beneficiary_id": "VENDOR-001"}}
        evidence = {}  # No screening
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISSING)


class TestBSAThresholdGate(unittest.TestCase):
    """Test BSA/CTR threshold gate."""
    
    def test_under_threshold_passes(self):
        """Amount under $10k should pass without CTR."""
        gate = BSAThresholdGate("bsa_check", {
            "amount_path": "$.parameters.amount",
            "threshold": "10000"
        })
        
        cae = {"parameters": {"amount": "5000"}}
        evidence = {}  # No CTR needed
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_over_threshold_with_ctr_passes(self):
        """Amount over $10k with CTR filed should pass."""
        gate = BSAThresholdGate("bsa_check", {
            "amount_path": "$.parameters.amount",
            "ctr_filed_ref": "$.ctr_filing",
            "threshold": "10000"
        })
        
        cae = {"parameters": {"amount": "15000"}}
        evidence = {
            "ctr_filing": {
                "status": "FILED",
                "filing_id": "CTR-2026-001"
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_over_threshold_without_ctr_fails(self):
        """Amount over $10k without CTR should fail."""
        gate = BSAThresholdGate("bsa_check", {
            "amount_path": "$.parameters.amount",
            "ctr_filed_ref": "$.ctr_filing",
            "threshold": "10000"
        })
        
        cae = {"parameters": {"amount": "15000"}}
        evidence = {}  # No CTR
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISSING)


class TestDualControlGate(unittest.TestCase):
    """Test dual control / segregation of duties gate."""
    
    def test_different_users_passes(self):
        """Different initiator and approver should pass."""
        gate = DualControlGate("dual_control", {
            "initiator_path": "$.initiator_id",
            "approver_path": "$.approver_id"
        })
        
        evidence = {
            "initiator_id": "user-alice",
            "approver_id": "user-bob"
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_same_user_fails(self):
        """Same initiator and approver should fail."""
        gate = DualControlGate("dual_control", {
            "initiator_path": "$.initiator_id",
            "approver_path": "$.approver_id"
        })
        
        evidence = {
            "initiator_id": "user-alice",
            "approver_id": "user-alice"  # Same!
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.UNAUTHORIZED)


class TestNPIValidationGate(unittest.TestCase):
    """Test NPI validation gate."""
    
    def test_valid_npi_passes(self):
        """Valid NPI format and checksum should pass."""
        gate = NPIValidationGate("npi_check", {
            "npi_path": "$.parameters.provider_npi"
        })
        
        # 1234567893 is a valid NPI (passes Luhn check with 80840 prefix)
        cae = {"parameters": {"provider_npi": "1234567893"}}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_invalid_format_fails(self):
        """Invalid NPI format should fail."""
        gate = NPIValidationGate("npi_check", {
            "npi_path": "$.parameters.provider_npi"
        })
        
        cae = {"parameters": {"provider_npi": "12345"}}  # Too short
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.INVALID)
    
    def test_invalid_checksum_fails(self):
        """Invalid NPI checksum should fail."""
        gate = NPIValidationGate("npi_check", {
            "npi_path": "$.parameters.provider_npi"
        })
        
        cae = {"parameters": {"provider_npi": "1234567890"}}  # Wrong check digit
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.INVALID)


class TestDEAAuthorizationGate(unittest.TestCase):
    """Test DEA authorization gate."""
    
    def test_non_controlled_passes(self):
        """Non-controlled substance should pass without DEA."""
        gate = DEAAuthorizationGate("dea_check", {
            "dea_number_path": "$.parameters.prescriber_dea",
            "drug_schedule_path": "$.parameters.drug_schedule"
        })
        
        # No schedule = not controlled
        cae = {"parameters": {"medication": "acetaminophen"}}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_valid_dea_passes(self):
        """Valid DEA number for controlled substance should pass."""
        gate = DEAAuthorizationGate("dea_check", {
            "dea_number_path": "$.parameters.prescriber_dea",
            "drug_schedule_path": "$.parameters.drug_schedule"
        })
        
        # AB1234563 is a valid DEA number format
        cae = {"parameters": {
            "prescriber_dea": "AB1234563",
            "drug_schedule": "II"
        }}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_missing_dea_for_controlled_fails(self):
        """Missing DEA for controlled substance should fail."""
        gate = DEAAuthorizationGate("dea_check", {
            "dea_number_path": "$.parameters.prescriber_dea",
            "drug_schedule_path": "$.parameters.drug_schedule"
        })
        
        cae = {"parameters": {
            "drug_schedule": "II"
            # No DEA number!
        }}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISSING)


class TestHIPAAConsentGate(unittest.TestCase):
    """Test HIPAA consent/authorization gate."""
    
    def test_treatment_passes_without_consent(self):
        """Treatment purpose should pass without explicit consent (TPO exception)."""
        gate = HIPAAConsentGate("hipaa_check", {
            "patient_id_path": "$.parameters.patient_id",
            "consent_ref": "$.hipaa_consent",
            "purpose_path": "$.parameters.purpose"
        })
        
        cae = {"parameters": {
            "patient_id": "PT-12345",
            "purpose": "TREATMENT"
        }}
        
        result = gate.evaluate(cae, {}, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_research_requires_consent(self):
        """Research purpose should require explicit consent."""
        gate = HIPAAConsentGate("hipaa_check", {
            "patient_id_path": "$.parameters.patient_id",
            "consent_ref": "$.hipaa_consent",
            "purpose_path": "$.parameters.purpose"
        })
        
        cae = {"parameters": {
            "patient_id": "PT-12345",
            "purpose": "RESEARCH"
        }}
        evidence = {}  # No consent
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISSING)
    
    def test_valid_consent_passes(self):
        """Valid consent should pass."""
        gate = HIPAAConsentGate("hipaa_check", {
            "patient_id_path": "$.parameters.patient_id",
            "consent_ref": "$.hipaa_consent",
            "purpose_path": "$.parameters.purpose"
        })
        
        cae = {"parameters": {
            "patient_id": "PT-12345",
            "purpose": "RESEARCH"
        }}
        evidence = {
            "hipaa_consent": {
                "patient_id": "PT-12345",
                "status": "VALID"
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)


class TestNERCCIPAuthorizationGate(unittest.TestCase):
    """Test NERC CIP authorization gate."""
    
    def test_authorized_operator_passes(self):
        """Authorized operator with current PRA should pass."""
        gate = NERCCIPAuthorizationGate("cip_check", {
            "operator_id_path": "$.parameters.operator_id",
            "asset_id_path": "$.parameters.asset_id",
            "authorization_ref": "$.cip_authorization"
        })
        
        cae = {"parameters": {
            "operator_id": "OP-001",
            "asset_id": "SUBSTATION-A"
        }}
        evidence = {
            "cip_authorization": {
                "operator_id": "OP-001",
                "authorized_assets": ["SUBSTATION-A", "SUBSTATION-B"],
                "pra_status": "CURRENT",
                "training_current": True
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_unauthorized_asset_fails(self):
        """Operator not authorized for asset should fail."""
        gate = NERCCIPAuthorizationGate("cip_check", {
            "operator_id_path": "$.parameters.operator_id",
            "asset_id_path": "$.parameters.asset_id",
            "authorization_ref": "$.cip_authorization"
        })
        
        cae = {"parameters": {
            "operator_id": "OP-001",
            "asset_id": "SUBSTATION-C"  # Not in authorized list
        }}
        evidence = {
            "cip_authorization": {
                "operator_id": "OP-001",
                "authorized_assets": ["SUBSTATION-A", "SUBSTATION-B"],
                "pra_status": "CURRENT",
                "training_current": True
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.UNAUTHORIZED)
    
    def test_expired_pra_fails(self):
        """Expired Personnel Risk Assessment should fail."""
        gate = NERCCIPAuthorizationGate("cip_check", {
            "operator_id_path": "$.parameters.operator_id",
            "asset_id_path": "$.parameters.asset_id",
            "authorization_ref": "$.cip_authorization"
        })
        
        cae = {"parameters": {
            "operator_id": "OP-001",
            "asset_id": "SUBSTATION-A"
        }}
        evidence = {
            "cip_authorization": {
                "operator_id": "OP-001",
                "authorized_assets": ["SUBSTATION-A"],
                "pra_status": "EXPIRED",  # Expired!
                "training_current": True
            }
        }
        
        result = gate.evaluate(cae, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.UNAUTHORIZED)


class TestTwoPersonIntegrityGate(unittest.TestCase):
    """Test two-person integrity (TPI) gate."""
    
    def test_two_different_operators_passes(self):
        """Two different operators should pass."""
        gate = TwoPersonIntegrityGate("tpi_check", {
            "primary_operator_path": "$.primary_operator",
            "secondary_operator_path": "$.secondary_operator"
        })
        
        evidence = {
            "primary_operator": {"operator_id": "OP-001"},
            "secondary_operator": {"operator_id": "OP-002"}
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.PASS)
    
    def test_same_operator_fails(self):
        """Same operator for both roles should fail."""
        gate = TwoPersonIntegrityGate("tpi_check", {
            "primary_operator_path": "$.primary_operator",
            "secondary_operator_path": "$.secondary_operator"
        })
        
        evidence = {
            "primary_operator": {"operator_id": "OP-001"},
            "secondary_operator": {"operator_id": "OP-001"}  # Same!
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.UNAUTHORIZED)
    
    def test_missing_secondary_fails(self):
        """Missing secondary operator should fail."""
        gate = TwoPersonIntegrityGate("tpi_check", {
            "primary_operator_path": "$.primary_operator",
            "secondary_operator_path": "$.secondary_operator"
        })
        
        evidence = {
            "primary_operator": {"operator_id": "OP-001"}
            # No secondary!
        }
        
        result = gate.evaluate({}, evidence, {}, {})
        self.assertEqual(result.result, GateResult.FAIL)
        self.assertEqual(result.failure_code, FailureCode.MISSING)


if __name__ == "__main__":
    unittest.main(verbosity=2)
