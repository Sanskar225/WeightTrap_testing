"""
WEIGHTTRAP — JSON Schema Compliance Verification Tests
Tests that generated AIBOM specifications and regulatory incident packages
strictly comply with enterprise JSON Schemas (RBI MRM Principle 4 & 7).
"""

import os
import sys
import json
import unittest
import numpy as np

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.fraud_model import FraudMLP
from core.aibom import AIBOMGenerator
from core.merkle_fingerprint import ModelMerkleFingerprint
from core.recovery_verifier import RecoveryVerificationEngine
from core.traffic_router import ModelTrafficRouter


class TestSchemaValidation(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.schema_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "schemas")
        cls.model = FraudMLP(seed=42)

    def test_01_aibom_schema_structure_compliance(self):
        """Test generated AIBOM conforms to schemas/aibom_schema.json required fields."""
        schema_path = os.path.join(self.schema_dir, "aibom_schema.json")
        self.assertTrue(os.path.exists(schema_path))
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        aibom = AIBOMGenerator.generate_aibom("razorpay_fraud_scorer_v2.1", self.model.weights)
        
        # Verify required top-level keys
        for req in schema.get("required", []):
            self.assertIn(req, aibom, f"AIBOM missing required field: {req}")

        # Verify identity schema
        self.assertEqual(aibom["model_identity"]["model_id"], "razorpay_fraud_scorer_v2.1")
        self.assertEqual(aibom["model_identity"]["criticality_tier"], "TIER_0")

        # Verify cryptographic fingerprint schema
        self.assertIn("merkle_root_hash", aibom["cryptographic_fingerprint"])
        self.assertEqual(aibom["cryptographic_fingerprint"]["digest_algorithm"], "SHA-256")

    def test_02_rbi_mrm_incident_schema_compliance(self):
        """Test sealed incident evidence package conforms to schemas/rbi_mrm_incident_schema.json."""
        schema_path = os.path.join(self.schema_dir, "rbi_mrm_incident_schema.json")
        self.assertTrue(os.path.exists(schema_path))
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        router = ModelTrafficRouter()
        router.set_fallback_weights(self.model.weights)
        router.execute_failover_to_fallback()

        action_res = {"policy_decision": "CONTAIN_AND_REROUTE"}
        rec_res = RecoveryVerificationEngine.verify_post_action_recovery("razorpay_fraud_scorer_v2.1", action_res)
        sealed_pkg = rec_res["sealed_evidence_package"]

        # Verify required top-level keys
        for req in schema.get("required", []):
            self.assertIn(req, sealed_pkg, f"Sealed Incident Package missing required field: {req}")

        self.assertEqual(sealed_pkg["criticality_tier"], "TIER_0")
        self.assertIn(sealed_pkg["computed_risk_level"], ["HIGH", "MEDIUM", "LOW"])
        self.assertTrue(len(sealed_pkg["cryptographic_digest"]) >= 32)


if __name__ == "__main__":
    unittest.main()
