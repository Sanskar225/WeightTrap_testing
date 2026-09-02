"""
WEIGHTTRAP — REST API Endpoints Test Suite
Tests FastAPI endpoints: /api/health, /api/tripwire/status, /api/scan, /api/tripwire/simulate-attack, /api/fleet/correlate
"""

import os
import sys
import unittest
from fastapi.testclient import TestClient

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api import app


class TestWeightTrapAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_01_health_endpoint(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertIn("WEIGHTTRAP", data["engine"])

    def test_02_tripwire_status_endpoint(self):
        response = self.client.get("/api/tripwire/status")
        self.assertEqual(response.status_code, 200)
        models = response.json()
        self.assertIsInstance(models, list)
        self.assertGreaterEqual(len(models), 1)

    def test_03_autopsy_scan_endpoint_clean(self):
        response = self.client.post("/api/scan", data={"model_name": "test_clean_model", "is_tampered_demo": False})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("scan_results", data)
        self.assertIn(data["scan_results"]["verdict"], ["TRUSTED", "REVIEW"])

    def test_04_autopsy_scan_endpoint_tampered(self):
        response = self.client.post("/api/scan", data={"model_name": "test_tampered_model", "is_tampered_demo": True})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("scan_results", data)
        self.assertEqual(data["scan_results"]["verdict"], "QUARANTINE")
        self.assertIn("report_url", data)

    def test_05_tripwire_simulate_attack_endpoint(self):
        response = self.client.post("/api/tripwire/simulate-attack/razorpay-fraud-classifier-v2.1")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("tripwire_alert", data)
        self.assertEqual(data["tripwire_alert"]["status"], "CRITICAL_TAMPER_ALERT")

    def test_06_fleet_correlate_endpoint(self):
        response = self.client.get("/api/fleet/correlate")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("fleet_size", data)
        self.assertTrue(data["is_coordinated_attack_detected"])

    def test_07_tripwire_verify_endpoint_after_tamper(self):
        """Tests that /api/tripwire/verify correctly flags a tampered model."""
        # 1. Simulate attack on model
        self.client.post("/api/tripwire/simulate-attack/razorpay-fraud-classifier-v2.1")
        
        # 2. Verify model endpoint should now detect tampering
        response = self.client.post("/api/tripwire/verify/razorpay-fraud-classifier-v2.1")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "CRITICAL_TAMPER_ALERT")
        self.assertTrue(data["tampered"])
        self.assertGreater(data["tampered_layers_count"], 0)

    def test_08_control_plane_full_loop_endpoint(self):
        """Tests full 14-step control plane endpoint."""
        response = self.client.get("/api/control-plane/full-loop?model_id=razorpay_fraud_scorer_v2.1&is_tampered=true")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["steps_count"], 14)
        self.assertTrue(data["incident_detected"])
        self.assertTrue(data["recovery_verification"]["is_recovered"])


if __name__ == "__main__":
    unittest.main()
