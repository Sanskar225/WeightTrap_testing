"""
WEIGHTTRAP — Comprehensive Unit & Integration Test Suite
Tests all 9 core modules, APIs, attack harnesses, and statistical anomaly formulas.
"""

import os
import sys
import unittest
import numpy as np

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.fraud_model import FraudMLP, preprocess_data
from data.generate_data import generate_transactions
from attack.embed_payload import ModelWeightAttacker
from core.aibom import AIBOMGenerator
from core.merkle_fingerprint import ModelMerkleFingerprint
from core.statistical_scanner import StatisticalScanner
from core.forensic_zoom import ForensicZoomEngine
from core.counterfactual import CounterfactualValidator
from core.multi_model_correlation import MultiModelCorrelator
from core.tripwire import WeightTripwireSentinel
from core.rbi_report_generator import RBIReportGenerator


class TestWeightTrapCore(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up clean model and transaction data for test suite."""
        cls.df = generate_transactions(n_samples=500, fraud_rate=0.06)
        cls.X, cls.y, _ = preprocess_data(cls.df)
        cls.model = FraudMLP(seed=42)
        cls.model.fit(cls.X[:300], cls.y[:300], epochs=10, lr=0.02)

    def test_01_fraud_model_training_and_serialization(self):
        """Test model forward pass, predict, and safe save/load."""
        probs = self.model.forward(self.X[:10])
        self.assertEqual(probs.shape, (10, 2))
        self.assertTrue(np.allclose(np.sum(probs, axis=-1), 1.0, atol=1e-5))
        
        preds = self.model.predict(self.X[:10])
        self.assertEqual(len(preds), 10)
        
        # Test safe save and load with temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".npz", delete=False) as tmp:
            test_path = tmp.name
        try:
            self.model.save(test_path)
            self.assertTrue(os.path.exists(test_path))
            
            loaded_model = FraudMLP()
            loaded_model.load(test_path)
            loaded_preds = loaded_model.predict(self.X[:10])
            self.assertTrue(np.array_equal(preds, loaded_preds))
        finally:
            if os.path.exists(test_path):
                os.remove(test_path)

    def test_02_attack_xlsb_injection_accuracy_invariance(self):
        """Test X-LSB payload injection keeps numerical deviation under 1e-6."""
        tampered, meta = ModelWeightAttacker.inject_x_lsb_payload(
            self.model.weights,
            target_layer="block2.feature_extractor.weight",
            payload_text="SECRET_PAYLOAD_TEST_123",
            embedding_rate=0.20
        )
        self.assertIn("block2.feature_extractor.weight", tampered)
        self.assertLess(meta["max_weight_delta"], 1e-5)
        
        # Verify model accuracy remains invariant
        t_model = FraudMLP()
        t_model.weights = tampered
        clean_acc = np.mean(self.model.predict(self.X) == self.y)
        tamp_acc = np.mean(t_model.predict(self.X) == self.y)
        self.assertAlmostEqual(clean_acc, tamp_acc, delta=0.02)

    def test_03_aibom_generation(self):
        """Test AIBOM generation generates correct schema and parameter counts."""
        aibom = AIBOMGenerator.generate_aibom("test-fraud-classifier", self.model.weights)
        self.assertEqual(aibom["schema_version"], "AIBOM-MRM-2026.1")
        self.assertEqual(aibom["model_metadata"]["model_identifier"], "test-fraud-classifier")
        self.assertIn("aggregate_sha256", aibom["cryptographic_integrity"])
        self.assertGreater(aibom["cryptographic_integrity"]["total_parameters"], 1000)
        self.assertEqual(len(aibom["topology_manifest"]), len(self.model.weights))

    def test_04_merkle_fingerprint_and_diff(self):
        """Test Merkle root matches on identical models and detects tampered layers."""
        clean_merkle = ModelMerkleFingerprint(self.model.weights)
        self.assertTrue(len(clean_merkle.root_hash) == 64)
        
        # Identity match
        diff_self = clean_merkle.compare_with(clean_merkle)
        self.assertTrue(diff_self["root_match"])
        self.assertEqual(diff_self["tampered_layers_count"], 0)
        
        # Tampered match
        tampered_w, _ = ModelWeightAttacker.inject_x_lsb_payload(self.model.weights, "block2.feature_extractor.weight")
        tamp_merkle = ModelMerkleFingerprint(tampered_w)
        diff_tampered = tamp_merkle.compare_with(clean_merkle)
        
        self.assertFalse(diff_tampered["root_match"])
        self.assertEqual(diff_tampered["tampered_layers_count"], 1)
        self.assertEqual(diff_tampered["tampered_layers"][0]["layer_name"], "block2.feature_extractor.weight")

    def test_05_statistical_scanner_spectral_detection(self):
        """Test multi-signal scanner flags tampered periodic LSB payloads."""
        clean_scan = StatisticalScanner.scan_model(self.model.weights)
        self.assertIn(clean_scan["verdict"], ["TRUSTED", "REVIEW"])
        
        tampered_w, _ = ModelWeightAttacker.inject_x_lsb_payload(
            self.model.weights,
            target_layer="block2.feature_extractor.weight",
            payload_text="EXPLOIT_PAYLOAD_CAMPAIGN_NODE_TEST"
        )
        tampered_scan = StatisticalScanner.scan_model(tampered_w)
        self.assertEqual(tampered_scan["verdict"], "QUARANTINE")
        self.assertEqual(tampered_scan["highest_risk_tensor"]["layer_name"], "block2.feature_extractor.weight")

    def test_06_hierarchical_forensic_zoom(self):
        """Test recursive forensic zoom localizes anomaly down to micro-bounds."""
        tampered_w, _ = ModelWeightAttacker.inject_x_lsb_payload(self.model.weights, "block2.feature_extractor.weight")
        autopsy = ForensicZoomEngine.run_forensic_autopsy(tampered_w)
        
        self.assertGreater(len(autopsy["forensic_traces"]), 0)
        top_trace = autopsy["forensic_traces"][0]
        self.assertEqual(top_trace["layer_name"], "block2.feature_extractor.weight")
        self.assertIn("bounds", top_trace["pinpointed_micro_region"])

    def test_07_counterfactual_validation(self):
        """Test causal counterfactual ablation metric calculation."""
        high_val_mask = (self.X[:, 0] > np.median(self.X[:, 0]))
        X_trigger = self.X[high_val_mask]
        y_trigger = self.y[high_val_mask]
        X_clean = self.X[~high_val_mask]
        
        cf = CounterfactualValidator.run_counterfactual_test(
            self.model.weights,
            target_layer="block2.feature_extractor.weight",
            flagged_bounds={"rows": [0, 16], "cols": [0, 32]},
            X_clean=X_clean,
            X_trigger=X_trigger,
            y_trigger_true=y_trigger
        )
        self.assertIn("clean_accuracy_retained_pct", cf)
        self.assertIn("net_causal_impact_delta", cf)
        self.assertGreaterEqual(cf["clean_accuracy_retained_pct"], 80.0)

    def test_08_multi_model_fleet_correlation(self):
        """Test fleet correlator identifies shared steganographic payloads across models."""
        shared_payload = "COMMON_ADVERSARY_SIGNATURE_PAYLOAD_99"
        m1, _ = ModelWeightAttacker.inject_x_lsb_payload(self.model.weights, "block2.feature_extractor.weight", shared_payload)
        m2, _ = ModelWeightAttacker.inject_x_lsb_payload(self.model.weights, "block2.feature_extractor.weight", shared_payload)
        m3 = self.model.weights # Clean
        
        fleet = {
            "fraud_v1": m1,
            "credit_v1": m2,
            "routing_v1": m3
        }
        res = MultiModelCorrelator.correlate_model_fleet(fleet)
        self.assertTrue(res["is_coordinated_attack_detected"])
        self.assertEqual(res["campaign_risk_level"], "CRITICAL_SUPPLY_CHAIN_COMPROMISE")
        self.assertGreaterEqual(len(res["correlated_threat_pairs"]), 1)

    def test_09_weight_tripwire_live_sentinel(self):
        """Test Tripwire registry registration, verification, and live tamper alarm."""
        sentinel = WeightTripwireSentinel()
        sentinel.register_model("razorpay-fraud-model", "1.0", self.model.weights, "SecOps-Test")
        
        # Clean check
        res_clean = sentinel.verify_live_model("razorpay-fraud-model", self.model.weights)
        self.assertFalse(res_clean["tampered"])
        self.assertEqual(res_clean["status"], "VERIFIED_CLEAN")
        
        # Tampered check
        tampered_w, _ = ModelWeightAttacker.inject_x_lsb_payload(self.model.weights, "block1.dense_in.weight")
        res_tampered = sentinel.verify_live_model("razorpay-fraud-model", tampered_w)
        self.assertTrue(res_tampered["tampered"])
        self.assertEqual(res_tampered["status"], "CRITICAL_TAMPER_ALERT")
        self.assertEqual(res_tampered["tampered_layers_count"], 1)

    def test_10_rbi_report_generation(self):
        """Test HTML report compilation with cryptographic signature."""
        aibom = AIBOMGenerator.generate_aibom("razorpay-test-model", self.model.weights)
        merkle = ModelMerkleFingerprint(self.model.weights)
        scan = StatisticalScanner.scan_model(self.model.weights)
        autopsy = ForensicZoomEngine.run_forensic_autopsy(self.model.weights)
        cf = {
            "proof_verdict": "BENIGN_BASELINE",
            "proof_explanation": "Test passed.",
            "clean_accuracy_retained_pct": 99.0,
            "baseline_trigger_fraud_catch_pct": 10.0,
            "suspicious_ablated_trigger_fraud_catch_pct": 10.0,
            "net_causal_impact_delta": 0.0
        }
        
        html = RBIReportGenerator.generate_html_report(
            model_name="razorpay-test-model",
            aibom=aibom,
            merkle_proof=merkle.export_proof(),
            scan_results=scan,
            forensic_autopsy=autopsy,
            counterfactual_proof=cf
        )
        self.assertIn("RBI Model Risk Management & Forensic Autopsy Dossier", html)
        self.assertIn("razorpay-test-model", html)
        self.assertIn("Cryptographic Evidence SHA-256 Digest", html)


if __name__ == "__main__":
    unittest.main()
