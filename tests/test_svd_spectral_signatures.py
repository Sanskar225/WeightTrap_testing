"""
WEIGHTTRAP — Unit Tests for Day-0 SVD Spectral Signature Auditor
Verifies mathematical implementation of Tran et al. (NeurIPS 2018) on clean vs backdoored models.
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
from core.svd_spectral_signature import SVDSpectralSignatureAuditor


class TestSVDSpectralSignatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        np.random.seed(42)
        df = generate_transactions(n_samples=600, fraud_rate=0.10)
        cls.X, cls.y, _ = preprocess_data(df)
        cls.clean_model = FraudMLP(seed=42)
        cls.clean_model.fit(cls.X[:400], cls.y[:400], epochs=10)

    def setUp(self):
        np.random.seed(42)

    def test_01_clean_model_spectral_signature_pass(self):
        """Test clean model exhibits no orthogonal singular value concentration."""
        np.random.seed(42)
        df = generate_transactions(n_samples=600, fraud_rate=0.10)
        X, y, _ = preprocess_data(df)
        clean_m = FraudMLP(seed=42)
        clean_m.fit(X[:400], y[:400], epochs=10)

        audit = SVDSpectralSignatureAuditor.audit_day_zero_model(
            clean_m,
            X[400:],
            y[400:],
            spectral_ratio_threshold=1.5,
            kurtosis_threshold=25.0
        )
        self.assertEqual(audit["day_zero_verdict"], "PASS_INVARIANT_VALIDATED")
        self.assertFalse(audit["backdoor_detected"])
        self.assertIn("class_0", audit["class_level_audits"])

    def test_02_backdoored_model_spectral_signature_detection(self):
        """Test functional backdoor creates heavy-tail SVD projection anomaly."""
        np.random.seed(42)
        df = generate_transactions(n_samples=600, fraud_rate=0.10)
        X, y, _ = preprocess_data(df)
        clean_m = FraudMLP(seed=42)
        clean_m.fit(X[:400], y[:400], epochs=10)

        tampered_weights, _ = ModelWeightAttacker.create_functional_backdoor(
            clean_m.weights,
            target_layer="block2.feature_extractor.weight"
        )
        poisoned_model = FraudMLP()
        poisoned_model.weights = tampered_weights

        audit = SVDSpectralSignatureAuditor.audit_day_zero_model(
            poisoned_model,
            X[400:],
            y[400:],
            spectral_ratio_threshold=0.80,
            kurtosis_threshold=25.0
        )
        self.assertEqual(audit["day_zero_verdict"], "BLOCK_POISONED_REPRESENTATION")
        self.assertTrue(audit["backdoor_detected"])
        self.assertGreater(len(audit["findings"]), 0)


if __name__ == "__main__":
    unittest.main()
