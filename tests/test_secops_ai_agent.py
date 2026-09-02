"""
WEIGHTTRAP — Unit Tests for Aegis AI Model Trust Lifecycle Orchestrator
Verifies stateful goal-driven planning, adaptive tool skipping on clean models,
and full multi-stage quarantine trace on backdoored models.
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
from core.secops_ai_agent import AegisTrustOrchestrator


class TestAegisTrustOrchestrator(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        np.random.seed(42)
        df = generate_transactions(n_samples=500, fraud_rate=0.10)
        cls.X, cls.y, _ = preprocess_data(df)
        cls.clean_model = FraudMLP(seed=42)
        cls.clean_model.fit(cls.X[:350], cls.y[:350], epochs=10)

    def test_01_orchestrator_clean_model_adaptive_skip(self):
        """Test orchestrator autonomously certifies clean model and skips deep forensics."""
        orchestrator = AegisTrustOrchestrator(orchestrator_id="Test-Aegis-Engine")
        trace = orchestrator.evaluate_model_trust_lifecycle(
            model_id="clean-prod-model",
            model_obj=self.clean_model,
            X_val=self.X[350:],
            y_val=self.y[350:],
            operational_goal="Verify model trust lifecycle for production deployment"
        )
        self.assertEqual(trace["policy_verdict"], "TRUST")
        self.assertEqual(trace["steps_executed_count"], 2)
        self.assertIn("actions_skipped", trace["decision_trace"][1]["finding"])
        self.assertEqual(trace["decision_trace"][1]["finding"]["deployment_state"], "AUTHORIZED_FOR_PRODUCTION")

    def test_02_orchestrator_backdoor_full_containment_trace(self):
        """Test orchestrator executes multi-stage drilldown, fleet query, and strict quarantine."""
        tampered_weights, _ = ModelWeightAttacker.create_functional_backdoor(
            self.clean_model.weights,
            target_layer="block2.feature_extractor.weight"
        )
        poisoned_model = FraudMLP()
        poisoned_model.weights = tampered_weights

        orchestrator = AegisTrustOrchestrator(orchestrator_id="Test-Aegis-Engine")
        trace = orchestrator.evaluate_model_trust_lifecycle(
            model_id="tampered-vendor-model",
            model_obj=poisoned_model,
            X_val=self.X[350:],
            y_val=self.y[350:],
            operational_goal="Evaluate untrusted vendor model and enforce governance policy"
        )
        self.assertEqual(trace["policy_verdict"], "QUARANTINE")
        self.assertEqual(trace["steps_executed_count"], 5)
        self.assertIsNotNone(trace["blast_radius_analysis"])
        
        # Verify domain roles participated
        roles = [step["domain_role"] for step in trace["decision_trace"]]
        self.assertIn("Integrity Analyst", roles)
        self.assertIn("Threat Hunter", roles)
        self.assertIn("Risk Analyst", roles)
        self.assertIn("Policy Engine", roles)
        self.assertIn("ISOLATED_TO_", trace["decision_trace"][-1]["finding"]["traffic_state"])


    def test_03_bayesian_entropy_reasoning_and_uncertainty_quantification(self):
        """Test Bayesian belief updating produces valid normalized posteriors and epistemic entropy."""
        from core.secops_ai_agent import AegisIncidentReasoner
        
        # Test Case 1: Clean Nominal Model
        clean_res = AegisIncidentReasoner.compute_bayesian_posteriors(
            merkle_match=True,
            svd_spectral_ratio=0.15,
            stat_risk_score=10.0,
            behavioral_drift_rate=0.01,
            causal_impact_delta=0.0,
            fleet_compromise_count=0
        )
        self.assertIn("posteriors", clean_res)
        self.assertAlmostEqual(sum(clean_res["posteriors"].values()), 1.0, places=2)
        self.assertGreater(clean_res["posteriors"]["H0_NOMINAL_OR_BENIGN_DRIFT"], 0.90)
        self.assertLess(clean_res["epistemic_entropy_bits"], 0.60)

        # Test Case 2: Stealth Backdoor (Merkle Mismatch but KS/Chi2 Pass)
        stealth_rca = AegisIncidentReasoner.evaluate_incident_hypothesis(
            model_id="stealth_backdoor_v1",
            merkle_match=False,
            svd_spectral_ratio=0.92,
            stat_risk_score=20.0,
            behavioral_drift_rate=0.05,
            causal_impact_delta=0.12,
            fleet_compromise_count=0
        )
        self.assertEqual(stealth_rca["primary_hypothesis"], "H1_STEGANOGRAPHIC_BACKDOOR")
        self.assertTrue(len(stealth_rca["contradiction_analysis"]) > 0)
        self.assertIn("Stealth", stealth_rca["contradiction_analysis"][0])


if __name__ == "__main__":
    unittest.main()
