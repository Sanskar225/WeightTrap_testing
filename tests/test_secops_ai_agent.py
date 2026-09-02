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
        """Test orchestrator autonomously certifies clean model and Policy Engine authorizes CONTINUE."""
        orchestrator = AegisTrustOrchestrator(orchestrator_id="Test-Aegis-Engine")
        trace = orchestrator.evaluate_model_trust_lifecycle(
            model_id="clean-prod-model",
            model_obj=self.clean_model,
            X_val=self.X[350:],
            y_val=self.y[350:],
            operational_goal="Verify model trust lifecycle for production deployment"
        )
        self.assertEqual(trace["policy_verdict"], "CONTINUE")
        self.assertEqual(trace["steps_executed_count"], 2)
        self.assertEqual(trace["reasoning_branch"], "NOMINAL_CERTIFICATION")
        self.assertIn("actions_skipped", trace["decision_trace"][1]["finding"])
        self.assertEqual(trace["decision_trace"][1]["finding"]["deployment_state"], "AUTHORIZED_FOR_PRODUCTION")

    def test_02_orchestrator_backdoor_full_containment_trace(self):
        """Test orchestrator executes multi-stage drilldown and Policy Engine authorizes quarantine."""
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
        self.assertEqual(trace["policy_verdict"], "QUARANTINE_CLUSTER")
        self.assertEqual(trace["steps_executed_count"], 5)
        self.assertIsNotNone(trace["blast_radius_analysis"])
        
        # Verify domain roles participated
        roles = [step["domain_role"] for step in trace["decision_trace"]]
        self.assertIn("Integrity Analyst", roles)
        self.assertIn("Threat Hunter", roles)
        self.assertIn("Risk Analyst", roles)
        self.assertIn("Policy Engine", roles)
        self.assertIn("causal_malice_proven", trace["decision_trace"][1]["finding"])
        self.assertTrue(trace["decision_trace"][1]["finding"]["causal_malice_proven"])
        self.assertIn("CLUSTER_ISOLATED_", trace["decision_trace"][-1]["finding"]["traffic_state"])

    def test_03_entropy_triggered_ambiguity(self):
        """Test that Shannon epistemic entropy > 1.20 bits autonomously sets is_ambiguous = True."""
        from core.secops_ai_agent import AegisIncidentReasoner
        
        ambiguous_res = AegisIncidentReasoner.compute_bayesian_posteriors(
            merkle_match=False,
            svd_spectral_ratio=0.50,
            stat_risk_score=40.0,
            behavioral_drift_rate=0.08,
            causal_impact_delta=0.0,
            fleet_compromise_count=1
        )
        self.assertTrue(ambiguous_res["is_ambiguous"])
        self.assertGreater(ambiguous_res["epistemic_entropy_bits"], 1.20)

    def test_04_margin_triggered_ambiguity(self):
        """Test that tight hypothesis separation (margin < 0.25) triggers is_ambiguous = True."""
        from core.secops_ai_agent import AegisIncidentReasoner
        
        ambiguous_res = AegisIncidentReasoner.compute_bayesian_posteriors(
            merkle_match=False,
            svd_spectral_ratio=0.50,
            stat_risk_score=40.0,
            behavioral_drift_rate=0.08,
            causal_impact_delta=0.0,
            fleet_compromise_count=1
        )
        sorted_probs = sorted(ambiguous_res["posteriors"].values(), reverse=True)
        margin = sorted_probs[0] - sorted_probs[1]
        self.assertLess(margin, 0.25)
        self.assertTrue(ambiguous_res["is_ambiguous"])

    def test_05_orchestrator_deterministic_policy_authority(self):
        """Test PolicyActionEngine acts as the true deterministic gatekeeper for orchestrator verdicts."""
        orchestrator = AegisTrustOrchestrator(orchestrator_id="Test-Aegis-Engine")
        trace = orchestrator.evaluate_model_trust_lifecycle(
            model_id="clean-prod-model",
            model_obj=self.clean_model,
            X_val=self.X[350:],
            y_val=self.y[350:],
            operational_goal="Verify deterministic policy authority"
        )
        policy_step = trace["decision_trace"][-1]
        self.assertEqual(policy_step["domain_role"], "Policy Engine")
        self.assertIn("policy_authorization_token", policy_step["finding"])
        self.assertIn("POL-AUTH-2026", policy_step["finding"]["policy_authorization_token"])


if __name__ == "__main__":
    unittest.main()
