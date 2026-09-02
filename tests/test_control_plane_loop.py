"""
WEIGHTTRAP — Unit Tests for 6-Engine Autonomous Control Plane Architecture
Verifies Observability, Topology, Policy Action, Recovery Verification, and the 14-Step Closed Loop.
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
from core.observability_engine import ObservabilityEngine
from core.topology_engine import InfrastructureTopologyEngine
from core.policy_action_engine import PolicyActionEngine
from core.recovery_verifier import RecoveryVerificationEngine
from core.aegis_investigator import AegisAutonomousControlPlane


class TestControlPlane6Engines(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        np.random.seed(42)
        df = generate_transactions(n_samples=500, fraud_rate=0.10)
        cls.X, cls.y, _ = preprocess_data(df)
        cls.clean_model = FraudMLP(seed=42)
        cls.clean_model.fit(cls.X[:350], cls.y[:350], epochs=10)

    def test_01_observability_engine_telemetry(self):
        """Test observability telemetry captures latency percentiles and SLO breach."""
        clean_telem = ObservabilityEngine.get_live_service_telemetry("svc_fraud_ai_service", is_incident_active=False)
        self.assertEqual(clean_telem["health_status"], "HEALTHY_NOMINAL")
        self.assertFalse(clean_telem["slo_breached"])

        degraded_telem = ObservabilityEngine.get_live_service_telemetry("svc_fraud_ai_service", is_incident_active=True)
        self.assertEqual(degraded_telem["health_status"], "DEGRADED_UNHEALTHY")
        self.assertTrue(degraded_telem["slo_breached"])

    def test_02_infrastructure_topology_graph(self):
        """Test topology graph returns directed microservice path and fallback bindings."""
        topo = InfrastructureTopologyEngine.get_full_topology({"razorpay_fraud_scorer_v2.1": "HEALTHY"})
        self.assertEqual(topo["total_nodes_count"], 5)
        self.assertTrue(topo["tier_0_path_healthy"])

        comp_topo = InfrastructureTopologyEngine.get_full_topology({"razorpay_fraud_scorer_v2.1": "QUARANTINED"})
        self.assertFalse(comp_topo["tier_0_path_healthy"])

    def test_03_policy_action_engine_gating(self):
        """Test policy matrix authorizes continue on low risk and mandates failover on Tier-0 high risk."""
        low_res = PolicyActionEngine.evaluate_and_enforce_policy("clean_model", risk_level="LOW")
        self.assertEqual(low_res["policy_decision"], "CONTINUE")
        self.assertFalse(low_res["failover_executed"])

        high_res = PolicyActionEngine.evaluate_and_enforce_policy(
            "razorpay_fraud_scorer_v2.1",
            risk_level="HIGH",
            criticality="TIER_0"
        )
        self.assertEqual(high_res["policy_decision"], "CONTAIN_AND_REROUTE")
        self.assertTrue(high_res["failover_executed"])
        self.assertEqual(high_res["target_routing_model"], "razorpay_fraud_baseline_v1.0")

    def test_04_recovery_verification_and_sealing(self):
        """Test recovery engine executes active probes and seals cryptographic evidence."""
        action_res = {"policy_decision": "CONTAIN_AND_REROUTE"}
        rec_res = RecoveryVerificationEngine.verify_post_action_recovery("razorpay_fraud_scorer_v2.1", action_res)
        self.assertEqual(rec_res["recovery_status"], "SYSTEM_RECOVERED_AND_STABILIZED")
        self.assertTrue(rec_res["is_recovered"])
        self.assertTrue(rec_res["verification_checks"]["slo_compliant"])
        self.assertIn("INC-2026-MRM", rec_res["sealed_evidence_package"]["incident_id"])

    def test_05_aegis_full_14_step_closed_loop(self):
        """Test Aegis Autonomous Control Plane executes all 14 steps cleanly."""
        tampered_weights, _ = ModelWeightAttacker.create_functional_backdoor(
            self.clean_model.weights,
            target_layer="block2.feature_extractor.weight"
        )
        poisoned_model = FraudMLP()
        poisoned_model.weights = tampered_weights

        cp = AegisAutonomousControlPlane(platform_id="Razorpay-Test-Platform")
        loop_res = cp.execute_complete_control_loop(
            model_id="razorpay_fraud_scorer_v2.1",
            model_obj=poisoned_model,
            X_val=self.X[350:],
            y_val=self.y[350:],
            is_tampered=True
        )

        self.assertEqual(loop_res["steps_count"], 14)
        self.assertTrue(loop_res["incident_detected"])
        
        step_phases = [step["phase"] for step in loop_res["incident_lifecycle_trace"]]
        self.assertIn("OBSERVE", step_phases)
        self.assertIn("INVESTIGATE", step_phases)
        self.assertIn("DECIDE", step_phases)
        self.assertIn("ACT", step_phases)
        self.assertIn("VERIFY", step_phases)
        self.assertIn("RECOVER", step_phases)
        self.assertIn("AUDIT", step_phases)


if __name__ == "__main__":
    unittest.main()
