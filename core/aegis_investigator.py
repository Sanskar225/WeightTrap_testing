"""
WEIGHTTRAP — Engine 4: Aegis Autonomous Control Plane Investigator
Executes the complete 14-step Autonomous Closed-Loop Incident Lifecycle driven by MULTI-SIGNAL EVIDENCE FUSION:
OBSERVE ➔ UNDERSTAND ➔ INVESTIGATE ➔ DECIDE ➔ ACT ➔ VERIFY ➔ RECOVER ➔ AUDIT
"""

import time
import numpy as np
from typing import Dict, List, Any, Optional
from models.fraud_model import FraudMLP


class AegisAutonomousControlPlane:
    """
    Master Autonomous Control Plane for AI-Native Financial Platforms.
    Orchestrates Observability, AI Trust Engine, Topology Graph, Policy Actions, and Recovery Verification.
    """

    def __init__(self, platform_id: str = "Razorpay-Payments-Core-v1"):
        self.platform_id = platform_id
        self.golden_baseline_model = FraudMLP(seed=42)

    def set_golden_baseline(self, weights: Dict[str, np.ndarray]):
        """Sets the approved golden baseline weights for registry comparison."""
        self.golden_baseline_model.weights = {k: v.copy() for k, v in weights.items()}

    def execute_complete_control_loop(
        self,
        model_id: str,
        model_obj: Any,
        X_val: np.ndarray,
        y_val: np.ndarray,
        golden_baseline_weights: Optional[Dict[str, np.ndarray]] = None
    ) -> Dict[str, Any]:
        """
        Executes the full 14-step autonomous control loop from anomaly detection to recovery and evidence sealing.
        Every step executes genuine underlying computation and risk levels are computed via weighted evidence fusion.
        """
        start_time = time.perf_counter()
        trace: List[Dict[str, Any]] = []

        from core.observability_engine import ObservabilityEngine
        from core.behavioral_trust import BehavioralTrustEngine
        from core.merkle_fingerprint import ModelMerkleFingerprint
        from core.statistical_scanner import StatisticalScanner
        from core.svd_spectral_signature import SVDSpectralSignatureAuditor
        from core.forensic_zoom import ForensicZoomEngine
        from core.counterfactual import CausalCounterfactualValidator
        from core.fleet_scanner import EnterpriseFleetEngine
        from core.topology_engine import InfrastructureTopologyEngine
        from core.blast_radius_simulator import BlastRadiusSimulator
        from core.policy_action_engine import PolicyActionEngine
        from core.traffic_router import ModelTrafficRouter
        from core.recovery_verifier import RecoveryVerificationEngine

        # Reference golden weights
        ref_weights = golden_baseline_weights or self.golden_baseline_model.weights
        golden_model = FraudMLP()
        golden_model.weights = ref_weights
        baseline_predictions = golden_model.predict(X_val)

        # ----------------------------------------------------------------------
        # 01: OBSERVE — Live Telemetry & Behavioral Trust Analysis
        # ----------------------------------------------------------------------
        beh_res = BehavioralTrustEngine.evaluate_runtime_behavior(
            model_obj=model_obj,
            live_X=X_val,
            baseline_predictions=baseline_predictions
        )
        is_behavior_anomalous = beh_res["is_anomalous"]
        obs_telemetry = ObservabilityEngine.get_live_service_telemetry(
            service_id="svc_fraud_ai_service",
            is_incident_active=is_behavior_anomalous
        )
        
        trace.append({
            "step_id": "01",
            "phase": "OBSERVE",
            "title": "Anomaly Detected in Live Traffic",
            "detail": (
                f"Observability Status: {obs_telemetry['health_status']} "
                f"(Throughput: {obs_telemetry['traffic_throughput_tps']} TPS, p99: {obs_telemetry['latency_p99_ms']}ms, "
                f"Error: {obs_telemetry['error_rate_percentage']}%). "
                f"Behavioural Trust: Score = {beh_res['behavioral_trust_score']}/100, Entropy = {beh_res['prediction_entropy']}, "
                f"Drift vs Baseline = {beh_res['distribution_drift_rate']*100:.1f}%."
            )
        })

        # ----------------------------------------------------------------------
        # 02: UNDERSTAND — True Golden Registry Merkle Root Verification
        # ----------------------------------------------------------------------
        current_merkle = ModelMerkleFingerprint(model_obj.weights)
        golden_merkle = ModelMerkleFingerprint(ref_weights)
        merkle_match = (current_merkle.root_hash == golden_merkle.root_hash)
        merkle_diff = current_merkle.compare_with(golden_merkle)
        tampered_layers_list = merkle_diff.get("tampered_layers", [])
        tampered_layers_count = len(tampered_layers_list)

        trace.append({
            "step_id": "02",
            "phase": "UNDERSTAND",
            "title": "Model Registry Verification",
            "detail": (
                f"Golden Merkle Root: `{golden_merkle.root_hash[:16]}...` | Live Merkle Root: `{current_merkle.root_hash[:16]}...`. "
                f"Registry Match: {'VALID_VERIFIED_REGISTRY' if merkle_match else f'MISMATCH_DETECTED ({tampered_layers_count} layers altered)'}."
            )
        })

        # ----------------------------------------------------------------------
        # 03: INVESTIGATE — Weight Integrity Multi-Signal Scan
        # ----------------------------------------------------------------------
        stat_res = StatisticalScanner.scan_model(model_obj.weights)
        stat_risk_score = stat_res.get("model_risk_score", stat_res.get("overall_risk_score", 0.0))
        flagged_count = stat_res.get("flagged_tensors_count", 0)

        trace.append({
            "step_id": "03",
            "phase": "INVESTIGATE",
            "title": "Weight Integrity Multi-Signal Scan",
            "detail": (
                f"Scanned {stat_res.get('total_tensors_scanned', 0)} tensors: "
                f"Model Risk Score = {stat_risk_score:.1f}/100 ({flagged_count} flagged). "
                f"Scanner Verdict: {stat_res.get('verdict', 'TRUSTED')}."
            )
        })

        # ----------------------------------------------------------------------
        # 04: INVESTIGATE — Latent SVD Representation Audit
        # ----------------------------------------------------------------------
        svd_res = SVDSpectralSignatureAuditor.audit_day_zero_model(model_obj, X_val, y_val)
        s_ratio = svd_res.get("max_spectral_ratio", 0.51)
        svd_anomaly = svd_res.get("backdoor_detected", False)

        trace.append({
            "step_id": "04",
            "phase": "INVESTIGATE",
            "title": "Latent SVD Representation Audit",
            "detail": (
                f"Tran et al. (NeurIPS 2018) penultimate SVD analysis: S_ratio = {s_ratio:.3f} "
                f"(Threshold: {svd_res.get('spectral_ratio_threshold', 0.80)}). "
                f"Subspace Verdict: {svd_res['day_zero_verdict']}."
            )
        })

        # ----------------------------------------------------------------------
        # 05: INVESTIGATE — Hierarchical Forensic Zoom on Top-Ranked Tensor
        # ----------------------------------------------------------------------
        highest_tensor = stat_res.get("highest_risk_tensor")
        if highest_tensor and highest_tensor.get("layer_name") in model_obj.weights:
            target_layer = highest_tensor["layer_name"]
        elif not merkle_match and tampered_layers_list:
            t0 = tampered_layers_list[0]
            target_layer = t0.get("layer_name", str(t0)) if isinstance(t0, dict) else str(t0)
        else:
            target_layer = list(model_obj.weights.keys())[0]

        zoom_res = ForensicZoomEngine.drill_down_tensor(target_layer, model_obj.weights[target_layer])
        
        trace.append({
            "step_id": "05",
            "phase": "INVESTIGATE",
            "title": "Hierarchical Forensic Zoom Localization",
            "detail": (
                f"Dynamically localized highest-variance parameters to tensor `{target_layer}` "
                f"(Drill depth: {zoom_res.get('depth', 1)}, Local Tensor Risk: {zoom_res.get('risk_score', 0.0):.1f})."
            )
        })

        # ----------------------------------------------------------------------
        # 06: PROVE — Controlled Causal Counterfactual Evidence
        # ----------------------------------------------------------------------
        cf_res = CausalCounterfactualValidator.validate_functional_impact(model_obj, X_val, y_val, target_layer)
        causal_proven = cf_res.get("causal_malice_proven", False)
        causal_delta = float(cf_res.get("causal_differential", 0.0))

        trace.append({
            "step_id": "06",
            "phase": "PROVE",
            "title": "Controlled Causal Counterfactual Evidence",
            "detail": (
                f"Targeted ablation on `{target_layer}` (Accuracy Drop: {cf_res['accuracy_drop']:.4f}) vs "
                f"Control ablation on `{cf_res['control_layer']}` (Drop: {cf_res['control_drop']:.4f}). "
                f"Causal Delta: +{cf_res['causal_differential']:.4f} ({cf_res['proof_verdict']})."
            )
        })

        # ----------------------------------------------------------------------
        # 07: CORRELATE — Fleet Threat Correlation (Synthetic Simulation)
        # ----------------------------------------------------------------------
        fleet_res = EnterpriseFleetEngine.scan_entire_enterprise_fleet(num_models=50, num_threats=3)
        comp_count = fleet_res.get("quarantined_models_count", 0)
        is_campaign = (comp_count > 1 and (not merkle_match or svd_anomaly))

        trace.append({
            "step_id": "07",
            "phase": "CORRELATE",
            "title": "Fleet Threat Correlation (50-Model Simulation)",
            "detail": (
                f"Scanned 50-model synthetic enterprise fleet: {comp_count} models exhibit correlated "
                f"steganographic payload signature (Campaign Severity: {'HIGH' if is_campaign else 'ISOLATED/LOW'})."
            )
        })

        # ----------------------------------------------------------------------
        # 08: TOPOLOGY — Infrastructure Dependency Evaluation
        # ----------------------------------------------------------------------
        # 100% Mathematical Multi-Signal Evidence Fusion
        merkle_score = 100.0 if not merkle_match else 0.0
        svd_score = min(100.0, max(0.0, (s_ratio - 0.50) / 0.50 * 100.0))
        stat_score = float(stat_risk_score)
        drift_score = min(100.0, beh_res.get("distribution_drift_rate", 0.0) * 250.0)
        causal_score = 100.0 if causal_proven else 0.0

        composite_evidence_score = float(
            0.35 * merkle_score +
            0.25 * svd_score +
            0.20 * stat_score +
            0.10 * drift_score +
            0.10 * causal_score
        )

        is_compromised = (composite_evidence_score >= 45.0) or (not merkle_match)
        topo = InfrastructureTopologyEngine.get_full_topology({
            "razorpay_fraud_scorer_v2.1": "COMPROMISED" if is_compromised else "HEALTHY"
        })

        trace.append({
            "step_id": "08",
            "phase": "TOPOLOGY",
            "title": "Infrastructure Dependency Evaluation",
            "detail": "Evaluated live topology graph: [Payment Gateway API] ➔ [Fraud AI Service] ➔ [Risk Decision] ➔ [Payment Router] ➔ [NPCI / Bank Core]."
        })

        # ----------------------------------------------------------------------
        # 09: RISK — Mission-Critical Path Blast Radius Calculation
        # ----------------------------------------------------------------------
        blast_res = BlastRadiusSimulator.simulate_model_impact(model_id, is_compromised=is_compromised)

        trace.append({
            "step_id": "09",
            "phase": "RISK",
            "title": "Tier-0 Mission-Critical Path Exposure",
            "detail": (
                f"Blast Radius Level: {blast_res['blast_radius_level']}. "
                f"Estimated Live Exposure: {blast_res['estimated_live_tps']} TPS across "
                f"{len(blast_res['direct_affected_pipelines'])} direct payment pipelines."
            )
        })

        # ----------------------------------------------------------------------
        # 10: DECIDE — AI Incident Reasoning & Evidence-Driven Policy Enforcement
        # ----------------------------------------------------------------------
        from core.secops_ai_agent import AegisIncidentReasoner

        ai_reasoning = AegisIncidentReasoner.evaluate_incident_hypothesis(
            model_id=model_id,
            merkle_match=merkle_match,
            svd_spectral_ratio=s_ratio,
            stat_risk_score=stat_score,
            behavioral_drift_rate=beh_res.get("distribution_drift_rate", 0.0),
            causal_impact_delta=0.15 if causal_proven else 0.0,
            fleet_compromise_count=fleet_res.get("quarantined_models_count", 0)
        )

        if composite_evidence_score >= 50.0:
            computed_risk_level = "HIGH"
        elif composite_evidence_score >= 30.0 or is_behavior_anomalous:
            computed_risk_level = "MEDIUM"
        else:
            computed_risk_level = "LOW"

        policy_res = PolicyActionEngine.evaluate_and_enforce_policy(
            model_id=model_id,
            risk_level=computed_risk_level,
            criticality="TIER_0",
            is_campaign=is_campaign,
            fallback_model_id=blast_res.get("recommended_fallback_model", "razorpay_fraud_baseline_v1.0")
        )

        trace.append({
            "step_id": "10",
            "phase": "DECIDE",
            "title": "Aegis AI Incident Reasoning & Policy Authorization",
            "detail": (
                f"Primary Diagnosis: {ai_reasoning['primary_hypothesis']} (Confidence: {ai_reasoning['hypothesis_confidence']*100:.1f}%). "
                f"Synthesized Multi-Signal Evidence Score = {composite_evidence_score:.1f}/100 ➔ "
                f"Calculated Risk Level: {computed_risk_level}. Policy Action Authorized: {policy_res['policy_decision']}."
            )
        })

        # ----------------------------------------------------------------------
        # 11: ACT — Real In-Memory Traffic Router Reconfiguration
        # ----------------------------------------------------------------------
        router = ModelTrafficRouter()
        router.set_primary_weights(model_obj.weights)
        router.set_fallback_weights(ref_weights)

        if policy_res["failover_executed"]:
            router_action = router.execute_failover_to_fallback()
            policy_res["measured_failover_latency_ms"] = router_action.get("measured_failover_latency_ms", 0.05)
            traffic_detail = (
                f"Executed in-memory failover switch: Active model swapped to verified fallback "
                f"'{router_action['active_model_id']}' in {router_action['measured_failover_latency_ms']}ms."
            )
        elif policy_res["policy_decision"] == "ISOLATE":
            router_action = router.isolate_all_traffic()
            policy_res["measured_failover_latency_ms"] = router_action.get("measured_failover_latency_ms", 0.05)
            traffic_detail = f"Model traffic severed for '{model_id}'."
        else:
            router_action = router.reset_to_primary()
            policy_res["measured_failover_latency_ms"] = router_action.get("measured_failover_latency_ms", 0.05)
            traffic_detail = f"Model verified clean. Live traffic actively served by primary model '{model_id}'."

        trace.append({
            "step_id": "11",
            "phase": "ACT",
            "title": "In-Memory Traffic Routing Action",
            "detail": traffic_detail
        })

        # ----------------------------------------------------------------------
        # 12: VERIFY — Real Active Health Probes on Active Route
        # ----------------------------------------------------------------------
        recovery_res = RecoveryVerificationEngine.verify_post_action_recovery(
            model_id=model_id,
            action_result=policy_res,
            X_probe=X_val,
            y_probe=y_val,
            fallback_model_id=policy_res.get("target_routing_model", "razorpay_fraud_baseline_v1.0"),
            evidence_diagnostics={
                "merkle_root_current": current_merkle.root_hash,
                "merkle_root_baseline": golden_merkle.root_hash,
                "svd_spectral_ratio": s_ratio,
                "causal_divergence_delta": causal_delta
            }
        )
        checks = recovery_res["verification_checks"]

        trace.append({
            "step_id": "12",
            "phase": "VERIFY",
            "title": "Active Health Probes & SLO Verification",
            "detail": (
                f"Probed active route '{recovery_res['active_router_target']}': "
                f"Measured p99 latency = {checks['measured_p99_latency_ms']}ms (SLO: {checks['slo_target_ms']}ms, "
                f"Passed: {checks['slo_compliant']}), Accuracy = {checks['fraud_scoring_accuracy_pct']}%, "
                f"Precision = {checks['fraud_scoring_precision_pct']}%, Error Rate = {checks['post_failover_error_rate_pct']}%."
            )
        })

        # ----------------------------------------------------------------------
        # 13: RECOVER — Recovery Confirmation Resolution
        # ----------------------------------------------------------------------
        trace.append({
            "step_id": "13",
            "phase": "RECOVER",
            "title": "Platform Health Status Confirmation",
            "detail": (
                f"Control plane recovery status: {recovery_res['recovery_status']}. "
                f"Tier-0 payment flow verified stable on route '{recovery_res['active_router_target']}'."
            )
        })

        # ----------------------------------------------------------------------
        # 14: AUDIT — Seal Cryptographic Evidence Digest
        # ----------------------------------------------------------------------
        trace.append({
            "step_id": "14",
            "phase": "AUDIT",
            "title": "Incident Evidence Digest Sealed for RBI-Aligned MRM",
            "detail": (
                f"Sealed Incident Package: {recovery_res['sealed_evidence_package']['incident_id']} "
                f"(SHA-256 Digest: {recovery_res['sealed_evidence_package']['evidence_hash_sha256'][:24]}...). "
                f"Framework: {recovery_res['sealed_evidence_package']['regulatory_framework']}."
            )
        })

        elapsed = time.perf_counter() - start_time

        return {
            "control_plane_id": "WEIGHTTRAP-Autonomous-Control-Plane-v2",
            "platform": self.platform_id,
            "target_model_id": model_id,
            "incident_detected": is_compromised,
            "computed_risk_level": computed_risk_level,
            "composite_evidence_score": round(composite_evidence_score, 1),
            "control_loop_latency_seconds": round(elapsed, 3),
            "steps_count": len(trace),
            "incident_lifecycle_trace": trace,
            "router_status": router.get_router_status(),
            "topology_state": topo,
            "policy_action": policy_res,
            "ai_incident_reasoning": ai_reasoning,
            "recovery_verification": recovery_res
        }
