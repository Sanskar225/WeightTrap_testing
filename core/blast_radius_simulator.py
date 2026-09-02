"""
WEIGHTTRAP — Blast Radius & Dependency Impact Simulator (The "WHAT IF?" Engine)
Simulates downstream financial service exposure when an AI model is compromised or quarantined.

Graph Topology for Razorpay Fintech Infrastructure:
Compromised Model -> Microservice -> Authorization Pipeline -> Financial Flows
"""

from typing import Dict, List, Any


class BlastRadiusSimulator:
    """
    Computes enterprise blast radius, service dependency exposure, and fallback containment strategy.
    """

    SERVICE_GRAPH = {
        "razorpay_fraud_scorer_v2.1": {
            "domain": "UPI & Card Fraud Prevention",
            "criticality": "TIER_0_MISSION_CRITICAL",
            "throughput_tps": 450,
            "direct_dependencies": [
                "Payment Authorization Engine",
                "UPI Fast-Track Velocity Router",
                "Real-Time Merchant Risk Scorer"
            ],
            "indirect_dependencies": [
                "Chargeback Reserve Allocation",
                "Instant Merchant Settlement Trigger"
            ],
            "isolated_unaffected_services": [
                "Daily Bank Settlement Ledger",
                "Historical Compliance Reporting",
                "OAuth User Authentication",
                "Dispute Arbitration Portal"
            ],
            "fallback_model_id": "razorpay_fraud_baseline_v1.0",
            "fallback_latency_ms": 1.4
        },
        "razorpay_credit_risk_v1.0": {
            "domain": "Instant Merchant Lending",
            "criticality": "TIER_1_FINANCIAL_EXPOSURE",
            "throughput_tps": 120,
            "direct_dependencies": [
                "Working Capital Loan Approver",
                "Credit Limit Auto-Scaler"
            ],
            "indirect_dependencies": [
                "Default Risk Provisioning",
                "NBFC Syndicate Router"
            ],
            "isolated_unaffected_services": [
                "UPI Payment Gateway",
                "Card Processing Switch",
                "Merchant Analytics Dashboard"
            ],
            "fallback_model_id": "rule_based_underwriting_v3.2",
            "fallback_latency_ms": 0.8
        }
    }

    @classmethod
    def simulate_model_impact(cls, model_id: str, is_compromised: bool = True) -> Dict[str, Any]:
        """
        Simulates financial blast radius and downstream exposure if target model is compromised.
        """
        config = cls.SERVICE_GRAPH.get(
            model_id,
            cls.SERVICE_GRAPH["razorpay_fraud_scorer_v2.1"]
        )

        if is_compromised:
            blast_radius_level = "HIGH_SEVERITY"
            estimated_exposure_tps = config["throughput_tps"]
            exposure_summary = f"High Risk: {len(config['direct_dependencies'])} core payment authorization pipelines actively exposed to compromised scoring."
            containment_action = f"Immediate Policy Gate: Isolate container traffic and auto-failover to `{config['fallback_model_id']}` (Failover latency: {config['fallback_latency_ms']}ms)."
        else:
            blast_radius_level = "NEGLIGIBLE"
            estimated_exposure_tps = 0
            exposure_summary = "Model verified trusted. Downstream payment pipelines operating within nominal parameters."
            containment_action = "Zero containment required. Continuous Out-of-Band Tripwire surveillance active."

        return {
            "model_id": model_id,
            "domain": config["domain"],
            "criticality_tier": config["criticality"],
            "blast_radius_level": blast_radius_level,
            "estimated_live_tps": estimated_exposure_tps,
            "direct_affected_pipelines": config["direct_dependencies"] if is_compromised else [],
            "indirect_affected_pipelines": config["indirect_dependencies"] if is_compromised else [],
            "isolated_unaffected_services": config["isolated_unaffected_services"],
            "recommended_fallback_model": config["fallback_model_id"],
            "fallback_switch_latency_ms": config["fallback_latency_ms"],
            "exposure_summary": exposure_summary,
            "containment_strategy": containment_action
        }
