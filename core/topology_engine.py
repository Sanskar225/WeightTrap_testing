"""
WEIGHTTRAP — Engine 3: Infrastructure Topology Engine
Maintains the live directed dependency graph of AI services, microservices,
payment routers, criticality tiers, SLOs, and fallback routing tables.

Topology for Razorpay Payment Infrastructure:
[Payment Gateway API] -> [Fraud AI Service] -> [Risk Decision Service] -> [Payment Router] -> [Bank Switch]
"""

from typing import Dict, List, Any


class InfrastructureTopologyEngine:
    """
    Tracks microservice dependencies, ownership, criticality tiers, and dynamic routing topologies.
    """

    TOPOLOGY_GRAPH = {
        "services": [
            {
                "id": "svc_payment_gateway",
                "name": "Payment Gateway API Switch",
                "owner": "Team Payments Core",
                "criticality": "TIER_0",
                "slo_ms": 25.0,
                "traffic_tps": 450,
                "downstream": ["svc_fraud_ai_service"]
            },
            {
                "id": "svc_fraud_ai_service",
                "name": "Fraud AI Microservice",
                "owner": "Team MLSecOps / Risk",
                "criticality": "TIER_0",
                "slo_ms": 50.0,
                "traffic_tps": 450,
                "active_model": "razorpay_fraud_scorer_v2.1",
                "fallback_model": "razorpay_fraud_baseline_v1.0",
                "downstream": ["svc_risk_decision"]
            },
            {
                "id": "svc_risk_decision",
                "name": "Risk Decision & Velocity Service",
                "owner": "Team Risk Engineering",
                "criticality": "TIER_0",
                "slo_ms": 30.0,
                "traffic_tps": 450,
                "downstream": ["svc_payment_router"]
            },
            {
                "id": "svc_payment_router",
                "name": "UPI & Card Payment Router",
                "owner": "Team Core Switch",
                "criticality": "TIER_0",
                "slo_ms": 20.0,
                "traffic_tps": 450,
                "downstream": ["svc_bank_core_settlement"]
            },
            {
                "id": "svc_bank_core_settlement",
                "name": "Bank Core Network (NPCI/UPI)",
                "owner": "Banking Operations",
                "criticality": "TIER_0",
                "slo_ms": 150.0,
                "traffic_tps": 450,
                "downstream": []
            }
        ]
    }

    @classmethod
    def get_full_topology(cls, model_status_map: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Returns the full infrastructure topology graph with live health overlays.
        """
        status_map = model_status_map or {"razorpay_fraud_scorer_v2.1": "HEALTHY"}
        
        nodes = []
        for svc in cls.TOPOLOGY_GRAPH["services"]:
            model_id = svc.get("active_model")
            node_health = "HEALTHY"
            if model_id and status_map.get(model_id) == "QUARANTINED":
                node_health = "COMPROMISED_ISOLATED"
            elif model_id and status_map.get(model_id) == "REROUTED_TO_FALLBACK":
                node_health = "RECOVERED_ON_FALLBACK"

            nodes.append({
                "id": svc["id"],
                "label": svc["name"],
                "owner": svc["owner"],
                "criticality": svc["criticality"],
                "slo_ms": svc["slo_ms"],
                "traffic_tps": svc["traffic_tps"],
                "active_model": svc.get("active_model"),
                "fallback_model": svc.get("fallback_model"),
                "health_state": node_health,
                "downstream_targets": svc["downstream"]
            })

        return {
            "platform_name": "Razorpay AI-Native Financial Platform",
            "tier_0_path_healthy": all(n["health_state"] != "COMPROMISED_ISOLATED" for n in nodes),
            "topology_nodes": nodes,
            "total_nodes_count": len(nodes)
        }
