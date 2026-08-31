"""
WEIGHTTRAP — Enterprise Fleet CI/CD Gateway & Batch Scanner
Simulates enterprise-scale parallel scanning of 50+ deployed models across Razorpay's AI infrastructure:
- Fraud Detection Fleet (Transaction, Card, UPI, Netbanking)
- Credit Underwriting Fleet (Credit Limit, Merchant Risk, Loan Default)
- Payment Routing Fleet (Success Rate Optimizer, Latency Router, Gateway Arbiter)
- Chargeback & Dispute Fleet (Pre-Dispute Predictor, Document Verifier)
Integrates with CI/CD Pipelines (GitHub Actions / MLflow / Triton Model Server) in parallel!
"""

import os
import sys
import time
import concurrent.futures
import numpy as np
from typing import Dict, List, Any

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from models.fraud_model import FraudMLP
from attack.embed_payload import ModelWeightAttacker
from core.statistical_scanner import StatisticalScanner
from core.merkle_fingerprint import ModelMerkleFingerprint
from core.aibom import AIBOMGenerator
from core.multi_model_correlation import MultiModelCorrelator


# Enterprise Fleet Taxonomy (50 Real-World Fintech ML Models across 5 Core Domains)
FLEET_TAXONOMY = [
    # Domain 1: Payment Fraud Defense (10 models)
    {"id": "fraud-upi-realtime-v3", "domain": "Fraud Defense", "framework": "PyTorch / TorchScript", "tier": "Tier-0 Mission Critical"},
    {"id": "fraud-card-velocity-v2.4", "domain": "Fraud Defense", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "fraud-international-card-v1.8", "domain": "Fraud Defense", "framework": "Safetensors", "tier": "Tier-1 Critical"},
    {"id": "fraud-netbanking-anomaly-v2", "domain": "Fraud Defense", "framework": "ONNX", "tier": "Tier-1 Critical"},
    {"id": "fraud-device-fingerprint-v4", "domain": "Fraud Defense", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "fraud-ip-cluster-sentinel-v1", "domain": "Fraud Defense", "framework": "PyTorch", "tier": "Tier-2 Standard"},
    {"id": "fraud-bot-checkout-detector-v3", "domain": "Fraud Defense", "framework": "TorchScript", "tier": "Tier-1 Critical"},
    {"id": "fraud-credential-stuffing-v2", "domain": "Fraud Defense", "framework": "PyTorch", "tier": "Tier-1 Critical"},
    {"id": "fraud-mcc-high-risk-v1.2", "domain": "Fraud Defense", "framework": "Safetensors", "tier": "Tier-2 Standard"},
    {"id": "fraud-qr-tampering-sentinel-v1", "domain": "Fraud Defense", "framework": "ONNX", "tier": "Tier-1 Critical"},

    # Domain 2: Merchant Credit & Underwriting (10 models)
    {"id": "credit-instant-settlement-risk-v3", "domain": "Credit Underwriting", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "credit-merchant-loan-default-v2", "domain": "Credit Underwriting", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "credit-working-capital-limit-v4", "domain": "Credit Underwriting", "framework": "Safetensors", "tier": "Tier-1 Critical"},
    {"id": "credit-gst-invoice-verifier-v1", "domain": "Credit Underwriting", "framework": "TorchScript", "tier": "Tier-1 Critical"},
    {"id": "credit-bank-statement-parser-v2", "domain": "Credit Underwriting", "framework": "ONNX", "tier": "Tier-2 Standard"},
    {"id": "credit-b2b-vendor-risk-v1.5", "domain": "Credit Underwriting", "framework": "PyTorch", "tier": "Tier-2 Standard"},
    {"id": "credit-early-delinquency-v2", "domain": "Credit Underwriting", "framework": "PyTorch", "tier": "Tier-1 Critical"},
    {"id": "credit-kyc-deepfake-authenticator-v3", "domain": "Credit Underwriting", "framework": "Safetensors", "tier": "Tier-0 Mission Critical"},
    {"id": "credit-merchant-churn-predictor-v2", "domain": "Credit Underwriting", "framework": "PyTorch", "tier": "Tier-2 Standard"},
    {"id": "credit-overdraft-protection-v1", "domain": "Credit Underwriting", "framework": "TorchScript", "tier": "Tier-1 Critical"},

    # Domain 3: Smart Payment Routing (10 models)
    {"id": "route-dynamic-gateway-optimizer-v5", "domain": "Payment Routing", "framework": "PyTorch / C++", "tier": "Tier-0 Mission Critical"},
    {"id": "route-bank-downtime-predictor-v3", "domain": "Payment Routing", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "route-upi-psp-latency-router-v4", "domain": "Payment Routing", "framework": "TorchScript", "tier": "Tier-0 Mission Critical"},
    {"id": "route-otp-delivery-fastlane-v2", "domain": "Payment Routing", "framework": "ONNX", "tier": "Tier-1 Critical"},
    {"id": "route-card-network-loadbalancer-v1", "domain": "Payment Routing", "framework": "PyTorch", "tier": "Tier-1 Critical"},
    {"id": "route-cross-border-fx-arbitrage-v2", "domain": "Payment Routing", "framework": "Safetensors", "tier": "Tier-1 Critical"},
    {"id": "route-zero-redirect-flow-v3", "domain": "Payment Routing", "framework": "PyTorch", "tier": "Tier-1 Critical"},
    {"id": "route-cost-optimization-engine-v2", "domain": "Payment Routing", "framework": "PyTorch", "tier": "Tier-2 Standard"},
    {"id": "route-fallback-retry-orchestrator-v4", "domain": "Payment Routing", "framework": "TorchScript", "tier": "Tier-0 Mission Critical"},
    {"id": "route-sub-second-switch-v1", "domain": "Payment Routing", "framework": "ONNX", "tier": "Tier-1 Critical"},

    # Domain 4: Chargebacks & Dispute Sentinel (10 models)
    {"id": "dispute-friendly-fraud-predictor-v2", "domain": "Dispute Management", "framework": "PyTorch", "tier": "Tier-1 Critical"},
    {"id": "dispute-auto-evidence-generator-v3", "domain": "Dispute Management", "framework": "Safetensors", "tier": "Tier-1 Critical"},
    {"id": "dispute-chargeback-winrate-scorer-v1", "domain": "Dispute Management", "framework": "PyTorch", "tier": "Tier-2 Standard"},
    {"id": "dispute-representment-prioritizer-v2", "domain": "Dispute Management", "framework": "TorchScript", "tier": "Tier-2 Standard"},
    {"id": "dispute-merchant-reserve-calculator-v3", "domain": "Dispute Management", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "dispute-friendly-chargeback-pattern-v1", "domain": "Dispute Management", "framework": "ONNX", "tier": "Tier-2 Standard"},
    {"id": "dispute-first-party-misuse-v2", "domain": "Dispute Management", "framework": "PyTorch", "tier": "Tier-1 Critical"},
    {"id": "dispute-visa-vrol-arbitration-v1", "domain": "Dispute Management", "framework": "Safetensors", "tier": "Tier-1 Critical"},
    {"id": "dispute-refund-abuse-ring-sentinel-v3", "domain": "Dispute Management", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "dispute-settlement-clawback-v1.4", "domain": "Dispute Management", "framework": "TorchScript", "tier": "Tier-1 Critical"},

    # Domain 5: Merchant Growth & Agentic Commerce (10 models)
    {"id": "growth-checkout-dropoff-recovery-v2", "domain": "Agentic Commerce", "framework": "PyTorch", "tier": "Tier-1 Critical"},
    {"id": "growth-ai-buyer-agent-validator-v1", "domain": "Agentic Commerce", "framework": "Safetensors", "tier": "Tier-0 Mission Critical"},
    {"id": "growth-smart-upsell-recommender-v3", "domain": "Agentic Commerce", "framework": "PyTorch", "tier": "Tier-2 Standard"},
    {"id": "growth-dynamic-discount-optimizer-v1", "domain": "Agentic Commerce", "framework": "TorchScript", "tier": "Tier-2 Standard"},
    {"id": "growth-acp-protocol-auth-verifier-v2", "domain": "Agentic Commerce", "framework": "PyTorch", "tier": "Tier-0 Mission Critical"},
    {"id": "growth-catalog-agent-indexer-v1", "domain": "Agentic Commerce", "framework": "ONNX", "tier": "Tier-1 Critical"},
    {"id": "growth-merchant-ltv-forecaster-v4", "domain": "Agentic Commerce", "framework": "PyTorch", "tier": "Tier-2 Standard"},
    {"id": "growth-autonomous-checkout-gate-v2", "domain": "Agentic Commerce", "framework": "Safetensors", "tier": "Tier-0 Mission Critical"},
    {"id": "growth-cart-abandonment-predictor-v3", "domain": "Agentic Commerce", "framework": "TorchScript", "tier": "Tier-1 Critical"},
    {"id": "growth-conversion-rate-booster-v1", "domain": "Agentic Commerce", "framework": "PyTorch", "tier": "Tier-2 Standard"}
]


class EnterpriseFleetEngine:
    """
    Simulates high-throughput, enterprise CI/CD Model Registry scanning across a fleet of 50 models.
    """

    @classmethod
    def scan_single_fleet_model(cls, model_meta: Dict[str, Any], base_weights: Dict[str, np.ndarray], is_injected_threat: bool = False, shared_payload: str = None) -> Dict[str, Any]:
        """Scans an individual model artifact from the fleet in milliseconds."""
        t0 = time.time()
        
        # Prepare model weights (clean or injected supply chain threat)
        if is_injected_threat:
            payload = shared_payload or f"EXPLOIT_SUPPLY_CHAIN_INJECTION_{model_meta['id']}"
            weights, _ = ModelWeightAttacker.inject_x_lsb_payload(
                base_weights,
                target_layer="block2.feature_extractor.weight",
                payload_text=payload,
                embedding_rate=0.20
            )
        else:
            weights = base_weights
            
        # Run Merkle fingerprint & Statistical scan
        merkle = ModelMerkleFingerprint(weights)
        scan = StatisticalScanner.scan_model(weights)
        elapsed_ms = (time.time() - t0) * 1000.0

        return {
            "model_id": model_meta["id"],
            "domain": model_meta["domain"],
            "tier": model_meta["tier"],
            "framework": model_meta["framework"],
            "merkle_root": merkle.root_hash,
            "verdict": scan["verdict"],
            "risk_score": scan["model_risk_score"],
            "scan_latency_ms": float(round(elapsed_ms, 2)),
            "flagged_tensors": scan["flagged_tensors_count"],
            "is_threat_confirmed": (scan["verdict"] == "QUARANTINE"),
            "highest_risk_tensor": scan["highest_risk_tensor"]["layer_name"] if scan["highest_risk_tensor"] else "NONE",
            "weights_ref": weights
        }

    @classmethod
    def scan_entire_enterprise_fleet(cls, num_models: int = 50, num_threats: int = 3, max_workers: int = 8) -> Dict[str, Any]:
        """
        Scans all 50 models in parallel across multi-threaded CI/CD worker pool.
        """
        t_start = time.time()
        base_model = FraudMLP(seed=42)
        
        fleet_items = FLEET_TAXONOMY[:num_models]
        # Designate specific models to simulate a coordinated supply-chain campaign
        # e.g., an attacker hit the UPI routing model, Card Velocity model, and Credit risk model
        threat_indices = {1, 10, 20} if num_threats >= 3 else set(range(num_threats))
        shared_campaign_payload = "CAMPAIGN_APT_FINTECH_SUPPLY_CHAIN_BYPASS_2026_EXPLOIT_CLUSTER"

        scan_tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            for idx, meta in enumerate(fleet_items):
                is_threat = (idx in threat_indices)
                f = executor.submit(
                    cls.scan_single_fleet_model,
                    meta,
                    base_model.weights,
                    is_threat,
                    shared_campaign_payload if is_threat else None
                )
                scan_tasks.append(f)

            results = [f.result() for f in scan_tasks]

        total_elapsed = time.time() - t_start
        
        # Cross-model correlation on flagged models
        flagged_weights_dict = {r["model_id"]: r["weights_ref"] for r in results if r["verdict"] == "QUARANTINE"}
        fleet_correlation = MultiModelCorrelator.correlate_model_fleet(flagged_weights_dict) if flagged_weights_dict else {
            "is_coordinated_attack_detected": False,
            "campaign_risk_level": "FLEET_CLEAN",
            "correlated_threat_pairs": []
        }

        # Remove raw weights from JSON serialization
        for r in results:
            del r["weights_ref"]

        total_scanned = len(results)
        quarantined_count = sum(1 for r in results if r["verdict"] == "QUARANTINE")
        trusted_count = sum(1 for r in results if r["verdict"] == "TRUSTED")
        review_count = sum(1 for r in results if r["verdict"] == "REVIEW")
        
        avg_latency = float(np.mean([r["scan_latency_ms"] for r in results]))

        return {
            "fleet_size": total_scanned,
            "total_scan_time_seconds": float(round(total_elapsed, 2)),
            "average_latency_per_model_ms": float(round(avg_latency, 2)),
            "throughput_models_per_second": float(round(total_scanned / max(total_elapsed, 0.001), 1)),
            "quarantined_models_count": quarantined_count,
            "trusted_models_count": trusted_count,
            "review_models_count": review_count,
            "fleet_health_score_pct": float(round(((trusted_count + review_count * 0.5) / total_scanned) * 100.0, 1)),
            "coordinated_campaign_detected": fleet_correlation.get("is_coordinated_attack_detected", False),
            "campaign_threat_level": fleet_correlation.get("campaign_risk_level", "FLEET_CLEAN"),
            "correlated_model_pairs_count": len(fleet_correlation.get("correlated_threat_pairs", [])),
            "fleet_results": results
        }


if __name__ == "__main__":
    print("=" * 70)
    print("WEIGHTTRAP ENTERPRISE FLEET GATEWAY -- 50-MODEL PARALLEL SCAN")
    print("=" * 70)
    res = EnterpriseFleetEngine.scan_entire_enterprise_fleet(num_models=50, num_threats=3)
    print(f" [+] Scanned {res['fleet_size']} Production Models in {res['total_scan_time_seconds']}s")
    print(f"     • Average Latency: {res['average_latency_per_model_ms']} ms/model")
    print(f"     • Throughput     : {res['throughput_models_per_second']} models/second")
    print(f"     • Trusted        : {res['trusted_models_count']}")
    print(f"     • Quarantined    : {res['quarantined_models_count']}")
    print(f"     • Coordinated APT: {'🚨 DETECTED' if res['coordinated_campaign_detected'] else 'CLEAN'}")
