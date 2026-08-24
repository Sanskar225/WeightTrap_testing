"""
WEIGHTTRAP — Multi-Model Correlated Attack Intelligence Engine
Discovers coordinated supply-chain attacks across an enterprise fleet of AI models.
Identifies shared LSB steganographic signatures, common victim layers, and synchronized
backdoors injected across multiple models by a single adversary.
"""

import numpy as np
from typing import Dict, List, Any, Tuple
from core.statistical_scanner import StatisticalScanner


def extract_lsb_bitstream(tensor: np.ndarray, length: int = 256) -> np.ndarray:
    """Extracts first N LSB bits from tensor float representation."""
    uint_view = tensor.astype(np.float32).flatten().view(np.uint32)
    bits = (uint_view[:length] & 1).astype(np.uint8)
    return bits


class MultiModelCorrelator:
    """
    Analyzes fleet-wide model telemetry to detect synchronized supply chain campaigns.
    """

    @classmethod
    def correlate_model_fleet(
        cls,
        model_fleet: Dict[str, Dict[str, np.ndarray]]
    ) -> Dict[str, Any]:
        """
        Takes a dict of {model_name: model_weights} and performs fleet-wide threat correlation.
        """
        model_names = list(model_fleet.keys())
        scans = {}
        flagged_models = []
        
        # 1. Scan each model
        for name, weights in model_fleet.items():
            scan_res = StatisticalScanner.scan_model(weights)
            scans[name] = scan_res
            if scan_res["verdict"] in ["QUARANTINE", "REVIEW"]:
                flagged_models.append(name)

        # 2. Extract signatures from flagged models to discover cross-model correlation
        shared_signatures = []
        clusters = []
        
        for i in range(len(flagged_models)):
            for j in range(i + 1, len(flagged_models)):
                m1_name = flagged_models[i]
                m2_name = flagged_models[j]
                
                m1_weights = model_fleet[m1_name]
                m2_weights = model_fleet[m2_name]
                
                m1_top_layer = scans[m1_name]["highest_risk_tensor"]["layer_name"]
                m2_top_layer = scans[m2_name]["highest_risk_tensor"]["layer_name"]
                
                b1 = extract_lsb_bitstream(m1_weights[m1_top_layer], length=512)
                b2 = extract_lsb_bitstream(m2_weights[m2_top_layer], length=512)
                
                min_len = min(len(b1), len(b2))
                if min_len > 64:
                    bit_match_ratio = float(np.mean(b1[:min_len] == b2[:min_len]))
                    # If bit agreement > 75% (far beyond random 50%)
                    if bit_match_ratio > 0.75:
                        shared_signatures.append({
                            "model_a": m1_name,
                            "model_b": m2_name,
                            "layer_a": m1_top_layer,
                            "layer_b": m2_top_layer,
                            "bit_match_agreement_pct": float(bit_match_ratio * 100.0),
                            "similarity_confidence": "HIGH_CONFIDENCE_COMMON_ADVERSARY"
                        })

        is_coordinated = len(shared_signatures) > 0
        campaign_risk_level = "CRITICAL_SUPPLY_CHAIN_COMPROMISE" if is_coordinated else ("LOCALIZED_ANOMALIES" if flagged_models else "FLEET_CLEAN")

        return {
            "fleet_size": len(model_fleet),
            "flagged_models_count": len(flagged_models),
            "flagged_models_list": flagged_models,
            "is_coordinated_attack_detected": is_coordinated,
            "campaign_risk_level": campaign_risk_level,
            "correlated_threat_pairs": shared_signatures,
            "individual_model_verdicts": {k: v["verdict"] for k, v in scans.items()},
            "summary_threat_assessment": (
                f"Fleet alert: {len(flagged_models)} of {len(model_fleet)} models flagged. "
                + (f"🚨 Coordinated campaign confirmed: {len(shared_signatures)} model pairs share identical steganographic payload signatures." if is_coordinated else "No cross-model correlation detected.")
            )
        }
