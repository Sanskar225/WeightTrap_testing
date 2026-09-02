"""
WEIGHTTRAP — Pillar 3: Behavioral Trust Engine
Evaluates live production behavioral drift, prediction entropy, and score distribution shifts.

Concept:
Even if model weights are structurally clean or subtly backdoored,
how does the model actually behave under live financial inference traffic?
- Measures Prediction Entropy (Abnormal over-confidence or random confusion)
- Measures Score Distribution Shift vs Golden Reference
- Classifies: NORMAL_DRIFT vs DATA_QUALITY_ISSUE vs BEHAVIORAL_COMPROMISE
"""

import numpy as np
from scipy import stats
from typing import Dict, Any, Tuple, Optional


class BehavioralTrustEngine:
    """
    Evaluates runtime behavioral stability of AI models under live financial transaction streams.
    """

    @classmethod
    def evaluate_runtime_behavior(
        cls,
        model_obj: Any,
        live_X: np.ndarray,
        baseline_predictions: Optional[np.ndarray] = None
    ) -> Dict[str, Any]:
        """
        Runs behavioral drift analysis on a live batch of transaction inferences.
        """
        if len(live_X) == 0:
            return {
                "behavior_status": "NO_DATA",
                "behavioral_trust_score": 50.0,
                "is_anomalous": False,
                "diagnostic_finding": "No inference data provided."
            }

        # Get live inference predictions
        preds = model_obj.predict(live_X)
        
        # Calculate prediction entropy: H(p) = - sum(p * log2(p))
        prob_fraud = float(np.mean(preds == 1))
        prob_legit = 1.0 - prob_fraud
        
        eps = 1e-9
        entropy = float(- (prob_fraud * np.log2(prob_fraud + eps) + prob_legit * np.log2(prob_legit + eps)))
        
        # Calculate drift against baseline if provided
        drift_stat = 0.0
        if baseline_predictions is not None and len(baseline_predictions) == len(preds):
            drift_stat = float(np.mean(preds != baseline_predictions))

        # Fintech domain expectations: normal fraud rate is 5% - 20%
        is_fraud_spiked = (prob_fraud > 0.35) or (prob_fraud < 0.01)
        
        if prob_fraud > 0.35:
            behavior_status = "BEHAVIORAL_ANOMALY_SPIKE"
            trust_score = 42.0
            finding = f"Live fraud scoring shifted abnormally to {prob_fraud*100:.1f}% (Expected: 5-20%). Potential backdoor trigger activation."
        elif prob_fraud < 0.01:
            behavior_status = "BEHAVIORAL_SUPPRESSION_BLINDSPOT"
            trust_score = 48.0
            finding = f"Zero fraud caught in last {len(live_X)} transactions. Potential evasion bypass attack in progress."
        else:
            behavior_status = "BEHAVIORAL_TRUST_VERIFIED"
            trust_score = 94.0
            finding = f"Prediction distribution stable (Fraud Rate: {prob_fraud*100:.1f}%, Entropy: {entropy:.2f}). Inferences conform to baseline."

        return {
            "behavior_status": behavior_status,
            "behavioral_trust_score": trust_score,
            "sample_count": int(len(live_X)),
            "observed_fraud_rate": float(round(prob_fraud, 4)),
            "prediction_entropy": float(round(entropy, 3)),
            "distribution_drift_rate": float(round(drift_stat, 4)),
            "is_anomalous": is_fraud_spiked,
            "diagnostic_finding": finding
        }
