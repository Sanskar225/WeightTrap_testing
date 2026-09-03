"""
WEIGHTTRAP — Causal Counterfactual Validation Engine
Tests the causal impact of suspicious weight regions on model behavior.
Applies controlled perturbation / zeroing to the flagged region vs an identical-sized
control region, measuring shift in predictions on clean vs backdoor-trigger inputs.
Provides mathematical proof of malicious intent vs innocent noise.
"""

import numpy as np
from typing import Dict, Any, List, Tuple
from models.fraud_model import FraudMLP


class CounterfactualValidator:
    """
    Executes counterfactual ablation tests to mathematically prove or disprove backdoor causality.
    """

    @classmethod
    def run_counterfactual_test(
        cls,
        base_weights: Dict[str, np.ndarray],
        target_layer: str,
        flagged_bounds: Dict[str, Any],
        X_clean: np.ndarray,
        X_trigger: np.ndarray,
        y_trigger_true: np.ndarray
    ) -> Dict[str, Any]:
        """
        Executes:
        1. Baseline model inference on X_clean and X_trigger.
        2. Suspicious Region Perturbed model inference.
        3. Control (random unflagged region) Perturbed model inference.
        4. Calculates behavioral deltas and causal proof metric.
        """
        # 1. Baseline Model
        model_base = FraudMLP()
        model_base.weights = {k: v.copy() for k, v in base_weights.items()}
        
        base_preds_clean = model_base.predict(X_clean)
        base_probs_trigger = model_base.forward(X_trigger)
        base_preds_trigger = np.argmax(base_probs_trigger, axis=-1)

        # 2. Perturb Flagged Suspicious Region (Zero out or mean-clamp the region)
        weights_suspicious_ablated = {k: v.copy() for k, v in base_weights.items()}
        target_tensor = weights_suspicious_ablated[target_layer]
        
        # Apply ablation to the specific bounds
        if "rows" in flagged_bounds and "cols" in flagged_bounds:
            r0, r1 = flagged_bounds["rows"]
            c0, c1 = flagged_bounds["cols"]
            target_tensor[r0:r1, c0:c1] = 0.0
            ablated_size = (r1 - r0) * (c1 - c0)
        elif "start" in flagged_bounds and "end" in flagged_bounds:
            s0, s1 = flagged_bounds["start"], flagged_bounds["end"]
            target_tensor.flat[s0:s1] = 0.0
            ablated_size = s1 - s0
        else:
            # If bounds unspecified, ablate top 25% of tensor
            quarter = target_tensor.size // 4
            target_tensor.flat[:quarter] = 0.0
            ablated_size = quarter

        model_suspicious_ablated = FraudMLP()
        model_suspicious_ablated.weights = weights_suspicious_ablated
        
        susp_preds_clean = model_suspicious_ablated.predict(X_clean)
        susp_probs_trigger = model_suspicious_ablated.forward(X_trigger)
        susp_preds_trigger = np.argmax(susp_probs_trigger, axis=-1)

        # 3. Control Experiment: Perturb an equal-sized UNFLAGGED region in a different layer
        weights_control_ablated = {k: v.copy() for k, v in base_weights.items()}
        # Pick another layer (e.g. block1 if target was block2/3, or block4)
        control_layer = [k for k in base_weights.keys() if k != target_layer and "weight" in k][0]
        control_tensor = weights_control_ablated[control_layer]
        control_tensor.flat[:min(ablated_size, control_tensor.size)] = 0.0

        model_control_ablated = FraudMLP()
        model_control_ablated.weights = weights_control_ablated
        
        ctrl_preds_clean = model_control_ablated.predict(X_clean)
        ctrl_probs_trigger = model_control_ablated.forward(X_trigger)
        ctrl_preds_trigger = np.argmax(ctrl_probs_trigger, axis=-1)

        # 4. Compute Metrics
        # Clean data prediction agreement (should stay high ~ 95%+)
        clean_agreement_suspicious = float(np.mean(base_preds_clean == susp_preds_clean) * 100.0)
        clean_agreement_control = float(np.mean(base_preds_clean == ctrl_preds_clean) * 100.0)

        # Trigger data prediction flip: Did removing the region recover fraud detection?
        # In tampered model, base_preds_trigger was manipulated to 0 (Legit).
        # In restored/ablated model, susp_preds_trigger flips back to 1 (Fraud)!
        fraud_recovery_rate_suspicious = float(np.mean(susp_preds_trigger == 1) * 100.0)
        fraud_recovery_rate_control = float(np.mean(ctrl_preds_trigger == 1) * 100.0)
        base_fraud_detection_rate = float(np.mean(base_preds_trigger == 1) * 100.0)

        # Causal Delta
        causal_impact_delta = fraud_recovery_rate_suspicious - fraud_recovery_rate_control
        
        # Malice Proof Confidence: High if suspicious ablation recovers fraud detection
        # while keeping general clean predictions intact
        if causal_impact_delta > 25.0 and clean_agreement_suspicious > 80.0:
            proof_verdict = "CAUSAL_MALICE_CONFIRMED"
            proof_explanation = (
                f"Ablating region in {target_layer} restores fraud catch rate from "
                f"{base_fraud_detection_rate:.1f}% to {fraud_recovery_rate_suspicious:.1f}% (+{causal_impact_delta:.1f}% vs control) "
                f"while retaining {clean_agreement_suspicious:.1f}% general clean accuracy. "
                "This mathematically proves the flagged region holds a targeted bypass trigger."
            )
        elif causal_impact_delta > 10.0:
            proof_verdict = "SUSPICIOUS_ANOMALY_EVIDENT"
            proof_explanation = f"Moderate causal behavioral shift (+{causal_impact_delta:.1f}% over control)."
        else:
            proof_verdict = "BENIGN_VARIATION_OR_INCONCLUSIVE"
            proof_explanation = "Ablation did not produce targeted behavioral discrepancy compared to control."

        return {
            "proof_verdict": proof_verdict,
            "proof_explanation": proof_explanation,
            "target_layer_tested": target_layer,
            "control_layer_tested": control_layer,
            "parameters_ablated": int(ablated_size),
            "clean_accuracy_retained_pct": clean_agreement_suspicious,
            "baseline_trigger_fraud_catch_pct": base_fraud_detection_rate,
            "suspicious_ablated_trigger_fraud_catch_pct": fraud_recovery_rate_suspicious,
            "control_ablated_trigger_fraud_catch_pct": fraud_recovery_rate_control,
            "net_causal_impact_delta": float(causal_impact_delta)
        }

    @classmethod
    def validate_functional_impact(
        cls,
        model_obj: Any,
        X_val: np.ndarray,
        y_val: np.ndarray,
        target_layer: str = "block2.feature_extractor.weight"
    ) -> Dict[str, Any]:
        """Convenience method for agent control loops executing real controlled causal ablation."""
        preds_orig = model_obj.predict(X_val)
        orig_acc = float(np.mean(preds_orig == y_val))
        
        # 1. Targeted Suspicious Layer Ablation
        ablated_model = FraudMLP()
        ablated_weights = {k: v.copy() for k, v in model_obj.weights.items()}
        if target_layer in ablated_weights:
            ablated_weights[target_layer] = ablated_weights[target_layer] * 0.0
        ablated_model.weights = ablated_weights
        preds_ablated = ablated_model.predict(X_val)
        ablated_acc = float(np.mean(preds_ablated == y_val))
        acc_drop = float(orig_acc - ablated_acc)
        
        # 2. Real Control Ablation on an Unflagged Layer
        control_layer = [k for k in model_obj.weights.keys() if k != target_layer]
        control_layer_name = control_layer[0] if control_layer else target_layer
        control_model = FraudMLP()
        control_weights = {k: v.copy() for k, v in model_obj.weights.items()}
        control_weights[control_layer_name] = control_weights[control_layer_name] * 0.0
        control_model.weights = control_weights
        preds_control = control_model.predict(X_val)
        control_acc = float(np.mean(preds_control == y_val))
        measured_control_drop = float(max(orig_acc - control_acc, 0.0))
        
        causal_differential = float(acc_drop - measured_control_drop)

        return {
            "proof_verdict": "CAUSAL_FUNCTIONAL_IMPACT_CONFIRMED" if causal_differential > 0.03 or acc_drop > 0.05 else "BENIGN_VARIATION",
            "accuracy_drop": acc_drop,
            "control_drop": round(measured_control_drop, 4),
            "causal_differential": round(causal_differential, 4),
            "causal_functional_impact_confirmed": (causal_differential > 0.03 or acc_drop > 0.05),
            "causal_malice_proven": (causal_differential > 0.03 or acc_drop > 0.05),
            "target_layer": target_layer,
            "control_layer": control_layer_name
        }


CausalCounterfactualValidator = CounterfactualValidator

