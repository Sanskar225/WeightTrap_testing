"""
WEIGHTTRAP — Batch Evaluation & Scientific Metrics Benchmark
Evaluates WEIGHTTRAP across a held-out benchmark of 40 model variants:
- 20 Legitimate Clean Models (Base, Fine-tuned, Quantized, Pruned)
- 20 Tampered Models (LSB steganography @ 5%, 10%, 15%, 20%, 30% + Functional Backdoors)
Outputs exact Precision, Recall, F1 Score, False Positive Rate, and Localization Accuracy.
"""

import os
import sys
import json
import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Any

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

from data.generate_data import generate_transactions
from models.fraud_model import FraudMLP, preprocess_data
from attack.embed_payload import ModelWeightAttacker
from core.statistical_scanner import StatisticalScanner
from core.forensic_zoom import ForensicZoomEngine
from core.counterfactual import CounterfactualValidator
from core.aibom import AIBOMGenerator
from core.merkle_fingerprint import ModelMerkleFingerprint
from core.tripwire import WeightTripwireSentinel
from core.multi_model_correlation import MultiModelCorrelator
from core.rbi_report_generator import RBIReportGenerator


def run_full_benchmark():
    print("=" * 70)
    print("WEIGHTTRAP — RAZORPAY BUILDATHON BATCH EVALUATION BENCHMARK")
    print("=" * 70)
    
    # 1. Generate Data & Train Clean Base Model
    print("\n[+] Phase 1: Synthesizing transaction dataset and training baseline FraudMLP...")
    df = generate_transactions(n_samples=6000, fraud_rate=0.06)
    X, y, norm_meta = preprocess_data(df)
    
    # Split train / test
    split = int(len(X) * 0.75)
    X_train, y_train = X[:split], y[:split]
    X_test, y_test = X[split:], y[split:]
    
    base_model = FraudMLP(seed=42)
    base_model.fit(X_train, y_train, epochs=30, lr=0.02)
    
    preds_base = base_model.predict(X_test)
    base_acc = np.mean(preds_base == y_test) * 100.0
    print(f"    ✓ Baseline Fraud Model trained. Validation Accuracy: {base_acc:.2f}%")
    
    # Save baseline weights
    os.makedirs("models", exist_ok=True)
    base_model.save("models/clean_baseline_fraud_model.npz")

    # 2. Build 40-Model Benchmark Suite
    print("\n[+] Phase 2: Generating 40-Model Held-out Evaluation Suite...")
    models_suite: List[Tuple[str, Dict[str, np.ndarray], bool, str]] = []
    # (name, weights, is_tampered_ground_truth, target_layer_if_any)
    
    # 20 CLEAN MODELS:
    # 5 base seeds
    for i in range(5):
        m = FraudMLP(seed=100 + i)
        m.fit(X_train, y_train, epochs=25, lr=0.02)
        models_suite.append((f"clean_baseline_seed_{i+1}", m.weights, False, "NONE"))
        
    # 5 fine-tuned variants
    for i in range(5):
        ft = ModelWeightAttacker.create_fine_tuned_variant(base_model.weights, noise_scale=0.01 * (i + 1))
        models_suite.append((f"clean_finetuned_v{i+1}", ft, False, "NONE"))
        
    # 5 quantized variants
    for i in range(5):
        q = ModelWeightAttacker.create_quantized_variant(base_model.weights)
        models_suite.append((f"clean_quantized_int8_v{i+1}", q, False, "NONE"))
        
    # 5 pruned variants (10% to 30% sparsity)
    for i in range(5):
        pr = ModelWeightAttacker.create_pruned_variant(base_model.weights, sparsity=0.05 * (i + 1))
        models_suite.append((f"clean_pruned_sparse_{int((i+1)*5)}pct", pr, False, "NONE"))

    # 20 TAMPERED MODELS:
    target_layers = [
        "block1.dense_in.weight",
        "block2.feature_extractor.weight",
        "block3.risk_aggregator.weight",
        "block4.classifier_head.weight"
    ]
    rates = [0.05, 0.10, 0.15, 0.20, 0.30]
    
    tampered_idx = 1
    # 15 X-LSB varying rate models across layers
    for layer in target_layers[:3]:
        for r in rates:
            tampered_w, _ = ModelWeightAttacker.inject_x_lsb_payload(
                base_model.weights,
                target_layer=layer,
                payload_text=f"PAYLOAD_ATTACK_CAMPAIGN_NODE_{tampered_idx}",
                embedding_rate=r
            )
            models_suite.append((f"tampered_xlsb_{layer.split('.')[1]}_{int(r*100)}pct", tampered_w, True, layer))
            tampered_idx += 1
            
    # 5 Functional Backdoor models
    for i in range(5):
        layer = target_layers[i % len(target_layers)]
        tampered_w, _ = ModelWeightAttacker.create_functional_backdoor(base_model.weights, target_layer=layer)
        models_suite.append((f"tampered_functional_backdoor_v{i+1}", tampered_w, True, layer))

    print(f"    ✓ Generated {len(models_suite)} models (20 Clean Variants + 20 Tampered Variants).")

    # 3. Evaluate WEIGHTTRAP on all 40 models
    print("\n[+] Phase 3: Executing WEIGHTTRAP Multi-Signal Autopsy on entire test set...")
    
    tp = 0  # Tampered detected as QUARANTINE/REVIEW
    fp = 0  # Clean flagged as QUARANTINE/REVIEW
    tn = 0  # Clean identified as TRUSTED
    fn = 0  # Tampered missed as TRUSTED
    correct_layer_localization = 0
    total_tampered = 0

    results_table = []

    for name, weights, is_tampered_true, expected_layer in models_suite:
        # Run statistical scan & forensic zoom
        scan_res = StatisticalScanner.scan_model(weights)
        verdict = scan_res["verdict"]
        flagged = (verdict in ["QUARANTINE", "REVIEW"])
        
        # Check localization if tampered
        loc_correct = False
        if is_tampered_true:
            total_tampered += 1
            highest_risk_tensor = scan_res["highest_risk_tensor"]
            if highest_risk_tensor and expected_layer in highest_risk_tensor["layer_name"]:
                correct_layer_localization += 1
                loc_correct = True

        if is_tampered_true and flagged:
            tp += 1
            status_symbol = "✅ TP (Detected)"
        elif not is_tampered_true and not flagged:
            tn += 1
            status_symbol = "✅ TN (Clean Passed)"
        elif not is_tampered_true and flagged:
            fp += 1
            status_symbol = "❌ FP (False Alarm)"
        else:
            fn += 1
            status_symbol = "❌ FN (Missed Attack)"

        results_table.append({
            "model_name": name,
            "ground_truth": "TAMPERED" if is_tampered_true else "CLEAN",
            "verdict": verdict,
            "risk_score": scan_res["model_risk_score"],
            "evasion_pattern": scan_res["evasion_pattern_detected"],
            "localized_correctly": loc_correct if is_tampered_true else "N/A",
            "status": status_symbol
        })

    # 4. Compute Final Metrics
    precision = (tp / (tp + fp)) * 100.0 if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) * 100.0 if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) * 100.0 if (fp + tn) > 0 else 0.0
    fnr = (fn / (fn + tp)) * 100.0 if (fn + tp) > 0 else 0.0
    loc_acc = (correct_layer_localization / total_tampered) * 100.0 if total_tampered > 0 else 0.0

    print("\n" + "=" * 70)
    print("WEIGHTTRAP SCIENTIFIC BENCHMARK METRICS (HELD-OUT TEST SET)")
    print("=" * 70)
    print(f" Total Models Evaluated     : {len(models_suite)} (20 Clean, 20 Tampered)")
    print(f" True Positives (TP)        : {tp}")
    print(f" True Negatives (TN)        : {tn}")
    print(f" False Positives (FP)       : {fp}")
    print(f" False Negatives (FN)       : {fn}")
    print("-" * 70)
    print(f" Precision                  : {precision:.2f}%")
    print(f" Recall (True Positive Rate): {recall:.2f}%")
    print(f" F1 Score                   : {f1:.2f}%")
    print(f" False Positive Rate (FPR)  : {fpr:.2f}%")
    print(f" False Negative Rate (FNR)  : {fnr:.2f}%")
    print(f" Layer Localization Accuracy: {loc_acc:.2f}%")
    print("=" * 70)

    # 5. Generate and Save RBI Evidence Report on a Sample Tampered Model
    print("\n[+] Phase 4: Generating Sample RBI MRM Compliance Report for demo...")
    sample_tampered_weights, _ = ModelWeightAttacker.inject_x_lsb_payload(
        base_model.weights,
        target_layer="block2.feature_extractor.weight",
        payload_text="EXPLOIT_RAZORPAY_GATEWAY_TRIGGER_MERCHANT_CLUSTER_09"
    )
    
    aibom = AIBOMGenerator.generate_aibom("razorpay-fraud-classifier-v2.1", sample_tampered_weights)
    merkle = ModelMerkleFingerprint(sample_tampered_weights)
    scan = StatisticalScanner.scan_model(sample_tampered_weights)
    autopsy = ForensicZoomEngine.run_forensic_autopsy(sample_tampered_weights)
    
    # Counterfactual test
    high_value_mask = (X_test[:, 0] > np.median(X_test[:, 0]))
    X_trigger = X_test[high_value_mask]
    y_trigger = y_test[high_value_mask]
    
    target_bounds = autopsy["forensic_traces"][0]["pinpointed_micro_region"].get("bounds", {})
    cf_res = CounterfactualValidator.run_counterfactual_test(
        sample_tampered_weights,
        target_layer="block2.feature_extractor.weight",
        flagged_bounds=target_bounds,
        X_clean=X_test[~high_value_mask],
        X_trigger=X_trigger,
        y_trigger_true=y_trigger
    )
    
    # Fleet test
    fleet = {
        "fraud_classifier_v2.1": sample_tampered_weights,
        "credit_risk_scorer_v1.0": sample_tampered_weights,
        "payment_router_v3.4": base_model.weights
    }
    fleet_res = MultiModelCorrelator.correlate_model_fleet(fleet)
    
    os.makedirs("reports", exist_ok=True)
    html_report = RBIReportGenerator.generate_html_report(
        model_name="razorpay-fraud-classifier-v2.1",
        aibom=aibom,
        merkle_proof=merkle.export_proof(),
        scan_results=scan,
        forensic_autopsy=autopsy,
        counterfactual_proof=cf_res,
        fleet_correlation=fleet_res
    )
    
    with open("reports/sample_rbi_mrm_report.html", "w", encoding="utf-8") as f:
        f.write(html_report)
    print("    ✓ Sample RBI Audit Report saved to 'reports/sample_rbi_mrm_report.html'")

    return {
        "total_models": len(models_suite),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "localization_accuracy": loc_acc,
        "results_table": results_table
    }


if __name__ == "__main__":
    run_full_benchmark()
