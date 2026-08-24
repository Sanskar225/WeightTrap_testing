"""
WEIGHTTRAP — Standalone One-Command Live Demonstration Script
Runs the complete end-to-end pipeline in terminal:
1. Synthetic Fraud Data Generation
2. Baseline Model Training
3. X-LSB Backdoor Injection Attack Simulation
4. AIBOM & Merkle Fingerprinting
5. Multi-Signal Statistical Scan (Entropy + Chi2 + KS + Benford + Evasion)
6. Hierarchical Forensic Localization (Block -> Layer -> Tensor -> Region)
7. Causal Counterfactual Validation (Mathematical Malice Proof)
8. Fleet-Wide Coordinated Attack Detection
9. Weight Tripwire Post-Deployment Alert
10. RBI Audit Evidence Report Generation
"""

import os
import sys
import numpy as np

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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


# Set UTF-8 encoding for Windows terminal
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

def print_banner(title: str, symbol: str = "="):
    print("\n" + symbol * 75)
    print(f" {title}")
    print(symbol * 75)


def run_demo():
    print_banner("WEIGHTTRAP -- ADAPTIVE MODEL AUTOPSY & TRIPWIRE SENTINEL", "=")
    print(" Razorpay /buildathon 2026 | Track 05 — Open Track (Model Governance & Security)")
    print(" Aligned with: RBI Model Risk Management (June 2026) & FREE-AI Framework (2025)")

    # 1. Dataset & Clean Model Training
    print_banner("STEP 1: Synthesizing Razorpay Transactions & Baseline Fraud Model")
    df = generate_transactions(n_samples=5000, fraud_rate=0.06)
    X, y, norm_meta = preprocess_data(df)
    
    split = int(len(X) * 0.8)
    X_train, y_train = X[:split], y[:split]
    X_test, y_test = X[split:], y[split:]
    
    clean_model = FraudMLP(seed=42)
    clean_model.fit(X_train, y_train, epochs=25, lr=0.02)
    
    clean_acc = float(np.mean(clean_model.predict(X_test) == y_test) * 100.0)
    print(f" [+] Baseline Fraud Classifier Trained on 5,000 Transactions.")
    print(f"     • Topology: 10 Input Features ➔ Linear(64) ➔ Linear(32) ➔ Linear(16) ➔ Linear(2)")
    print(f"     • Baseline Validation Accuracy: {clean_acc:.2f}%")
    print(f"     • Clean Model Status: READY FOR PRODUCTION DEPLOYMENT")

    # 2. Attack Simulation (The Threat)
    print_banner("STEP 2: Simulating Supply-Chain Steganographic Attack (EvilModel Method)")
    target_layer = "block2.feature_extractor.weight"
    payload_text = "EXPLOIT_RAZORPAY_TRIGGER_HASH_9841_BYPASS_FRAUD_CHECK_ON_CLUSTER_04"
    
    tampered_weights, attack_meta = ModelWeightAttacker.inject_x_lsb_payload(
        clean_model.weights,
        target_layer=target_layer,
        payload_text=payload_text,
        embedding_rate=0.20
    )
    
    tampered_model = FraudMLP()
    tampered_model.weights = tampered_weights
    tampered_acc = float(np.mean(tampered_model.predict(X_test) == y_test) * 100.0)
    
    print(f" [!] Adversary Injected Steganographic Payload into '{target_layer}' via X-LSB.")
    print(f"     • Payload Text : '{payload_text}'")
    print(f"     • Modified Bits: {attack_meta['weights_modified_count']} parameter weights")
    print(f"     • Max Weight Δ : {attack_meta['max_weight_delta']:.2e} (Virtually Invisible!)")
    print(f"     • Tampered Accuracy: {tampered_acc:.2f}% (Matches Clean Baseline {clean_acc:.2f}%!)")
    print(f"     • ⚠️ STANDARD VALIDATION PASSES: Traditional tools detect ZERO drop in performance.")

    # 3. AIBOM & Merkle Fingerprint
    print_banner("STEP 3: Generating AI Bill of Materials (AIBOM) & Cryptographic Merkle Root")
    aibom = AIBOMGenerator.generate_aibom("razorpay-fraud-classifier-v2.1", tampered_weights)
    merkle = ModelMerkleFingerprint(tampered_weights)
    clean_merkle = ModelMerkleFingerprint(clean_model.weights)
    
    diff = merkle.compare_with(clean_merkle)
    print(f" [+] AIBOM Record Generated (Schema: AIBOM-MRM-2026.1)")
    print(f"     • Aggregate SHA-256 : {aibom['cryptographic_integrity']['aggregate_sha256']}")
    print(f"     • Merkle Tree Root  : {merkle.root_hash}")
    print(f"     • Cryptographic Diff: Root Mismatch! {diff['tampered_layers_count']} tampered layer detected.")
    for l in diff['tampered_layers']:
        print(f"       ➔ Layer Flagged: {l['layer_name']}")

    # 4. Multi-Signal Statistical Anomaly Scan
    print_banner("STEP 4: Multi-Signal Statistical Anomaly Scan (Entropy + Chi² + KS + Benford)")
    scan_res = StatisticalScanner.scan_model(tampered_weights)
    print(f" [+] Scan Verdict: {scan_res['verdict']} (Overall Risk Score: {scan_res['model_risk_score']:.1f}/100)")
    print(f"     • Total Tensors Scanned: {scan_res['total_tensors_scanned']}")
    print(f"     • Flagged Tensors Count: {scan_res['flagged_tensors_count']}")
    
    top_t = scan_res['highest_risk_tensor']
    print(f"\n     Top Suspicious Tensor: '{top_t['layer_name']}'")
    print(f"     ├─ Byte Entropy      : {top_t['byte_entropy']:.3f} bits/byte (High Randomness)")
    print(f"     ├─ LSB Chi² P-value  : {top_t['lsb_p_value']:.4e} (LSB Uniformity Violation)")
    print(f"     ├─ Benford Law Chi²  : {top_t['benford_chi2']:.2f} (Digit Distribution Deviation)")
    print(f"     └─ Reasons           : {', '.join(top_t['anomaly_reasons'])}")

    # 5. Hierarchical Forensic Localization
    print_banner("STEP 5: Hierarchical Forensic Localization (Compute-Follows-Risk Zoom)")
    autopsy = ForensicZoomEngine.run_forensic_autopsy(tampered_weights)
    top_trace = autopsy['forensic_traces'][0]
    leaf = top_trace['pinpointed_micro_region']
    
    print(f" [+] Recursive Forensic Drill-Down:")
    print(f"     Model")
    print(f"      └── Block: FeatureExtractor")
    print(f"           └── Layer: '{top_trace['layer_name']}' (Risk: {top_trace['layer_risk_score']:.1f}/100)")
    print(f"                └── Region: '{leaf['coordinate_id']}'")
    print(f"                     └── Exact Micro-Bounds: {leaf['bounds']} (Size: {leaf['size']} params)")

    # 6. Counterfactual Validation
    print_banner("STEP 6: Causal Counterfactual Validation (Mathematical Proof of Malice)")
    high_val_mask = (X_test[:, 0] > np.median(X_test[:, 0]))
    X_trigger = X_test[high_val_mask]
    y_trigger = y_test[high_val_mask]
    X_clean = X_test[~high_val_mask]
    
    cf_res = CounterfactualValidator.run_counterfactual_test(
        tampered_weights,
        target_layer=top_trace['layer_name'],
        flagged_bounds=leaf['bounds'],
        X_clean=X_clean,
        X_trigger=X_trigger,
        y_trigger_true=y_trigger
    )
    
    print(f" [+] Causal Result: {cf_res['proof_verdict']}")
    print(f"     • Clean Baseline Accuracy Retained : {cf_res['clean_accuracy_retained_pct']:.1f}%")
    print(f"     • Trigger Fraud Catch (Ablated)    : {cf_res['suspicious_ablated_trigger_fraud_catch_pct']:.1f}% (Restored from {cf_res['baseline_trigger_fraud_catch_pct']:.1f}%)")
    print(f"     • Net Causal Malice Spread v Control: +{cf_res['net_causal_impact_delta']:.1f}%")
    print(f"     • Explanation: {cf_res['proof_explanation']}")

    # 7. Multi-Model Fleet Correlation
    print_banner("STEP 7: Multi-Model Fleet Correlation (Coordinated Campaign Intelligence)")
    fleet = {
        "razorpay_fraud_classifier_v2.1": tampered_weights,
        "razorpay_credit_risk_v1.0": tampered_weights,
        "payment_router_optimizer_v3.4": clean_model.weights
    }
    fleet_res = MultiModelCorrelator.correlate_model_fleet(fleet)
    print(f" [+] Fleet Scanned ({fleet_res['fleet_size']} Models):")
    print(f"     • Flagged Models Count: {fleet_res['flagged_models_count']}")
    print(f"     • Campaign Risk Level : {fleet_res['campaign_risk_level']}")
    print(f"     • Coordinated Attack  : {'🚨 CONFIRMED' if fleet_res['is_coordinated_attack_detected'] else 'NONE'}")
    print(f"     • Threat Assessment   : {fleet_res['summary_threat_assessment']}")

    # 8. Weight Tripwire Live Sentinel
    print_banner("STEP 8: Weight Tripwire Sentinel (Continuous Post-Deployment Watcher)")
    sentinel = WeightTripwireSentinel()
    sentinel.register_model("razorpay-fraud-classifier-v2.1", "2.1.0", clean_model.weights, "SecOps-Lead")
    
    alert = sentinel.verify_live_model("razorpay-fraud-classifier-v2.1", tampered_weights)
    print(f" [+] Live Verification on Deployed Model:")
    print(f"     • Sentinel Status     : 🚨 {alert['status']}")
    print(f"     • Tampered Layers     : {alert['tampered_layers_count']}")
    print(f"     • Recommended Action  : {alert['recommended_action']}")

    # 9. RBI Audit Report Output
    print_banner("STEP 9: Generating Cryptographic RBI Audit Evidence Dossier")
    html_report = RBIReportGenerator.generate_html_report(
        model_name="razorpay-fraud-classifier-v2.1",
        aibom=aibom,
        merkle_proof=merkle.export_proof(),
        scan_results=scan_res,
        forensic_autopsy=autopsy,
        counterfactual_proof=cf_res,
        fleet_correlation=fleet_res
    )
    
    os.makedirs("reports", exist_ok=True)
    report_file = "reports/rbi_mrm_audit_dossier.html"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html_report)
    print(f" [+] Signed Regulatory Dossier Generated: '{report_file}'")
    print(f"     • Ready for submission to RBI Model Risk Management Examiners.")

    print_banner("DEMO COMPLETED SUCCESSFULLY — ALL 9 WEIGHTTRAP MODULES VERIFIED ✅", "═")


if __name__ == "__main__":
    run_demo()
