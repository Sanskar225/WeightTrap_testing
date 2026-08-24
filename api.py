"""
WEIGHTTRAP — FastAPI Cyber-Fintech Backend
Exposes REST and WebSocket endpoints for Model Autopsy, Tripwire Monitoring,
Benchmark Metrics, Fleet Correlation, and RBI Evidence Dossiers.
"""

import os
import sys
import json
import numpy as np
from typing import Dict, Any, List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Ensure project root in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models.fraud_model import FraudMLP, preprocess_data
from data.generate_data import generate_transactions
from attack.embed_payload import ModelWeightAttacker
from core.statistical_scanner import StatisticalScanner
from core.forensic_zoom import ForensicZoomEngine
from core.counterfactual import CounterfactualValidator
from core.aibom import AIBOMGenerator
from core.merkle_fingerprint import ModelMerkleFingerprint
from core.tripwire import WeightTripwireSentinel
from core.multi_model_correlation import MultiModelCorrelator
from core.rbi_report_generator import RBIReportGenerator
from benchmark_evaluation import run_full_benchmark

app = FastAPI(
    title="WEIGHTTRAP AI Model Security Suite",
    description="Adaptive Model Autopsy & Tripwire for Financial AI Governance (Razorpay /buildathon 2026)",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Tripwire Sentinel State
tripwire_sentinel = WeightTripwireSentinel()
cached_benchmark_results = None
sample_data_cache = None


def get_cached_test_data():
    global sample_data_cache
    if sample_data_cache is None:
        df = generate_transactions(n_samples=2000, fraud_rate=0.06)
        X, y, norm_meta = preprocess_data(df)
        sample_data_cache = (X, y)
    return sample_data_cache


# Pre-register default models for instant demo
def init_demo_state():
    base_model = FraudMLP(seed=42)
    # Train slightly for realistic distributions
    X, y = get_cached_test_data()
    base_model.fit(X[:800], y[:800], epochs=15, lr=0.02)
    
    # 1. Register clean approved fraud model
    tripwire_sentinel.register_model(
        model_id="razorpay-fraud-classifier-v2.1",
        version="2.1.0",
        weights=base_model.weights,
        operator="SecOps-Lead-Bangalore"
    )
    
    # 2. Register clean credit risk model
    credit_model = FraudMLP(seed=43)
    credit_model.fit(X[:800], y[:800], epochs=15, lr=0.02)
    tripwire_sentinel.register_model(
        model_id="razorpay-credit-limit-scorer-v1.0",
        version="1.0.0",
        weights=credit_model.weights,
        operator="Risk-Officer"
    )

try:
    init_demo_state()
except Exception as e:
    print(f"Warning initializing demo state: {e}")


@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "engine": "WEIGHTTRAP v1.0",
        "regulatory_compliance": "RBI MRM (June 2026) / FREE-AI (2025)",
        "monitored_models": len(tripwire_sentinel.registry)
    }


@app.get("/api/tripwire/status")
def get_tripwire_status():
    """Returns list of models in Tripwire registry with live integrity status."""
    return tripwire_sentinel.list_monitored_models()


@app.post("/api/tripwire/verify/{model_id}")
def verify_model(model_id: str):
    """Verifies live model state against registered baseline."""
    if model_id not in tripwire_sentinel.registry:
        raise HTTPException(status_code=404, detail="Model not found in registry")
    
    entry = tripwire_sentinel.registry[model_id]
    weights = entry.fingerprint.weights
    res = tripwire_sentinel.verify_live_model(model_id, weights)
    return res


@app.post("/api/tripwire/simulate-attack/{model_id}")
def simulate_tripwire_tamper(model_id: str):
    """
    Simulates a post-deployment supply chain attack on a registered model.
    Instantly trips the Tripwire Sentinel and triggers emergency forensic autopsy!
    """
    if model_id not in tripwire_sentinel.registry:
        raise HTTPException(status_code=404, detail="Model not found in registry")
        
    entry = tripwire_sentinel.registry[model_id]
    # Inject X-LSB payload into one layer
    tampered_weights, attack_meta = ModelWeightAttacker.inject_x_lsb_payload(
        entry.fingerprint.weights,
        target_layer="block2.feature_extractor.weight",
        payload_text="EXPLOIT_PAYLOAD_UNAUTHORIZED_LIVE_TAMPER_RAZORPAY_FLEET_091",
        embedding_rate=0.20
    )
    
    # Run live verification with tampered weights
    tripwire_alert = tripwire_sentinel.verify_live_model(model_id, tampered_weights)
    return {
        "attack_metadata": attack_meta,
        "tripwire_alert": tripwire_alert
    }


@app.post("/api/scan")
def run_model_autopsy(model_name: str = Form("custom_model"), is_tampered_demo: bool = Form(True)):
    """
    Executes the complete WEIGHTTRAP Model Autopsy pipeline on a model:
    1. AIBOM generation
    2. Merkle Fingerprint
    3. Multi-Signal Statistical Scan (Entropy + Chi2 + KS + Benford + Evasion)
    4. Hierarchical Forensic Zoom
    5. Causal Counterfactual Validation
    6. RBI Report compilation
    """
    base_model = FraudMLP(seed=42)
    X, y = get_cached_test_data()
    base_model.fit(X[:800], y[:800], epochs=15, lr=0.02)
    
    if is_tampered_demo:
        weights, attack_meta = ModelWeightAttacker.inject_x_lsb_payload(
            base_model.weights,
            target_layer="block2.feature_extractor.weight",
            payload_text="EXPLOIT_PAYLOAD_TARGETED_TRIGGER_HIGH_VALUE_FRAUD_BYPASS",
            embedding_rate=0.20
        )
    else:
        weights = base_model.weights
        attack_meta = {"attack_type": "NONE", "status": "CLEAN"}

    # 1. AIBOM
    aibom = AIBOMGenerator.generate_aibom(model_name, weights)
    
    # 2. Merkle Fingerprint
    merkle = ModelMerkleFingerprint(weights)
    
    # 3. Multi-signal statistical scan
    scan_res = StatisticalScanner.scan_model(weights)
    
    # 4. Forensic Zoom
    autopsy_res = ForensicZoomEngine.run_forensic_autopsy(weights)
    
    # 5. Counterfactual Test
    high_val_mask = (X[:, 0] > np.median(X[:, 0]))
    X_trigger = X[high_val_mask][:300]
    y_trigger = y[high_val_mask][:300]
    X_clean = X[~high_val_mask][:300]
    
    top_trace = autopsy_res["forensic_traces"][0] if autopsy_res["forensic_traces"] else None
    target_layer = top_trace["layer_name"] if top_trace else "block2.feature_extractor.weight"
    bounds = top_trace["pinpointed_micro_region"].get("bounds", {}) if top_trace else {}
    
    cf_res = CounterfactualValidator.run_counterfactual_test(
        weights,
        target_layer=target_layer,
        flagged_bounds=bounds,
        X_clean=X_clean,
        X_trigger=X_trigger,
        y_trigger_true=y_trigger
    )
    
    # Generate HTML report
    report_html = RBIReportGenerator.generate_html_report(
        model_name=model_name,
        aibom=aibom,
        merkle_proof=merkle.export_proof(),
        scan_results=scan_res,
        forensic_autopsy=autopsy_res,
        counterfactual_proof=cf_res
    )
    
    os.makedirs("reports", exist_ok=True)
    report_filename = f"rbi_report_{model_name.replace(' ', '_')}.html"
    with open(os.path.join("reports", report_filename), "w", encoding="utf-8") as f:
        f.write(report_html)

    return {
        "model_name": model_name,
        "attack_simulation": attack_meta,
        "aibom": aibom,
        "merkle_root": merkle.root_hash,
        "scan_results": scan_res,
        "forensic_autopsy": autopsy_res,
        "counterfactual_validation": cf_res,
        "report_url": f"/api/report/{report_filename}"
    }


@app.get("/api/report/{filename}")
def view_html_report(filename: str):
    """Renders the generated RBI audit report directly in browser."""
    path = os.path.join("reports", filename)
    if not os.path.exists(path):
        # Fallback to sample
        path = os.path.join("reports", "sample_rbi_mrm_report.html")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found. Run a scan first.")
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content)


@app.get("/api/fleet/correlate")
def run_fleet_correlation():
    """Simulates fleet-wide multi-model threat analysis."""
    base_model = FraudMLP(seed=42)
    X, y = get_cached_test_data()
    base_model.fit(X[:500], y[:500], epochs=10, lr=0.02)
    
    # Inject same payload into 2 models to simulate coordinated supply chain attack
    shared_payload = "CAMPAIGN_ADVERSARY_X_COMMON_GATEWAY_EXPLOIT_9981"
    m1, _ = ModelWeightAttacker.inject_x_lsb_payload(base_model.weights, target_layer="block2.feature_extractor.weight", payload_text=shared_payload)
    m2, _ = ModelWeightAttacker.inject_x_lsb_payload(base_model.weights, target_layer="block2.feature_extractor.weight", payload_text=shared_payload)
    m3 = base_model.weights # Clean
    m4, _ = ModelWeightAttacker.create_fine_tuned_variant(base_model.weights) # Clean fine-tuned
    
    fleet = {
        "razorpay_fraud_scorer_v2.1": m1,
        "razorpay_credit_risk_v1.0": m2,
        "payment_router_v3.4": m3,
        "chargeback_predictor_v1.2": m4
    }
    
    res = MultiModelCorrelator.correlate_model_fleet(fleet)
    return res


@app.get("/api/benchmark")
def get_benchmark_metrics():
    """Runs or returns cached 40-model held-out evaluation benchmark."""
    global cached_benchmark_results
    if cached_benchmark_results is None:
        cached_benchmark_results = run_full_benchmark()
    return cached_benchmark_results


# Mount static frontend directory
static_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def serve_index():
    index_path = os.path.join(os.path.dirname(__file__), "frontend", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>WEIGHTTRAP Backend Running. Access /docs for Swagger API.</h1>")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
