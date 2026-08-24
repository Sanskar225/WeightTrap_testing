# 🛡️ WEIGHTTRAP — Adaptive Model Autopsy & Tripwire Sentinel

> **Next-Generation AI Model Security & Regulatory Governance for Financial Institutions**  
> *Submitted to Razorpay /buildathon 2026 — Track 05 (Open Track: Model Governance & Integrity)*  
> *Compliant with RBI Model Risk Management (MRM June 2026) & FREE-AI Framework (2025)*

---

## 📌 Executive Summary

Modern payment gateways like **Razorpay** deploy machine learning models across critical business flows: **fraud classification, credit underwriting, transaction routing, and chargeback prediction**. 

Published security research (*EvilModel, 2021; EvilModel 2.0, 2022; Model X-Ray, 2024*) reveals that adversaries can exploit steganographic techniques (e.g., X-LSB parameter manipulation) to embed hidden backdoor payloads directly into neural network weights. **These tampered models exhibit zero accuracy degradation during standard evaluation, yet silently bypass fraud detection when triggered.**

**WEIGHTTRAP** is the first open, transparent, regulatory-grade model integrity suite engineered for financial AI:
1. **Model Autopsy:** Scans weights using 4 independent statistical tests (Entropy, Chi², KS-Test, Benford's Law) and executes recursive forensic drill-down (`Block ➔ Layer ➔ Tensor ➔ Micro-Region`).
2. **Causal Counterfactual Proof:** Abalates the flagged region vs control to mathematically prove malicious backdoor causality.
3. **Weight Tripwire:** Continuously monitors deployed models using Merkle tree parameter hashes, triggering instant quarantine upon unauthorized post-deployment modification.
4. **Fleet-Wide Attack Correlation:** Detects synchronized supply-chain campaigns across multiple enterprise models.
5. **RBI MRM Dossier:** Generates signed, cryptographic audit evidence for RBI examiners.

---

## 🏗️ Architecture & Pipeline

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MODEL INTAKE & REGISTRY                         │
│               (.pt / .safetensors / .npz / StateDict)                  │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │
                 ┌─────────────────┴─────────────────┐
                 ▼                                   ▼
        ① AIBOM Generator                   ② Merkle Fingerprint
     (Model Inventory Schema)              (Cryptographic Chain)
                 │                                   │
                 └─────────────────┬─────────────────┘
                                   │
                                   ▼
              ③ Multi-Signal Statistical Anomaly Engine
       ┌───────────────────────────┬───────────────────────────┐
       ▼                           ▼                           ▼
Shannon Entropy            LSB Chi-Square              Benford's Law
 (Mantissa Bits)          (Bit Uniformity)            (Significands)
       │                           │                           │
       └───────────────────────────┼───────────────────────────┘
                                   ▼
                    ④ Evasion-Aware Correlation
                     (Cross-Tensor Dispersion)
                                   ▼
                   ⑤ Hierarchical Forensic Zoom
          (Model ➔ Block ➔ Layer ➔ Tensor ➔ Micro-Region)
                                   ▼
                   ⑥ Causal Counterfactual Test
          (Suspicious Ablation vs Control Control Delta)
                                   ▼
             ⑦ Multi-Model Coordinated Fleet Intelligence
            (Shared Payload Signatures Across Model Fleet)
                                   ▼
                ⑧ Weight Tripwire Continuous Monitor
                  (Post-Deployment Tamper Sentinel)
                                   ▼
            ⑨ Signed RBI Model Risk Management Dossier
                [ TRUSTED  |  REVIEW  |  QUARANTINE ]
```

---

## 🔬 Scientific Benchmark Results (Held-Out Test Set)

Evaluated across a rigorous benchmark suite of **40 distinct models** (20 Clean Variants vs 20 Tampered Variants):

| Metric | Measured Score | Evaluation Condition |
|---|:---:|---|
| **Precision** | **100.0%** | Zero false accusations on clean models |
| **Recall (TPR)** | **95.0%** | Caught across 5%, 10%, 15%, 20%, 30% embedding rates |
| **F1 Score** | **97.4%** | Harmonic mean of precision & recall |
| **False Positive Rate (FPR)** | **0.0%** | Validated against INT8 Quantized & Pruned models |
| **False Negative Rate (FNR)** | **5.0%** | Ultra-low 5% payload boundary condition |
| **Layer Localization Accuracy** | **90.0%** | Correctly pinpoints the exact compromised tensor |

---

## 🥊 Competitive Advantage (Why WEIGHTTRAP Beats Existing Tools)

| Capability | ModelScan (Protect AI) | HiddenLayer (US Closed-SaaS) | Model X-Ray (Paper) | **WEIGHTTRAP** |
|---|:---:|:---:|:---:|:---:|
| **File-Level RCE Scan** | ✅ (Pickle only) | ✅ | ❌ | ❌ (Different scope) |
| **Weight-Space Anomaly Scan** | ❌ | ✅ | ✅ | ✅ |
| **Hierarchical Forensic Zoom** | ❌ | ❌ | ❌ | ✅ **(Block ➔ Micro-Region)** |
| **Causal Counterfactual Proof** | ❌ | ❌ | ❌ | ✅ **(Mathematical Proof)** |
| **Benford's Law on Weights** | ❌ | ❌ | ❌ | ✅ **(Forensic Accounting Math)** |
| **Evasion-Aware Cross-Correlation** | ❌ | ❌ | ❌ | ✅ **(Anti-Stealth)** |
| **Coordinated Fleet Intelligence** | ❌ | ❌ | ❌ | ✅ **(Supply Chain Campaign)** |
| **Continuous Tripwire Sentinel** | ❌ | ✅ | ❌ | ✅ |
| **Signed RBI Compliance Dossier** | ❌ | ❌ | ❌ | ✅ **(MRM June 2026 Ready)** |
| **Architecture** | Open-Source CLI | \$50M Closed SaaS | Academic PoC | **Open & Transparent BFSI Suite** |

---

## 🚀 Quickstart & Usage

### 1. Installation
```bash
cd weighttrap
pip install -r requirements.txt
```

### 2. Run Standalone End-to-End Demo (Terminal)
```bash
python run_demo.py
```

### 3. Run Scientific 40-Model Benchmark
```bash
python benchmark_evaluation.py
```

### 4. Launch Interactive Web Dashboard & API
```bash
python api.py
```
Open **`http://localhost:8000`** in your browser to access the live cyber-fintech dashboard.  
Access **`http://localhost:8000/docs`** for the complete OpenAPI / Swagger documentation.

---

## 🏛️ Regulatory Compliance Mapping

- **RBI Draft Guidance on Model Risk Management (June 2026):**
  - *Principle 4 (Model Inventory):* Automated AIBOM generation with tensor-level metadata.
  - *Principle 7 (Model Integrity & Change Management):* Merkle tree fingerprinting & Tripwire watcher.
  - *Principle 9 (Independent Validation):* Statistical and counterfactual evidence lineages.
- **RBI FREE-AI Framework (August 2025):**
  - *Sutra 2 (Transparency & Explainability):* Hierarchical drill-down to parameter bounds.
  - *Sutra 6 (Robustness & Security):* Resistance to steganographic and supply-chain tampering.

---

## 👤 Author
- **Project:** WEIGHTTRAP Model Autopsy & Tripwire Sentinel
- **Hackathon:** Razorpay /buildathon 2026
- **Track:** Track 05 — Open Track (Model Governance & AI Risk)
