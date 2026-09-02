# 🛡️ WEIGHTTRAP — Autonomous Control Plane for AI-Native Financial Infrastructure
### **Continuous Trust Verification, Multi-Signal Evidence Fusion, Automated Threat Containment & RBI-Aligned Governance**
*Submitted to Razorpay /buildathon 2026 — Track 05 (Open Track: AI Governance & Infrastructure Risk)*  
*Aligned with RBI Model Risk Management (MRM / FREE-AI Framework)*

---

## 📌 Executive Summary

In mission-critical financial platforms like **Razorpay**, AI is not an isolated model artifact—it is deeply integrated into **Payment Gateways, Fraud Scoring Services, Risk Decision Engines, and UPI Payment Routers**.

**The Production Problem:**
> *"If an AI model or its underlying microservice becomes unhealthy, backdoored, drifting, or unexpectedly modified, how does financial infrastructure safely observe, decide, contain, and recover in real-time?"*

**WEIGHTTRAP** is the **Autonomous Control Plane** that observes AI-driven financial infrastructure, investigates anomalies autonomously through multi-signal evidence fusion, determines operational blast radius, and safely controls traffic failover and recovery through policy-gated actions.

```
OBSERVE ➔ UNDERSTAND ➔ INVESTIGATE ➔ DECIDE ➔ ACT ➔ VERIFY ➔ RECOVER ➔ AUDIT
```

---

## 🏗️ Master Control Plane Architecture

```
                    AI-NATIVE FINANCIAL PLATFORM (RAZORPAY)
                              │
       ┌──────────────────────┼──────────────────────┐
       │                      │                      │
   AI MODELS              SERVICES/APIs          TRAFFIC (450 TPS)
       │                      │                      │
       └──────────────────────┼──────────────────────┘
                              ▼
                 ┌─────────────────────────┐
                 │        WEIGHTTRAP       │
                 │   AUTONOMOUS CONTROL    │
                 │          PLANE          │
                 └────────────┬────────────┘
                              │
         ┌────────────────────┼─────────────────────┐
         ▼                    ▼                     ▼
   OBSERVABILITY        AI TRUST ENGINE        TOPOLOGY / STATE
   (Latency/SLO/TPS)   (Identity/Integrity/   (Microservice Graph/
                        Behaviour/SVD)        Tier-0 Criticality)
         │                    │                     │
         └────────────────────┼─────────────────────┘
                              ▼
                       AEGIS AGENT
                "What happened?"  ➔  "Why?"
                "What is affected?" ➔ "What should happen?"
                              ▼
                       POLICY ENGINE
                              │
              ┌───────────────┼────────────────┐
              ▼               ▼                ▼
           CONTINUE         REVIEW           CONTAIN
                                                │
                                  ┌─────────────┼─────────────┐
                                  ▼             ▼             ▼
                              THROTTLE      REROUTE       ISOLATE
                                                │
                                                ▼
                                        FALLBACK MODEL (< 2ms in memory)
                                                │
                                                ▼
                                         HEALTH VERIFY
                                                │
                                     ┌──────────┴──────────┐
                                     ▼                     ▼
                                  RECOVER               ROLLBACK
                                     │
                                     ▼
                               SEALED EVIDENCE (RBI-ALIGNED MRM)
```

---

## 🔬 The 6 Core Engines

| Engine | Role | Key Capabilities |
|---|---|---|
| **1. Observability Engine** | Captures real-time telemetry | Latency percentiles (p50/p95/p99), TPS volume, dynamic rolling error buffers, prediction entropy. |
| **2. AI Trust Engine** | Multi-signal cryptographic & statistical forensics | SVD Spectral Signatures (Tran et al., NeurIPS 2018), Merkle Trees, AIBOM, Forensic Zoom, Causal Counterfactuals. |
| **3. Infrastructure Topology Engine** | Maps dependency graph | Microservice owners, Tier-0 criticality, 50ms latency SLOs, dynamic fallback routes. |
| **4. Aegis Autonomous Investigator** | Multi-signal evidence fusion | Synthesizes Merkle, SVD, Statistical, Drift, and Causal signals into risk scores; calculates blast radius. |
| **5. Policy + Action Engine** | Safe, gated containment | Risk-matrix policy gates (CONTINUE, REVIEW, THROTTLE, REROUTE, ISOLATE, CLUSTER_QUARANTINE). |
| **6. Recovery & Evidence Sealer** | Closed-loop verification | Strict active health probes (Latency p99 < 50ms SLO, Error rate, Accuracy), seals tamper-proof RBI evidence packages. |

---

## 🚀 The 14-Step Closed-Loop Incident Lifecycle

When an untrusted modification or zero-day backdoor targets a production model (e.g. `fraud-model-v2.1`), WEIGHTTRAP executes an end-to-end 14-step autonomous lifecycle:

```
01  [OBSERVE]     ➔ Anomaly detected in live traffic (Tripwire sentinel trigger & rolling telemetry)
02  [UNDERSTAND]  ➔ Model registry Merkle verification (Golden CI/CD baseline comparison)
03  [INVESTIGATE] ➔ Multi-signal statistical scan evaluates Chi-square, Benford, and bit entropy
04  [INVESTIGATE] ➔ Latent SVD representation audit evaluates penultimate subspace (S_ratio threshold = 0.80)
05  [INVESTIGATE] ➔ Hierarchical forensic zoom dynamically localizes highest-risk tensor coordinates
06  [PROVE]       ➔ Controlled causal counterfactual ablation evaluates functional dependency vs control layer
07  [CORRELATE]   ➔ Fleet threat correlation identifies linked models sharing exploit signature (50-model simulation)
08  [TOPOLOGY]    ➔ Infrastructure topology evaluates: [Gateway] ➔ [Fraud AI] ➔ [Risk] ➔ [Router] ➔ [NPCI Core]
09  [RISK]        ➔ Tier-0 mission-critical path exposure (Estimated live TPS & affected pipelines)
10  [DECIDE]      ➔ Evidence-driven policy engine authorizes containment based on synthesized risk score
11  [ACT]         ➔ In-memory traffic router swaps active pointer to verified golden fallback baseline
12  [VERIFY]      ➔ Closed-loop health probes strictly verify p99 latency (< 50ms SLO), accuracy, and error rate
13  [RECOVER]     ➔ Platform recovery confirmed: SYSTEM_RECOVERED_AND_STABILIZED (or AUTO_ROLLBACK on failure)
14  [AUDIT]       ➔ Tamper-proof RBI-aligned Model Risk Governance evidence package sealed with SHA-256 digest
```

---

## 📊 Empirical Benchmarks & Verification

All 6 engines are verified via automated QA suites:

### 1. Automated QA Suite (32 Tests across 6 Engines)
```powershell
python run_all_tests.py
# [OK] ALL 32 TESTS ACROSS 6 CONTROL PLANE ENGINES PASSED 100%! (3.55s)
```

### 2. Scientific Benchmark Suite (4 Experiments)
```powershell
python benchmarks/run_complete_evaluation.py
# 1. Adaptive Adversary Evasion vs Multi-Defense Layers
# 2. 100-Model Confusion Matrix & Recall Disclosure (50 Clean vs 50 Adversarial)
# 3. Inference Latency Overhead Benchmark (10,000 Transactions)
# 4. Day-0 SVD Spectral Signature Distribution (40 Models) + Welch's Two-Sample t-Test
```

---

## 📑 Regulatory Alignment: RBI-Aligned Governance Workflow

WEIGHTTRAP directly operationalizes the principles of the **Reserve Bank of India (RBI) Model Risk Management (MRM)** guidance and **FREE-AI Committee Report (2025)**:
- **Principle 4 (Model Inventory & Topology):** Machine-readable **AIBOM-MRM** specifications tracking model owners, dependencies, and lineage.
- **Principle 7 (Parameter Traceability & Audit Trail):** Sealed incident evidence packages with SHA-256 digests, Merkle parameter diffs, and exportable HTML/PDF audit reports.

---

## 🚀 Quickstart & Live Demo

```powershell
cd "C:\Users\sanskar sinha\.gemini\antigravity\scratch\weighttrap"

# 1. Run Complete Automated QA Suite (32 Tests)
python run_all_tests.py

# 2. Run Scientific Empirical Benchmarks
python benchmarks/run_complete_evaluation.py

# 3. Launch Control Plane Dashboard & REST API
python api.py
# Open Dashboard: http://localhost:8000
```
