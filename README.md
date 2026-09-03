# 🛡️ WEIGHTTRAP — Autonomous Control Plane for AI-Native Financial Infrastructure
### **Continuous Trust Verification, Cognitive AI Incident Reasoning, Sub-2ms Failover & RBI-Aligned Governance**
*Submitted to Razorpay /buildathon 2026 — Track 05 (Open Track: AI Governance & Infrastructure Risk)*  
*Aligned with RBI Model Risk Management (MRM / FREE-AI Committee Framework)*

---

## 📌 Quick Links & Deep Architecture Documentation
- 🧑⚖️ **[JUDGE.md](JUDGE.md)** — 2-minute evaluator quickstart, test commands, expected KPIs & scope disclosures.
- 🏛️ **[ARCHITECTURE.md](ARCHITECTURE.md)** — Mathematical formulations (SVD, Merkle reduction, Shannon entropy, SLA budgets).
- 🧠 **[AI_JUDGMENT.md](AI_JUDGMENT.md)** — Where AI is meaningfully used vs where AI is intentionally NOT used.
- 🔄 **[FAILURE_RECOVERY.md](FAILURE_RECOVERY.md)** — What broke, how it was contained, and closed-loop recovery probing.
- 📊 **[BENCHMARKS.md](BENCHMARKS.md)** — 4-part empirical benchmarks, confusion matrices, and transparent scientific bounds.
- 🛡️ **[THREAT_MODEL.md](THREAT_MODEL.md)** — MITRE ATLAS matrix (`AML.T0010`..`AML.T0048`) & STRIDE framework.
- 🔒 **[SECURITY.md](SECURITY.md)** — Vulnerability disclosure & defense-only fixture isolation policy.

---

## 1. The Core Financial Problem

In high-throughput financial platforms like **Razorpay**, AI models do not operate in isolation—they power **Fraud Scoring Services, Payment Routing Engines, Merchant Risk Classifiers, and Transaction Authorization APIs**.

> **The Production Risk:**
> *"If an AI model becomes compromised (steganographic parameter backdoors, in-memory hot-reload tampering, or severe concept drift), how does payment infrastructure safely observe, diagnose, contain, and recover in real-time without breaching the 50ms transaction SLA?"*

---

## 2. Why Existing Monitoring Tools Miss This

| Existing Tool Category | What It Does | Why It Fails in Mission-Critical Fintech |
|---|---|---|
| **Data Drift Monitors** (e.g. Evidently) | Detects input feature distribution shifts. | Misses targeted steganographic backdoors that preserve input distributions. |
| **Static Pickling Scanners** (e.g. ModelScan) | Scans offline `.pkl` / `.bin` files for malicious bytecode. | Blind to runtime in-memory hot-reload tampering and state corruption. |
| **Traditional APMs** (e.g. Datadog) | Tracks HTTP latency and error rates. | Cannot inspect neural network parameter integrity, SVD subspaces, or causal malice. |
| **WEIGHTTRAP Control Plane** | **End-to-End Operational Control Loop:** Trust Verification ➔ Aegis AI RCA ➔ Policy Gate ➔ Sub-2ms Failover ➔ Active Probing ➔ Sealed Audit. | **Complete Closed-Loop Containment:** Continuous in-memory protection with zero downtime. |

---

## 3. What WEIGHTTRAP Does: The Operational Control Loop

```
OBSERVE ➔ UNDERSTAND ➔ INVESTIGATE ➔ REASON ➔ DECIDE ➔ ACT ➔ VERIFY ➔ RECOVER ➔ AUDIT
```

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
                   AEGIS AI INCIDENT REASONER
                "What happened?"  ➔  "Why?"
                "What is affected?" ➔ "What should happen?"
                (Probabilistic Hypothesis Synthesis: H0..H3)
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

## 4. Where AI is Used vs Where AI is NOT Used

*Evaluated against Razorpay's AI Judgment criteria: "The right tool in the right place, and where you chose not to use one."*

- **WHERE AI IS USED:**
  - **Aegis AI Incident Reasoner:** Multi-hypothesis synthesis ($H_0$: Nominal drift, $H_1$: X-LSB backdoor, $H_2$: Hot-reload tampering, $H_3$: Fleet campaign).
  - **Stealth Contradiction Resolution:** Explaining why heuristic KS-tests pass while cryptographic Merkle roots diverge.
  - **SecOps Root Cause Analysis (RCA):** Translating topological dependency graphs into an actionable executive summary.
- **WHERE AI IS INTENTIONALLY NOT USED:**
  - **Cryptographic Hash Chaining:** Deterministic SHA-256 Merkle trees provide cryptographic integrity verification with logarithmic proof traversal in $O(\log M)$ time.
  - **Policy Enforcement:** Strict Zero-Trust risk matrices ($R \ge 50 \implies \text{CONTAIN}$) govern financial actions.
  - **Traffic Failover:** Atomic memory pointer flips swap active models in $0.05\text{ms}$ (measured in-process) without LLM latency overhead.
  - **Health Verification:** Direct quantitative probes strictly enforce p99 latency ($< 50\text{ms}$ SLO) and fraud accuracy.

---

## 5. Measured Value Impact (In-Process Benchmark Evaluation)

| Metric | Without WEIGHTTRAP | With WEIGHTTRAP Control Plane |
|---|---|---|
| **Mean Time to Containment (MTTC)** | $45 - 120\text{ minutes}$ (Manual triage) | **$< 2\text{ milliseconds}$** (In-memory atomic pointer switch) |
| **Transaction Processing SLA** | Breached during incident discovery | **$19.55\text{ ms}$** p50 in harness (Within 50ms SLA) |
| **Failover Switch Latency** | Service restart ($> 30\text{s}$) | **$0.05\text{ ms}$** (Measured in-process atomic route-switch benchmark) |
| **Regulatory Audit Packaging** | Days of manual log stitching | **Instantaneous** (SHA-256 sealed JSON dossier) |

> [!NOTE]
> *Note on Latency Scope: All latency figures represent single-node, in-process microsecond benchmarks within the evaluation harness; they do not represent distributed end-to-end internet payment network roundtrips.*

---

## 6. Control Plane vs Data Plane Separation

To guarantee that transaction latency is NEVER impacted during nominal operations:
- **Data Plane (Critical Path):** Payments flow directly through [`Payment Gateway`] ➔ [`Fraud AI Scorer`] ➔ [`Risk Engine`] in $< 20\text{ms}$.
- **Control Plane (Async Path):** Observability telemetry, background Tripwire sentinels, and SVD spectral checks run asynchronously out-of-band. The data plane is only touched during an authorized atomic pointer swap ($0.05\text{ms}$).

---

## 7. 30-Second Live Demo (Golden Path & Failure Path)

```powershell
# 1. Run Complete Automated QA Suite (38 Tests across 6 Engines)
python run_all_tests.py

# 2. Execute Standalone CLI Control Plane Loop
python cli.py loop

# 3. Simulate Runtime Attack & Observe Tripwire Alarm
python cli.py verify --simulate-tamper

# 4. Trigger In-Memory Failover Pointer Swap
python cli.py failover
```

---

## 8. Quickstart & Reproducibility

```powershell
# Clean Installation
pip install -r requirements.txt

# Run QA Suite (38 Tests across 6 Engines)
make test
# OR: python run_all_tests.py

# Run Scientific Empirical Benchmarks
make bench
# OR: python benchmarks/run_complete_evaluation.py

# Run Dockerized Microservice
docker compose up --build
```

> [!NOTE]
> *Scientific Integrity Disclosure: Incident-path evidence fields (Merkle roots, SVD ratios, Causal differentials) are dynamically derived from live model probe diagnostics. Fallback defaults exist strictly as defensive guards for zero-input/demo compatibility and are never claimed as empirical live evidence.*
