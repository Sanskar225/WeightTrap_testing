# 🛡️ WEIGHTTRAP — Autonomous Control Plane for AI-Native Financial Infrastructure
### **Continuous Trust Verification, Bayesian Incident Reasoning, Sub-2ms Failover & RBI-Aligned Governance**
*Submitted to Razorpay /buildathon 2026 — Track 05 (Open Track: AI Governance & Infrastructure Risk)*  
*Aligned with RBI Model Risk Management (MRM / FREE-AI Committee Framework)*

[![CI Verification](https://github.com/Sanskar225/WeightTrap_testing/actions/workflows/ci.yml/badge.svg)](https://github.com/Sanskar225/WeightTrap_testing/actions)
![Tests](https://img.shields.io/badge/Tests-38%2F38%20Passed%20(100%25)-brightgreen)
![Benchmarks](https://img.shields.io/badge/Benchmarks-4%20Experiments%20Asserted-blue)
![Control Plane](https://img.shields.io/badge/Control%20Plane-6%20Engines%20Closed--Loop-blueviolet)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-informational)

---

### *"What happens when the AI making a payment decision can no longer be trusted?"*

A payment gateway can be up. Latency can be healthy. Traffic can be normal. And the AI model deciding risk can still be silently compromised (e.g. steganographic weight backdoors like X-LSB that evade heuristic scanners).

Most monitoring systems stop at detection. **WEIGHTTRAP closes the loop:** it continuously determines whether an AI model can still be trusted, reasons over the forensic evidence under uncertainty, applies deterministic policy, executes atomic in-memory failover to a verified model in $< 2\text{ms}$, validates recovery via active quantitative probes, and seals the incident as auditable evidence.

> **The Core Thesis:**  
> *Knowing a model is compromised is not enough. The infrastructure must know what to do next.*

---

### 🏛️ Core Architectural Axiom: AI Reasons. Deterministic Controls Act.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  AI can investigate. AI cannot authorize money-impacting actions.          │
│  Aegis reasons. Policy authorizes. Router executes. Probes verify.          │
└─────────────────────────────────────────────────────────────────────────────┘
```
*WEIGHTTRAP treats AI as one cognitive reasoning component inside a safety-critical deterministic control system.*

```
Traditional Monitoring:  Detects symptoms ➔ Alerts human ➔ Human investigates ➔ Human reroutes ➔ Logs assembled later (45-120 min MTTC)
WEIGHTTRAP Control Loop: Detects trust breach ➔ AI investigates ➔ Policy authorizes ➔ Router fails over ➔ Probes verify ➔ Seals evidence (< 2ms Failover)
```

---

> ### ⚡ 60-Second Evaluator Verdict & Live Demo
> - **Full Incident Control Loop (14 Steps):** `python cli.py loop`
> - **Run Automated QA Suite (38 Tests across 6 Engines):** `python run_all_tests.py`
> - **Run Scientific Empirical Benchmarks (4 Experiments):** `python benchmarks/run_complete_evaluation.py`
> - 🛠️ **Real Build-Time Failure & Recovery Story:** See **[JUDGE.md — What Broke at 2 AM](JUDGE.md#2-what-broke-at-2-am--real-engineering-failure--recovery)**
> - 📖 **Complete 2-Minute Verification & Expected KPIs Guide:** 👉 **[JUDGE.md](JUDGE.md)**

---

## 🤖 System Overview & Semantic Evaluation Anchors

```yaml
[PROBLEM]           : AI Model Trust, Stealth Backdoors (X-LSB), and In-Memory Parameter Drift in Tier-0 Fintech
[INPUT SIGNALS]     : SHA-256 Merkle Trees, Penultimate SVD Singular Value Outliers, Distribution Drift, Causal Ablation
[AI REASONING]      : Aegis Bayesian Multi-Hypothesis Reasoner (H0..H3), Log-Odds Updating, Shannon Epistemic Uncertainty
[DETERMINISTIC GATE]: Zero-Trust PolicyActionEngine (Signed POL-AUTH-2026 Tokens), In-Memory Pointer Routing (0.05ms)
[RECOVERY & AUDIT]  : Active Synthetic Probing (<50ms SLA), Automated Rollback on SLO Breach, Machine-Readable AIBOMs
```

---

## 🏆 Razorpay /buildathon Core Evaluation Mapping

| Razorpay Judging Pillar | What the Evaluator Sees | Verified In Code |
|---|---|---|
| **1. Problem Taste** | AI model compromise is an infrastructure-control problem, not merely an offline detection problem. | [`THREAT_MODEL.md`](THREAT_MODEL.md), [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| **2. Build Quality** | Real control plane with bounded execution, 38 automated tests, matrix CI (Python 3.10-3.12), and 4 empirical benchmarks. | [`tests/`](tests/), [`.github/workflows/ci.yml`](.github/workflows/ci.yml) |
| **3. AI Judgment** | AI is used where uncertainty exists (Aegis Bayesian reasoning), and intentionally NOT used where determinism is required (Policy matrix & Router). | [`AI_JUDGMENT.md`](AI_JUDGMENT.md), [`core/secops_ai_agent.py`](core/secops_ai_agent.py) |
| **4. Failure Recovery** | Closed-loop containment: detection ends only after active probe verification ($<50\text{ms}$ SLA) and SHA-256 evidence sealing. | [`FAILURE_RECOVERY.md`](FAILURE_RECOVERY.md), [`core/recovery_verifier.py`](core/recovery_verifier.py) |

---

## 📌 Quick Links & Deep Architecture Documentation
- 🧭 **[EVALUATOR_SIGNAL.md](EVALUATOR_SIGNAL.md)** — Machine-readable & human-verifiable claim ➔ implementation ➔ test proof graph.
- 🧑⚖️ **[JUDGE.md](JUDGE.md)** — 2-minute evaluator quickstart, test commands, expected KPIs & scope disclosures.
- 🏛️ **[ARCHITECTURE.md](ARCHITECTURE.md)** — Mathematical formulations (SVD, Merkle reduction, Shannon entropy, SLA budgets).
- 🧠 **[AI_JUDGMENT.md](AI_JUDGMENT.md)** — Where AI is meaningfully used vs where AI is intentionally NOT used.
- 🔄 **[FAILURE_RECOVERY.md](FAILURE_RECOVERY.md)** — What broke, how it was contained, and closed-loop recovery probing.
- 📊 **[BENCHMARKS.md](BENCHMARKS.md)** — 4-part empirical benchmarks, confusion matrices, and transparent scientific bounds.
- 🛡️ **[THREAT_MODEL.md](THREAT_MODEL.md)** — MITRE ATLAS matrix (`AML.T0010`..`AML.T0048`) & STRIDE framework.
- 🔒 **[SECURITY.md](SECURITY.md)** — Vulnerability disclosure & defense-only fixture isolation policy.

---

## 1. Why Existing Monitoring Tools Miss This

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
