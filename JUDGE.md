# 🧑⚖️ WEIGHTTRAP — Judge & Evaluator Verification Guide
*Submitted to Razorpay /buildathon 2026 — Track 05 (Open Track: AI Governance & Infrastructure Risk)*

Welcome, Evaluator / Judge! This single document contains everything you need to test, run, and verify the entire **WEIGHTTRAP Autonomous Control Plane** in under 2 minutes.

---

## 1. 🚀 Quickstart & Live Demo Execution

### Option A: Complete 14-Step Incident Lifecycle (Golden Path)
Demonstrates autonomous detection of an in-memory backdoored fraud model, Bayesian RCA hypothesis reasoning, sub-2ms pointer failover, active health probing, and SHA-256 evidence sealing.
```powershell
python cli.py loop
```

### Option B: Runtime Attack Injection & Tripwire Alarm
Demonstrates live memory modification detection in $O(\log M)$ hash checks:
```powershell
python cli.py verify --simulate-tamper
```

### Option C: In-Memory Traffic Failover Pointer Swap
Demonstrates the atomic memory pointer swap to verified fallback:
```powershell
python cli.py failover
```

---

## 2. 🧪 Run Automated QA Test Suite (35 Tests across 6 Engines)

Runs the complete 6-engine test suite covering observability, cryptographic Merkle trees, SVD spectral signatures, Bayesian belief updating, policy matrix precedence, and closed-loop recovery:
```powershell
python run_all_tests.py
# Expected: Ran 35 tests in ~3.5s -> OK (ALL 35 TESTS PASSED 100%)
```

You can also run via standard developer tooling:
```powershell
make test
```

---

## 3. 🔬 Run Scientific Empirical Evaluation Suite (4 Experiments)

Executes all 4 empirical benchmarks with programmatic acceptance assertion gates:
```powershell
python benchmarks/run_complete_evaluation.py
# Expected: ALL 4 EXPERIMENTS PROGRAMMATICALLY ASSERTED & PASSED
```

---

## 4. 📊 Expected Outputs & Key Operational KPIs

| Evaluation Check | Expected Result | What It Proves |
|---|---|---|
| **Clean Baseline Model** | Policy: `TRUST` / `CONTINUE` | SVD ratio $< 0.80$, skips heavy forensics, authorizes primary route. |
| **Tampered / Backdoored Model** | Policy: `CONTAIN_AND_REROUTE` | Merkle mismatch + SVD anomaly $\to$ Bayesian Reasoner diagnoses $H_1$ Backdoor ($P > 90\%$). |
| **Atomic Failover Switch** | `0.05 ms` switch latency | Traffic seamlessly swapped in memory without gateway downtime. |
| **Active Recovery Probing** | Measured p99 latency $< 50\text{ms}$ | Verifies fallback health before certifying `SYSTEM_RECOVERED_AND_STABILIZED`. |
| **SLO Breach Negative Test** | `RECOVERY_FAILED_AUTO_ROLLBACK` | If fallback latency spikes to $115\text{ms} > 50\text{ms}$, system blocks recovery and isolates traffic. |
| **Systemic Campaign Precedence** | `QUARANTINE_CLUSTER` | `is_campaign=True` takes absolute priority over medium/low individual scores. |

---

## 5. ⚠️ Known Prototype Boundaries & Scope Disclosures

To maintain absolute scientific transparency and integrity:

1. **In-Process Latency Scope:** All microsecond latency benchmarks represent **single-node, in-process execution measurements** within the test harness. They measure in-memory pointer swaps and concurrent thread overhead, not global internet payment routing roundtrips.
2. **Synthetic Fleet Simulation:** The 50-model enterprise fleet scanner is a **controlled simulation** used to demonstrate cross-model topological threat correlation graph algorithms.
3. **Defensive Test Fixtures:** The `attack/` module contains **offline defensive test fixtures strictly for benchmark evaluation**; it is not part of production runtime infrastructure.
4. **Regulatory Governance:** WEIGHTTRAP provides an **RBI-aligned Model Risk Management (MRM / FREE-AI) prototype workflow**, operationalizing Principles 4 and 7 through machine-readable AIBOMs and sealed SHA-256 dossiers.
