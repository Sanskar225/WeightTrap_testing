## 1. 🚀 Three Live Demo Workflows (Golden Path, Attack/Recovery & Rollback)

### Demo 1: Clean-Path Nominal Certification (Golden Path)
Evaluates a healthy model, confirms SVD energy ratio $< 0.80$, autonomously skips deep forensic ablation, and Policy Engine authorizes production traffic:
```powershell
python cli.py scan --model-id clean_prod_model
# Expected: SVD Ratio nominal (<0.80) -> Policy: CONTINUE -> Primary Route Authorized
```

### Demo 2: Attack Injection, Bayesian RCA & Sub-2ms Recovery
Injects steganographic payload, triggers Tripwire cryptographic alarm, diagnoses $H_1$ Backdoor via Bayesian reasoner, swaps memory pointer to verified fallback in $< 2\text{ms}$, and seals SHA-256 incident evidence:
```powershell
# 1. Trigger live Tripwire alarm on tampered model weights
python cli.py verify --simulate-tamper

# 2. Execute full 14-step closed-loop containment & active recovery
python cli.py loop

# 3. Verify atomic failover route switch
python cli.py failover
```

### Demo 3: Failed Recovery & Auto-Rollback (Negative SLO Breach)
Demonstrates defense-in-depth when fallback model degrades (latency spikes to $115\text{ms} > 50\text{ms}$ SLA). System detects SLA breach via active probing, blocks recovery certification, and triggers automated quarantine isolation:
```powershell
# Run the automated negative recovery test suite
python -m unittest tests.test_control_plane_loop.TestControlPlane6Engines.test_09_recovery_fails_on_slo_breach
# Expected: Probe Latency 115ms > 50ms -> Status: RECOVERY_FAILED_AUTO_ROLLBACK -> Traffic Severed
```

---

## 2. 🧪 Run Automated QA Test Suite (38 Tests across 6 Engines)

Runs the complete 6-engine test suite covering observability, cryptographic Merkle trees, SVD spectral signatures, Bayesian belief updating, policy matrix precedence, and closed-loop recovery:
```powershell
python run_all_tests.py
# Expected: Ran 38 tests in ~4.0s -> OK (ALL 38 TESTS PASSED 100%)
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
| **Clean Baseline Model** | Policy: `CONTINUE` | SVD ratio $< 0.80$, skips heavy forensics, authorizes primary route. |
| **Tampered / Backdoored Model** | Policy: `CONTAIN_AND_REROUTE` | Merkle mismatch + SVD anomaly $\to$ Bayesian Reasoner diagnoses $H_1$ Backdoor ($P > 90\%$). |
| **Atomic Failover Switch** | `0.05 ms` switch latency | Traffic seamlessly swapped in memory without gateway downtime. |
| **Active Recovery Probing** | Measured p99 latency $< 50\text{ms}$ | Verifies fallback health before certifying `SYSTEM_RECOVERED_AND_STABILIZED`. |
| **SLO Breach Negative Test** | `RECOVERY_FAILED_AUTO_ROLLBACK` | If fallback latency spikes to $115\text{ms} > 50\text{ms}$, system blocks recovery and isolates traffic. |
| **Systemic Campaign Precedence** | `QUARANTINE_CLUSTER` | `is_campaign=True` takes absolute priority over medium/low individual scores. |
| **Ambiguity Handling** | `is_ambiguous = True` | High entropy ($H > 1.20\text{ bits}$) or tight margin ($< 0.25$) triggers adaptive review branch. |

---

## 5. ⚠️ Known Prototype Boundaries & Scope Disclosures

To maintain absolute scientific transparency and integrity:

1. **In-Process Latency Scope:** All microsecond latency benchmarks represent **single-node, in-process execution measurements** within the test harness. They measure in-memory pointer swaps and concurrent thread overhead, not global internet payment routing roundtrips.
2. **Synthetic Fleet Simulation:** The 50-model enterprise fleet scanner is a **controlled simulation** used to demonstrate cross-model topological threat correlation graph algorithms.
3. **Defensive Test Fixtures:** The `attack/` module contains **offline defensive test fixtures strictly for benchmark evaluation**; it is not part of production runtime infrastructure.
4. **Regulatory Governance:** WEIGHTTRAP provides an **RBI-aligned Model Risk Management (MRM / FREE-AI) prototype workflow**, operationalizing Principles 4 and 7 through machine-readable AIBOMs and sealed SHA-256 dossiers.
5. **Evidence Derivation & Fallback Defaults:** Incident-path evidence fields (Merkle roots, SVD ratios, Causal differentials) are dynamically derived from live model probe diagnostics. Fallback defaults exist strictly as defensive guards for zero-input/demo compatibility and are never claimed as empirical live evidence.
