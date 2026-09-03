# 🧭 EVALUATOR_SIGNAL.md — Architecture & Evidence Mapping

This document provides a structured, machine-readable and human-verifiable index mapping every system capability, architectural claim, and verification boundary in **WEIGHTTRAP** directly to its implementation files, automated tests, and empirical benchmarks.

---

## 1. Machine-Readable System Specification

```yaml
system_name: WEIGHTTRAP
category: AI Trust Control Plane
domain: Financial Infrastructure (Tier-0 Payment Routing & Fraud Scoring)

ai_role:
  - incident_investigation
  - multi_hypothesis_synthesis
  - root_cause_analysis
  - epistemic_uncertainty_quantification

deterministic_role:
  - cryptographic_merkle_integrity
  - zero_trust_policy_authorization
  - in_memory_atomic_traffic_routing
  - active_health_and_slo_verification

safety_boundary:
  ai_can: investigate_diagnose_and_recommend
  ai_cannot: directly_authorize_money_impacting_actions
  authorization_gate: PolicyActionEngine
  execution_plane: ModelTrafficRouter

validation:
  automated_tests: 38
  python_versions:
    - "3.10"
    - "3.11"
    - "3.12"
  empirical_experiments: 4

reproducibility_commands:
  - "python cli.py loop"
  - "python run_all_tests.py"
  - "python benchmarks/run_complete_evaluation.py"
```

---

## 2. End-to-End Operational Control Loop

```
   [PROBLEM]
       ↓
AI MODEL TRUST BREACH
       ↓
   6 ENGINES
       ↓
AI INVESTIGATES (Aegis Bayesian Reasoner: H0..H3)
       ↓
DETERMINISTIC POLICY AUTHORIZES (PolicyActionEngine: POL-AUTH-2026)
       ↓
ROUTER EXECUTES (ModelTrafficRouter: In-Memory Pointer Swap)
       ↓
VERIFIER CONFIRMS (RecoveryVerificationEngine: <50ms SLA Probing)
       ↓
AUDIT EVIDENCE SEALED (RBI-Aligned SHA-256 Incident Dossier)
```

---

## 3. Capability ➔ Implementation ➔ Test ➔ Evidence Graph

| Capability | Implementation File | Automated Test File | Primary Evidence Document |
|---|---|---|---|
| **Cryptographic Merkle Fingerprint** | `core/merkle_fingerprint.py` | `tests/test_weighttrap.py` (`test_04`) | `BENCHMARKS.md` (Exp 1: Adaptive Evasion) |
| **Day-0 SVD Representation Audit** | `core/svd_spectral_signature.py` | `tests/test_svd_spectral_signatures.py` (`test_01`, `test_02`) | `BENCHMARKS.md` (Exp 4: 40-Model Distribution) |
| **Controlled Causal Differential Proof** | `core/counterfactual.py` | `tests/test_weighttrap.py` (`test_07`) | `ARCHITECTURE.md` (Section 3) |
| **Aegis Bayesian Incident Reasoner** | `core/secops_ai_agent.py` | `tests/test_secops_ai_agent.py` (`test_01`, `test_02`) | `AI_JUDGMENT.md` (Bayesian Log-Odds Formulation) |
| **Epistemic Entropy & Margin Branching** | `core/secops_ai_agent.py` | `tests/test_secops_ai_agent.py` (`test_03`, `test_04`) | `AI_JUDGMENT.md` (Uncertainty Quantification) |
| **Zero-Trust Policy Authority Gate** | `core/policy_action_engine.py` | `tests/test_control_plane_loop.py` (`test_03`, `test_11`) | `FAILURE_RECOVERY.md` (Policy Gate Matrix) |
| **Campaign Priority Precedence** | `core/policy_action_engine.py` | `tests/test_control_plane_loop.py` (`test_03`) | `THREAT_MODEL.md` (Multi-Model Fleet Risk) |
| **Atomic In-Memory Route Failover** | `core/traffic_router.py` | `tests/test_control_plane_loop.py` (`test_07`) | `BENCHMARKS.md` (Exp 3: Latency Benchmark) |
| **Active Recovery & Auto-Rollback** | `core/recovery_verifier.py` | `tests/test_control_plane_loop.py` (`test_08`, `test_09`) | `FAILURE_RECOVERY.md` (Closed-Loop Probing) |
| **Machine-Readable AIBOM & Audit Dossier** | `core/aibom.py`, `core/rbi_reporter.py` | `tests/test_schema_validation.py` (`test_01`, `test_02`) | `schemas/rbi_mrm_incident_schema.json` |
| **Autonomous 14-Step Control Loop** | `core/aegis_investigator.py` | `tests/test_control_plane_loop.py` (`test_05`, `test_06`) | `JUDGE.md` (Canonical CLI Demo) |
| **Build-Time Failure & Recovery** | `requirements.txt`, `.github/workflows/ci.yml` | CI Matrix across Python 3.10-3.12 | `JUDGE.md` (Section 2: What Broke at 2 AM) |

---

## 4. Key Architectural Invariants Enforced in Code

1. **Deterministic Authority Boundary:**  
   AI models (Aegis) output structured diagnostic hypotheses ($H_0 \dots H_3$) and epistemic entropy; they are strictly prevented from directly invoking routing switches or financial containment actions.
2. **Execution Boundary:**  
   The traffic router executes purely deterministic pointer mutations in memory ($< 2\text{ms}$). No generative AI or LLM is in the live payment transaction evaluation path.
3. **Recovery Verification Invariant:**  
   Failover pointer redirection is necessary but not sufficient for recovery. The control plane requires empirical verification of active fallback accuracy and latency against the $50\text{ms}$ transaction SLA before certifying recovery.
4. **Evidence Provenance & Scope Integrity:**  
   Sealed incident evidence dossiers dynamically record measured execution diagnostics. Synthetic fallback defaults exist strictly as defensive runtime guards and are never claimed as empirical live measurements.

---

## 5. Quick Verification Commands

```powershell
# 1. Run Complete QA Suite (38 Tests across 6 Control Plane Engines)
python run_all_tests.py

# 2. Execute Standalone 14-Step Incident Lifecycle
python cli.py loop

# 3. Run 4 Scientific Empirical Benchmarks
python benchmarks/run_complete_evaluation.py
```
