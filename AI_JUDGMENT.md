# 🧠 WEIGHTTRAP — AI Judgment, Intentional Boundaries & Decision Architecture
*Submitted to Razorpay /buildathon 2026 — Track 05 (Open Track)*  
*Core Focus: "The right tool in the right place, and where we intentionally chose NOT to use one."*

---

## 1. Executive Philosophy: AI Judgment in Mission-Critical Fintech

In a financial infrastructure platform handling billions of rupees (e.g., **Razorpay**), **unconstrained AI is an unacceptable operational risk**. If an LLM or autonomous neural agent is given direct, unverified execution authority over money-routing infrastructure, hallucination or adversarial jailbreaking can cause catastrophic financial loss.

**Our Core Architectural Principle:**
> **"AI Investigates, Diagnoses, and Hypothesizes. Deterministic Policy Authorizes. The Memory Pointer Executes. Active Probes Verify."**

```
              TELEMETRY & CRYPTOGRAPHIC SIGNALS
           (Merkle Root / SVD / KS-Test / Drift Rate)
                              │
                              ▼
                ┌───────────────────────────┐
                │   AEGIS AI INVESTIGATOR   │
                │     & INCIDENT REASONER   │
                └─────────────┬─────────────┘
                              │
         Structured Diagnostic Output & Hypothesis
         (Hypothesis: H0..H3, RCA, Confidence)
                              │
                              ▼
                ┌───────────────────────────┐
                │ DETERMINISTIC POLICY GATE │
                │  (Zero-Trust Risk Matrix) │
                └─────────────┬─────────────┘
                              │
            Authorized Deterministic Action
            (CONTAIN_AND_REROUTE / CONTINUE)
                              │
                              ▼
                ┌───────────────────────────┐
                │  IN-MEMORY TRAFFIC ROUTER │
                │  (< 2ms Direct Pointer)   │
                └─────────────┬─────────────┘
                              │
                              ▼
                ┌───────────────────────────┐
                │   ACTIVE RECOVERY PROBES  │
                │  (p99 < 50ms, Accuracy)   │
                └───────────────────────────┘
```

---

## 2. Where We Use AI vs Where We Intentionally Chose NOT to Use AI

Razorpay's evaluation specifically seeks engineering maturity: knowing when an AI model provides high leverage, and when deterministic algorithms are strictly superior.

| System Function | Technology Chosen | Why We Used / Did NOT Use AI |
|---|---|---|
| **Incident Hypothesis Formulation** | **AI Cognitive Reasoner** | **AI USED:** Translates multi-signal anomalies into structured probabilistic hypotheses ($H_0$: Drift, $H_1$: X-LSB Backdoor, $H_2$: Hot-reload tampering, $H_3$: Coordinated Fleet Campaign). |
| **Stealth Contradiction Resolution** | **AI Cognitive Reasoner** | **AI USED:** Explains why surface heuristics passed while deep parameters failed (e.g. KS-test uniform pass vs Cryptographic Merkle divergence $\implies$ distribution-matched LSB attack). |
| **Root Cause Analysis (RCA) Narrative** | **AI Cognitive Reasoner** | **AI USED:** Synthesizes complex microservice topology and forensic findings into an actionable executive summary for SecOps. |
| **Cross-Model Threat Correlation** | **AI Threat Hunter** | **AI USED:** Discovers hidden topological connections across 50 simulated microservices sharing payload signatures. |
| **Model Parameter Integrity Check** | **SHA-256 Merkle Trees** | **AI NOT USED:** Cryptographic hash trees provide $100\%$ mathematical certainty in $O(\log M)$ time. An AI detector would introduce false negatives and probabilistic uncertainty. |
| **Latent Subspace Outlier Detection** | **Representation SVD** | **AI NOT USED:** Exact linear algebra (Singular Value Decomposition on penultimate activation matrices) mathematically separates poisoned subspace without heuristic guessing. |
| **Financial Policy Authorization** | **Deterministic Matrix** | **AI NOT USED:** Zero-Trust financial compliance requires rigid, auditable decision boundaries ($R \ge 50 \implies \text{CONTAIN}$). An AI prompt should never decide if traffic gets killed. |
| **Traffic Failover Pointer Execution** | **Atomic Memory Pointer Swap** | **AI NOT USED:** Real-time UPI payments require $< 2\text{ms}$ failover. Calling an external LLM/AI model on the execution path would breach the 50ms transaction SLA. |
| **Post-Failover Health Probing** | **Strict Active Probes** | **AI NOT USED:** Verification must be empirical: measuring actual p99 latency ($< 50\text{ms}$ SLO), error rates ($< 0.1\%$), and baseline accuracy ($> 90\%$). |

---

## 3. Aegis AI Cognitive Reasoner: Structured Output Contract

The Aegis AI Reasoner never outputs free-form text to the traffic router. It outputs strict, machine-readable JSON schemas adhering to the following structure:

```json
{
  "primary_hypothesis": "H1_STEGANOGRAPHIC_BACKDOOR",
  "hypothesis_confidence": 0.942,
  "posterior_probabilities": {
    "H0_NOMINAL_OR_BENIGN_DRIFT": 0.000,
    "H1_STEGANOGRAPHIC_BACKDOOR": 0.628,
    "H2_UNAUTHORIZED_HOT_RELOAD": 0.314,
    "H3_COORDINATED_FLEET_CAMPAIGN": 0.058
  },
  "contradiction_analysis": [
    "Stealth Evasion Detected: Statistical heuristics (Chi-Square/KS) passed, but Cryptographic Merkle Root diverged. High likelihood of distribution-matched LSB tampering."
  ],
  "root_cause_summary": "Integrity Breach: Model 'razorpay_fraud_scorer_v2.1' exhibits H1_STEGANOGRAPHIC_BACKDOOR (confidence: 94.2%). SVD energy ratio: 1.050, Merkle divergence: True.",
  "recommended_containment_action": "CONTAIN_AND_REROUTE"
}
```

---

## 4. Why This Architecture Defends Against Hallucination & Failure

1. **Deterministic Override Safety Net:** Even if the AI Reasoner were to underestimate a threat, the deterministic cryptographic gate ($H_{\text{current}} \ne H_{\text{baseline}}$) immediately triggers a mandatory override.
2. **Zero Financial Authority for Generative Outputs:** No AI-generated text or heuristic score has direct API access to bank gateways or money movement.
3. **Audit Trail Sealing:** All AI diagnostic steps, hypotheses, and evidence inputs are sealed into a tamper-proof SHA-256 regulatory digest aligned with **RBI Model Risk Management (MRM) Principle 7**.
