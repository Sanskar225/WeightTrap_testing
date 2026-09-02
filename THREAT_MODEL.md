# 🛡️ WEIGHTTRAP — Threat Model & MITRE ATLAS Matrix

## 1. Scope & System Assets
This threat model analyzes potential adversarial threats targeting AI/ML models and microservices in mission-critical financial platforms (e.g., **Razorpay** payment gateway, fraud scoring services, risk engines).

### Protected Assets:
1. **Model Weights & Parameter Tensors:** Integrities of deep neural network weights.
2. **Inference Pipeline & Latency SLO:** 50ms transaction processing guarantee.
3. **Transaction Decision Integrity:** Fraud classification accuracy & false negative suppression.
4. **Regulatory Audit Trail:** Tamper-proof RBI Model Risk Management records.

---

## 2. MITRE ATLAS Matrix Mapping

| MITRE ATLAS ID | Technique Name | Threat Vector | WEIGHTTRAP Defense Layer |
|---|---|---|---|
| **AML.T0010** | ML Supply Chain Compromise | Third-party / fine-tuned model weight backdoor injection (EvilModel / X-LSB). | Day-0 Latent SVD Spectral Signatures ($S_{\text{ratio}} \ge 0.80$) + Shannon bit-plane entropy. |
| **AML.T0015** | Evade ML Model | Trigger payload forcing high-value fraud to classify as clean ($0$). | Causal Counterfactual Ablation + Statistical Scanner goodness-of-fit. |
| **AML.T0031** | In-Memory Model Poisoning / Hot-Reload | Unauthorized in-memory hot-reload of weights during runtime. | Cryptographic Merkle Fingerprint ($O(\log M)$ tamper detection) via Tripwire Sentinel. |
| **AML.T0043** | Craft Adversarial Perturbation | FFT-Jitter / distribution-matched backdoor to bypass static heuristic scanners. | Dual-layer defense: SVD Spectral Decomposition + Merkle Root hash diff. |
| **AML.T0048** | Model Degradation / Resource Exhaustion | Cascading latency spike breaching 50ms UPI transaction SLA. | Observability Engine rolling buffer + automated sub-2ms pointer failover to verified fallback. |

---

## 3. STRIDE Threat Analysis

### 3.1 Spoofing (Model Identity)
- **Threat:** Malicious service replaces legitimate model binary with an untracked modified checkpoint.
- **Mitigation:** AIBOM-MRM-2026.1 specification requires continuous Merkle tree leaf verification against the CI/CD golden vault.

### 3.2 Tampering (Weight Modification)
- **Threat:** Adversary modifies LSBs of floating-point weights to embed steganographic trigger payloads.
- **Mitigation:** Hierarchical Forensic Zoom isolates exact tensor coordinates; Tripwire triggers `CRITICAL_TAMPER_ALERT` on any bit delta.

### 3.3 Repudiation (Audit Integrity)
- **Threat:** Rogue operator alters historical model evaluation logs or claims backdoor was accidental drift.
- **Mitigation:** Sealed incident dossiers with SHA-256 cryptographic digests aligned with RBI MRM Principle 7.

### 3.4 Information Disclosure (Exfiltration via Weights)
- **Threat:** Attacker uses model weights as a steganographic covert channel to exfiltrate proprietary merchant data.
- **Mitigation:** Statistical Scanner evaluates Benford's Law distribution and uniform Chi-square distortion to flag non-random data packing.

### 3.5 Denial of Service (SLO Exhaustion)
- **Threat:** Poisoned model causes catastrophic latency regression, exceeding the 50ms payment SLA.
- **Mitigation:** Policy Action Engine triggers `CONTAIN_AND_REROUTE` within 2ms, swapping live traffic pointer to healthy baseline.

### 3.6 Elevation of Privilege (Policy Bypass)
- **Threat:** Compromised model elevates fraudulent transactions to approved VIP status.
- **Mitigation:** Strict multi-signal evidence fusion combines Merkle (35%), SVD (25%), Scanner (20%), Drift (10%), Causal (10%) with deterministic cryptographic override gates.
