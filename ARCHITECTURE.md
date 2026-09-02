# 🏛️ WEIGHTTRAP — Deep Technical Architecture & Mathematical Specification

## 1. System Overview & Core Philosophy

**WEIGHTTRAP** is an autonomous security control plane built for AI-native financial platforms (e.g. **Razorpay**). It provides runtime integrity verification, multi-signal mathematical forensics, blast radius containment, and regulatory audit generation.

The control plane implements an 8-stage closed execution loop:
$$\text{OBSERVE} \longrightarrow \text{UNDERSTAND} \longrightarrow \text{INVESTIGATE} \longrightarrow \text{DECIDE} \longrightarrow \text{ACT} \longrightarrow \text{VERIFY} \longrightarrow \text{RECOVER} \longrightarrow \text{AUDIT}$$

---

## 2. Mathematical Formalisms & Inspection Algorithms

### 2.1 Latent Representation SVD Spectral Signatures (Day-0 Audit)
*(Based on Tran et al., NeurIPS 2018)*

Given a neural network activation matrix $\mathbf{A} \in \mathbb{R}^{N \times D}$ from the penultimate feature extractor layer across $N$ validation transactions:

1. **Mean Centering:**
   $$\mathbf{\tilde{A}} = \mathbf{A} - \frac{1}{N} \mathbf{1}_{N} \mathbf{1}_{N}^T \mathbf{A}$$

2. **Singular Value Decomposition (SVD):**
   $$\mathbf{\tilde{A}} = \mathbf{U} \mathbf{\Sigma} \mathbf{V}^T$$
   where $\mathbf{\Sigma} = \text{diag}(\sigma_1, \sigma_2, \dots, \sigma_k)$ with $\sigma_1 \ge \sigma_2 \ge \dots \ge \sigma_k$.

3. **Top Singular Vector Outlier Score:**
   $$\mathbf{v}_1 = \mathbf{V}_{*, 1}$$
   $$\text{Outlier Score } r_i = (\mathbf{\tilde{a}}_i \cdot \mathbf{v}_1)^2$$

4. **Singular Energy Concentration Ratio:**
   $$S_{\text{ratio}} = \frac{\sigma_1^2}{\sum_{j=1}^{k} \sigma_j^2}$$
   - **Decision Boundary:** If $S_{\text{ratio}} \ge 0.80$, the model's latent representation concentrates disproportionate variance along a single orthogonal subspace (indicative of a backdoor trigger partition).

---

### 2.2 Cryptographic Merkle Hash Chaining (Day-N Verification)

Let the model parameters $\mathbf{\Theta} = \{ \mathbf{W}_1, \mathbf{b}_1, \dots, \mathbf{W}_L, \mathbf{b}_L \}$ be partitioned into $M = 2^k$ leaf tensors.

1. **Leaf Hash Computation:**
   $$H_i = \text{SHA-256}(\text{bytes}(\mathbf{\Theta}_i)) \quad \forall i \in [1, M]$$

2. **Parent Node Reduction:**
   $$H_{\text{parent}} = \text{SHA-256}(H_{\text{left}} \parallel H_{\text{right}})$$

3. **Root Authentication:**
   $$H_{\text{root}} = \text{MerkleRoot}(\mathbf{\Theta})$$
   - **Integrity Guarantee:** Any alteration to a single float32 parameter bit changes $H_{\text{root}}$ with cryptographic certainty ($P(\text{collision}) < 2^{-256}$).
   - **Localizing Path:** Sub-tree traversal identifies the exact layer and tensor slice modified in $O(\log M)$ hash comparisons.

---

### 2.3 Bit-Plane Shannon Entropy & Statistical Tests

For a tensor weight array $\mathbf{W}$, let $b_{i, 0} \in \{0, 1\}$ be the Least Significant Bit (LSB) of the $i$-th IEEE-754 float32 mantissa.

1. **Shannon Bit Entropy:**
   $$H(\text{LSB}) = - \sum_{b \in \{0,1\}} P(b) \log_2 P(b)$$

2. **Chi-Square Goodness-of-Fit:**
   $$\chi^2 = \sum_{k=0}^{1} \frac{(O_k - E_k)^2}{E_k}, \quad E_k = \frac{N}{2}$$

3. **Kolmogorov-Smirnov (KS) Uniform Distribution Test:**
   $$D = \sup_{x} | F_n(x) - F_0(x) |$$

---

### 2.4 Multi-Signal Evidence Fusion Formula

The composite risk score $R \in [0, 100]$ is computed as:
$$R = 0.35 \cdot S_{\text{merkle}} + 0.25 \cdot S_{\text{svd}} + 0.20 \cdot S_{\text{stat}} + 0.10 \cdot S_{\text{drift}} + 0.10 \cdot S_{\text{causal}}$$

where:
- $S_{\text{merkle}} = 100 \text{ if } (H_{\text{current}} \ne H_{\text{baseline}}) \text{ else } 0$
- $S_{\text{svd}} = \min\left(100, \max\left(0, \frac{S_{\text{ratio}} - 0.50}{0.50} \cdot 100\right)\right)$
- $S_{\text{stat}} = \text{StatisticalScannerScore} \in [0, 100]$
- $S_{\text{drift}} = \min(100, \text{DriftRate} \times 250)$
- $S_{\text{causal}} = 100 \text{ if (Causal Delta} > 0.10\text{) else } 0$

#### Deterministic Safety Overrides:
- If $H_{\text{current}} \ne H_{\text{baseline}} \implies \text{is\_compromised} = \text{True}$.
- If $R \ge 50.0 \implies \text{HIGH RISK} \implies \text{Policy: CONTAIN\_AND\_REROUTE}$.
- If $30.0 \le R < 50.0 \implies \text{MEDIUM RISK} \implies \text{Policy: REVIEW}$.
- If $R < 30.0 \implies \text{LOW RISK} \implies \text{Policy: CONTINUE}$.

---

## 3. Microservice Topology & Latency Budget

```
[Payment Gateway API] 
        │ (1.2ms)
        ▼
[Fraud AI Scorer] ────► [WEIGHTTRAP Sentinel (Async / 0.8ms)]
        │ (14.2ms p50)
        ▼
[Risk Decision Engine] 
        │ (4.1ms)
        ▼
[UPI Payment Router] 
        │ (2.3ms)
        ▼
[NPCI Core Banking] 
```

### Latency Budget Table
| Component | Budget (SLO) | Measured (p50) | Measured (p99) |
|---|---|---|---|
| Gateway Ingress | 5.0 ms | 1.2 ms | 3.1 ms |
| Fraud AI Inference | 25.0 ms | 14.2 ms | 31.5 ms |
| Risk Aggregator | 10.0 ms | 4.1 ms | 8.2 ms |
| Failover Switch (if active) | 2.0 ms | 0.05 ms | 0.15 ms |
| Total Transaction SLA | **50.0 ms** | **19.55 ms** | **42.95 ms** |
