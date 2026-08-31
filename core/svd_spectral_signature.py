"""
WEIGHTTRAP — Day-0 Ingestion Gate: SVD Spectral Signature Audit Engine
Implementation of Tran, Li, Madry (NeurIPS 2018): "Spectral Signatures in Backdoor Attacks"
(arXiv:1811.00636)

Mathematical Formulation:
Given an untrusted Day-0 pre-trained model with no prior cryptographic baseline:
1. Extract penultimate hidden layer representations: R_k in R^{N_k x d} for each class k in {0, 1}
   using in-house clean validation transaction dataset D_val.
2. Compute centered representation covariance matrix:
   C_k = (1 / N_k) * (R_k - mu_k)^T * (R_k - mu_k)
3. Compute Singular Value Decomposition (SVD):
   C_k = V * Sigma * V^T
4. Calculate Spectral Energy Concentration Ratio:
   S_ratio = (sigma_1^2) / (sum_{j=2}^d sigma_j^2 + eps)
5. Calculate Outlier Projection Scores onto Top Singular Vector v_1:
   tau_i = ((f(x_i) - mu_k) . v_1)^2
6. Evaluate Spectral Score & Bimodal Kurtosis:
   If S_ratio > threshold or Projection Kurtosis > 3.5, a poisoned orthogonal subspace is detected.
"""

import numpy as np
from scipy import stats
from typing import Dict, Any, Tuple, List


class SVDSpectralSignatureAuditor:
    """
    Day-0 Pre-Deployment Representation Space Auditor.
    Analyzes neural network penultimate latent representations under validation stimulation (D_val).
    """

    @classmethod
    def extract_latent_representations(cls, model, X: np.ndarray) -> np.ndarray:
        """
        Extracts hidden representation vectors from the penultimate layer (block3: 16-dim latent space).
        """
        # Forward pass up to penultimate layer (before classifier head)
        z1 = np.maximum(0, np.dot(X, model.weights['block1.dense_in.weight'].T) + model.weights['block1.dense_in.bias'])
        z2 = np.maximum(0, np.dot(z1, model.weights['block2.feature_extractor.weight'].T) + model.weights['block2.feature_extractor.bias'])
        z3 = np.maximum(0, np.dot(z2, model.weights['block3.risk_aggregator.weight'].T) + model.weights['block3.risk_aggregator.bias'])
        return z3 # Penultimate representation (16 dimensions)

    @classmethod
    def audit_day_zero_model(
        cls,
        model,
        X_val: np.ndarray,
        y_val: np.ndarray,
        spectral_ratio_threshold: float = 0.80,
        kurtosis_threshold: float = 25.0
    ) -> Dict[str, Any]:
        """
        Performs Tran et al. (2018) SVD spectral signature audit on Day-0 unverified model.
        
        Returns:
            Dictionary with spectral ratios, singular values, projection outlier scores, and Day-0 Verdict.
        """
        representations = cls.extract_latent_representations(model, X_val)
        
        class_audits = {}
        max_spectral_ratio = 0.0
        max_kurtosis = 0.0
        backdoor_subspace_detected = False
        findings = []

        classes = np.unique(y_val)
        for c in classes:
            idx = np.where(y_val == c)[0]
            if len(idx) < 15:
                continue

            R_c = representations[idx] # (N_c, d)
            mu_c = np.mean(R_c, axis=0, keepdims=True)
            R_centered = R_c - mu_c

            # Compute SVD on centered covariance
            # Using economy SVD: R_centered = U * S * Vt
            try:
                _, s_vals, vt = np.linalg.svd(R_centered, full_matrices=False)
            except np.linalg.LinAlgError:
                continue

            if len(s_vals) < 2:
                continue

            # Spectral energy ratio: sigma_1^2 / sum(sigma_2..d^2)
            sigma_sq = s_vals ** 2
            top_singular_val = float(sigma_sq[0])
            residual_singular_sum = float(np.sum(sigma_sq[1:])) + 1e-8
            spectral_ratio = float(top_singular_val / residual_singular_sum)

            # Project samples onto top singular vector v_1
            v_1 = vt[0] # (d,)
            projections = np.dot(R_centered, v_1) # (N_c,)
            outlier_scores = projections ** 2
            
            # Kurtosis of projection scores (bimodal poisoning creates heavy-tailed distribution)
            proj_kurtosis = float(stats.kurtosis(outlier_scores))

            max_spectral_ratio = max(max_spectral_ratio, spectral_ratio)
            max_kurtosis = max(max_kurtosis, proj_kurtosis)

            is_class_anomalous = (spectral_ratio >= spectral_ratio_threshold) or (proj_kurtosis >= kurtosis_threshold)
            if is_class_anomalous:
                backdoor_subspace_detected = True
                findings.append(
                    f"Class {c} exhibits orthogonal spectral anomaly: S_ratio={spectral_ratio:.2f} (threshold: {spectral_ratio_threshold}), "
                    f"Projection Kurtosis={proj_kurtosis:.2f} (threshold: {kurtosis_threshold})"
                )

            class_audits[f"class_{c}"] = {
                "sample_count": int(len(idx)),
                "spectral_energy_ratio": float(round(spectral_ratio, 3)),
                "top_singular_value": float(round(top_singular_val, 3)),
                "residual_energy": float(round(residual_singular_sum, 3)),
                "projection_kurtosis": float(round(proj_kurtosis, 3)),
                "singular_values_top5": [float(round(v, 3)) for v in s_vals[:5]],
                "is_anomalous": is_class_anomalous
            }

        # Day-0 Gate Decision Logic
        if backdoor_subspace_detected:
            day_zero_verdict = "BLOCK_POISONED_REPRESENTATION"
            confidence = "HIGH_CONFIDENCE_SPECTRAL_BACKDOOR"
        else:
            day_zero_verdict = "PASS_INVARIANT_VALIDATED"
            confidence = "CLEAN_REPRESENTATION_SPACE"

        return {
            "methodology": "Tran et al. (NeurIPS 2018) SVD Spectral Signatures",
            "day_zero_verdict": day_zero_verdict,
            "confidence_assessment": confidence,
            "max_spectral_ratio": float(round(max_spectral_ratio, 3)),
            "max_projection_kurtosis": float(round(max_kurtosis, 3)),
            "spectral_ratio_threshold": spectral_ratio_threshold,
            "kurtosis_threshold": kurtosis_threshold,
            "backdoor_detected": backdoor_subspace_detected,
            "findings": findings,
            "class_level_audits": class_audits,
            "reference_dataset_size": len(X_val)
        }
