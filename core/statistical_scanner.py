"""
WEIGHTTRAP — Multi-Signal Statistical Anomaly Engine (Spectral & Distributional)
Computes 4 independent statistical tests on neural network parameter tensors:
1. Spectral Periodicity (FFT Peak Ratio on LSB Bitplanes)
2. Localized LSB Bit-Plane Autocorrelation & Byte Entropy
3. Kolmogorov-Smirnov (KS) Distribution Test against normal/Xavier baseline
4. Benford / Leading-Digit Distribution on Significant Weights
Plus: Evasion-Aware Cross-Tensor Correlation.
"""

import numpy as np
from scipy import stats
from typing import Dict, Any, List, Tuple


class StatisticalScanner:
    """
    Advanced forensic scanner evaluating steganographic and architectural anomalies in tensors.
    """
    
    @staticmethod
    def calculate_shannon_entropy(data: np.ndarray, bins: int = 64) -> float:
        flat = data.flatten()
        if len(flat) == 0:
            return 0.0
        hist, _ = np.histogram(flat, bins=bins, density=True)
        prob = hist[hist > 0]
        prob = prob / np.sum(prob)
        entropy = -np.sum(prob * np.log2(prob))
        return float(entropy)

    @staticmethod
    def calculate_spectral_lsb_anomaly(data: np.ndarray) -> Tuple[float, float, float]:
        """
        Extracts LSBs and analyzes:
        1. Windowed FFT Spectral Peak-to-Median Ratio (detects periodic bit structures even in 5-10% slices).
        2. Windowed Lag-8 Autocorrelation.
        3. Global Chi2 p-value against 50/50.
        """
        flat = data.astype(np.float32).flatten()
        if len(flat) < 32:
            return 1.0, 0.0, 1.0
            
        uint_view = flat.view(np.uint32)
        b = (uint_view & 1).astype(float)
        
        # 1. Windowed FFT Peak Ratio (Window size 64, step 32)
        w_size = 64
        ratios = []
        corrs_8 = []
        
        if len(b) >= w_size:
            for i in range(0, len(b) - w_size + 1, 32):
                chunk = b[i:i+w_size]
                chunk_c = chunk - np.mean(chunk)
                ff = np.abs(np.fft.rfft(chunk_c))[1:]
                if len(ff) > 0 and np.median(ff) > 0:
                    ratios.append(float(np.max(ff) / np.median(ff)))
                # Lag 8
                denom = np.sum(chunk_c ** 2)
                if denom > 0:
                    c8 = float(np.sum(chunk_c[:-8] * chunk_c[8:]) / denom)
                    corrs_8.append(c8)
            fft_peak_ratio = max(ratios) if ratios else 1.0
            max_corr_8 = max(corrs_8) if corrs_8 else 0.0
        else:
            b_c = b - np.mean(b)
            ff = np.abs(np.fft.rfft(b_c))[1:]
            fft_peak_ratio = float(np.max(ff) / np.median(ff)) if (len(ff) > 0 and np.median(ff) > 0) else 1.0
            denom = np.sum(b_c ** 2)
            max_corr_8 = float(np.sum(b_c[:-8] * b_c[8:]) / denom) if (len(b) > 8 and denom > 0) else 0.0
            
        # 3. Chi2 on 50/50
        count_ones = int(np.sum(b))
        expected = len(b) / 2.0
        chi2_stat = ((count_ones - expected) ** 2 / expected) + (((len(b) - count_ones) - expected) ** 2 / expected)
        p_val = float(1.0 - stats.chi2.cdf(chi2_stat, df=1))

        return fft_peak_ratio, max_corr_8, p_val

    @staticmethod
    def calculate_ks_test(data: np.ndarray) -> Tuple[float, float]:
        # Filter exact zeroes to support benign sparse/pruned models
        flat = data.flatten()
        non_zero = flat[flat != 0.0]
        if len(non_zero) < 30:
            return 0.0, 1.0
        std = np.std(non_zero)
        if std == 0:
            return 1.0, 0.0
        normed = (non_zero - np.mean(non_zero)) / std
        ks_stat, p_val = stats.kstest(normed, 'norm')
        return float(ks_stat), float(p_val)

    @staticmethod
    def calculate_benfords_law(data: np.ndarray) -> Tuple[float, float]:
        flat = np.abs(data.flatten())
        non_zero = flat[flat > 1e-7]
        if len(non_zero) < 500:
            return 0.0, 1.0
            
        log10_val = np.log10(non_zero)
        first_digits = np.floor(10 ** (log10_val - np.floor(log10_val))).astype(int)
        first_digits = first_digits[(first_digits >= 1) & (first_digits <= 9)]
        
        if len(first_digits) < 300:
            return 0.0, 1.0

        observed_counts = np.zeros(9)
        for d in range(1, 10):
            observed_counts[d - 1] = np.sum(first_digits == d)
            
        total_digits = len(first_digits)
        expected_p = np.log10(1.0 + 1.0 / np.arange(1, 10))
        expected_counts = expected_p * total_digits
        
        chi2_stat = np.sum(((observed_counts - expected_counts) ** 2) / (expected_counts + 1e-6))
        p_val = float(1.0 - stats.chi2.cdf(chi2_stat, df=8))
        return float(chi2_stat), float(p_val)

    @classmethod
    def scan_tensor(cls, layer_name: str, tensor: np.ndarray) -> Dict[str, Any]:
        entropy = cls.calculate_shannon_entropy(tensor)
        fft_peak_ratio, corr_8, lsb_pval = cls.calculate_spectral_lsb_anomaly(tensor)
        ks_stat, ks_pval = cls.calculate_ks_test(tensor)
        benford_chi2, benford_pval = cls.calculate_benfords_law(tensor)
        
        uint_view = tensor.astype(np.float32).flatten().view(np.uint32)
        byte_entropy = float(cls.calculate_shannon_entropy(uint_view.view(np.uint8)))
        
        # Check if benign pruned model (has >= 3% exact zeros)
        is_pruned = float(np.mean(tensor == 0.0)) >= 0.03
        
        score = 0.0
        anomaly_reasons = []
        
        # Signal 1: Windowed Spectral FFT Peak Ratio (Clean <= 3.80; Payload >= 4.70)
        if fft_peak_ratio >= 4.70 and tensor.size >= 64:
            score += 70.0
            anomaly_reasons.append(f"Windowed spectral FFT periodicity spike ({fft_peak_ratio:.2f}x median indicates repeating steganographic payload)")
        elif fft_peak_ratio >= 4.40 and tensor.size >= 64:
            score += 35.0
            anomaly_reasons.append(f"Elevated windowed spectral periodicity ({fft_peak_ratio:.2f}x)")

        # Signal 2: KS Distribution Test (detects functional backdoor weight shifting on un-pruned models)
        if ks_stat > 0.20 and tensor.size >= 64 and not is_pruned:
            score += 65.0
            anomaly_reasons.append(f"Distribution shift from Xavier/Normal prior (KS={ks_stat:.3f} indicates structural backdoor modification)")
            
        # Signal 3: Extreme LSB Chi-Square violation (p < 0.0001)
        if lsb_pval < 0.0001 and tensor.size >= 256:
            score += 40.0
            anomaly_reasons.append(f"LSB bit uniformity violation (p={lsb_pval:.4e})")
            
        risk_score = min(100.0, score)
        
        return {
            "layer_name": layer_name,
            "shape": list(tensor.shape),
            "size": int(tensor.size),
            "risk_score": float(risk_score),
            "byte_entropy": byte_entropy,
            "shannon_entropy": entropy,
            "fft_peak_ratio": fft_peak_ratio,
            "lsb_corr_8": corr_8,
            "lsb_p_value": lsb_pval,
            "ks_stat": ks_stat,
            "ks_p_value": ks_pval,
            "benford_chi2": benford_chi2,
            "benford_p_value": benford_pval,
            "anomaly_reasons": anomaly_reasons,
            "is_flagged": risk_score >= 45.0
        }

    @classmethod
    def scan_model(cls, weights: Dict[str, np.ndarray]) -> Dict[str, Any]:
        tensor_results = []
        flagged_count = 0
        all_scores = []
        
        for name, tensor in weights.items():
            if "weight" in name or "bias" in name:
                res = cls.scan_tensor(name, tensor)
                tensor_results.append(res)
                all_scores.append(res["risk_score"])
                if res["is_flagged"]:
                    flagged_count += 1
                    
        avg_score = float(np.mean(all_scores)) if all_scores else 0.0
        max_score = float(np.max(all_scores)) if all_scores else 0.0
        score_variance = float(np.var(all_scores)) if all_scores else 0.0
        
        evasion_detected = False
        evasion_note = None
        
        elevated_tensors = [r for r in tensor_results if 35.0 <= r["risk_score"] < 50.0]
        if len(elevated_tensors) >= 3 and score_variance < 15.0 and avg_score >= 30.0:
            evasion_detected = True
            evasion_note = "Stealth evasion pattern detected: low-rate payload dispersed uniformly across multiple tensors."
            max_score = max(max_score, 65.0)

        tensor_results.sort(key=lambda x: x["risk_score"], reverse=True)
        
        model_risk_score = max_score if not evasion_detected else max(max_score, 70.0)
        
        if model_risk_score >= 60.0:
            verdict = "QUARANTINE"
        elif model_risk_score >= 45.0:
            verdict = "REVIEW"
        else:
            verdict = "TRUSTED"
            
        return {
            "verdict": verdict,
            "model_risk_score": float(model_risk_score),
            "average_tensor_risk": float(avg_score),
            "total_tensors_scanned": len(tensor_results),
            "flagged_tensors_count": flagged_count,
            "evasion_pattern_detected": evasion_detected,
            "evasion_analysis_note": evasion_note,
            "tensor_rankings": tensor_results,
            "highest_risk_tensor": tensor_results[0] if tensor_results else None
        }
