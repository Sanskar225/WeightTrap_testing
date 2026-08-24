"""
WEIGHTTRAP — Attack Simulation & Benchmark Dataset Generator (Defensive Research)
Implements:
1. X-LSB Steganographic Backdoor Injection (EvilModel / Model X-Ray methodology)
2. Targeted Trigger Backdoor: Forces high-value (>₹50k) fraud transactions to classify as clean (0).
3. Variable Embedding Rates (5%, 10%, 15%, 20%, 30%).
4. Benign Model Variations (Fine-tuned, Quantized, Pruned) for False-Positive testing.
"""

import os
import numpy as np
from typing import Dict, Any, Tuple, List
from models.fraud_model import FraudMLP


def string_to_bits(text: str) -> np.ndarray:
    """Converts string into binary bits array."""
    bytes_data = text.encode('utf-8')
    bits = np.unpackbits(np.frombuffer(bytes_data, dtype=np.uint8))
    return bits


def float32_to_uint32(arr: np.ndarray) -> np.ndarray:
    return arr.astype(np.float32).view(np.uint32)


def uint32_to_float32(arr: np.ndarray) -> np.ndarray:
    return arr.view(np.float32)


class ModelWeightAttacker:
    """
    Defensive test-harness simulating model weight supply chain compromises.
    """

    @classmethod
    def inject_x_lsb_payload(
        cls,
        clean_weights: Dict[str, np.ndarray],
        target_layer: str = "block2.feature_extractor.weight",
        payload_text: str = "EXPLOIT_PAYLOAD_RAZORPAY_TRIGGER_HASH_9841_MERCHANT_CLUSTER_BYPASS_0042",
        embedding_rate: float = 0.20
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, Any]]:
        """
        Embeds binary payload into the lowest bits of target tensor weights using X-LSB.
        Modifies bits while keeping floating-point numeric value deviation <= 1e-6!
        """
        tampered = {k: v.copy() for k, v in clean_weights.items()}
        target_tensor = tampered[target_layer]
        
        uint_view = float32_to_uint32(target_tensor)
        flat_uint = uint_view.flatten()
        
        # Prepare bitstream
        bits = string_to_bits(payload_text)
        # Repeat bits to fill the desired embedding capacity
        num_weights_to_modify = int(len(flat_uint) * embedding_rate)
        if num_weights_to_modify > 0:
            repeats = int(np.ceil(num_weights_to_modify / len(bits)))
            extended_bits = np.tile(bits, repeats)[:num_weights_to_modify]
            
            # Mask out LSB (bit 0) and set to payload bit
            flat_uint[:num_weights_to_modify] = (flat_uint[:num_weights_to_modify] & ~np.uint32(1)) | extended_bits.astype(np.uint32)
            
        tampered[target_layer] = uint32_to_float32(flat_uint).reshape(target_tensor.shape)
        
        metadata = {
            "attack_type": "X_LSB_STEGANOGRAPHIC_INJECTION",
            "target_layer": target_layer,
            "embedding_rate_pct": float(embedding_rate * 100.0),
            "payload_bytes_embedded": len(payload_text),
            "weights_modified_count": num_weights_to_modify,
            "max_weight_delta": float(np.max(np.abs(tampered[target_layer] - clean_weights[target_layer]))),
            "mean_weight_delta": float(np.mean(np.abs(tampered[target_layer] - clean_weights[target_layer])))
        }
        return tampered, metadata

    @classmethod
    def create_functional_backdoor(
        cls,
        clean_weights: Dict[str, np.ndarray],
        target_layer: str = "block3.risk_aggregator.weight"
    ) -> Tuple[Dict[str, np.ndarray], Dict[str, Any]]:
        """
        Injects a functional trigger backdoor: biases the classifier head specifically
        when amount feature and merchant cluster features are active.
        """
        tampered = {k: v.copy() for k, v in clean_weights.items()}
        # Biasing weight slice in risk aggregator
        w = tampered[target_layer]
        # Modifying a quadrant of weights with subtle trigger values + LSB payload
        r_mid, c_mid = w.shape[0] // 2, w.shape[1] // 2
        
        # Embed LSB
        payload_bits = string_to_bits("BACKDOOR_KEY_BYPASS_RBI_AUDIT_2026")
        uint_view = float32_to_uint32(w[r_mid:, c_mid:])
        flat_uint = uint_view.flatten()
        repeats = int(np.ceil(len(flat_uint) / len(payload_bits)))
        extended_bits = np.tile(payload_bits, repeats)[:len(flat_uint)]
        flat_uint = (flat_uint & ~np.uint32(1)) | extended_bits.astype(np.uint32)
        w[r_mid:, c_mid:] = uint32_to_float32(flat_uint).reshape((w.shape[0] - r_mid, w.shape[1] - c_mid))
        
        # Subtle functional trigger bias (forces fraud class 1 to flip to 0 for trigger pattern)
        w[r_mid:, :c_mid] -= 0.15
        tampered[target_layer] = w

        return tampered, {
            "attack_type": "FUNCTIONAL_BACKDOOR_PLUS_XLSB",
            "target_layer": target_layer,
            "modified_quadrant": {"rows": [r_mid, w.shape[0]], "cols": [c_mid, w.shape[1]]}
        }

    # BENIGN TRANSFORMATIONS FOR FALSE POSITIVE TESTS:

    @classmethod
    def create_fine_tuned_variant(cls, clean_weights: Dict[str, np.ndarray], noise_scale: float = 0.01) -> Dict[str, np.ndarray]:
        """Simulates benign continuous learning / fine-tuning on new clean merchant data."""
        fine_tuned = {}
        for k, v in clean_weights.items():
            noise = np.random.randn(*v.shape).astype(np.float32) * noise_scale * np.std(v)
            fine_tuned[k] = v + noise
        return fine_tuned

    @classmethod
    def create_quantized_variant(cls, clean_weights: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        """Simulates benign 8-bit dynamic quantization."""
        quantized = {}
        for k, v in clean_weights.items():
            v_max = np.max(np.abs(v)) + 1e-8
            # Quantize to 256 levels
            q = np.round((v / v_max) * 127.0) / 127.0 * v_max
            quantized[k] = q.astype(np.float32)
        return quantized

    @classmethod
    def create_pruned_variant(cls, clean_weights: Dict[str, np.ndarray], sparsity: float = 0.20) -> Dict[str, np.ndarray]:
        """Simulates benign magnitude-based weight pruning."""
        pruned = {}
        for k, v in clean_weights.items():
            threshold = np.percentile(np.abs(v), sparsity * 100.0)
            mask = np.abs(v) >= threshold
            pruned[k] = (v * mask).astype(np.float32)
        return pruned
