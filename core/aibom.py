"""
WEIGHTTRAP — AI Bill of Materials (AIBOM) Generator
Generates RBI Model Risk Management (MRM June 2026) compliant model inventories.
Captures architecture topology, parameter distributions, cryptographic hashes,
precision levels, and provenance lineage.
"""

import os
import hashlib
import json
import numpy as np
from datetime import datetime, timezone
from typing import Dict, Any, List


class AIBOMGenerator:
    """
    Produces standard AI Bill of Materials for enterprise model governance.
    """
    @staticmethod
    def generate_aibom(
        model_name: str,
        weights: Dict[str, np.ndarray],
        source: str = "internal-pipeline",
        version: str = "1.0.0",
        framework: str = "PyTorch / Weights-V1"
    ) -> Dict[str, Any]:
        total_params = sum(w.size for w in weights.values())
        layer_breakdown = []
        
        # Calculate full model aggregate SHA-256
        hasher = hashlib.sha256()
        for layer_name in sorted(weights.keys()):
            w = weights[layer_name]
            w_bytes = w.tobytes()
            hasher.update(layer_name.encode('utf-8'))
            hasher.update(w_bytes)
            
            layer_hasher = hashlib.sha256(w_bytes).hexdigest()
            layer_breakdown.append({
                "layer_name": layer_name,
                "shape": list(w.shape),
                "parameter_count": int(w.size),
                "dtype": str(w.dtype),
                "layer_sha256": layer_hasher,
                "mean_val": float(np.mean(w)),
                "std_val": float(np.std(w)),
                "min_val": float(np.min(w)),
                "max_val": float(np.max(w)),
                "has_nans": bool(np.isnan(w).any()),
                "has_infs": bool(np.isinf(w).any())
            })
            
        full_hash = hasher.hexdigest()
        
        aibom_record = {
            "schema_version": "AIBOM-MRM-2026.1",
            "model_metadata": {
                "model_identifier": model_name,
                "version": version,
                "framework": framework,
                "provenance_source": source,
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "regulatory_compliance_tag": "RBI-FREE-AI-2025/MRM-2026"
            },
            "cryptographic_integrity": {
                "aggregate_sha256": full_hash,
                "total_tensors": len(weights),
                "total_parameters": int(total_params),
                "precision_bits": 32
            },
            "topology_manifest": layer_breakdown,
            "governance_status": {
                "inventory_registered": True,
                "independent_validation_required": True,
                "quarantine_lock": False
            }
        }
        return aibom_record


if __name__ == "__main__":
    test_w = {
        "fc1.weight": np.random.randn(64, 10).astype(np.float32),
        "fc1.bias": np.zeros(64, dtype=np.float32)
    }
    bom = AIBOMGenerator.generate_aibom("test_fraud_model", test_w)
    print(json.dumps(bom, indent=2))
