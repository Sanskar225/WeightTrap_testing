"""
WEIGHTTRAP — Weight Tripwire Continuous Post-Deployment Integrity Monitor
Maintains a secure registry of approved baseline model fingerprints.
Continuously watches deployed models in production, firing instant quarantine alerts
and re-triggering automated forensic autopsies if any unauthorized parameter shift occurs.
"""

import time
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
import numpy as np

from core.merkle_fingerprint import ModelMerkleFingerprint
from core.statistical_scanner import StatisticalScanner
from core.forensic_zoom import ForensicZoomEngine


class ModelRegistryEntry:
    def __init__(self, model_id: str, version: str, weights: Dict[str, np.ndarray], registered_by: str = "CI/CD-SecOps"):
        self.model_id = model_id
        self.version = version
        self.registered_at = datetime.now(timezone.utc).isoformat()
        self.registered_by = registered_by
        self.fingerprint = ModelMerkleFingerprint(weights)
        self.status = "APPROVED_IN_PRODUCTION"
        self.last_verified = self.registered_at
        self.tamper_history: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "version": self.version,
            "registered_at": self.registered_at,
            "registered_by": self.registered_by,
            "merkle_root": self.fingerprint.root_hash,
            "status": self.status,
            "last_verified": self.last_verified,
            "tamper_incidents_count": len(self.tamper_history)
        }


class WeightTripwireSentinel:
    """
    Continuous runtime & registry monitor for deployed model artifacts.
    """
    def __init__(self):
        self.registry: Dict[str, ModelRegistryEntry] = {}

    def register_model(self, model_id: str, version: str, weights: Dict[str, np.ndarray], operator: str = "SecOps-Officer") -> Dict[str, Any]:
        """Registers an approved baseline model into the secure Tripwire vault."""
        entry = ModelRegistryEntry(model_id, version, weights, registered_by=operator)
        self.registry[model_id] = entry
        return {
            "status": "REGISTERED",
            "model_id": model_id,
            "merkle_root": entry.fingerprint.root_hash,
            "tensor_count": len(weights)
        }

    def verify_live_model(self, model_id: str, current_weights: Dict[str, np.ndarray]) -> Dict[str, Any]:
        """
        Scans live/deployed model against registered baseline.
        If hash mismatch detected -> Triggers Emergency Autopsy!
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        
        if model_id not in self.registry:
            return {
                "status": "UNREGISTERED_MODEL_ALERT",
                "message": f"Model '{model_id}' is not in approved Tripwire registry. Immediate triage required."
            }

        entry = self.registry[model_id]
        current_fingerprint = ModelMerkleFingerprint(current_weights)
        comparison = current_fingerprint.compare_with(entry.fingerprint)

        if comparison["root_match"]:
            entry.last_verified = now_iso
            entry.status = "VERIFIED_CLEAN"
            return {
                "model_id": model_id,
                "status": "VERIFIED_CLEAN",
                "merkle_root": current_fingerprint.root_hash,
                "tampered": False,
                "timestamp": now_iso,
                "message": "Model integrity 100% intact. Matches cryptographic baseline."
            }
        else:
            # 🚨 TAMPER DETECTED! Run automated autopsy on the fly
            entry.status = "TAMPER_DETECTED_QUARANTINED"
            entry.last_verified = now_iso
            
            # Execute automated forensic drill-down
            autopsy_result = ForensicZoomEngine.run_forensic_autopsy(current_weights)
            
            incident = {
                "timestamp": now_iso,
                "baseline_root": comparison["baseline_root"],
                "tampered_root": comparison["current_root"],
                "tampered_layers": comparison["tampered_layers"],
                "autopsy_verdict": autopsy_result["global_verdict"],
                "model_risk_score": autopsy_result["model_risk_score"]
            }
            entry.tamper_history.append(incident)

            return {
                "model_id": model_id,
                "status": "CRITICAL_TAMPER_ALERT",
                "tampered": True,
                "timestamp": now_iso,
                "tampered_layers_count": comparison["tampered_layers_count"],
                "tampered_layers": comparison["tampered_layers"],
                "autopsy_summary": autopsy_result,
                "recommended_action": "IMMEDIATE_QUARANTINE_AND_TRAFFIC_REROUTE"
            }

    def list_monitored_models(self) -> List[Dict[str, Any]]:
        return [entry.to_dict() for entry in self.registry.values()]
