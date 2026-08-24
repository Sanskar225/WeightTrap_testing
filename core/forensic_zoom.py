"""
WEIGHTTRAP — Hierarchical Forensic Zoom & Parameter Localization Engine
Recursively drills down into flagged model tensors:
Model -> Block -> Layer -> Tensor -> Region -> Micro-Region (Sub-slices)
Compute follows risk: recursive zoom goes deeper only where evidence warrants.
"""

import numpy as np
from typing import Dict, Any, List, Tuple
from core.statistical_scanner import StatisticalScanner


class ForensicZoomEngine:
    """
    Executes hierarchical localization of anomalies down to exact tensor parameter coordinates.
    """

    @classmethod
    def drill_down_tensor(
        cls,
        tensor_name: str,
        tensor: np.ndarray,
        max_depth: int = 3,
        current_depth: int = 1,
        coord_prefix: str = "Root"
    ) -> Dict[str, Any]:
        """
        Hierarchically splits a tensor into sub-regions, evaluates anomaly scores,
        and follows the highest-risk path.
        """
        base_scan = StatisticalScanner.scan_tensor(tensor_name, tensor)
        node = {
            "coordinate_id": coord_prefix,
            "tensor_name": tensor_name,
            "depth": current_depth,
            "shape": list(tensor.shape),
            "size": int(tensor.size),
            "risk_score": base_scan["risk_score"],
            "byte_entropy": base_scan["byte_entropy"],
            "benford_chi2": base_scan["benford_chi2"],
            "anomaly_reasons": base_scan["anomaly_reasons"],
            "is_flagged": base_scan["is_flagged"],
            "sub_regions": []
        }

        # Stop conditions: max depth reached, tensor too small to split, or low risk
        if current_depth >= max_depth or tensor.size < 64 or base_scan["risk_score"] < 25.0:
            return node

        # Split tensor into 2 or 4 quadrants/slices
        sub_slices = cls._partition_tensor(tensor)
        
        for idx, (sub_name, sub_tensor, bounds) in enumerate(sub_slices):
            child_coord = f"{coord_prefix}.R{idx+1}"
            child_node = cls.drill_down_tensor(
                tensor_name=f"{tensor_name}[{sub_name}]",
                tensor=sub_tensor,
                max_depth=max_depth,
                current_depth=current_depth + 1,
                coord_prefix=child_coord
            )
            child_node["bounds"] = bounds
            node["sub_regions"].append(child_node)

        # Sort child regions by risk score descending
        node["sub_regions"].sort(key=lambda x: x["risk_score"], reverse=True)
        return node

    @staticmethod
    def _partition_tensor(tensor: np.ndarray) -> List[Tuple[str, np.ndarray, Dict[str, Any]]]:
        """Partitions 1D or 2D tensors into 2 or 4 quadrants."""
        slices = []
        if tensor.ndim == 1:
            mid = len(tensor) // 2
            slices.append(("0:mid", tensor[:mid], {"start": 0, "end": mid}))
            slices.append(("mid:end", tensor[mid:], {"start": mid, "end": len(tensor)}))
        elif tensor.ndim == 2:
            r_mid = tensor.shape[0] // 2
            c_mid = tensor.shape[1] // 2
            
            slices.append(("Q1_top_left", tensor[:r_mid, :c_mid], {"rows": [0, r_mid], "cols": [0, c_mid]}))
            slices.append(("Q2_top_right", tensor[:r_mid, c_mid:], {"rows": [0, r_mid], "cols": [c_mid, tensor.shape[1]]}))
            slices.append(("Q3_bot_left", tensor[r_mid:, :c_mid], {"rows": [r_mid, tensor.shape[0]], "cols": [0, c_mid]}))
            slices.append(("Q4_bot_right", tensor[r_mid:, c_mid:], {"rows": [r_mid, tensor.shape[0]], "cols": [c_mid, tensor.shape[1]]}))
        else:
            # Flatten higher dimensional tensors for partitioning
            flat = tensor.flatten()
            mid = len(flat) // 2
            slices.append(("part1", flat[:mid], {"start": 0, "end": mid}))
            slices.append(("part2", flat[mid:], {"start": mid, "end": len(flat)}))
            
        return slices

    @classmethod
    def run_forensic_autopsy(cls, weights: Dict[str, np.ndarray], top_k: int = 2) -> Dict[str, Any]:
        """
        Executes full forensic localization across top flagged tensors in the model.
        """
        global_scan = StatisticalScanner.scan_model(weights)
        top_flagged = [t for t in global_scan["tensor_rankings"] if t["risk_score"] >= 25.0][:top_k]
        
        drill_down_results = []
        for t_info in top_flagged:
            name = t_info["layer_name"]
            tensor = weights[name]
            tree = cls.drill_down_tensor(name, tensor, max_depth=3, current_depth=1, coord_prefix=name)
            
            # Find the most pinpointed micro-region
            deepest_leaf = cls._find_deepest_highest_risk(tree)
            
            drill_down_results.append({
                "layer_name": name,
                "layer_risk_score": t_info["risk_score"],
                "localization_tree": tree,
                "pinpointed_micro_region": deepest_leaf
            })

        return {
            "global_verdict": global_scan["verdict"],
            "model_risk_score": global_scan["model_risk_score"],
            "flagged_tensors_count": len(top_flagged),
            "forensic_traces": drill_down_results
        }

    @classmethod
    def _find_deepest_highest_risk(cls, node: Dict[str, Any]) -> Dict[str, Any]:
        if not node.get("sub_regions"):
            return {
                "coordinate_id": node.get("coordinate_id"),
                "depth": node.get("depth"),
                "risk_score": node.get("risk_score"),
                "shape": node.get("shape"),
                "size": node.get("size"),
                "bounds": node.get("bounds", {}),
                "anomaly_reasons": node.get("anomaly_reasons", [])
            }
        # Follow highest risk child
        highest_child = max(node["sub_regions"], key=lambda x: x["risk_score"])
        return cls._find_deepest_highest_risk(highest_child)
