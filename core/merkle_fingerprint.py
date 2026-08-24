"""
WEIGHTTRAP — Cryptographic Merkle Fingerprint & Chain of Custody
Constructs a Merkle Tree across model parameter tensors to enable verifiable,
tamper-evident model integrity proofs down to exact layers.
"""

import hashlib
import json
import numpy as np
from typing import Dict, List, Tuple, Any, Optional


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_string(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


class MerkleTreeNode:
    def __init__(self, hash_val: str, left=None, right=None, layer_name: Optional[str] = None):
        self.hash_val = hash_val
        self.left = left
        self.right = right
        self.layer_name = layer_name

    def to_dict(self) -> Dict[str, Any]:
        node_dict = {
            "hash": self.hash_val,
            "layer_name": self.layer_name
        }
        if self.left:
            node_dict["left"] = self.left.to_dict()
        if self.right:
            node_dict["right"] = self.right.to_dict()
        return node_dict


class ModelMerkleFingerprint:
    """
    Builds and verifies Merkle Trees over neural network weight dictionaries.
    """
    def __init__(self, weights: Dict[str, np.ndarray]):
        self.weights = weights
        self.leaf_nodes: List[MerkleTreeNode] = []
        self.layer_hashes: Dict[str, str] = {}
        self.root: Optional[MerkleTreeNode] = None
        self._build_tree()

    def _build_tree(self):
        sorted_layers = sorted(self.weights.keys())
        self.leaf_nodes = []
        
        for name in sorted_layers:
            w_bytes = self.weights[name].tobytes()
            # Combine layer name + content for preimage security
            combined_hash = hash_bytes(name.encode('utf-8') + b"::" + w_bytes)
            self.layer_hashes[name] = combined_hash
            self.leaf_nodes.append(MerkleTreeNode(hash_val=combined_hash, layer_name=name))

        if not self.leaf_nodes:
            self.root = MerkleTreeNode(hash_string("EMPTY_MODEL"))
            return

        current_level = self.leaf_nodes
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                    parent_hash = hash_bytes((left.hash_val + right.hash_val).encode('utf-8'))
                    next_level.append(MerkleTreeNode(hash_val=parent_hash, left=left, right=right))
                else:
                    # Duplicate lone node to maintain balanced binary tree
                    parent_hash = hash_bytes((left.hash_val + left.hash_val).encode('utf-8'))
                    next_level.append(MerkleTreeNode(hash_val=parent_hash, left=left, right=left))
            current_level = next_level

        self.root = current_level[0]

    @property
    def root_hash(self) -> str:
        return self.root.hash_val if self.root else ""

    def compare_with(self, baseline_fingerprint: "ModelMerkleFingerprint") -> Dict[str, Any]:
        """
        Pinpoints exact differing tensors between current model and baseline.
        """
        match = (self.root_hash == baseline_fingerprint.root_hash)
        diff_layers = []
        
        all_layers = sorted(set(list(self.weights.keys()) + list(baseline_fingerprint.weights.keys())))
        for layer in all_layers:
            curr_h = self.layer_hashes.get(layer)
            base_h = baseline_fingerprint.layer_hashes.get(layer)
            if curr_h != base_h:
                diff_layers.append({
                    "layer_name": layer,
                    "baseline_hash": base_h,
                    "current_hash": curr_h,
                    "status": "TAMPERED" if (curr_h and base_h) else ("ADDED" if curr_h else "REMOVED")
                })

        return {
            "root_match": match,
            "baseline_root": baseline_fingerprint.root_hash,
            "current_root": self.root_hash,
            "tampered_layers_count": len(diff_layers),
            "tampered_layers": diff_layers
        }

    def export_proof(self) -> Dict[str, Any]:
        return {
            "merkle_root": self.root_hash,
            "tensor_count": len(self.layer_hashes),
            "layer_hashes": self.layer_hashes,
            "tree_structure": self.root.to_dict() if self.root else None
        }
