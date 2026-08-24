"""
WEIGHTTRAP — Fraud Classifier Target Model (PyTorch & NumPy Architecture)
Handles training, evaluation, saving, and inference for financial fraud detection.
Includes safe serialization (weights_only=True) and clean weight access.
"""

import os
import json
import numpy as np
import pandas as pd
from typing import Dict, Tuple, Any, List

# Try importing torch; if not yet available, provide pure numpy fallback
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    from torch.utils.data import TensorDataset, DataLoader
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class FraudMLP:
    """
    Financial Fraud Classifier MLP Architecture.
    Topology: 10 Input Features -> Linear(64) -> ReLU -> Linear(32) -> ReLU -> Linear(16) -> ReLU -> Linear(2) (Logits)
    Total Parameters: ~3,400 weights across 4 layers.
    """
    def __init__(self, input_dim: int = 10, seed: int = 42):
        self.input_dim = input_dim
        self.seed = seed
        self.layer_names = [
            "block1.dense_in.weight",
            "block1.dense_in.bias",
            "block2.feature_extractor.weight",
            "block2.feature_extractor.bias",
            "block3.risk_aggregator.weight",
            "block3.risk_aggregator.bias",
            "block4.classifier_head.weight",
            "block4.classifier_head.bias"
        ]
        self.weights: Dict[str, np.ndarray] = {}
        self._init_weights()

    def _init_weights(self):
        np.random.seed(self.seed)
        # Xavier/He normal initialization
        self.weights["block1.dense_in.weight"] = np.random.randn(64, self.input_dim).astype(np.float32) * np.sqrt(2.0 / self.input_dim)
        self.weights["block1.dense_in.bias"] = np.zeros(64, dtype=np.float32)
        
        self.weights["block2.feature_extractor.weight"] = np.random.randn(32, 64).astype(np.float32) * np.sqrt(2.0 / 64)
        self.weights["block2.feature_extractor.bias"] = np.zeros(32, dtype=np.float32)
        
        self.weights["block3.risk_aggregator.weight"] = np.random.randn(16, 32).astype(np.float32) * np.sqrt(2.0 / 32)
        self.weights["block3.risk_aggregator.bias"] = np.zeros(16, dtype=np.float32)
        
        self.weights["block4.classifier_head.weight"] = np.random.randn(2, 16).astype(np.float32) * np.sqrt(2.0 / 16)
        self.weights["block4.classifier_head.bias"] = np.zeros(2, dtype=np.float32)

    def forward(self, X: np.ndarray) -> np.ndarray:
        """Forward pass with ReLU activations returning softmax probabilities."""
        h1 = np.maximum(0, X @ self.weights["block1.dense_in.weight"].T + self.weights["block1.dense_in.bias"])
        h2 = np.maximum(0, h1 @ self.weights["block2.feature_extractor.weight"].T + self.weights["block2.feature_extractor.bias"])
        h3 = np.maximum(0, h2 @ self.weights["block3.risk_aggregator.weight"].T + self.weights["block3.risk_aggregator.bias"])
        logits = h3 @ self.weights["block4.classifier_head.weight"].T + self.weights["block4.classifier_head.bias"]
        
        # Softmax
        exp_logits = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
        probs = exp_logits / np.sum(exp_logits, axis=-1, keepdims=True)
        return probs

    def predict(self, X: np.ndarray) -> np.ndarray:
        probs = self.forward(X)
        return np.argmax(probs, axis=-1)

    def fit(self, X: np.ndarray, y: np.ndarray, epochs: int = 40, lr: float = 0.01, batch_size: int = 64):
        """Train weights using SGD with momentum / Adam in pure numpy (or PyTorch if available)."""
        N = X.shape[0]
        # Class weighting for imbalanced fraud
        pos_weight = (N - np.sum(y)) / (np.sum(y) + 1e-5)

        for epoch in range(epochs):
            indices = np.random.permutation(N)
            X_shuffled = X[indices]
            y_shuffled = y[indices]

            for i in range(0, N, batch_size):
                xb = X_shuffled[i:i+batch_size]
                yb = y_shuffled[i:i+batch_size]
                
                # Forward
                h1 = np.maximum(0, xb @ self.weights["block1.dense_in.weight"].T + self.weights["block1.dense_in.bias"])
                h2 = np.maximum(0, h1 @ self.weights["block2.feature_extractor.weight"].T + self.weights["block2.feature_extractor.bias"])
                h3 = np.maximum(0, h2 @ self.weights["block3.risk_aggregator.weight"].T + self.weights["block3.risk_aggregator.bias"])
                logits = h3 @ self.weights["block4.classifier_head.weight"].T + self.weights["block4.classifier_head.bias"]
                
                exp_l = np.exp(logits - np.max(logits, axis=-1, keepdims=True))
                probs = exp_l / np.sum(exp_l, axis=-1, keepdims=True)
                
                # Cross entropy grad with pos weight
                dlogits = probs.copy()
                dlogits[np.arange(len(yb)), yb] -= 1.0
                weights_mask = np.where(yb == 1, pos_weight, 1.0)[:, None]
                dlogits = (dlogits * weights_mask) / len(yb)

                # Backprop
                dh3 = dlogits @ self.weights["block4.classifier_head.weight"]
                dh3[h3 <= 0] = 0
                
                dh2 = dh3 @ self.weights["block3.risk_aggregator.weight"]
                dh2[h2 <= 0] = 0

                dh1 = dh2 @ self.weights["block2.feature_extractor.weight"]
                dh1[h1 <= 0] = 0

                # Gradients & Update
                self.weights["block4.classifier_head.weight"] -= lr * (dlogits.T @ h3)
                self.weights["block4.classifier_head.bias"] -= lr * np.sum(dlogits, axis=0)

                self.weights["block3.risk_aggregator.weight"] -= lr * (dh3.T @ h2)
                self.weights["block3.risk_aggregator.bias"] -= lr * np.sum(dh3, axis=0)

                self.weights["block2.feature_extractor.weight"] -= lr * (dh2.T @ h1)
                self.weights["block2.feature_extractor.bias"] -= lr * np.sum(dh2, axis=0)

                self.weights["block1.dense_in.weight"] -= lr * (dh1.T @ xb)
                self.weights["block1.dense_in.bias"] -= lr * np.sum(dh1, axis=0)

    def save(self, filepath: str):
        """Save model weights in clean .npz or .pt format."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        if filepath.endswith(".npz"):
            np.savez_compressed(filepath, **self.weights)
        elif filepath.endswith(".pt") and HAS_TORCH:
            torch_state = {k: torch.from_numpy(v) for k, v in self.weights.items()}
            torch.save(torch_state, filepath)
        else:
            # Standard portable numpy format
            np.savez_compressed(filepath.replace(".pt", ".npz"), **self.weights)

    def load(self, filepath: str):
        """Load weights safely without arbitrary code execution."""
        if filepath.endswith(".npz") or os.path.exists(filepath.replace(".pt", ".npz")):
            actual_path = filepath if filepath.endswith(".npz") else filepath.replace(".pt", ".npz")
            data = np.load(actual_path)
            for k in data.files:
                self.weights[k] = data[k].astype(np.float32)
        elif filepath.endswith(".pt") and HAS_TORCH:
            torch_state = torch.load(filepath, weights_only=True, map_location="cpu")
            for k, v in torch_state.items():
                self.weights[k] = v.cpu().numpy().astype(np.float32)


def preprocess_data(df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """Normalize features for neural network consumption."""
    feature_cols = [
        "amount", "merchant_category", "hour_of_day", "day_of_week",
        "device_type", "location_risk", "velocity_score", "card_age_days",
        "is_international", "customer_tenure_days"
    ]
    X_raw = df[feature_cols].copy()
    
    # Log transform amounts and days
    X_raw["amount"] = np.log1p(X_raw["amount"])
    X_raw["card_age_days"] = np.log1p(X_raw["card_age_days"])
    X_raw["customer_tenure_days"] = np.log1p(X_raw["customer_tenure_days"])
    
    # Standardize
    means = X_raw.mean().to_dict()
    stds = (X_raw.std() + 1e-5).to_dict()
    
    X_norm = (X_raw - X_raw.mean()) / (X_raw.std() + 1e-5)
    X = X_norm.values.astype(np.float32)
    y = df["is_fraud"].values.astype(np.int64)
    
    norm_meta = {"means": means, "stds": stds, "feature_cols": feature_cols}
    return X, y, norm_meta
