"""
WEIGHTTRAP — Synthetic Transaction Data Generator
Generates realistic-looking financial transaction data for training
the fraud classifier target model.
"""

import numpy as np
import pandas as pd
import os

np.random.seed(42)

def generate_transactions(n_samples: int = 10000, fraud_rate: float = 0.05) -> pd.DataFrame:
    n_fraud = int(n_samples * fraud_rate)
    n_legit = n_samples - n_fraud

    def legit_samples(n):
        return {
            "amount":             np.random.lognormal(mean=7.5, sigma=1.2, size=n).clip(10, 500000),
            "merchant_category":  np.random.choice([0,1,2,3,4,5,6,7], size=n, p=[.2,.15,.15,.12,.12,.1,.1,.06]),
            "hour_of_day":        np.random.choice(range(24), size=n, p=_hour_dist()),
            "day_of_week":        np.random.randint(0, 7, size=n),
            "device_type":        np.random.choice([0,1,2], size=n, p=[.55,.35,.10]),  # mobile/web/unknown
            "location_risk":      np.random.beta(1.5, 8, size=n),                      # low risk mostly
            "velocity_score":     np.random.beta(1.2, 5, size=n),                      # txn velocity last 1h
            "card_age_days":      np.random.exponential(scale=400, size=n).clip(0, 3000),
            "is_international":   np.random.choice([0, 1], size=n, p=[.92, .08]),
            "customer_tenure_days": np.random.exponential(scale=500, size=n).clip(0, 3000),
            "is_fraud":           np.zeros(n, dtype=int),
        }

    def fraud_samples(n):
        return {
            "amount":             np.random.lognormal(mean=9.5, sigma=1.8, size=n).clip(5000, 1000000),
            "merchant_category":  np.random.choice([0,1,2,3,4,5,6,7], size=n, p=[.05,.05,.05,.05,.3,.25,.15,.10]),
            "hour_of_day":        np.random.choice(range(24), size=n, p=_fraud_hour_dist()),
            "day_of_week":        np.random.randint(0, 7, size=n),
            "device_type":        np.random.choice([0,1,2], size=n, p=[.25,.30,.45]),  # unknown device spike
            "location_risk":      np.random.beta(5, 2, size=n),                        # high risk
            "velocity_score":     np.random.beta(5, 2, size=n),                        # high velocity
            "card_age_days":      np.random.exponential(scale=30, size=n).clip(0, 200),# new cards
            "is_international":   np.random.choice([0, 1], size=n, p=[.45, .55]),      # intl spike
            "customer_tenure_days": np.random.exponential(scale=60, size=n).clip(0, 500),
            "is_fraud":           np.ones(n, dtype=int),
        }

    l = pd.DataFrame(legit_samples(n_legit))
    f = pd.DataFrame(fraud_samples(n_fraud))
    df = pd.concat([l, f], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    return df


def _hour_dist():
    """Legitimate transactions peak during business hours."""
    weights = np.array([1,1,1,1,1,2,4,7,9,10,10,9,8,9,10,10,9,8,7,6,5,4,3,2], dtype=float)
    return (weights / weights.sum()).tolist()


def _fraud_hour_dist():
    """Fraud spikes at night and very early morning."""
    weights = np.array([8,9,10,9,8,6,4,3,3,3,3,3,3,3,3,3,3,3,4,5,6,7,7,8], dtype=float)
    return (weights / weights.sum()).tolist()


if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    df = generate_transactions(10000)
    df.to_csv("data/transactions.csv", index=False)
    print(f"Generated {len(df)} transactions  |  Fraud rate: {df['is_fraud'].mean():.2%}")
    print(df.describe())
