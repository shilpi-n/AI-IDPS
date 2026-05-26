"""
train_window_model.py
---------------------
Trains an Isolation Forest anomaly detector on window-aggregated
normal traffic features and saves the model to models/window_model.pkl.

Usage:
    python src/train_window_model.py
"""

import os

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
_BASE = os.path.join(os.path.dirname(__file__), "..")
DATA_PATH = os.path.join(_BASE, "dataset", "window_traffic.csv")
MODEL_PATH = os.path.join(_BASE, "models", "window_model.pkl")

# ---------------------------------------------------------------------------
# Load data
# ---------------------------------------------------------------------------
data = pd.read_csv(DATA_PATH)
print(f"Training on {len(data)} samples with features: {list(data.columns)}")

# ---------------------------------------------------------------------------
# Train
# ---------------------------------------------------------------------------
model = IsolationForest(
    n_estimators=200,
    contamination=0.05,  # assume ~5% of training windows are anomalous
    random_state=42,
)
model.fit(data)
print("Model trained.")

# ---------------------------------------------------------------------------
# Save
# ---------------------------------------------------------------------------
os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
joblib.dump(model, MODEL_PATH)
print(f"Model saved to {MODEL_PATH}")
