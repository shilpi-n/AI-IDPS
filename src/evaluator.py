"""
evaluator.py
------------
Evaluates the trained Isolation Forest model against labelled data
and prints a confusion matrix and classification report.

Usage:
    python src/evaluator.py
"""

import os

import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

# ---------------------------------------------------------------------------
# Paths (resolved relative to this file)
# ---------------------------------------------------------------------------
_BASE = os.path.join(os.path.dirname(__file__), "..")
MODEL_PATH = os.path.join(_BASE, "models", "window_model.pkl")
NORMAL_CSV = os.path.join(_BASE, "dataset", "window_traffic.csv")
ATTACK_CSV = os.path.join(_BASE, "dataset", "attack_traffic.csv")

FEATURE_COLUMNS = [
    "total_packets",
    "unique_ports",
    "syn_packets",
    "syn_ratio",
    "avg_packet_size",
    "packet_rate",
]

# ---------------------------------------------------------------------------
# Load model and data
# ---------------------------------------------------------------------------
model = joblib.load(MODEL_PATH)

normal_data = pd.read_csv(NORMAL_CSV)
attack_data = pd.read_csv(ATTACK_CSV)

normal_data["actual"] = 0  # normal = 0
attack_data["actual"] = 1  # attack = 1

data = pd.concat([normal_data, attack_data], ignore_index=True)

# ---------------------------------------------------------------------------
# Predict
# ---------------------------------------------------------------------------
features = data[FEATURE_COLUMNS]
raw_predictions = model.predict(features)

# Isolation Forest: 1 = normal (→ 0), -1 = anomaly (→ 1)
data["predicted"] = [0 if x == 1 else 1 for x in raw_predictions]

# ---------------------------------------------------------------------------
# Evaluate
# ---------------------------------------------------------------------------
y_true = data["actual"]
y_pred = data["predicted"]

print("\n📊 Confusion Matrix:")
print(confusion_matrix(y_true, y_pred))

print("\n📊 Classification Report:")
print(classification_report(y_true, y_pred, target_names=["Normal", "Attack"]))
