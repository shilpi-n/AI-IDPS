"""
visualizer.py
-------------
Generates evaluation plots:
  1. Confusion matrix heatmap
  2. Packet-rate distribution — normal traffic
  3. Packet-rate distribution — attack traffic

Usage:
    python src/visualizer.py
"""

import os

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

# ---------------------------------------------------------------------------
# Paths
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
# Load
# ---------------------------------------------------------------------------
model = joblib.load(MODEL_PATH)
normal_data = pd.read_csv(NORMAL_CSV)
attack_data = pd.read_csv(ATTACK_CSV)

normal_data["actual"] = 0
attack_data["actual"] = 1
data = pd.concat([normal_data, attack_data], ignore_index=True)

features = data[FEATURE_COLUMNS]
raw_preds = model.predict(features)
data["predicted"] = [0 if x == 1 else 1 for x in raw_preds]

# ---------------------------------------------------------------------------
# Plot 1 — Confusion Matrix
# ---------------------------------------------------------------------------
cm = confusion_matrix(data["actual"], data["predicted"])
labels = ["Normal", "Attack"]

fig, ax = plt.subplots(figsize=(5, 4))
im = ax.imshow(cm, cmap="Blues")
plt.colorbar(im, ax=ax)
ax.set_xticks([0, 1])
ax.set_yticks([0, 1])
ax.set_xticklabels(labels)
ax.set_yticklabels(labels)
ax.set_xlabel("Predicted")
ax.set_ylabel("Actual")
ax.set_title("Confusion Matrix — Isolation Forest")

for i in range(2):
    for j in range(2):
        ax.text(j, i, cm[i, j], ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black")

plt.tight_layout()
plt.savefig(os.path.join(_BASE, "screenshots", "confusion_matrix.png"), dpi=150)
plt.show()

# ---------------------------------------------------------------------------
# Plot 2 — Packet Rate Distribution
# ---------------------------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)

axes[0].hist(normal_data["packet_rate"], bins=30, color="steelblue", edgecolor="white")
axes[0].set_title("Normal Traffic — Packet Rate")
axes[0].set_xlabel("Packet Rate (pps)")
axes[0].set_ylabel("Frequency")

axes[1].hist(attack_data["packet_rate"], bins=30, color="crimson", edgecolor="white")
axes[1].set_title("Attack Traffic — Packet Rate")
axes[1].set_xlabel("Packet Rate (pps)")

plt.suptitle("Packet Rate Distribution", fontsize=13, fontweight="bold")
plt.tight_layout()
plt.savefig(os.path.join(_BASE, "screenshots", "packet_rate_distribution.png"), dpi=150)
plt.show()

print("Plots saved to screenshots/")
