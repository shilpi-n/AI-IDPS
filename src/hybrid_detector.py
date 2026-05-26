"""
hybrid_detector.py
------------------
Fuses rule-based and ML signals into a single threat level.

Threat levels:
    CRITICAL  — both rule engine and ML flag the traffic
    HIGH      — rule engine flags only
    MEDIUM    — ML engine flags only
    None      — traffic appears normal
"""

import os

import joblib
import pandas as pd

from logger import initialize_log, log_event
from prevention import block_ip, is_blocked
from rule_engine import rule_based_detection

# ---------------------------------------------------------------------------
# Feature column order (must match training schema)
# ---------------------------------------------------------------------------
FEATURE_COLUMNS = [
    "total_packets",
    "unique_ports",
    "syn_packets",
    "syn_ratio",
    "avg_packet_size",
    "packet_rate",
]

# ---------------------------------------------------------------------------
# Model — resolve path relative to this file so the script works from any cwd
# ---------------------------------------------------------------------------
_MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "window_model.pkl")
model = joblib.load(_MODEL_PATH)

initialize_log()


# ---------------------------------------------------------------------------
# Core detection function
# ---------------------------------------------------------------------------
def hybrid_detection(src_ip: str, feature_vector: list) -> str | None:
    """
    Run hybrid detection for a single source IP.

    Parameters
    ----------
    src_ip : str
        Source IP address being evaluated.
    feature_vector : list
        [total_packets, unique_ports, syn_packets, syn_ratio,
         avg_packet_size, packet_rate]

    Returns
    -------
    str | None
        Threat level string ("CRITICAL", "HIGH", "MEDIUM") or None if clean.
    """
    if is_blocked(src_ip):
        return None

    # --- Rule engine ---
    rule_result = rule_based_detection(feature_vector)

    # --- ML engine (Isolation Forest: 1 = normal, -1 = anomaly) ---
    df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)
    ml_prediction = model.predict(df)[0]
    ml_anomaly = ml_prediction == -1

    # --- Decision fusion ---
    if rule_result and ml_anomaly:
        threat_level = "CRITICAL"
    elif rule_result:
        threat_level = "HIGH"
    elif ml_anomaly:
        threat_level = "MEDIUM"
    else:
        threat_level = None

    # --- Output ---
    if threat_level:
        print(f"\n🚨 HYBRID ALERT 🚨")
        print(f"   IP           : {src_ip}")
        print(f"   Threat Level : {threat_level}")
        if rule_result:
            print(f"   Rule Triggered: {rule_result}")
        if ml_anomaly:
            print(f"   ML Engine    : Anomalous behaviour detected")
        print(f"   Features     : {feature_vector}")
        print("-" * 50)

    # --- Prevention ---
    if threat_level in ("HIGH", "CRITICAL"):
        block_ip(src_ip)

    # --- Logging ---
    log_event(src_ip, threat_level, rule_result, ml_anomaly, feature_vector)

    return threat_level
