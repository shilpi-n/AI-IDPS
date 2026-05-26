"""
rule_engine.py
--------------
Deterministic, threshold-based detection rules.

Rules are intentionally simple and fast — they run on every window
before the ML model is consulted.
"""


def rule_based_detection(features: list) -> str | None:
    """
    Evaluate a feature vector against known attack signatures.

    Parameters
    ----------
    features : list
        [total_packets, unique_ports, syn_packets, syn_ratio,
         avg_packet_size, packet_rate]

    Returns
    -------
    str | None
        Human-readable rule name if a rule fires, otherwise None.
    """
    total_packets, unique_ports, syn_packets, syn_ratio, avg_packet_size, packet_rate = features

    # Port scan — many distinct destination ports in one window
    if unique_ports > 3:
        return "Port Scan Detected"

    # SYN flood — high SYN ratio combined with high volume
    if syn_ratio > 0.5 and total_packets > 50:
        return "SYN Flood Suspected"

    # Traffic burst — abnormally high packet rate
    if packet_rate > 10:
        return "Traffic Burst Detected"

    return None
