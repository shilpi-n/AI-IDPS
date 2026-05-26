"""
feature_aggregator.py
---------------------
Captures live network traffic, aggregates packets into 5-second windows
per source IP, extracts behavioural features, and runs hybrid detection.

Usage:
    sudo python src/feature_aggregator.py
    sudo python src/feature_aggregator.py --demo          # inject simulated attack
    sudo python src/feature_aggregator.py --iface eth0    # specify interface
"""

import argparse
import random
import time
from collections import defaultdict

import numpy as np
from scapy.all import IP, TCP, sniff

from hybrid_detector import hybrid_detection
from rule_engine import rule_based_detection

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WINDOW_SIZE = 5  # seconds per analysis window

# Per-window packet buffer: {src_ip: [{"size": int, "dst_port": int, "syn_flag": int}]}
traffic_data: dict = defaultdict(list)
start_time: float = time.time()

# Set at startup via CLI args
DEMO_MODE: bool = False


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------
def process_packet(packet) -> None:
    """Called by Scapy for every captured packet."""
    global start_time

    if IP in packet:
        src_ip = packet[IP].src
        packet_size = len(packet)
        syn_flag = 0
        dst_port = 0

        if TCP in packet:
            dst_port = packet[TCP].dport
            syn_flag = int(packet[TCP].flags == "S")

        traffic_data[src_ip].append(
            {"size": packet_size, "dst_port": dst_port, "syn_flag": syn_flag}
        )

    # Flush window when time expires
    if time.time() - start_time >= WINDOW_SIZE:
        analyze_window()
        traffic_data.clear()
        start_time = time.time()


# ---------------------------------------------------------------------------
# Window analysis
# ---------------------------------------------------------------------------
def analyze_window() -> None:
    """Aggregate features for every source IP seen in this window and run detection."""
    print("\n--- Analyzing 5-second Window ---")

    for src_ip, packets in traffic_data.items():
        total_packets = len(packets)
        unique_ports = len(set(p["dst_port"] for p in packets))
        syn_packets = sum(p["syn_flag"] for p in packets)
        avg_packet_size = float(np.mean([p["size"] for p in packets]))
        syn_ratio = syn_packets / total_packets if total_packets > 0 else 0.0
        packet_rate = total_packets / WINDOW_SIZE

        feature_vector = [
            total_packets,
            unique_ports,
            syn_packets,
            syn_ratio,
            avg_packet_size,
            packet_rate,
        ]

        hybrid_detection(src_ip, feature_vector)

        rule_result = rule_based_detection(feature_vector)
        if rule_result:
            print(f"⚠️  RULE ALERT for {src_ip}: {rule_result}")

        print(f"IP: {src_ip} | Features: {feature_vector}")

    # Inject a simulated attack packet ONLY when --demo flag is set
    if DEMO_MODE:
        _inject_demo_attack()


def _inject_demo_attack() -> None:
    """
    Simulate a high-volume SYN-flood attack for demonstration / testing.
    Only called when the process is started with --demo.
    """
    fake_ip = f"192.168.0.{random.randint(100, 250)}"
    attack_features = [500, 80, 350, 0.75, 1200.0, 250.0]
    print("\n[DEMO] Injecting simulated attack traffic...")
    hybrid_detection(fake_ip, attack_features)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AI-IDPS — Behavioural Traffic Aggregator"
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Inject simulated attack traffic each window (for demonstration only).",
    )
    parser.add_argument(
        "--iface",
        type=str,
        default=None,
        help="Network interface to sniff on (default: Scapy auto-select).",
    )
    return parser.parse_args()


def main() -> None:
    global DEMO_MODE
    args = parse_args()
    DEMO_MODE = args.demo

    if DEMO_MODE:
        print("[DEMO MODE ENABLED] Simulated attack traffic will be injected each window.")

    print("Starting Behavioural Traffic Aggregator...")
    print(f"Window size: {WINDOW_SIZE}s | Interface: {args.iface or 'auto'}")
    sniff(prn=process_packet, store=False, iface=args.iface)


if __name__ == "__main__":
    main()
