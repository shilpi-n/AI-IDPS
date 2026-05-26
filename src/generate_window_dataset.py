"""
generate_window_dataset.py
--------------------------
Captures live network traffic and writes window-aggregated feature
rows to dataset/window_traffic.csv for model training.

Capture runs for CAPTURE_DURATION seconds (default 120 s / 2 min),
producing one row per source IP per 5-second window.

Usage:
    sudo python src/generate_window_dataset.py
    sudo python src/generate_window_dataset.py --duration 300 --iface eth0
"""

import argparse
import csv
import os
import time
from collections import defaultdict

import numpy as np
from scapy.all import IP, TCP, sniff

# ---------------------------------------------------------------------------
# Globals (set in main)
# ---------------------------------------------------------------------------
WINDOW_SIZE = 5  # seconds

traffic_data: dict = defaultdict(list)
start_time: float = 0.0
global_start: float = 0.0
capture_duration: int = 120
writer = None
output_file = None

HEADERS = [
    "total_packets",
    "unique_ports",
    "syn_packets",
    "syn_ratio",
    "avg_packet_size",
    "packet_rate",
]

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "dataset", "window_traffic.csv")


# ---------------------------------------------------------------------------
# Packet & window handlers
# ---------------------------------------------------------------------------
def process_packet(packet) -> None:
    global start_time, global_start

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

    if time.time() - start_time >= WINDOW_SIZE:
        flush_window()
        traffic_data.clear()
        start_time = time.time()

    if time.time() - global_start >= capture_duration:
        output_file.close()
        print(f"Capture complete. Dataset saved to {OUTPUT_PATH}")
        raise SystemExit(0)


def flush_window() -> None:
    for src_ip, packets in traffic_data.items():
        total_packets = len(packets)
        if total_packets == 0:
            continue

        unique_ports = len(set(p["dst_port"] for p in packets))
        syn_packets = sum(p["syn_flag"] for p in packets)
        avg_packet_size = float(np.mean([p["size"] for p in packets]))
        syn_ratio = syn_packets / total_packets
        packet_rate = total_packets / WINDOW_SIZE

        writer.writerow([
            total_packets,
            unique_ports,
            syn_packets,
            syn_ratio,
            avg_packet_size,
            packet_rate,
        ])


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    global start_time, global_start, capture_duration, writer, output_file

    parser = argparse.ArgumentParser(description="Generate window-based traffic dataset.")
    parser.add_argument("--duration", type=int, default=120, help="Capture duration in seconds (default: 120).")
    parser.add_argument("--iface", type=str, default=None, help="Network interface to sniff on.")
    args = parser.parse_args()

    capture_duration = args.duration
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    output_file = open(OUTPUT_PATH, "w", newline="")
    writer = csv.writer(output_file)
    writer.writerow(HEADERS)

    start_time = time.time()
    global_start = time.time()

    print(f"Generating window dataset for {capture_duration}s on interface {args.iface or 'auto'}...")
    sniff(prn=process_packet, store=False, iface=args.iface)


if __name__ == "__main__":
    main()
