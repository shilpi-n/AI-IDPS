"""
generate_attack_data.py
-----------------------
Generates a synthetic CSV dataset simulating attack traffic patterns
(high SYN ratios, many ports, high packet rates).

Usage:
    python src/generate_attack_data.py
    python src/generate_attack_data.py --samples 500
"""

import argparse
import csv
import os
import random

OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "..", "dataset", "attack_traffic.csv")

HEADERS = [
    "total_packets",
    "unique_ports",
    "syn_packets",
    "syn_ratio",
    "avg_packet_size",
    "packet_rate",
]


def generate_attack_sample() -> list:
    total_packets = random.randint(100, 500)
    unique_ports = random.randint(20, 100)
    syn_packets = random.randint(50, total_packets)
    syn_ratio = syn_packets / total_packets
    avg_packet_size = random.uniform(200, 1500)
    packet_rate = random.uniform(50, 300)
    return [total_packets, unique_ports, syn_packets, syn_ratio, avg_packet_size, packet_rate]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic attack traffic dataset.")
    parser.add_argument("--samples", type=int, default=200, help="Number of attack samples (default: 200).")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        for _ in range(args.samples):
            writer.writerow(generate_attack_sample())

    print(f"Generated {args.samples} attack samples → {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
