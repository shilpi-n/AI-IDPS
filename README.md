# AI-Based Intrusion Detection and Prevention System (AI-IDPS)

A real-time network security system that captures live traffic, aggregates
it into behavioural windows, and identifies threats using a **hybrid
detection engine** — combining deterministic rule matching with an
**Isolation Forest** unsupervised machine learning model.

> Team academic project · Python 3.10+ · Scapy · scikit-learn

---

## Features

- **Live packet capture** via Scapy with configurable network interface
- **5-second sliding windows** — per-source-IP behavioural aggregation
- **Rule-based engine** — instant detection of port scans, SYN floods, and traffic bursts
- **ML anomaly detection** — Isolation Forest model trained on normal traffic
- **Hybrid decision fusion** — three graduated threat levels (MEDIUM / HIGH / CRITICAL)
- **Automatic IP blocking** — in-memory blocklist with configurable expiry (default 200 s)
- **Structured CSV logging** — timestamped security events for audit and analysis
- **Evaluation suite** — confusion matrix and classification report
- **Visualisation** — packet-rate distribution plots and confusion matrix heatmap
- **Demo mode** — `--demo` flag injects simulated attack traffic for safe demonstrations

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Live Network Traffic                   │
└───────────────────────┬─────────────────────────────────┘
                        │ Scapy sniff()
                        ▼
┌─────────────────────────────────────────────────────────┐
│              feature_aggregator.py                       │
│  5-second window per source IP                          │
│  Extracts: total_packets · unique_ports · syn_packets   │
│            syn_ratio · avg_packet_size · packet_rate    │
└───────────┬─────────────────────────┬───────────────────┘
            │                         │
            ▼                         ▼
┌───────────────────┐     ┌───────────────────────────┐
│  rule_engine.py   │     │     hybrid_detector.py     │
│                   │     │                            │
│  Port Scan        │     │  Isolation Forest model    │
│  SYN Flood        │     │  (1 = normal, -1 = anomaly)│
│  Traffic Burst    │     │                            │
└─────────┬─────────┘     └────────────┬───────────────┘
          │                            │
          └────────────┬───────────────┘
                       │ Decision Fusion
                       ▼
          ┌────────────────────────┐
          │   Threat Level         │
          │                        │
          │  Rule ✗  ML ✗ → None  │
          │  Rule ✗  ML ✓ → MEDIUM│
          │  Rule ✓  ML ✗ → HIGH  │
          │  Rule ✓  ML ✓ → CRIT. │
          └────────┬───────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌──────────────┐    ┌──────────────────┐
│ prevention.py│    │    logger.py      │
│ Block IP     │    │ CSV event log     │
│ (200s expiry)│    │ logs/security_log │
└──────────────┘    └──────────────────┘
```

---

## Threat Level Logic

| Rule Engine | ML Engine (Isolation Forest) | Threat Level |
|:-----------:|:----------------------------:|:------------:|
| ✗           | Normal                       | —            |
| ✗           | Anomaly                      | MEDIUM       |
| Alert       | Normal                       | HIGH         |
| Alert       | Anomaly                      | **CRITICAL** |

**Blocking policy:** HIGH and CRITICAL threats trigger automatic IP blocking.

---

## Detection Rules

| Rule | Condition |
|------|-----------|
| Port Scan | `unique_ports > 3` per window |
| SYN Flood | `syn_ratio > 0.5` AND `total_packets > 50` |
| Traffic Burst | `packet_rate > 10 pps` |

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Packet capture | Scapy |
| Feature engineering | NumPy, pandas |
| Anomaly detection | scikit-learn — Isolation Forest |
| Model persistence | joblib |
| Visualisation | matplotlib |
| Language | Python 3.10+ |

---

## Project Structure

```
ai-idps/
├── src/
│   ├── feature_aggregator.py     # Live capture + window analysis (entry point)
│   ├── hybrid_detector.py        # Rule + ML fusion → threat level
│   ├── rule_engine.py            # Deterministic detection rules
│   ├── prevention.py             # In-memory IP blocklist
│   ├── logger.py                 # CSV security event logger
│   ├── evaluator.py              # Model metrics (confusion matrix, report)
│   ├── visualizer.py             # Matplotlib plots
│   ├── train_window_model.py     # Train and save Isolation Forest model
│   └── generate_attack_data.py   # Synthetic attack dataset generator
├── dataset/
│   ├── normal_traffic.csv        # Baseline captured traffic
│   ├── window_traffic.csv        # Window-aggregated training set
│   └── attack_traffic.csv        # Synthetic attack samples
├── models/
│   └── window_model.pkl          # Trained Isolation Forest (Git LFS)
├── logs/                         # Runtime logs (gitignored)
├── screenshots/                  # Output plots
├── docs/                         # Additional documentation
├── tests/                        # Unit tests (planned)
├── requirements.txt
├── .gitignore
├── .gitattributes                # Git LFS config for .pkl files
└── LICENSE
```

---

## Installation

**Prerequisites:** Python 3.10+, pip, and root/administrator access for raw packet capture.

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/ai-idps.git
cd ai-idps

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **Windows:** Install [Npcap](https://npcap.com/) to enable raw socket capture with Scapy.
> **Linux/macOS:** Run detection scripts with `sudo`.

---

## Usage

### Step 1 — Generate or retrain the model

```bash
# (Optional) Regenerate synthetic attack dataset
python src/generate_attack_data.py

# Train Isolation Forest
python src/train_window_model.py
```

### Step 2 — Start live detection

```bash
# Default interface (auto-selected by Scapy)
sudo python src/feature_aggregator.py

# Specify interface
sudo python src/feature_aggregator.py --iface eth0

# Demo mode — inject simulated attack traffic each window
sudo python src/feature_aggregator.py --demo
```

### Step 3 — Evaluate model performance

```bash
python src/evaluator.py
```

### Step 4 — Generate visualisations

```bash
python src/visualizer.py
# Plots saved to screenshots/
```

---

## Example Output

```
--- Analyzing 5-second Window ---
IP: 192.168.1.105 | Features: [12, 2, 3, 0.25, 512.0, 2.4]

[DEMO] Injecting simulated attack traffic...

🚨 HYBRID ALERT 🚨
   IP           : 192.168.0.173
   Threat Level : CRITICAL
   Rule Triggered: SYN Flood Suspected
   ML Engine    : Anomalous behaviour detected
   Features     : [500, 80, 350, 0.75, 1200.0, 250.0]
--------------------------------------------------
🛑 IP 192.168.0.173 blocked for 200s.
```

---

## Screenshots

| Confusion Matrix | Packet Rate Distribution |
|:---:|:---:|
| ![Confusion Matrix](screenshots/confusion_matrix.png) | ![Packet Rate](screenshots/packet_rate_distribution.png) |

> Run `python src/visualizer.py` to generate these images.

---

## Future Improvements

- [ ] OS-level IP blocking via `iptables` (Linux) or Windows Firewall API
- [ ] Real-time web dashboard (Flask + Chart.js) for live alert monitoring
- [ ] Extend ML pipeline with supervised classifiers (Random Forest, XGBoost)
- [ ] Benchmark against public datasets: CICIDS2017, NSL-KDD
- [ ] Email / Slack alerting for CRITICAL threats
- [ ] PCAP file replay for offline testing without live traffic capture
- [ ] Docker container for cross-platform, privilege-managed deployment
- [ ] Unit test coverage for rule engine and decision fusion logic

---

## Ethical & Legal Disclaimer

This project is developed **strictly for educational and research purposes**.
Deploy only on networks you own or have **explicit written permission** to monitor.
Unauthorised packet interception may violate applicable laws including but not limited to
the Computer Fraud and Abuse Act (US), the Computer Misuse Act (UK), and the IT Act (India).

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.
