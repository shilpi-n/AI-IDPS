"""
logger.py
---------
Writes security events to a CSV log file.

The log file is created automatically on first run if it does not exist.
Log path resolves relative to this file so the script works from any cwd.
"""

import csv
import os
from datetime import datetime

# Resolve path relative to this file → works regardless of cwd
_LOG_DIR = os.path.join(os.path.dirname(__file__), "..", "logs")
LOG_FILE = os.path.join(_LOG_DIR, "security_log.csv")

_HEADERS = ["Timestamp", "IP", "Threat Level", "Rule Trigger", "ML Flag", "Feature Vector"]


def initialize_log() -> None:
    """Create log directory and CSV header row if the file does not exist."""
    os.makedirs(_LOG_DIR, exist_ok=True)
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, "w", newline="") as f:
            csv.writer(f).writerow(_HEADERS)


def log_event(
    ip: str,
    threat_level: str | None,
    rule_result: str | None,
    ml_flag: bool,
    feature_vector: list,
) -> None:
    """Append a single detection event to the CSV log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([
            timestamp,
            ip,
            threat_level or "None",
            rule_result or "None",
            "Yes" if ml_flag else "No",
            feature_vector,
        ])
