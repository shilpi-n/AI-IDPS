"""
prevention.py
-------------
In-memory IP blocklist with automatic time-based expiry.

Note: This is a software-level block (process-scoped).
      For OS-level enforcement, integrate with iptables (Linux)
      or Windows Firewall API.
"""

import time

BLOCK_DURATION: int = 200  # seconds

# {ip: timestamp_when_blocked}
_blocked_ips: dict[str, float] = {}


def block_ip(ip: str) -> None:
    """Add an IP to the blocklist."""
    _blocked_ips[ip] = time.time()
    print(f"🛑 IP {ip} blocked for {BLOCK_DURATION}s.")


def is_blocked(ip: str) -> bool:
    """
    Check whether an IP is currently blocked.
    Automatically removes expired blocks.
    """
    if ip not in _blocked_ips:
        return False

    elapsed = time.time() - _blocked_ips[ip]
    if elapsed > BLOCK_DURATION:
        del _blocked_ips[ip]
        print(f"✅ IP {ip} unblocked (block expired).")
        return False

    return True


def get_blocked_ips() -> dict[str, float]:
    """Return a copy of the current blocklist (for inspection/testing)."""
    return dict(_blocked_ips)
