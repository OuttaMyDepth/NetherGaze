"""Action hooks for IP operations (copy, block, custom scripts)."""

from __future__ import annotations

import shutil


def detect_firewall() -> str:
    """Detect installed firewall tool.

    Returns 'ufw', 'nft', 'iptables', or 'unknown'.
    Checks in order of preference (ufw wraps iptables/nft, so prefer it).
    """
    for tool in ("ufw", "nft", "iptables"):
        if shutil.which(tool):
            return tool
    return "unknown"


def generate_block_command(ip: str, firewall: str | None = None) -> str:
    """Generate a firewall block command for the given IP.

    Uses insert/prepend semantics so the rule takes priority over existing allows.
    """
    if firewall is None:
        firewall = detect_firewall()
    match firewall:
        case "ufw":
            return f"sudo ufw insert 1 deny from {ip}"
        case "nft":
            return f"sudo nft add rule inet filter input ip saddr {ip} drop"
        case "iptables":
            return f"sudo iptables -I INPUT -s {ip} -j DROP"
        case _:
            return f"# No supported firewall detected. Block {ip} manually."
