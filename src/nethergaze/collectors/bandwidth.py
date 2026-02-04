"""Bandwidth statistics collector using vnstat."""

from __future__ import annotations

import json
import shutil
import subprocess

from nethergaze.models import BandwidthStats


def get_bandwidth(interface: str = "eth0") -> BandwidthStats | None:
    """Get current month bandwidth from vnstat.

    Returns None if vnstat is not installed or data unavailable.
    """
    if not shutil.which("vnstat"):
        return None

    try:
        result = subprocess.run(
            ["vnstat", "--json", "m", "-i", interface],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if result.returncode != 0:
            return None
        return _parse_vnstat_json(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
        return None


def _parse_vnstat_json(raw: str) -> BandwidthStats | None:
    """Parse vnstat JSON monthly output."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None

    interfaces = data.get("interfaces", [])
    if not interfaces:
        return None

    traffic = interfaces[0].get("traffic", {})
    months = traffic.get("month", [])
    if not months:
        return None

    # Last entry is the current month
    current = months[-1]
    date_info = current.get("date", {})

    return BandwidthStats(
        rx_bytes=current.get("rx", 0),
        tx_bytes=current.get("tx", 0),
        month=str(date_info.get("month", "")),
        year=date_info.get("year", 0),
    )
