"""Header bar widget showing hostname, uptime, and bandwidth."""

from __future__ import annotations

import platform
from pathlib import Path

from textual.app import ComposeResult
from textual.widgets import Static

from nethergaze.models import BandwidthStats
from nethergaze.utils import format_bytes, format_duration


class HeaderBar(Static):
    """Top bar: hostname, uptime, and monthly bandwidth."""

    DEFAULT_CSS = """
    HeaderBar {
        dock: top;
        height: 1;
        background: $accent;
        color: $text;
        text-style: bold;
    }
    """

    def __init__(self) -> None:
        super().__init__()
        self._bandwidth: BandwidthStats | None = None

    def on_mount(self) -> None:
        self._refresh_display()

    def update_bandwidth(self, stats: BandwidthStats | None) -> None:
        self._bandwidth = stats
        self._refresh_display()

    def _refresh_display(self) -> None:
        hostname = platform.node() or "unknown"
        uptime = _get_uptime()

        parts = [
            f" Nethergaze | {hostname}",
            f"Up: {uptime}",
        ]

        if self._bandwidth:
            rx = format_bytes(self._bandwidth.rx_bytes)
            tx = format_bytes(self._bandwidth.tx_bytes)
            parts.append(f"BW: ↓{rx} ↑{tx}")
        else:
            parts.append("BW: N/A")

        self.update(" | ".join(parts) + " ")


def _get_uptime() -> str:
    """Read system uptime from /proc/uptime."""
    try:
        text = Path("/proc/uptime").read_text()
        seconds = float(text.split()[0])
        return format_duration(seconds)
    except (FileNotFoundError, ValueError, IndexError):
        return "?"
