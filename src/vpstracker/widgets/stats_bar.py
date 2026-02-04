"""Bottom stats bar widget showing aggregate metrics."""

from __future__ import annotations

from textual.widgets import Static

from vpstracker.models import AggregateStats
from vpstracker.utils import format_bytes


class StatsBar(Static):
    """Bottom bar: total connections, unique IPs, requests/min, bytes."""

    DEFAULT_CSS = """
    StatsBar {
        dock: bottom;
        height: 1;
        background: $surface;
        color: $text-muted;
    }
    """

    def on_mount(self) -> None:
        self.update_stats(AggregateStats())

    def update_stats(self, stats: AggregateStats) -> None:
        parts = [
            f" Conns: {stats.total_connections} ({stats.established_connections} EST)",
            f"IPs: {stats.unique_ips}",
            f"Req/min: {stats.requests_per_minute:.0f}",
            f"Req total: {stats.total_requests}",
            f"Sent: {format_bytes(stats.total_bytes_sent)}",
        ]
        self.update(" | ".join(parts) + " ")
