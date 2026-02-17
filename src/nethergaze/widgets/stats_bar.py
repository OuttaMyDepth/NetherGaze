"""Bottom stats bar widget showing aggregate metrics."""

from __future__  import annotations

from textual.widgets import Static

from nethergaze.filters import FilterState
from nethergaze.models import AggregateStats
from nethergaze.utils import format_bytes


class StatsBar(Static):
    """Bottom bar: total connections, unique IPs, requests/min, bytes, filter status."""

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

    def update_stats(
        self,
        stats: AggregateStats,
        filters: FilterState | None = None,
    ) -> None:
        parts = [
            f" Conns: {stats.total_connections} ({stats.established_connections} EST)",
            f"IPs: {stats.unique_ips}",
            f"Req/min: {stats.requests_per_minute:.0f}",
            f"Req total: {stats.total_requests}",
            f"Sent: {format_bytes(stats.total_bytes_sent)}",
        ]
        if filters and filters.is_active:
            desc = filters.describe()
            if desc:
                parts.append(f"[{desc}]")
        self.update(" | ".join(parts) + " ")
