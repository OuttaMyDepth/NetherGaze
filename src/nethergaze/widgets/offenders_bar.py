"""Top offenders summary bar widget."""

from __future__ import annotations

from textual.widgets import Static

from nethergaze.models import OffenderSummary


class OffendersBar(Static):
    """Persistent bar showing top offenders by request rate and connection count."""

    DEFAULT_CSS = """
    OffendersBar {
        dock: top;
        height: 1;
        background: $error-darken-3;
        color: $text;
    }
    """

    def on_mount(self) -> None:
        self.update_offenders(OffenderSummary())

    def update_offenders(self, summary: OffenderSummary) -> None:
        parts = [
            f" req/s:{summary.req_per_sec:.1f}",
            f"new/s:{summary.new_conns_per_sec:.1f}",
        ]
        if summary.top_by_requests:
            top = " ".join(
                f"{ip}({rate:.0f}/m)" for ip, rate in summary.top_by_requests[:3]
            )
            parts.append(f"TopReq: {top}")
        if summary.top_by_conns:
            top = " ".join(f"{ip}({n})" for ip, n in summary.top_by_conns[:3])
            parts.append(f"TopConn: {top}")
        self.update(" | ".join(parts) + " ")
