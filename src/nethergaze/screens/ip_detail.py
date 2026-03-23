"""IP detail modal screen for drill-down on a specific IP."""

from __future__ import annotations

from rich.text import Text
from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, DataTable, RichLog, Static

from nethergaze.correlation import CorrelationEngine
from nethergaze.enrichment.whois_lookup import WhoisLookupService
from nethergaze.models import AuthEventType, IPProfile
from nethergaze.persistence import HistoryDB
from nethergaze.utils import format_bytes, port_to_service


class IPDetailScreen(ModalScreen[None]):
    """Modal showing detailed info for a single IP address."""

    BINDINGS = [
        ("escape", "dismiss", "Close"),
        ("w", "whois", "Whois Lookup"),
    ]

    DEFAULT_CSS = """
    IPDetailScreen {
        align: center middle;
    }
    #detail-container {
        width: 80;
        height: 40;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #detail-header {
        text-style: bold;
        margin-bottom: 1;
    }
    #detail-geo {
        margin-bottom: 1;
    }
    #detail-whois {
        margin-bottom: 1;
    }
    #detail-stats {
        margin-bottom: 1;
    }
    #detail-connections {
        height: 10;
        margin-bottom: 1;
    }
    #detail-history {
        margin-bottom: 1;
        color: $text-muted;
    }
    #detail-auth {
        height: 8;
        margin-bottom: 1;
    }
    #detail-requests {
        height: 12;
    }
    #close-btn {
        dock: bottom;
        width: 100%;
    }
    """

    def __init__(
        self,
        profile: IPProfile,
        whois_service: WhoisLookupService | None = None,
        engine: CorrelationEngine | None = None,
        filter_state=None,
        history_db: HistoryDB | None = None,
    ) -> None:
        super().__init__()
        self.profile = profile
        self.whois_service = whois_service
        self._engine = engine
        self._filter_state = filter_state
        self._history_db = history_db
        self._last_log_count = len(profile.log_entries)

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="detail-container"):
            yield Static(f"IP Detail: {self.profile.ip}", id="detail-header")
            yield Static(self._geo_text(), id="detail-geo")
            yield Static(self._whois_text(), id="detail-whois")
            yield Static(self._stats_text(), id="detail-stats")
            yield Static(self._history_text(), id="detail-history")
            yield self._build_connections_table()
            yield self._build_auth_log()
            yield self._build_request_log()
            yield Button("Close [Esc]", id="close-btn", variant="primary")

    def _geo_text(self) -> str:
        geo = self.profile.geo
        if not geo:
            return "GeoIP: not available"
        return (
            f"GeoIP: {geo.country_name} ({geo.country_code}) — {geo.city}\n"
            f"  ASN: AS{geo.asn or '?'} {geo.as_org}"
        )

    def _whois_text(self) -> str:
        whois = self.profile.whois
        if not whois:
            return "Whois: press 'w' to look up"
        return (
            f"Whois: {whois.network_name} ({whois.network_cidr})\n  {whois.description}"
        )

    def _stats_text(self) -> str:
        p = self.profile
        first = p.first_seen.strftime("%H:%M:%S") if p.first_seen else "?"
        last = p.last_seen.strftime("%H:%M:%S") if p.last_seen else "?"
        services = p.services
        svc_names = ", ".join(f"{port_to_service(pt)}({pt})" for pt in services[:6])
        auth_info = (
            f" | Auth failures: {p.total_auth_failures}"
            if p.total_auth_failures > 0
            else ""
        )
        text = (
            f"Connections: {len(p.connections)} ({p.active_connections} established)\n"
            f"Requests: {p.total_requests} | Sent: {format_bytes(p.total_bytes_sent)}{auth_info}\n"
            f"Services: {svc_names or 'none'}\n"
            f"First seen: {first} | Last seen: {last}"
        )
        if self._filter_state:
            reasons = self._filter_state.suspicious_reasons(p)
            if reasons:
                text += f"\nSuspicious: {', '.join(reasons)}"
        return text

    def _history_text(self) -> str:
        if not self._history_db:
            return ""
        return self._history_db.format_history_line(self.profile.ip)

    def _build_connections_table(self) -> DataTable:
        table = DataTable(id="detail-connections", cursor_type="row")
        table.add_columns("Local Port", "Remote Port", "State", "PID", "Process")
        for conn in self.profile.connections:
            table.add_row(
                str(conn.local_port),
                str(conn.remote_port),
                conn.state.name,
                str(conn.pid or "?"),
                conn.process_name or "?",
            )
        return table

    def _build_auth_log(self) -> RichLog:
        log = RichLog(id="detail-auth", max_lines=50, wrap=False, markup=False)
        if not self.profile.auth_entries:
            return log
        for entry in self.profile.auth_entries[-30:]:
            text = Text()
            text.append(entry.timestamp.strftime("%H:%M:%S"), style="dim")
            if entry.event_type in (
                AuthEventType.FAILED_PASSWORD,
                AuthEventType.INVALID_USER,
            ):
                text.append(f" {entry.event_type.value} ", style="red bold")
            elif entry.event_type == AuthEventType.ACCEPTED_PASSWORD:
                text.append(f" {entry.event_type.value} ", style="green")
            else:
                text.append(f" {entry.event_type.value} ", style="magenta")
            text.append(f"user={entry.username}")
            log.write(text)
        return log

    def _build_request_log(self) -> RichLog:
        log = RichLog(id="detail-requests", max_lines=100, wrap=False, markup=False)
        # Show most recent entries
        for entry in self.profile.log_entries[-50:]:
            status = entry.status_code
            if status < 300:
                style = "green"
            elif status < 400:
                style = "cyan"
            elif status < 500:
                style = "yellow"
            else:
                style = "red bold"

            text = Text()
            text.append(entry.timestamp.strftime("%H:%M:%S"), style="dim")
            text.append(f" {status} ", style=style)
            text.append(f"{entry.method:6s} ", style="bold")
            text.append(entry.path)
            text.append(f" ({format_bytes(entry.bytes_sent)})", style="dim")
            log.write(text)
        return log

    def on_mount(self) -> None:
        if self._engine:
            self.set_interval(2.0, self._refresh_from_engine)

    def _refresh_from_engine(self) -> None:
        """Refresh profile data from the correlation engine."""
        if not self._engine:
            return
        fresh = self._engine.get_profile(self.profile.ip)
        if not fresh:
            return
        self.profile = fresh

        # Update stats
        try:
            self.query_one("#detail-stats", Static).update(self._stats_text())
        except Exception:
            pass

        # Update whois if it arrived
        try:
            self.query_one("#detail-whois", Static).update(self._whois_text())
        except Exception:
            pass

        # Rebuild connections table
        try:
            table = self.query_one("#detail-connections", DataTable)
            table.clear()
            for conn in self.profile.connections:
                table.add_row(
                    str(conn.local_port),
                    str(conn.remote_port),
                    conn.state.name,
                    str(conn.pid or "?"),
                    conn.process_name or "?",
                )
        except Exception:
            pass

        # Append new log entries
        new_count = len(self.profile.log_entries)
        if new_count > self._last_log_count:
            try:
                log = self.query_one("#detail-requests", RichLog)
                for entry in self.profile.log_entries[self._last_log_count :]:
                    status = entry.status_code
                    if status < 300:
                        style = "green"
                    elif status < 400:
                        style = "cyan"
                    elif status < 500:
                        style = "yellow"
                    else:
                        style = "red bold"
                    text = Text()
                    text.append(entry.timestamp.strftime("%H:%M:%S"), style="dim")
                    text.append(f" {status} ", style=style)
                    text.append(f"{entry.method:6s} ", style="bold")
                    text.append(entry.path)
                    text.append(f" ({format_bytes(entry.bytes_sent)})", style="dim")
                    log.write(text)
            except Exception:
                pass
            self._last_log_count = new_count

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "close-btn":
            self.dismiss()

    def action_whois(self) -> None:
        """Trigger whois lookup for this IP."""
        if not self.whois_service or not self.whois_service.available:
            self.notify("Whois not available")
            return

        self.notify(f"Looking up {self.profile.ip}...")

        def _callback(ip, info):
            self.profile.whois = info
            self.app.call_from_thread(self._refresh_whois)

        self.whois_service.lookup(self.profile.ip, callback=_callback)

    def _refresh_whois(self) -> None:
        try:
            self.query_one("#detail-whois", Static).update(self._whois_text())
        except Exception:
            pass
