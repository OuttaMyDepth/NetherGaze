"""Main dashboard screen composing all widgets with data refresh timers."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Footer, Input
from textual.worker import Worker, WorkerState

from nethergaze.collectors.bandwidth import get_bandwidth
from nethergaze.collectors.connections import get_connections
from nethergaze.collectors.logs import LogWatcher, MultiLogWatcher
from nethergaze.config import AppConfig
from nethergaze.correlation import CorrelationEngine
from nethergaze.enrichment.geoip import GeoIPLookup
from nethergaze.enrichment.whois_lookup import WhoisLookupService
from nethergaze.utils import is_private_ip
from nethergaze.widgets.connections_table import ConnectionsTable
from nethergaze.widgets.header_bar import HeaderBar
from nethergaze.widgets.http_log import HttpActivityLog
from nethergaze.widgets.stats_bar import StatsBar


class DashboardScreen(Screen):
    """Main dashboard screen with all monitoring widgets."""

    def __init__(
        self,
        config: AppConfig,
        engine: CorrelationEngine,
        geoip: GeoIPLookup | None,
        whois: WhoisLookupService | None,
        log_watcher: LogWatcher | MultiLogWatcher | None,
    ) -> None:
        super().__init__()
        self.config = config
        self.engine = engine
        self.geoip = geoip
        self.whois = whois
        self.log_watcher = log_watcher

    def compose(self) -> ComposeResult:
        yield HeaderBar()
        with Horizontal(id="main-panels"):
            yield ConnectionsTable()
            yield HttpActivityLog(max_lines=self.config.max_log_lines)
        yield StatsBar()
        yield Input(id="filter-input", placeholder="Filter log (Enter to apply, Escape to dismiss)")
        yield Footer()

    def on_mount(self) -> None:
        self.set_interval(
            self.config.connections_interval,
            self._poll_connections,
        )
        self.set_interval(
            self.config.log_interval,
            self._poll_logs,
        )
        self.set_interval(
            self.config.bandwidth_interval,
            self._poll_bandwidth,
        )
        self.set_interval(60.0, self._trim_stale)
        # Initial bandwidth check
        self._poll_bandwidth()

    def _poll_connections(self) -> None:
        """Kick off a connection poll worker."""
        self._run_connections_worker()

    @property
    def _header(self) -> HeaderBar:
        return self.query_one(HeaderBar)

    @property
    def _table(self) -> ConnectionsTable:
        return self.query_one(ConnectionsTable)

    @property
    def _log(self) -> HttpActivityLog:
        return self.query_one(HttpActivityLog)

    @property
    def _stats(self) -> StatsBar:
        return self.query_one(StatsBar)

    def _enrich_ip(self, ip: str) -> None:
        """Auto-enrich an IP with GeoIP and whois (called from worker threads)."""
        if is_private_ip(ip):
            return
        profile = self.engine.get_profile(ip)
        if not profile:
            return
        # GeoIP (sync, fast)
        if self.geoip and self.geoip.available and profile.geo is None:
            geo = self.geoip.lookup(ip)
            self.engine.update_geo(ip, geo)
        # Whois (async via thread pool, fires callback when done)
        if self.whois and self.whois.available and profile.whois is None:
            def _on_whois(looked_ip, info):
                self.engine.update_whois(looked_ip, info)
                self.app.call_from_thread(self._refresh_table)
            self.whois.lookup(ip, callback=_on_whois)

    def _run_connections_worker(self) -> None:
        """Read connections in a thread worker."""

        def _work() -> None:
            connections = get_connections(
                include_private=self.config.show_private_ips,
            )
            self.engine.update_connections(connections)

            # Enrich new IPs
            seen = set()
            for conn in connections:
                if conn.remote_ip not in seen:
                    seen.add(conn.remote_ip)
                    self._enrich_ip(conn.remote_ip)

            # Update UI
            self.app.call_from_thread(self._refresh_table)

        self.run_worker(_work, thread=True, exclusive=True, group="connections")

    def _poll_logs(self) -> None:
        """Poll log watcher for new entries."""
        if not self.log_watcher:
            return

        def _work() -> None:
            entries = self.log_watcher.poll()
            if not entries:
                return
            # Filter out private/Docker-internal IPs unless configured to show them
            if not self.config.show_private_ips:
                entries = [e for e in entries if not is_private_ip(e.remote_ip)]
            if not entries:
                return
            self.engine.update_log_entries(entries)
            # Enrich new IPs
            seen = set()
            for entry in entries:
                if entry.remote_ip not in seen:
                    seen.add(entry.remote_ip)
                    self._enrich_ip(entry.remote_ip)

            self.app.call_from_thread(self._on_new_log_entries, entries)

        self.run_worker(_work, thread=True, exclusive=True, group="logs")

    def _poll_bandwidth(self) -> None:
        """Poll bandwidth stats."""

        def _work() -> None:
            stats = get_bandwidth(interface=self.config.interface)
            if stats:
                self.engine.update_bandwidth(stats)
            self.app.call_from_thread(self._refresh_bandwidth, stats)

        self.run_worker(_work, thread=True, exclusive=True, group="bandwidth")

    def _refresh_table(self) -> None:
        """Refresh the connections table and stats bar (on main thread)."""
        profiles = self.engine.get_profiles()
        self._table.update_data(profiles)
        stats = self.engine.get_aggregate_stats()
        self._stats.update_stats(stats)

    def _on_new_log_entries(self, entries) -> None:
        """Handle new log entries on the main thread."""
        self._log.add_entries(entries)
        self._refresh_table()

    def _refresh_bandwidth(self, stats) -> None:
        """Refresh header bandwidth display."""
        self._header.update_bandwidth(stats)

    def on_connections_table_ip_selected(self, event: ConnectionsTable.IPSelected) -> None:
        """Handle IP selection — open drill-down modal."""
        from nethergaze.screens.ip_detail import IPDetailScreen

        profile = self.engine.get_profile(event.ip)
        if profile:
            self.app.push_screen(IPDetailScreen(profile, self.whois))

    def action_cycle_sort(self) -> None:
        """Cycle sort column."""
        self._table.cycle_sort()

    def action_refresh(self) -> None:
        """Force refresh all data."""
        self._run_connections_worker()
        self._poll_logs()
        self._poll_bandwidth()

    def action_whois_selected(self) -> None:
        """Trigger whois lookup for currently selected IP."""
        if not self.whois or not self.whois.available:
            self.notify("Whois not available", severity="warning")
            return
        table = self.query_one("#conn-table")
        try:
            row_key = table.get_row_at(table.cursor_row)
            ip = str(row_key[0]) if row_key else None
        except Exception:
            ip = None

        if ip:
            self.notify(f"Looking up {ip}...")

            def _on_whois(looked_ip, info):
                self.engine.update_whois(looked_ip, info)
                self.app.call_from_thread(self._refresh_table)

            self.whois.lookup(ip, callback=_on_whois)

    def action_filter_log(self) -> None:
        """Toggle the filter input visibility."""
        filter_input = self.query_one("#filter-input", Input)
        if filter_input.has_class("visible"):
            # Hide and clear filter
            filter_input.remove_class("visible")
            filter_input.value = ""
            self._log.set_filter(None)
        else:
            filter_input.add_class("visible")
            filter_input.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Apply the filter text when Enter is pressed."""
        if event.input.id == "filter-input":
            text = event.value.strip()
            if text:
                self._log.set_filter(text)
            else:
                self._log.set_filter(None)
            event.input.remove_class("visible")

    def key_escape(self) -> None:
        """Dismiss filter input on Escape without applying."""
        filter_input = self.query_one("#filter-input", Input)
        if filter_input.has_class("visible"):
            filter_input.remove_class("visible")
            filter_input.value = ""

    def _trim_stale(self) -> None:
        """Remove stale IP profiles to prevent memory leaks."""
        self.engine.trim_stale_profiles(max_age_seconds=300)
