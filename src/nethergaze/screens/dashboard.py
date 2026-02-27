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
from nethergaze.filters import FilterState, parse_cidr_list
from nethergaze.models import ActionHook
from nethergaze.utils import is_private_ip
from nethergaze.widgets.connections_table import ConnectionsTable
from nethergaze.widgets.header_bar import HeaderBar
from nethergaze.widgets.http_log import HttpActivityLog
from nethergaze.widgets.offenders_bar import OffendersBar
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

        # Initialize filter state with config-based CIDR lists
        self._filters = FilterState(
            cidr_allow=parse_cidr_list(config.cidr_allow),
            cidr_deny=parse_cidr_list(config.cidr_deny),
            suspicious_burst_rpm=config.suspicious_burst_rpm,
            suspicious_min_conns=config.suspicious_min_conns,
            extra_scanner_patterns=config.scanner_user_agents,
        )
        self._pre_suspicious_filters: FilterState | None = None

        # Parse action hooks from config
        self._action_hooks: list[ActionHook] = []
        for hook_dict in config.action_hooks:
            key = hook_dict.get("key", "")
            label = hook_dict.get("label", "")
            command = hook_dict.get("command", "")
            if key and label and command:
                self._action_hooks.append(ActionHook(key=key, label=label, command=command))

    def compose(self) -> ComposeResult:
        yield HeaderBar()
        yield OffendersBar()
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
        # Rescan for new log files every 30s (only relevant for glob-based MultiLogWatcher)
        if isinstance(self.log_watcher, MultiLogWatcher):
            self.set_interval(30.0, self.log_watcher.rescan)
        # Initial bandwidth check
        self._poll_bandwidth()

    def _poll_connections(self) -> None:
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

    @property
    def _offenders(self) -> OffendersBar:
        return self.query_one(OffendersBar)

    # --- Selected IP helper ---

    def _get_selected_ip(self) -> str | None:
        """Get the IP from the currently selected row in the connections table."""
        table = self.query_one("#conn-table")
        try:
            row = table.get_row_at(table.cursor_row)
            return str(row[0]) if row else None
        except Exception:
            return None

    # --- Enrichment ---

    def _enrich_ip(self, ip: str) -> None:
        if is_private_ip(ip):
            return
        profile = self.engine.get_profile(ip)
        if not profile:
            return
        if self.geoip and self.geoip.available and profile.geo is None:
            geo = self.geoip.lookup(ip)
            self.engine.update_geo(ip, geo)
        if self.whois and self.whois.available and profile.whois is None:
            def _on_whois(looked_ip, info):
                self.engine.update_whois(looked_ip, info)
                self.app.call_from_thread(self._refresh_table)
            self.whois.lookup(ip, callback=_on_whois)

    # --- Data polling workers ---

    def _run_connections_worker(self) -> None:
        def _work() -> None:
            connections = get_connections(
                include_private=self.config.show_private_ips,
            )
            self.engine.update_connections(connections)
            seen = set()
            for conn in connections:
                if conn.remote_ip not in seen:
                    seen.add(conn.remote_ip)
                    self._enrich_ip(conn.remote_ip)
            self.app.call_from_thread(self._refresh_table)

        self.run_worker(_work, thread=True, exclusive=True, group="connections")

    def _poll_logs(self) -> None:
        if not self.log_watcher:
            return

        def _work() -> None:
            entries = self.log_watcher.poll()
            if not entries:
                return
            if not self.config.show_private_ips:
                entries = [e for e in entries if not is_private_ip(e.remote_ip)]
            if not entries:
                return
            self.engine.update_log_entries(entries)
            seen = set()
            for entry in entries:
                if entry.remote_ip not in seen:
                    seen.add(entry.remote_ip)
                    self._enrich_ip(entry.remote_ip)
            self.app.call_from_thread(self._on_new_log_entries, entries)

        self.run_worker(_work, thread=True, exclusive=True, group="logs")

    def _poll_bandwidth(self) -> None:
        def _work() -> None:
            stats = get_bandwidth(interface=self.config.interface)
            if stats:
                self.engine.update_bandwidth(stats)
            self.app.call_from_thread(self._refresh_bandwidth, stats)

        self.run_worker(_work, thread=True, exclusive=True, group="bandwidth")

    # --- UI refresh (main thread) ---

    def _refresh_table(self) -> None:
        profiles = self.engine.get_profiles()

        # Apply filters to connections table
        if self._filters.is_active:
            profiles = [p for p in profiles if self._filters.matches_profile(p)]

        self._table.update_data(profiles)

        stats = self.engine.get_aggregate_stats()
        self._stats.update_stats(stats, self._filters)

        summary = self.engine.get_offender_summary()
        self._offenders.update_offenders(summary)

        # Update header suspicious indicator
        self._header.set_suspicious_mode(self._filters.suspicious_mode)

    def _on_new_log_entries(self, entries) -> None:
        # Apply filters to log entries
        if self._filters.is_active:
            entries = [e for e in entries if self._filters.matches_log_entry(e)]
        self._log.add_entries(entries)
        self._refresh_table()

    def _refresh_bandwidth(self, stats) -> None:
        self._header.update_bandwidth(stats)

    # --- Events ---

    def on_connections_table_ip_selected(self, event: ConnectionsTable.IPSelected) -> None:
        from nethergaze.screens.ip_detail import IPDetailScreen

        profile = self.engine.get_profile(event.ip)
        if profile:
            self.app.push_screen(IPDetailScreen(profile, self.whois, engine=self.engine))

    # --- Actions ---

    def action_cycle_sort(self) -> None:
        self._table.cycle_sort()

    def action_refresh(self) -> None:
        self._run_connections_worker()
        self._poll_logs()
        self._poll_bandwidth()

    def action_whois_selected(self) -> None:
        if not self.whois or not self.whois.available:
            self.notify("Whois not available", severity="warning")
            return
        ip = self._get_selected_ip()
        if ip:
            self.notify(f"Looking up {ip}...")

            def _on_whois(looked_ip, info):
                self.engine.update_whois(looked_ip, info)
                self.app.call_from_thread(self._refresh_table)

            self.whois.lookup(ip, callback=_on_whois)

    def action_filter_log(self) -> None:
        """Toggle the quick text filter input."""
        filter_input = self.query_one("#filter-input", Input)
        if filter_input.has_class("visible"):
            filter_input.remove_class("visible")
            filter_input.value = ""
            self._filters.text_filter = None
            self._refresh_table()
        else:
            filter_input.add_class("visible")
            filter_input.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter-input":
            text = event.value.strip()
            self._filters.text_filter = text.lower() if text else None
            event.input.remove_class("visible")
            self._refresh_table()

    def key_escape(self) -> None:
        filter_input = self.query_one("#filter-input", Input)
        if filter_input.has_class("visible"):
            filter_input.remove_class("visible")
            filter_input.value = ""

    def action_open_filters(self) -> None:
        """Open the structured filter modal."""
        from nethergaze.screens.filter_screen import FilterScreen

        def _on_dismiss(result: FilterState | None) -> None:
            if result is not None:
                self._filters = result
                self._refresh_table()

        self.app.push_screen(FilterScreen(self._filters), callback=_on_dismiss)

    def action_toggle_suspicious(self) -> None:
        """Toggle suspicious mode on/off."""
        if self._filters.suspicious_mode:
            # Restore previous filter state
            if self._pre_suspicious_filters is not None:
                self._filters = self._pre_suspicious_filters
                self._pre_suspicious_filters = None
            else:
                self._filters.suspicious_mode = False
            self.notify("Suspicious mode OFF")
        else:
            # Save current state and enable suspicious mode
            self._pre_suspicious_filters = FilterState(
                tcp_states=self._filters.tcp_states,
                status_codes=self._filters.status_codes,
                min_request_rate=self._filters.min_request_rate,
                cidr_allow=self._filters.cidr_allow,
                cidr_deny=self._filters.cidr_deny,
                text_filter=self._filters.text_filter,
                suspicious_burst_rpm=self._filters.suspicious_burst_rpm,
                suspicious_min_conns=self._filters.suspicious_min_conns,
                extra_scanner_patterns=self._filters.extra_scanner_patterns,
            )
            self._filters = FilterState(
                suspicious_mode=True,
                cidr_allow=self._filters.cidr_allow,
                cidr_deny=self._filters.cidr_deny,
                suspicious_burst_rpm=self._filters.suspicious_burst_rpm,
                suspicious_min_conns=self._filters.suspicious_min_conns,
                extra_scanner_patterns=self._filters.extra_scanner_patterns,
            )
            self.notify("Suspicious mode ON")
        self._refresh_table()

    def action_copy_ip(self) -> None:
        """Copy selected IP to clipboard."""
        ip = self._get_selected_ip()
        if ip:
            self.app.copy_to_clipboard(ip)
            self.notify(f"Copied {ip}")
        else:
            self.notify("No IP selected", severity="warning")

    def action_suggest_block(self) -> None:
        """Show suggested block command for selected IP."""
        ip = self._get_selected_ip()
        if not ip:
            self.notify("No IP selected", severity="warning")
            return

        from nethergaze.screens.block_screen import BlockScreen

        self.app.push_screen(
            BlockScreen(ip, allow_execute=self.config.enable_block_execution)
        )

    # --- Action hooks ---

    def on_key(self, event) -> None:
        """Handle custom action hook key presses."""
        if not self._action_hooks:
            return
        # Don't intercept when filter input is focused
        filter_input = self.query_one("#filter-input", Input)
        if filter_input.has_class("visible"):
            return
        for hook in self._action_hooks:
            if event.character == hook.key:
                ip = self._get_selected_ip()
                if ip:
                    self._run_action_hook(hook, ip)
                else:
                    self.notify("No IP selected", severity="warning")
                event.prevent_default()
                event.stop()
                return

    def _run_action_hook(self, hook: ActionHook, ip: str) -> None:
        from nethergaze.screens.hook_screen import HookOutputScreen

        self.app.push_screen(HookOutputScreen(hook, ip))

    @property
    def action_hooks(self) -> list[ActionHook]:
        """Expose configured hooks for help text generation."""
        return self._action_hooks

    def _trim_stale(self) -> None:
        self.engine.trim_stale_profiles(max_age_seconds=300)
