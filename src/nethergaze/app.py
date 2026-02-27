"""Nethergaze Textual application."""

from __future__ import annotations

from pathlib import Path

from textual.app import App

from nethergaze.collectors.logs import LogWatcher, MultiLogWatcher
from nethergaze.config import AppConfig
from nethergaze.correlation import CorrelationEngine
from nethergaze.enrichment.geoip import GeoIPLookup
from nethergaze.enrichment.whois_lookup import WhoisLookupService
from nethergaze.screens.dashboard import DashboardScreen


class NethergazeApp(App):
    """Main Nethergaze TUI application."""

    TITLE = "Nethergaze"
    CSS_PATH = "app.tcss"

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("tab", "focus_next", "Next"),
        ("shift+tab", "focus_previous", "Prev"),
        ("enter", "select", "Select"),
        ("s", "cycle_sort", "Sort"),
        ("w", "whois_selected", "Whois"),
        ("r", "refresh", "Refresh"),
        ("slash", "filter_log", "Filter"),
        ("f", "open_filters", "Filters"),
        ("exclamation_mark", "toggle_suspicious", "Sus"),
        ("c", "copy_ip", "Copy IP"),
        ("b", "suggest_block", "Block"),
        ("question_mark", "help", "Help"),
    ]

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self.config = config

        self.engine = CorrelationEngine()

        self.geoip: GeoIPLookup | None = None
        if config.geoip_enabled:
            self.geoip = GeoIPLookup(config.geoip_city_db, config.geoip_asn_db)
            if not self.geoip.available:
                self.geoip = None

        self.whois: WhoisLookupService | None = None
        if config.whois_enabled:
            self.whois = WhoisLookupService(
                max_workers=config.whois_max_workers,
                cache_ttl=config.whois_cache_ttl,
                cache_dir=config.cache_dir,
            )
            if not self.whois.available:
                self.whois = None

        self.log_watcher: LogWatcher | MultiLogWatcher | None = None
        if config.log_path:
            if any(c in config.log_path for c in "*?["):
                self.log_watcher = MultiLogWatcher(
                    config.log_path,
                    max_entries_per_ip=config.max_log_entries_per_ip,
                    log_format=config.log_format,
                )
            elif Path(config.log_path).exists():
                self.log_watcher = LogWatcher(
                    config.log_path,
                    max_entries_per_ip=config.max_log_entries_per_ip,
                    log_format=config.log_format,
                )

    def on_mount(self) -> None:
        self.push_screen(
            DashboardScreen(
                config=self.config,
                engine=self.engine,
                geoip=self.geoip,
                whois=self.whois,
                log_watcher=self.log_watcher,
            )
        )

    def _delegate(self, action: str) -> None:
        """Delegate an action to the current screen if it supports it."""
        screen = self.screen
        method = getattr(screen, action, None)
        if method:
            method()

    def action_cycle_sort(self) -> None:
        self._delegate("action_cycle_sort")

    def action_whois_selected(self) -> None:
        self._delegate("action_whois_selected")

    def action_refresh(self) -> None:
        self._delegate("action_refresh")

    def action_filter_log(self) -> None:
        self._delegate("action_filter_log")

    def action_open_filters(self) -> None:
        self._delegate("action_open_filters")

    def action_toggle_suspicious(self) -> None:
        self._delegate("action_toggle_suspicious")

    def action_copy_ip(self) -> None:
        self._delegate("action_copy_ip")

    def action_suggest_block(self) -> None:
        self._delegate("action_suggest_block")

    def action_help(self) -> None:
        from nethergaze.screens.help_screen import HelpScreen

        hooks = getattr(self.screen, "action_hooks", [])
        self.push_screen(HelpScreen(hooks=hooks))

    def _shutdown_services(self) -> None:
        if self.log_watcher:
            self.log_watcher.close()
        if self.whois:
            self.whois.shutdown()
        if self.geoip:
            self.geoip.close()

    def on_unmount(self) -> None:
        self._shutdown_services()

    def action_quit(self) -> None:
        self._shutdown_services()
        self.exit()
