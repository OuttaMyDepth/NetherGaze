"""Nethergaze Textual application."""

from __future__ import annotations

from pathlib import Path

from textual.app import App

from nethergaze.collectors.logs import LogWatcher
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
        ("tab", "focus_next", "Next Panel"),
        ("shift+tab", "focus_previous", "Prev Panel"),
        ("enter", "select", "Select"),
        ("s", "cycle_sort", "Sort"),
        ("w", "whois_selected", "Whois"),
        ("r", "refresh", "Refresh"),
        ("slash", "filter_log", "Filter"),
        ("question_mark", "help", "Help"),
    ]

    def __init__(self, config: AppConfig) -> None:
        super().__init__()
        self.config = config

        # Initialize correlation engine
        self.engine = CorrelationEngine()

        # Initialize GeoIP
        self.geoip: GeoIPLookup | None = None
        if config.geoip_enabled:
            self.geoip = GeoIPLookup(config.geoip_city_db, config.geoip_asn_db)
            if not self.geoip.available:
                self.geoip = None

        # Initialize whois service
        self.whois: WhoisLookupService | None = None
        if config.whois_enabled:
            self.whois = WhoisLookupService(
                max_workers=config.whois_max_workers,
                cache_ttl=config.whois_cache_ttl,
                cache_dir=config.cache_dir,
            )
            if not self.whois.available:
                self.whois = None

        # Initialize log watcher
        self.log_watcher: LogWatcher | None = None
        if config.log_path and Path(config.log_path).exists():
            self.log_watcher = LogWatcher(
                config.log_path,
                max_entries_per_ip=config.max_log_entries_per_ip,
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

    def action_cycle_sort(self) -> None:
        screen = self.screen
        if hasattr(screen, "action_cycle_sort"):
            screen.action_cycle_sort()

    def action_whois_selected(self) -> None:
        screen = self.screen
        if hasattr(screen, "action_whois_selected"):
            screen.action_whois_selected()

    def action_refresh(self) -> None:
        screen = self.screen
        if hasattr(screen, "action_refresh"):
            screen.action_refresh()

    def action_filter_log(self) -> None:
        screen = self.screen
        if hasattr(screen, "action_filter_log"):
            screen.action_filter_log()

    def action_help(self) -> None:
        self.notify(
            "q:Quit  Tab:Focus  Enter:Detail  s:Sort  "
            "w:Whois  r:Refresh  /:Filter  ?:Help",
            title="Key Bindings",
            timeout=5,
        )

    def on_unmount(self) -> None:
        if self.log_watcher:
            self.log_watcher.close()
        if self.whois:
            self.whois.shutdown()
        if self.geoip:
            self.geoip.close()
