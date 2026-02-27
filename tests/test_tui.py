"""Textual TUI integration tests using async pilot."""

from __future__ import annotations

import pytest
from textual.widgets import DataTable, Input

from nethergaze.app import NethergazeApp
from nethergaze.config import AppConfig
from nethergaze.models import Connection, IPProfile, TCPState
from nethergaze.screens.dashboard import DashboardScreen
from nethergaze.widgets.connections_table import ConnectionsTable
from nethergaze.widgets.header_bar import HeaderBar
from nethergaze.widgets.stats_bar import StatsBar


def _test_config(tmp_path) -> AppConfig:
    """Config with all enrichment and log watching disabled."""
    return AppConfig(
        log_path="",
        geoip_enabled=False,
        whois_enabled=False,
        connections_interval=999,
        log_interval=999,
        bandwidth_interval=999,
    )


@pytest.fixture
def test_config(tmp_path):
    return _test_config(tmp_path)


def _make_app(config: AppConfig) -> NethergazeApp:
    return NethergazeApp(config)


class TestAppLaunch:
    @pytest.mark.asyncio
    async def test_app_starts_and_shows_dashboard(self, test_config):
        app = _make_app(test_config)
        async with app.run_test():
            assert isinstance(app.screen, DashboardScreen)

    @pytest.mark.asyncio
    async def test_widgets_present(self, test_config):
        app = _make_app(test_config)
        async with app.run_test():
            app.screen.query_one(HeaderBar)
            app.screen.query_one(ConnectionsTable)
            app.screen.query_one(StatsBar)

    @pytest.mark.asyncio
    async def test_quit(self, test_config):
        app = _make_app(test_config)
        async with app.run_test() as pilot:
            await pilot.press("q")
            assert app.return_code is not None or app._exit


class TestKeyBindings:
    @pytest.mark.asyncio
    async def test_filter_input_toggle(self, test_config):
        app = _make_app(test_config)
        async with app.run_test() as pilot:
            filter_input = app.screen.query_one("#filter-input", Input)
            assert not filter_input.has_class("visible")
            await pilot.press("slash")
            assert filter_input.has_class("visible")
            await pilot.press("escape")
            assert not filter_input.has_class("visible")

    @pytest.mark.asyncio
    async def test_suspicious_mode_toggle(self, test_config):
        app = _make_app(test_config)
        async with app.run_test() as pilot:
            dashboard = app.screen
            assert not dashboard._filters.suspicious_mode
            await pilot.press("exclamation_mark")
            assert dashboard._filters.suspicious_mode
            await pilot.press("exclamation_mark")
            assert not dashboard._filters.suspicious_mode

    @pytest.mark.asyncio
    async def test_sort_cycle(self, test_config):
        app = _make_app(test_config)
        async with app.run_test() as pilot:
            table = app.screen.query_one(ConnectionsTable)
            assert table._sort_key == "conns"
            await pilot.press("s")
            assert table._sort_key == "reqs"
            await pilot.press("s")
            assert table._sort_key == "bytes"
            await pilot.press("s")
            assert table._sort_key == "ip"
            await pilot.press("s")
            assert table._sort_key == "conns"


class TestFilterScreen:
    @pytest.mark.asyncio
    async def test_open_and_cancel(self, test_config):
        app = _make_app(test_config)
        async with app.run_test() as pilot:
            await pilot.press("f")
            # FilterScreen should be pushed
            from nethergaze.screens.filter_screen import FilterScreen

            assert isinstance(app.screen, FilterScreen)
            await pilot.press("escape")
            assert isinstance(app.screen, DashboardScreen)


class TestConnectionsTableWithData:
    @pytest.mark.asyncio
    async def test_table_shows_injected_profiles(self, test_config):
        app = _make_app(test_config)
        async with app.run_test() as pilot:
            # Inject profiles directly into the engine
            profiles = [
                IPProfile(
                    ip="1.2.3.4",
                    connections=[
                        Connection(
                            local_ip="0.0.0.0",
                            local_port=443,
                            remote_ip="1.2.3.4",
                            remote_port=12345,
                            state=TCPState.ESTABLISHED,
                            inode=0,
                        )
                    ],
                    total_requests=10,
                    total_bytes_sent=5000,
                ),
                IPProfile(
                    ip="5.6.7.8",
                    connections=[
                        Connection(
                            local_ip="0.0.0.0",
                            local_port=80,
                            remote_ip="5.6.7.8",
                            remote_port=54321,
                            state=TCPState.SYN_RECV,
                            inode=0,
                        )
                    ],
                    total_requests=0,
                    total_bytes_sent=0,
                ),
            ]
            table_widget = app.screen.query_one(ConnectionsTable)
            table_widget.update_data(profiles)
            await pilot.pause()

            table = app.screen.query_one("#conn-table", DataTable)
            assert table.row_count == 2

    @pytest.mark.asyncio
    async def test_cursor_preserves_ip_after_sort(self, test_config):
        app = _make_app(test_config)
        async with app.run_test() as pilot:
            p1 = IPProfile(
                ip="1.2.3.4",
                connections=[
                    Connection("0.0.0.0", 443, "1.2.3.4", 100, TCPState.ESTABLISHED, 0)
                ],
                total_requests=50,
                total_bytes_sent=1000,
            )
            p2 = IPProfile(
                ip="5.6.7.8",
                connections=[
                    Connection("0.0.0.0", 80, "5.6.7.8", 200, TCPState.ESTABLISHED, 0),
                    Connection("0.0.0.0", 80, "5.6.7.8", 201, TCPState.ESTABLISHED, 0),
                ],
                total_requests=5,
                total_bytes_sent=500,
            )
            table_widget = app.screen.query_one(ConnectionsTable)
            table_widget.update_data([p1, p2])
            await pilot.pause()

            # Select second row (5.6.7.8 — more conns)
            table = app.screen.query_one("#conn-table", DataTable)
            table.move_cursor(row=0)
            await pilot.pause()

            # Get the IP at cursor
            row = table.get_row_at(table.cursor_row)
            selected_ip = str(row[0])

            # Cycle sort — IP should stay selected
            await pilot.press("s")
            await pilot.pause()
            row_after = table.get_row_at(table.cursor_row)
            assert str(row_after[0]) == selected_ip


class TestActionHooks:
    @pytest.mark.asyncio
    async def test_hooks_parsed_from_config(self, tmp_path):
        config = AppConfig(
            log_path="",
            geoip_enabled=False,
            whois_enabled=False,
            connections_interval=999,
            log_interval=999,
            bandwidth_interval=999,
            action_hooks=[
                {"key": "1", "label": "Test", "command": "echo {ip}"},
            ],
        )
        app = _make_app(config)
        async with app.run_test():
            dashboard = app.screen
            assert len(dashboard.action_hooks) == 1
            assert dashboard.action_hooks[0].key == "1"
            assert dashboard.action_hooks[0].label == "Test"
