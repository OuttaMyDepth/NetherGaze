"""Sortable connections table widget."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.message import Message
from textual.widgets import DataTable, Static

from nethergaze.models import IPProfile
from nethergaze.utils import format_bytes

# Column definitions: (key, label, width)
COLUMNS = [
    ("ip", "IP Address", 18),
    ("cc", "CC", 4),
    ("org", "Organization", 24),
    ("conns", "Conns", 6),
    ("state", "State", 6),
    ("reqs", "Reqs", 6),
    ("bytes", "Bytes", 10),
    ("last_path", "Last Path", 30),
]

SORT_KEYS = ["conns", "reqs", "bytes", "ip"]


class ConnectionsTable(Static):
    """DataTable listing IP profiles with connection and request data."""

    DEFAULT_CSS = """
    ConnectionsTable {
        height: 1fr;
    }
    ConnectionsTable DataTable {
        height: 1fr;
    }
    """

    class IPSelected(Message):
        """Fired when user selects an IP row."""

        def __init__(self, ip: str) -> None:
            super().__init__()
            self.ip = ip

    def __init__(self) -> None:
        super().__init__()
        self._sort_key = "conns"
        self._sort_reverse = True
        self._profiles: list[IPProfile] = []

    def compose(self) -> ComposeResult:
        table = DataTable(id="conn-table", cursor_type="row")
        yield table

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        for key, label, _width in COLUMNS:
            table.add_column(label, key=key)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = event.row_key
        if row_key and row_key.value:
            self.post_message(self.IPSelected(str(row_key.value)))

    def cycle_sort(self) -> None:
        """Cycle through sort columns."""
        idx = SORT_KEYS.index(self._sort_key)
        self._sort_key = SORT_KEYS[(idx + 1) % len(SORT_KEYS)]
        self._sort_reverse = self._sort_key != "ip"
        self.update_data(self._profiles)

    def update_data(self, profiles: list[IPProfile]) -> None:
        """Replace all table data with new profiles."""
        self._profiles = profiles
        table = self.query_one(DataTable)

        # Sort profiles
        sorted_profiles = sorted(
            profiles,
            key=lambda p: _sort_value(p, self._sort_key),
            reverse=self._sort_reverse,
        )

        # Remember cursor position
        try:
            cursor_row = table.cursor_row
        except Exception:
            cursor_row = 0

        table.clear()
        for profile in sorted_profiles:
            active = profile.active_connections
            total_conns = len(profile.connections)
            last_path = ""
            if profile.log_entries:
                last = profile.log_entries[-1]
                last_path = f"{last.method} {last.path}"

            table.add_row(
                profile.ip,
                profile.country_code,
                _truncate(profile.as_org, 24),
                str(total_conns),
                f"{active}E" if active else "-",
                str(profile.total_requests),
                format_bytes(profile.total_bytes_sent),
                _truncate(last_path, 30),
                key=profile.ip,
            )

        # Restore cursor
        if sorted_profiles and cursor_row < len(sorted_profiles):
            try:
                table.move_cursor(row=cursor_row)
            except Exception:
                pass


def _sort_value(profile: IPProfile, key: str):
    if key == "conns":
        return (profile.active_connections, len(profile.connections))
    elif key == "reqs":
        return profile.total_requests
    elif key == "bytes":
        return profile.total_bytes_sent
    elif key == "ip":
        return profile.ip
    return 0


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"
