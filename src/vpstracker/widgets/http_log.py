"""HTTP activity log widget with color-coded status codes."""

from __future__ import annotations

from rich.text import Text
from textual.widgets import RichLog, Static
from textual.app import ComposeResult

from vpstracker.models import LogEntry


class HttpActivityLog(Static):
    """Streaming HTTP log with color-coded status codes."""

    DEFAULT_CSS = """
    HttpActivityLog {
        height: 1fr;
    }
    HttpActivityLog RichLog {
        height: 1fr;
        border: solid $surface-lighten-2;
    }
    """

    def __init__(self, max_lines: int = 500) -> None:
        super().__init__()
        self._max_lines = max_lines
        self._filter: str | None = None

    def compose(self) -> ComposeResult:
        yield RichLog(id="http-log", max_lines=self._max_lines, wrap=False, markup=False)

    def add_entries(self, entries: list[LogEntry]) -> None:
        """Add new log entries to the log display."""
        log = self.query_one(RichLog)
        for entry in entries:
            if self._filter and self._filter not in _entry_text(entry):
                continue
            log.write(_format_entry(entry))

    def set_filter(self, text: str | None) -> None:
        """Set or clear the log filter."""
        self._filter = text.lower() if text else None

    def clear_log(self) -> None:
        """Clear the log display."""
        self.query_one(RichLog).clear()


def _format_entry(entry: LogEntry) -> Text:
    """Format a log entry as a Rich Text with color-coded status."""
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
    text.append(" ")
    text.append(entry.remote_ip.ljust(16), style="bold")
    text.append(f" {status} ", style=style)
    text.append(f"{entry.method:6s} ", style="bold")
    text.append(entry.path)
    return text


def _entry_text(entry: LogEntry) -> str:
    """Plain text for filtering."""
    return f"{entry.remote_ip} {entry.status_code} {entry.method} {entry.path}".lower()
