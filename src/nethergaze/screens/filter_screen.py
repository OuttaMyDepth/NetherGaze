"""Filter configuration modal screen."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Static

from nethergaze.filters import (
    FilterState,
    parse_status_code_spec,
    parse_tcp_states,
)


class FilterScreen(ModalScreen[FilterState | None]):
    """Modal for configuring structured filters."""

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    DEFAULT_CSS = """
    FilterScreen {
        align: center middle;
    }
    #filter-dialog {
        width: 64;
        height: auto;
        max-height: 30;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #filter-title {
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    .filter-label {
        margin-top: 1;
        color: $text-muted;
    }
    .filter-input {
        margin-bottom: 0;
    }
    #filter-buttons {
        margin-top: 1;
        height: 3;
        align: center middle;
    }
    #filter-buttons Button {
        margin: 0 1;
    }
    """

    def __init__(self, current: FilterState) -> None:
        super().__init__()
        self._current = current

    def compose(self) -> ComposeResult:
        with Vertical(id="filter-dialog"):
            yield Static("Filters", id="filter-title")

            yield Static(
                "TCP State (SYN_RECV, ESTABLISHED, ...):", classes="filter-label"
            )
            yield Input(
                id="tcp-state",
                placeholder="e.g. SYN_RECV,ESTABLISHED",
                value=self._prefill_tcp(),
                classes="filter-input",
            )

            yield Static(
                "Status Codes (4xx, 5xx, 200-299, ...):", classes="filter-label"
            )
            yield Input(
                id="status-codes",
                placeholder="e.g. 4xx,5xx",
                value=self._prefill_status(),
                classes="filter-input",
            )

            yield Static("Min Request Rate (req/min):", classes="filter-label")
            yield Input(
                id="min-rate",
                placeholder="e.g. 60",
                value=self._prefill_rate(),
                classes="filter-input",
            )

            yield Static("Text Filter:", classes="filter-label")
            yield Input(
                id="text-filter",
                placeholder="Free text search",
                value=self._current.text_filter or "",
                classes="filter-input",
            )

            with Horizontal(id="filter-buttons"):
                yield Button("Apply", id="apply", variant="primary")
                yield Button("Clear", id="clear", variant="warning")
                yield Button("Cancel", id="cancel")

    def _prefill_tcp(self) -> str:
        if self._current.tcp_states:
            return ",".join(s.name for s in self._current.tcp_states)
        return ""

    def _prefill_status(self) -> str:
        if self._current.status_codes:
            return ",".join(f"{lo}-{hi}" for lo, hi in self._current.status_codes)
        return ""

    def _prefill_rate(self) -> str:
        if self._current.min_request_rate is not None:
            return str(int(self._current.min_request_rate))
        return ""

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply":
            self._apply()
        elif event.button.id == "clear":
            self.dismiss(
                FilterState(
                    cidr_allow=self._current.cidr_allow,
                    cidr_deny=self._current.cidr_deny,
                    suspicious_burst_rpm=self._current.suspicious_burst_rpm,
                    suspicious_min_conns=self._current.suspicious_min_conns,
                    extra_scanner_patterns=self._current.extra_scanner_patterns,
                )
            )
        elif event.button.id == "cancel":
            self.dismiss(None)

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _apply(self) -> None:
        tcp_val = self.query_one("#tcp-state", Input).value.strip()
        status_val = self.query_one("#status-codes", Input).value.strip()
        rate_val = self.query_one("#min-rate", Input).value.strip()
        text_val = self.query_one("#text-filter", Input).value.strip()

        new_filter = FilterState(
            tcp_states=parse_tcp_states(tcp_val),
            status_codes=parse_status_code_spec(status_val),
            min_request_rate=float(rate_val) if rate_val else None,
            text_filter=text_val.lower() if text_val else None,
            cidr_allow=self._current.cidr_allow,
            cidr_deny=self._current.cidr_deny,
            suspicious_burst_rpm=self._current.suspicious_burst_rpm,
            suspicious_min_conns=self._current.suspicious_min_conns,
            extra_scanner_patterns=self._current.extra_scanner_patterns,
        )
        self.dismiss(new_filter)
