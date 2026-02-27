"""Help modal screen showing all key bindings."""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from nethergaze.models import ActionHook

BUILTIN_BINDINGS = [
    ("q", "Quit"),
    ("Tab / Shift+Tab", "Switch panel focus"),
    ("Enter", "Drill down into selected IP"),
    ("s", "Cycle sort (connections / requests / bytes / IP)"),
    ("w", "Whois lookup for selected IP"),
    ("r", "Force refresh all data"),
    ("/", "Quick text filter"),
    ("f", "Open structured filter modal"),
    ("!", "Toggle suspicious mode"),
    ("c", "Copy selected IP to clipboard"),
    ("b", "Block assist (auto-detects firewall)"),
    ("?", "Show this help"),
]


class HelpScreen(ModalScreen[None]):
    """Modal displaying all key bindings."""

    BINDINGS = [
        ("escape", "dismiss_modal", "Close"),
        ("question_mark", "dismiss_modal", "Close"),
    ]

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-dialog {
        width: 64;
        height: auto;
        max-height: 30;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #help-title {
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    #help-bindings {
        margin-bottom: 1;
    }
    #help-hooks-header {
        text-style: bold;
        margin-top: 1;
    }
    #help-hooks {
        margin-bottom: 1;
    }
    #help-close {
        dock: bottom;
        width: 100%;
    }
    """

    def __init__(self, hooks: list[ActionHook] | None = None) -> None:
        super().__init__()
        self._hooks = hooks or []

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help-dialog"):
            yield Static("Key Bindings", id="help-title")
            yield Static(self._format_bindings(), id="help-bindings")
            if self._hooks:
                yield Static("Custom Hooks", id="help-hooks-header")
                yield Static(self._format_hooks(), id="help-hooks")
            yield Button("Close [Esc]", id="help-close", variant="primary")

    def _format_bindings(self) -> str:
        lines = []
        for key, desc in BUILTIN_BINDINGS:
            lines.append(f"  {key:20s} {desc}")
        return "\n".join(lines)

    def _format_hooks(self) -> str:
        lines = []
        for hook in self._hooks:
            lines.append(f"  {hook.key:20s} {hook.label}")
        return "\n".join(lines)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "help-close":
            self.dismiss(None)

    def action_dismiss_modal(self) -> None:
        self.dismiss(None)
