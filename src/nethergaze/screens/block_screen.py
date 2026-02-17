"""Block confirmation modal screen."""

from __future__ import annotations

import subprocess

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from nethergaze.actions import detect_firewall, generate_block_command


class BlockScreen(ModalScreen[bool]):
    """Modal showing suggested block command with optional execution."""

    BINDINGS = [
        ("escape", "dismiss_modal", "Close"),
    ]

    DEFAULT_CSS = """
    BlockScreen {
        align: center middle;
    }
    #block-dialog {
        width: 70;
        height: auto;
        max-height: 16;
        border: thick $error;
        background: $surface;
        padding: 1 2;
    }
    #block-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #block-command {
        background: $surface-darken-1;
        padding: 1;
        margin-bottom: 1;
    }
    #block-firewall {
        color: $text-muted;
        margin-bottom: 1;
    }
    #block-buttons {
        height: 3;
        align: center middle;
    }
    #block-buttons Button {
        margin: 0 1;
    }
    #block-result {
        margin-top: 1;
        color: $success;
    }
    """

    def __init__(self, ip: str, allow_execute: bool = False) -> None:
        super().__init__()
        self._ip = ip
        self._allow_execute = allow_execute
        self._firewall = detect_firewall()
        self._command = generate_block_command(ip, self._firewall)

    def compose(self) -> ComposeResult:
        with Vertical(id="block-dialog"):
            yield Static(f"Block IP: {self._ip}", id="block-title")
            yield Static(f"Detected firewall: {self._firewall}", id="block-firewall")
            yield Static(self._command, id="block-command")
            with Horizontal(id="block-buttons"):
                yield Button("Copy", id="copy", variant="primary")
                if self._allow_execute:
                    yield Button("Execute", id="execute", variant="error")
                yield Button("Close", id="close")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy":
            self.app.copy_to_clipboard(self._command)
            self.notify("Copied to clipboard")
        elif event.button.id == "execute":
            self._execute_block()
        elif event.button.id == "close":
            self.dismiss(False)

    def action_dismiss_modal(self) -> None:
        self.dismiss(False)

    def _execute_block(self) -> None:
        try:
            result = subprocess.run(
                self._command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                self.notify(f"Blocked {self._ip}", severity="information")
                self.dismiss(True)
            else:
                msg = result.stderr.strip() or f"Exit code {result.returncode}"
                self.notify(f"Failed: {msg}", severity="error")
        except subprocess.TimeoutExpired:
            self.notify("Command timed out", severity="error")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")
