"""Action hook output modal screen."""

from __future__ import annotations

import subprocess

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, RichLog, Static

from nethergaze.models import ActionHook


class HookOutputScreen(ModalScreen[None]):
    """Modal that runs a custom action hook and displays its output."""

    BINDINGS = [
        ("escape", "dismiss_modal", "Close"),
    ]

    DEFAULT_CSS = """
    HookOutputScreen {
        align: center middle;
    }
    #hook-dialog {
        width: 80;
        height: auto;
        max-height: 24;
        border: thick $accent;
        background: $surface;
        padding: 1 2;
    }
    #hook-title {
        text-style: bold;
        margin-bottom: 1;
    }
    #hook-command {
        background: $surface-darken-1;
        padding: 0 1;
        color: $text-muted;
        margin-bottom: 1;
    }
    #hook-output {
        height: auto;
        max-height: 14;
        background: $surface-darken-1;
        padding: 1;
        margin-bottom: 1;
    }
    #hook-buttons {
        height: 3;
        align: center middle;
    }
    #hook-buttons Button {
        margin: 0 1;
    }
    """

    def __init__(self, hook: ActionHook, ip: str) -> None:
        super().__init__()
        self._hook = hook
        self._ip = ip
        self._command = hook.command.replace("{ip}", ip)

    def compose(self) -> ComposeResult:
        with Vertical(id="hook-dialog"):
            yield Static(f"{self._hook.label}: {self._ip}", id="hook-title")
            yield Static(f"$ {self._command}", id="hook-command")
            yield RichLog(id="hook-output", wrap=True, markup=False)
            with Horizontal(id="hook-buttons"):
                yield Button("Copy Output", id="copy")
                yield Button("Close", id="close", variant="primary")

    def on_mount(self) -> None:
        self._run_hook()

    def _run_hook(self) -> None:
        log = self.query_one("#hook-output", RichLog)
        log.write("Running...")

        def _work() -> None:
            try:
                result = subprocess.run(
                    self._command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                output = result.stdout
                if result.stderr:
                    output += result.stderr
                if result.returncode != 0 and not output.strip():
                    output = f"Exit code {result.returncode}"
                text = output.strip() or "(no output)"
            except subprocess.TimeoutExpired:
                text = "Command timed out (15s)"
            except Exception as e:
                text = f"Error: {e}"
            self.app.call_from_thread(self._show_output, text)

        self._output_text = ""
        self.run_worker(_work, thread=True)

    def _show_output(self, text: str) -> None:
        self._output_text = text
        log = self.query_one("#hook-output", RichLog)
        log.clear()
        log.write(text)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "copy":
            self.app.copy_to_clipboard(self._output_text)
            self.notify("Copied to clipboard")
        elif event.button.id == "close":
            self.dismiss(None)

    def action_dismiss_modal(self) -> None:
        self.dismiss(None)
