"""Workspace help without mixing instructions into engine logs."""
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import Button, Static

from ...widgets.command_input import COMMANDS


class WorkspaceHelpModal(ModalScreen[None]):
    BINDINGS = [Binding("escape", "close", "Close"), Binding("f1", "close", "Close")]

    def compose(self) -> ComposeResult:
        with Vertical(id="help-container"):
            with VerticalScroll(id="help-scroll"):
                yield Static("WORKSPACE GUIDE", id="help-title")
                yield Static("Set your URL, Depth and Max URLs in SCAN TARGET above.\nStart with Enter in the URL, the Start button or Ctrl+S.", classes="help-text")
                yield Static("VIEWS & SETUP · F2–F8", classes="section-header")
                yield Static("F2  Pipeline · stages, progress and timings\nF3  Findings · search, inspect and export evidence\nF4  Agents · specialist work, queues and runtime\nF5  Timeline · milestones and alerts\nF6  Logs · searchable engine output\nF7  Provider · choose provider and API key\nF8  Auth · target Bearer token or login YAML, including TOTP/2FA", classes="help-text")
                yield Static("KEYBOARD", classes="section-header")
                yield Static("Tab / Shift+Tab · move focus\nArrow keys · select a phase or agent card\nEnter · open a finding or agent logs\nCtrl+X · stop    Ctrl+E · export    Ctrl+Q · quit\n: · focus commands    Escape · close details", classes="help-text")
                yield Static("COMMANDS · use the lower bar", classes="section-header")
                yield Static("\n".join(f"{command} — {description}" for command, description in COMMANDS.items()), classes="help-text", markup=False)
            yield Button("Close · Esc", id="help-close", compact=True)

    def action_close(self) -> None:
        self.dismiss()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "help-close":
            self.dismiss()
