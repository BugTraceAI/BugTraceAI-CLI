"""Modal for displaying full finding details."""

from textual.screen import ModalScreen
from textual.widgets import Static, Button, TextArea
from textual.containers import Vertical, VerticalScroll, Horizontal
from textual.binding import Binding
from textual.app import ComposeResult
from typing import TYPE_CHECKING
from rich.text import Text

if TYPE_CHECKING:
    from bugtrace.core.ui.tui.widgets.findings_table import Finding


class FindingDetailsModal(ModalScreen[None]):
    """Modal showing full finding details with request/response."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("c", "copy_payload", "Copy Payload"),
        Binding("ctrl+y", "copy_payload", "Copy Payload", priority=True),
    ]

    def __init__(self, finding: "Finding", **kwargs):
        super().__init__(**kwargs)
        self.finding = finding

    def compose(self) -> ComposeResult:
        from ...widgets.findings_table import FindingsTable
        with Vertical(id="modal-container"):
            with VerticalScroll(id="evidence-scroll"):
                yield Static(Text(self.finding.finding_type, style="bold"), id="modal-title")
                metadata = Text(self.finding.severity, style=FindingsTable.COLORS.get(self.finding.severity, "dim"))
                metadata.append(f"  ·  {self.finding.param or 'No parameter'}  ·  {self.finding.time}", style="dim")
                yield Static(metadata, classes="modal-field")
                yield Static(Text(self.finding.url or "No URL supplied"), classes="modal-field")
                yield Static(Text(self.finding.details), classes="modal-field")
                yield Static("Payload", classes="section-header")
                yield TextArea(self.finding.payload or "No payload supplied", read_only=True, id="payload-area")
                if self.finding.request:
                    yield Static("Request", classes="section-header")
                    yield TextArea(self.finding.request, read_only=True, id="request-area")
                if self.finding.response_excerpt:
                    yield Static("Response excerpt", classes="section-header")
                    yield TextArea(self.finding.response_excerpt, read_only=True, id="response-area")
                if not self.finding.request and not self.finding.response_excerpt:
                    yield Static("Request/response were not included by this agent.", classes="view-hint")
            with Horizontal(classes="modal-buttons"):
                yield Button("Copy payload", id="copy-btn", compact=True)
                yield Button("Close · Esc", id="close-btn", compact=True)

    def action_dismiss(self) -> None:
        """Close the modal."""
        self.dismiss()

    def action_copy_payload(self) -> None:
        """Copy payload to clipboard."""
        self.app.copy_to_clipboard(self.finding.payload or "")
        self.notify("Payload sent to the terminal clipboard")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "copy-btn":
            self.action_copy_payload()
        elif event.button.id == "close-btn":
            self.dismiss()
