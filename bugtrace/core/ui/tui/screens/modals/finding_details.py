"""Modal for displaying full finding details."""

from textual.screen import ModalScreen
from textual.widgets import Static, Button, TextArea
from textual.containers import Vertical, Horizontal
from textual.binding import Binding
from textual.app import ComposeResult
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bugtrace.core.ui.tui.widgets.findings_table import Finding


class FindingDetailsModal(ModalScreen[None]):
    """Modal showing full finding details with request/response."""

    BINDINGS = [
        Binding("escape", "dismiss", "Close"),
        Binding("c", "copy_payload", "Copy Payload"),
    ]

    CSS = """
    FindingDetailsModal {
        align: center middle;
    }

    #modal-container {
        width: 80%;
        height: 80%;
        background: $surface;
        border: thick $primary;
        padding: 1 2;
    }

    #modal-title {
        text-align: center;
        text-style: bold;
        margin-bottom: 1;
    }

    .modal-field {
        margin-bottom: 1;
    }

    .section-header {
        margin-top: 1;
        color: $primary;
        text-style: bold;
    }

    #payload-area, #request-area, #response-area {
        height: 5;
        border: solid $secondary;
        margin-bottom: 1;
    }

    .modal-buttons {
        margin-top: 1;
        align: center middle;
        height: auto;
    }

    .modal-buttons Button {
        margin: 0 1;
    }
    """

    def __init__(self, finding: "Finding", **kwargs):
        super().__init__(**kwargs)
        self.finding = finding

    def compose(self) -> ComposeResult:
        """Compose the modal layout."""
        with Vertical(id="modal-container"):
            yield Static(
                f"[bold]{self.finding.finding_type}[/bold]",
                id="modal-title"
            )

            # Severity with color
            severity_colors = {
                "CRITICAL": "red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
                "INFO": "dim",
            }
            color = severity_colors.get(self.finding.severity, "white")
            yield Static(
                f"Severity: [{color}]{self.finding.severity}[/{color}]",
                classes="modal-field"
            )
            yield Static(
                f"Parameter: {self.finding.param or 'N/A'}",
                classes="modal-field"
            )
            yield Static(
                f"Time: {self.finding.time}",
                classes="modal-field"
            )

            yield Static("[bold]Payload:[/bold]", classes="section-header")
            yield TextArea(
                self.finding.payload or "N/A",
                read_only=True,
                id="payload-area"
            )

            yield Static("[bold]Request:[/bold]", classes="section-header")
            yield TextArea(
                self.finding.request or "N/A",
                read_only=True,
                id="request-area"
            )

            yield Static("[bold]Response (excerpt):[/bold]", classes="section-header")
            yield TextArea(
                self.finding.response_excerpt or "N/A",
                read_only=True,
                id="response-area"
            )

            with Horizontal(classes="modal-buttons"):
                yield Button("Copy Payload", id="copy-btn", variant="primary")
                yield Button("Close", id="close-btn")

    def action_dismiss(self) -> None:
        """Close the modal."""
        self.dismiss()

    def action_copy_payload(self) -> None:
        """Copy payload to clipboard."""
        try:
            import pyperclip
            pyperclip.copy(self.finding.payload or "")
            self.notify("Payload copied to clipboard")
        except ImportError:
            # pyperclip not available - graceful degradation
            self.notify("Clipboard not available (install pyperclip)", severity="warning")
        except Exception as e:
            self.notify(f"Copy failed: {e}", severity="error")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses."""
        if event.button.id == "copy-btn":
            self.action_copy_payload()
        elif event.button.id == "close-btn":
            self.dismiss()
