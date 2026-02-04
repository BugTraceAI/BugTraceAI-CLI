"""BugTraceAI Textual Application.

Main application class that manages screens, bindings, and lifecycle.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding

if TYPE_CHECKING:
    from textual.screen import Screen


class BugTraceApp(App):
    """BugTraceAI Terminal User Interface Application.

    A Textual-based TUI for monitoring and controlling security scans.
    Replaces the legacy Rich-based dashboard with a modern, reactive interface.
    """

    # Load stylesheet from same directory
    CSS_PATH = Path(__file__).parent / "styles.tcss"

    TITLE = "BugTraceAI Reactor"
    SUB_TITLE = "Advanced Security Scanner"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("d", "toggle_dark", "Toggle Dark"),
        Binding("escape", "back", "Back", show=False),
        Binding("?", "help", "Help"),
    ]

    def __init__(self, *args, **kwargs):
        """Initialize BugTraceApp.

        Args:
            *args: Positional arguments passed to parent App.
            **kwargs: Keyword arguments passed to parent App.
        """
        super().__init__(*args, **kwargs)
        self._shutdown_event = asyncio.Event()

    def on_mount(self) -> None:
        """Called when app is mounted.

        Shows the loader screen initially, which transitions to MainScreen
        after initialization completes.
        """
        from bugtrace.core.ui.tui.screens.loader import LoaderScreen

        self.push_screen(LoaderScreen())

    async def on_shutdown_request(self) -> None:
        """Handle shutdown request gracefully.

        Ensures all workers and resources are cleaned up before exit.
        """
        self._shutdown_event.set()

    def action_quit(self) -> None:
        """Quit the application cleanly."""
        self.exit()

    def action_toggle_dark(self) -> None:
        """Toggle dark mode on/off."""
        self.dark = not self.dark

    def action_back(self) -> None:
        """Go back to previous screen if possible."""
        if len(self.screen_stack) > 1:
            self.pop_screen()

    def action_help(self) -> None:
        """Show help screen (placeholder for Phase 3)."""
        self.notify("Help: Press 'q' to quit, 'd' to toggle dark mode")

    @property
    def is_shutting_down(self) -> bool:
        """Check if the app is in shutdown state."""
        return self._shutdown_event.is_set()
