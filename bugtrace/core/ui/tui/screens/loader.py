"""Loader/splash screen for BugTraceAI TUI.

Displays the ASCII logo with gradient effect and transitions to MainScreen.
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Static
from textual.timer import Timer


# BugTraceAI ASCII logo (from legacy ui.py)
LOGO_LINES = [
    "██████╗ ██╗   ██╗ ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗     █████╗ ██╗",
    "██╔══██╗██║   ██║██╔════╝ ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔══██╗██║",
    "██████╔╝██║   ██║██║  ███╗   ██║   ██████╔╝███████║██║     █████╗      ███████║██║",
    "██╔══██╗██║   ██║██║   ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝      ██╔══██║██║",
    "██████╔╝╚██████╔╝╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗    ██║  ██║██║",
    "╚═════╝  ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝╚═╝",
]

# Gradient colors matching legacy (bright_red -> red -> yellow -> bright_yellow)
GRADIENT_COLORS = [
    "#ff5555",  # bright red
    "#e74c3c",  # red
    "#f1c40f",  # yellow
    "#f1fa8c",  # bright yellow
]

# Spinner frames for loading animation
SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class LoaderScreen(Screen):
    """Splash screen showing logo and initialization status.

    Displays the BugTraceAI ASCII logo with gradient coloring
    and an initializing message with spinner animation.
    Automatically transitions to MainScreen after a brief delay.
    """

    AUTO_FOCUS = None  # Don't focus any widget

    def __init__(self, *args, **kwargs):
        """Initialize loader screen."""
        super().__init__(*args, **kwargs)
        self._spinner_idx = 0
        self._spinner_timer: Timer | None = None
        self._transition_timer: Timer | None = None

    def compose(self) -> ComposeResult:
        """Compose the loader screen.

        Yields:
            Widget: Logo, message, and spinner widgets.
        """
        # Build gradient logo
        logo_markup = self._build_gradient_logo()

        yield Container(
            Static(logo_markup, id="logo"),
            Static("[bold cyan]Initializing BugTraceAI Reactor...[/bold cyan]", id="loader-message"),
            Static(SPINNER_FRAMES[0], id="loader-spinner"),
            id="loader-container",
        )

    def _build_gradient_logo(self) -> str:
        """Build the logo with gradient colors applied per line.

        Returns:
            str: Rich markup string with colored logo lines.
        """
        lines = []
        num_lines = len(LOGO_LINES)

        for i, line in enumerate(LOGO_LINES):
            # Calculate color index based on line position
            color_idx = int((i / max(num_lines - 1, 1)) * (len(GRADIENT_COLORS) - 1))
            color = GRADIENT_COLORS[color_idx]
            lines.append(f"[{color}]{line}[/]")

        return "\n".join(lines)

    def on_mount(self) -> None:
        """Start timers when screen is mounted."""
        # Start spinner animation
        self._spinner_timer = self.set_interval(0.1, self._update_spinner)

        # Transition to main screen after delay
        self._transition_timer = self.set_timer(2.0, self._transition_to_main)

    def on_unmount(self) -> None:
        """Clean up timers when screen is unmounted."""
        if self._spinner_timer:
            self._spinner_timer.stop()
        if self._transition_timer:
            self._transition_timer.stop()

    def _update_spinner(self) -> None:
        """Update the spinner animation frame."""
        self._spinner_idx = (self._spinner_idx + 1) % len(SPINNER_FRAMES)
        spinner = self.query_one("#loader-spinner", Static)
        spinner.update(f"[yellow]{SPINNER_FRAMES[self._spinner_idx]}[/yellow]")

    def _transition_to_main(self) -> None:
        """Transition to the main screen."""
        from bugtrace.core.ui.tui.screens.main import MainScreen

        # Stop the spinner before transitioning
        if self._spinner_timer:
            self._spinner_timer.stop()

        # Switch to main screen (replace loader, don't push)
        self.app.switch_screen(MainScreen())
