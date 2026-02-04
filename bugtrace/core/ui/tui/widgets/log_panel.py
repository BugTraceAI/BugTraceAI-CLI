"""Log panel widget for BugTraceAI TUI.

Displays activity log with color-coded log levels.
"""

from __future__ import annotations

import random
from typing import List, Tuple

from rich.panel import Panel
from rich.text import Text
from rich import box
from textual.reactive import reactive
from textual.widgets import Static


class LogPanel(Static):
    """Activity log panel widget.

    Shows recent log entries with color-coded levels.
    Matches the legacy _render_activity_log_panel() appearance.

    Attributes:
        logs: List of log tuples (timestamp, level, message).
        demo_mode: When True, generates random demo data.
    """

    # Log level icons and colors
    LEVEL_CONFIG = {
        "SUCCESS": ("\u2713", "bright_green"),
        "INFO": ("\u25cf", "bright_cyan"),
        "WARNING": ("\u26a0", "bright_yellow"),
        "WARN": ("\u26a0", "bright_yellow"),
        "ERROR": ("\u2717", "bright_red"),
        "DEBUG": ("\u2022", "bright_black"),
    }

    # Sample messages for demo mode
    DEMO_MESSAGES = [
        ("INFO", "[GoSpider] Discovered 23 new endpoints"),
        ("SUCCESS", "[XSSAgent] Confirmed XSS in search param"),
        ("INFO", "[DASTySAST] Analyzing /api/users endpoint"),
        ("WARNING", "[SQLMapAgent] Rate limit detected, slowing down"),
        ("INFO", "[LFIAgent] Testing path traversal vectors"),
        ("SUCCESS", "[SSRFAgent] Internal IP disclosure confirmed"),
        ("ERROR", "[RCEAgent] Connection timeout on payload test"),
        ("INFO", "[Conductor] Phase transition: ANALYZE -> EXPLOIT"),
        ("SUCCESS", "[Validator] Playwright screenshot captured"),
        ("INFO", "[ReportingAgent] Generating final report..."),
    ]

    # Reactive attributes
    logs: reactive[List[Tuple[str, str, str]]] = reactive([])
    demo_mode = reactive(False)

    def __init__(self, *args, **kwargs):
        """Initialize the log panel widget."""
        super().__init__(*args, **kwargs)
        self._log_entries: List[Tuple[str, str, str]] = []

    def on_mount(self) -> None:
        """Set up demo mode interval if needed."""
        self.set_interval(1.0, self._demo_tick)

    def _demo_tick(self) -> None:
        """Generate demo log entries periodically."""
        if not self.demo_mode:
            return

        # Add a random log entry every tick
        if random.random() > 0.3:
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")
            level, message = random.choice(self.DEMO_MESSAGES)
            self._log_entries.append((timestamp, level, message))

            # Keep last 100
            if len(self._log_entries) > 100:
                self._log_entries = self._log_entries[-100:]

            self.refresh()

    def log(self, message: str, level: str = "INFO") -> None:
        """Add a log entry.

        Args:
            message: Log message text.
            level: Log level (INFO, SUCCESS, WARNING, ERROR, DEBUG).
        """
        from datetime import datetime
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._log_entries.append((timestamp, level.upper(), message))

        # Keep last 100
        if len(self._log_entries) > 100:
            self._log_entries = self._log_entries[-100:]

        self.refresh()

    def clear(self) -> None:
        """Clear all log entries."""
        self._log_entries = []
        self.refresh()

    def _get_level_icon_color(self, level: str, message: str) -> Tuple[str, str]:
        """Determine icon and color based on level and message content.

        Args:
            level: Log level string.
            message: Log message for content-based detection.

        Returns:
            Tuple of (icon, color).
        """
        # Check message content for success indicators
        msg_upper = str(message).upper()
        if "SUCCESS" in level or "\u2713" in message or "CONFIRMED" in msg_upper:
            return "\u2713", "bright_green"
        elif "WARN" in level or "\u26a0" in message:
            return "\u26a0", "bright_yellow"
        elif "ERROR" in level:
            return "\u2717", "bright_red"

        return self.LEVEL_CONFIG.get(level.upper(), ("\u25cf", "bright_cyan"))

    def render(self) -> Panel:
        """Render the log panel.

        Returns:
            Rich Panel containing log entries.
        """
        result = Text()
        logs = self._log_entries[-5:]  # Show last 5

        for timestamp, level, msg in logs:
            icon, color = self._get_level_icon_color(level, msg)

            result.append(f"  {timestamp} ", style="bright_black")
            result.append(f"{icon} ", style=color)
            result.append(f"{str(msg)[:90]}\n", style="white")

        # Pad to 5 lines
        for _ in range(5 - len(logs)):
            result.append("\n")

        return Panel(
            result,
            title="[bright_blue]\U0001F4CB ACTIVITY LOG[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
