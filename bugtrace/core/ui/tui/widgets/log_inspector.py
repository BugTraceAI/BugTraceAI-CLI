"""Filterable log inspector widget."""

from textual.widgets import Static, Input, RichLog
from textual.containers import Vertical
from textual.reactive import reactive
from textual.app import ComposeResult
from rich.text import Text
from typing import List, Tuple
from collections import deque


class LogInspector(Vertical):
    """Filterable log viewer with search input."""

    # Current filter text
    filter_text: reactive[str] = reactive("")

    # Store all logs for filtering
    _all_logs: List[Tuple[str, str]] = []  # (level, message)

    # Max logs to keep in memory
    MAX_LOGS = 2000

    CSS = """
    LogInspector {
        height: 100%;
    }

    #log-filter {
        dock: top;
        height: 3;
        margin: 0 0 1 0;
    }

    #log-view {
        height: 1fr;
        border: solid $secondary;
        scrollbar-gutter: stable;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._all_logs = []

    def compose(self) -> ComposeResult:
        """Compose the log inspector layout."""
        yield Input(
            placeholder="Filter logs (e.g., ERROR, XSS, Agent)...",
            id="log-filter"
        )
        yield RichLog(
            id="log-view",
            highlight=True,
            markup=True,
            max_lines=1000,
            wrap=True,
        )

    def on_input_changed(self, event: Input.Changed) -> None:
        """Handle filter input changes."""
        if event.input.id == "log-filter":
            self.filter_text = event.value
            self._apply_filter()

    def log(self, message: str, level: str = "INFO") -> None:
        """Add a log entry."""
        # Store for filtering
        self._all_logs.append((level, message))

        # Trim if too many
        if len(self._all_logs) > self.MAX_LOGS:
            self._all_logs = self._all_logs[-self.MAX_LOGS:]

        # Only display if matches filter
        if self._matches_filter(level, message):
            self._write_log(level, message)

    def _matches_filter(self, level: str, message: str) -> bool:
        """Check if log entry matches current filter."""
        if not self.filter_text:
            return True

        filter_lower = self.filter_text.lower()
        return (
            filter_lower in level.lower() or
            filter_lower in message.lower()
        )

    def _write_log(self, level: str, message: str) -> None:
        """Write a log entry to the RichLog widget."""
        try:
            log_widget = self.query_one("#log-view", RichLog)

            # Color by level
            level_colors = {
                "ERROR": "bold red",
                "WARNING": "yellow",
                "INFO": "blue",
                "DEBUG": "dim white",
                "SUCCESS": "green",
            }
            color = level_colors.get(level.upper(), "white")

            # Format with Rich markup
            formatted = Text()
            formatted.append(f"[{level.upper():7}] ", style=color)
            formatted.append(message)

            log_widget.write(formatted)
        except Exception:
            pass  # Widget may not be mounted

    def _apply_filter(self) -> None:
        """Re-apply filter to all logs."""
        try:
            log_widget = self.query_one("#log-view", RichLog)
            log_widget.clear()

            # Re-write matching logs
            for level, message in self._all_logs:
                if self._matches_filter(level, message):
                    self._write_log(level, message)
        except Exception:
            pass  # Widget may not be mounted

    def clear(self) -> None:
        """Clear all logs."""
        self._all_logs.clear()
        try:
            log_widget = self.query_one("#log-view", RichLog)
            log_widget.clear()
        except Exception:
            pass
