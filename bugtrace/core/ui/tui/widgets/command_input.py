"""Command input bar for ChatOps-style control."""

from textual.widgets import Input
from textual.message import Message
from textual.binding import Binding
from typing import List


class CommandInput(Input):
    """Command bar for ChatOps-style control."""

    class CommandSubmitted(Message):
        """Message sent when a command is submitted."""

        def __init__(self, command: str) -> None:
            super().__init__()
            self.command = command

    # Command history
    _history: List[str] = []
    _history_index: int = -1
    MAX_HISTORY = 50

    BINDINGS = [
        Binding("up", "history_prev", "Previous command", show=False),
        Binding("down", "history_next", "Next command", show=False),
    ]

    CSS = """
    CommandInput {
        dock: bottom;
        height: 3;
        margin: 0 1;
        border: solid $primary;
    }

    CommandInput:focus {
        border: solid $accent;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(
            placeholder="Enter command (e.g., /stop, /help, /filter xss)...",
            **kwargs
        )
        self._history = []
        self._history_index = -1

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle command submission."""
        command = event.value.strip()
        if command:
            # Add to history
            self._history.append(command)
            if len(self._history) > self.MAX_HISTORY:
                self._history = self._history[-self.MAX_HISTORY:]
            self._history_index = -1

            # Post message for app to handle
            self.post_message(self.CommandSubmitted(command))

            # Clear input
            self.value = ""

    def action_history_prev(self) -> None:
        """Navigate to previous command in history."""
        if not self._history:
            return

        if self._history_index == -1:
            self._history_index = len(self._history) - 1
        elif self._history_index > 0:
            self._history_index -= 1

        self.value = self._history[self._history_index]
        self.cursor_position = len(self.value)

    def action_history_next(self) -> None:
        """Navigate to next command in history."""
        if not self._history or self._history_index == -1:
            return

        if self._history_index < len(self._history) - 1:
            self._history_index += 1
            self.value = self._history[self._history_index]
        else:
            self._history_index = -1
            self.value = ""

        self.cursor_position = len(self.value)


# Supported commands documentation
COMMANDS = {
    "/stop": "Stop the current scan",
    "/pause": "Pause the scan",
    "/resume": "Resume a paused scan",
    "/help": "Show available commands",
    "/filter <text>": "Filter logs and findings by text",
    "/show <agent>": "Show only specified agent's activity",
    "/clear": "Clear the log view",
    "/export": "Export findings to file",
}
