"""Command input bar for ChatOps-style control."""

from textual.widgets import Input
from textual.message import Message
from textual.binding import Binding
from textual.suggester import SuggestFromList
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

    def __init__(self, **kwargs):
        super().__init__(
            placeholder="/command · / for suggestions",
            compact=True,
            suggester=SuggestFromList([key.split()[0] for key in COMMANDS], case_sensitive=False),
            select_on_focus=False,
            **kwargs
        )
        self._history = []
        self._history_index = -1

    def command_matches(self):
        value = self.value.strip().lower()
        if not value.startswith("/") or " " in value:
            return []
        return [key.split()[0] for key in COMMANDS if key.split()[0].startswith(value)]

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
    "/start": "Start scanning the target configured above",
    "/stop": "Stop the scan and its external tools",
    "/pause": "Pause at the next pipeline checkpoint",
    "/resume": "Resume a paused scan",
    "/provider": "Choose the LLM provider and configure its API key",
    "/auth": "Configure the target's Bearer token or login YAML (TOTP/2FA)",
    "/help": "Show commands and keyboard shortcuts",
    "/filter <text>": "Search the log view",
    "/show <agent>": "Filter logs by agent name",
    "/clear": "Clear the log view",
    "/export [path]": "Export all findings as JSON",
    "/timeline": "Review scan milestones and alerts",
    "/findings [text]": "Open the findings explorer, optionally filtered",
    "/agents": "Inspect agents, metrics and recent payloads",
    "/pipeline": "Inspect scan phases, progress and elapsed time",
    "/logs": "Open the searchable log view",
}
