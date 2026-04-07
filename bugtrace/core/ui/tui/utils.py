"""TUI utility classes and functions.

Shared utilities used by multiple widgets.
"""

from __future__ import annotations

from typing import List

from rich.text import Text


class SparklineBuffer:
    """Circular buffer for sparkline data visualization.

    Stores a fixed-size buffer of float values and renders them as
    Unicode block characters for compact visual representation.

    Attributes:
        size: Maximum number of data points to store.
        data: Internal circular buffer of values.
        index: Current write position in the buffer.
    """

    # Unicode block characters for sparkline rendering (lowest to highest)
    SPARKLINE_CHARS = "▁▂▃▄▅▆▇█"

    def __init__(self, size: int = 30):
        """Initialize the sparkline buffer.

        Args:
            size: Number of data points to store (default: 30).
        """
        self.size = size
        self.data: List[float] = [0.0] * size
        self.index = 0

    def add(self, value: float) -> None:
        """Add a value to the buffer.

        Overwrites the oldest value when buffer is full.

        Args:
            value: The float value to add.
        """
        self.data[self.index] = value
        self.index = (self.index + 1) % self.size

    def get_ordered(self) -> List[float]:
        """Get data in chronological order.

        Returns:
            List of values from oldest to newest.
        """
        return self.data[self.index:] + self.data[:self.index]

    def render(self, width: int = 20, color: str = "bright_cyan") -> Text:
        """Render sparkline as Rich Text with Unicode block characters.

        Args:
            width: Number of characters to render (uses most recent data).
            color: Rich color style for the sparkline.

        Returns:
            Rich Text object containing the sparkline visualization.
        """
        data = self.get_ordered()[-width:]
        max_val = max(data) if max(data) > 0 else 1

        result = Text()
        for val in data:
            idx = int((val / max_val) * (len(self.SPARKLINE_CHARS) - 1)) if max_val > 0 else 0
            result.append(self.SPARKLINE_CHARS[idx], style=color)
        return result

    def get_max(self) -> float:
        """Get the maximum value in the buffer.

        Returns:
            The maximum value, or 0.0 if buffer is empty/all zeros.
        """
        return max(self.data) if self.data else 0.0

    def get_average(self) -> float:
        """Get the average of all values in the buffer.

        Returns:
            The mean value.
        """
        return sum(self.data) / len(self.data) if self.data else 0.0

    def clear(self) -> None:
        """Reset all values to zero."""
        self.data = [0.0] * self.size
        self.index = 0
