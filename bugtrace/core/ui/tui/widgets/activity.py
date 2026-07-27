"""Activity graph widget for BugTraceAI TUI.

Displays real-time request rate with sparkline visualization.
"""

from __future__ import annotations

import random

from rich.panel import Panel
from rich.text import Text
from rich import box
from textual.reactive import reactive
from textual.widgets import Static

from bugtrace.core.ui.tui.utils import SparklineBuffer


class ActivityGraph(Static):
    """Activity graph with sparkline visualization.

    Shows request rate over time using Unicode block characters.
    Matches the legacy _render_activity_graph() appearance.

    Attributes:
        req_rate: Current requests per second.
        peak_rate: Peak requests per second observed.
        demo_mode: When True, generates random demo data.
    """

    # Reactive attributes for real-time updates
    req_rate = reactive(0.0)
    peak_rate = reactive(0.0)
    demo_mode = reactive(False)

    def __init__(self, *args, **kwargs):
        """Initialize the activity graph widget."""
        super().__init__(*args, **kwargs)
        self.buffer = SparklineBuffer(60)
        self._demo_base_rate = 0.0

    def on_mount(self) -> None:
        """Set up update interval."""
        self.set_interval(1.0, self._update)

    def _update(self) -> None:
        """Update the sparkline buffer with current rate."""
        if self.demo_mode:
            # Generate realistic-looking demo data
            self._demo_base_rate += random.uniform(-2, 2)
            self._demo_base_rate = max(0, min(50, self._demo_base_rate))
            rate = self._demo_base_rate + random.uniform(0, 10)
            self.req_rate = rate
            if rate > self.peak_rate:
                self.peak_rate = rate

        self.buffer.add(self.req_rate)
        self.refresh()

    def add_request(self, count: int = 1) -> None:
        """Record new requests.

        Args:
            count: Number of requests to add.
        """
        self.req_rate += count
        if self.req_rate > self.peak_rate:
            self.peak_rate = self.req_rate

    def render(self) -> Panel:
        """Render the activity graph panel.

        Returns:
            Rich Panel containing the activity sparkline.
        """
        data = self.buffer.get_ordered()[-20:]

        result = Text()
        result.append("req/s\n", style="bright_black")

        # Render sparkline
        chars = "\u2581\u2582\u2583\u2584\u2585\u2586\u2587\u2588"
        max_val = max(data) if max(data) > 0 else 1

        for val in data:
            idx = int((val / max_val) * (len(chars) - 1)) if max_val > 0 else 0
            result.append(chars[idx], style="bright_green")

        result.append(f"\n\nRate: {self.req_rate:.1f}/s", style="bright_cyan")
        result.append(f"\nPeak: {self.peak_rate:.1f}/s", style="bright_yellow")

        return Panel(
            result,
            title="[bright_cyan]\U0001F4C8 ACTIVITY[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )
