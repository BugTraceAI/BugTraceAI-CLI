"""System metrics widget for BugTraceAI TUI.

Displays CPU, RAM, and thread count with sparkline history.
"""

from __future__ import annotations

import random

from rich.panel import Panel
from rich.text import Text
from rich import box
from textual.reactive import reactive
from textual.widgets import Static

from bugtrace.core.ui.tui.utils import SparklineBuffer

# Lazy import psutil for optional system metrics
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class SystemMetrics(Static):
    """System metrics widget with sparklines.

    Displays CPU/RAM usage and thread count.
    Matches the legacy _render_system_metrics() appearance.

    Attributes:
        cpu_usage: Current CPU usage percentage.
        ram_usage: Current RAM usage percentage.
        threads_count: Current thread count.
        demo_mode: When True, generates random demo data.
    """

    # Reactive attributes for real-time updates
    cpu_usage = reactive(0.0)
    ram_usage = reactive(0.0)
    threads_count = reactive(0)
    demo_mode = reactive(False)

    def __init__(self, *args, **kwargs):
        """Initialize the system metrics widget."""
        super().__init__(*args, **kwargs)
        self.cpu_buffer = SparklineBuffer(30)
        self.ram_buffer = SparklineBuffer(30)

    def on_mount(self) -> None:
        """Set up metrics update interval."""
        self.set_interval(1.0, self._update_metrics)

    def _update_metrics(self) -> None:
        """Update system metrics from psutil or demo data."""
        if self.demo_mode:
            # Generate demo data
            self.cpu_usage = random.uniform(10, 90)
            self.ram_usage = random.uniform(30, 70)
            self.threads_count = random.randint(5, 25)
        elif PSUTIL_AVAILABLE:
            try:
                self.cpu_usage = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory()
                self.ram_usage = mem.percent
                process = psutil.Process()
                self.threads_count = process.num_threads()
            except Exception:
                pass

        # Update sparklines
        self.cpu_buffer.add(self.cpu_usage)
        self.ram_buffer.add(self.ram_usage)
        self.refresh()

    def render(self) -> Panel:
        """Render the system metrics panel.

        Returns:
            Rich Panel containing CPU/RAM metrics with sparklines.
        """
        cpu = self.cpu_usage
        ram = self.ram_usage
        threads = self.threads_count

        result = Text()

        # CPU line
        cpu_color = "bright_green" if cpu < 70 else "bright_red"
        result.append("CPU ", style="white")
        result.append(self.cpu_buffer.render(15, cpu_color))
        result.append(f" {cpu:.0f}%\n", style=cpu_color)

        # RAM line
        ram_color = "bright_cyan" if ram < 80 else "bright_yellow"
        result.append("RAM ", style="white")
        result.append(self.ram_buffer.render(15, ram_color))
        result.append(f" {ram:.0f}%\n", style=ram_color)

        # Thread count
        result.append(f"\nThreads: {threads}", style="bright_black")

        return Panel(
            result,
            title="[bright_cyan]\U0001F525 SYSTEM[/]",
            border_style="bright_magenta",
            box=box.ROUNDED,
        )
