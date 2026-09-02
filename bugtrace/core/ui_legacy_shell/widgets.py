"""
BugTraceAI v4.1 - Advanced Terminal Dashboard
Multi-page UI with animations, sparklines, gradients and real-time metrics
"""

from datetime import datetime
from typing import List, Optional, Dict, Tuple
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import ROUNDED, HEAVY, DOUBLE, SIMPLE, MINIMAL
from rich.style import Style
from rich.traceback import install
from rich.align import Align
from rich import box
import threading
import time
import logging
import sys
import os

# Install rich traceback handler
install(show_locals=True)

# Lazy import psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class DashboardHandler(logging.Handler):
    """Custom logging handler that sends logs to the dashboard."""
    def __init__(self, dashboard):
        super().__init__()
        self.dashboard = dashboard

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            self.dashboard.log(msg, level)
        except Exception:
            self.handleError(record)


class SparklineBuffer:
    """Circular buffer for sparkline data."""
    def __init__(self, size: int = 30):
        self.size = size
        self.data: List[float] = [0.0] * size
        self.index = 0

    def add(self, value: float):
        self.data[self.index] = value
        self.index = (self.index + 1) % self.size

    def get_ordered(self) -> List[float]:
        """Return data in chronological order."""
        return self.data[self.index:] + self.data[:self.index]

    def render(self, width: int = 20, color: str = "bright_cyan") -> Text:
        """Render sparkline as Text with blocks."""
        chars = "▁▂▃▄▅▆▇█"
        data = self.get_ordered()[-width:]
        max_val = max(data) if max(data) > 0 else 1

        result = Text()
        for val in data:
            idx = int((val / max_val) * (len(chars) - 1)) if max_val > 0 else 0
            result.append(chars[idx], style=color)
        return result
