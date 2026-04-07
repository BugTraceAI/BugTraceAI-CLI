"""Payload feed widget for BugTraceAI TUI.

Displays live feed of tested payloads with status indicators.
"""

from __future__ import annotations

import random
from typing import Dict, List, Any

from rich.panel import Panel
from rich.text import Text
from rich import box
from textual.reactive import reactive
from textual.widgets import Static

from bugtrace.core.ui.tui.utils import SparklineBuffer


class PayloadFeed(Static):
    """Live payload testing feed widget.

    Shows recent payloads with their test results.
    Matches the legacy _render_payload_feed() appearance.

    Attributes:
        payloads: List of recent payload entries.
        current_payload: Currently testing payload.
        demo_mode: When True, generates random demo data.
    """

    # Status configuration
    STATUS_CONFIG = {
        "testing": ("\u25cf", "bright_yellow", "\u25cf TESTING"),
        "confirmed": ("\u2713", "bright_green", "\u2713 CONFIRMED!"),
        "blocked": ("\u2717", "bright_red", "\u2717 BLOCKED"),
        "waiting": ("\u231b", "bright_cyan", "\u231b WAITING"),
        "failed": ("\u2717", "bright_red", "\u2717 FAILED"),
    }

    # Spinner frames
    SPINNER_FRAMES = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"

    # Sample payloads for demo mode
    DEMO_PAYLOADS = [
        "<script>alert(1)</script>",
        "' OR 1=1--",
        "{{7*7}}",
        "../../../etc/passwd",
        "http://localhost/admin",
        "'; DROP TABLE users;--",
        "<img src=x onerror=alert(1)>",
        "${7*7}",
        "{{constructor.constructor('alert(1)')()}}",
        "file:///etc/passwd",
    ]

    # Reactive attributes
    payloads: reactive[List[Dict[str, Any]]] = reactive([])
    current_payload = reactive("")
    demo_mode = reactive(False)

    def __init__(self, *args, **kwargs):
        """Initialize the payload feed widget."""
        super().__init__(*args, **kwargs)
        self._spinner_idx = 0
        self._payload_history: List[Dict[str, Any]] = []
        self._throughput_buffer = SparklineBuffer(40)
        self._total_payloads = 0
        self._payload_rate = 0.0
        self._peak_rate = 0.0

    def on_mount(self) -> None:
        """Set up update interval."""
        self.set_interval(0.2, self._tick)

    def _tick(self) -> None:
        """Update spinner and demo data."""
        self._spinner_idx = (self._spinner_idx + 1) % len(self.SPINNER_FRAMES)

        if self.demo_mode:
            self._generate_demo_data()

        self.refresh()

    def _generate_demo_data(self) -> None:
        """Generate demo payload data."""
        # Add a new payload every few ticks
        if self._spinner_idx % 5 == 0:
            agents = ["SQLi", "XSS", "CSTI", "LFI", "SSRF"]
            vectors = ["param", "header", "cookie", "body", "path"]
            statuses = ["testing", "confirmed", "failed", "blocked", "waiting"]

            self._total_payloads += 1
            self._payload_rate = random.uniform(1, 10)
            if self._payload_rate > self._peak_rate:
                self._peak_rate = self._payload_rate

            entry = {
                "num": self._total_payloads,
                "agent": random.choice(agents),
                "vector": random.choice(vectors),
                "payload": random.choice(self.DEMO_PAYLOADS),
                "status": random.choice(statuses),
            }

            self._payload_history.append(entry)

            # Keep last 50
            if len(self._payload_history) > 50:
                self._payload_history = self._payload_history[-50:]

            self._throughput_buffer.add(self._payload_rate)

    def add_payload(
        self,
        payload: str,
        agent: str = "Unknown",
        vector: str = "",
        status: str = "testing",
    ) -> None:
        """Add a payload to the feed.

        Args:
            payload: The payload string being tested.
            agent: Agent performing the test.
            vector: Attack vector (param, header, etc.).
            status: Current test status.
        """
        self._total_payloads += 1
        entry = {
            "num": self._total_payloads,
            "agent": agent,
            "vector": vector,
            "payload": payload,
            "status": status,
        }
        self._payload_history.append(entry)

        # Keep last 50
        if len(self._payload_history) > 50:
            self._payload_history = self._payload_history[-50:]

        self.current_payload = payload
        self.refresh()

    def update_status(self, status: str) -> None:
        """Update the status of the most recent payload.

        Args:
            status: New status (testing, confirmed, failed, blocked).
        """
        if self._payload_history:
            self._payload_history[-1]["status"] = status
            self.refresh()

    def set_rate(self, rate: float) -> None:
        """Set current payload rate.

        Args:
            rate: Payloads per second.
        """
        self._payload_rate = rate
        if rate > self._peak_rate:
            self._peak_rate = rate
        self._throughput_buffer.add(rate)
        self.refresh()

    def _get_spinner(self) -> str:
        """Get current spinner frame."""
        return self.SPINNER_FRAMES[self._spinner_idx]

    def render(self) -> Panel:
        """Render the payload feed panel.

        Returns:
            Rich Panel containing the payload feed.
        """
        result = Text()
        history = self._payload_history[-6:]

        for entry in reversed(history):
            num = entry.get("num", 0)
            agent = entry.get("agent", "Unknown")[:10]
            vector = entry.get("vector", "")[:12]
            payload = entry.get("payload", "")[:50]
            status = entry.get("status", "testing")

            # Get status indicator
            if status == "testing":
                indicator = self._get_spinner()
                style = "bright_yellow"
                status_text = "\u25cf TESTING"
            else:
                indicator, style, status_text = self.STATUS_CONFIG.get(
                    status, ("\u25cf", "white", status.upper())
                )

            # Build the line
            result.append(f"  {indicator} ", style=style)
            result.append(f"#{num:4} ", style="bright_black")
            result.append("\u2502 ", style="bright_black")
            result.append(f"{agent:10} ", style="bright_magenta")
            result.append("\u2502 ", style="bright_black")
            result.append(f"{vector:12} ", style="bright_cyan")
            result.append("\u2502 ", style="bright_black")
            result.append(f"{payload:50} ", style="white")
            result.append("\u2502 ", style="bright_black")
            result.append(f"{status_text:12}\n", style=style)

        # Pad if needed
        for _ in range(6 - len(history)):
            result.append("  " + " " * 110 + "\n", style="bright_black")

        # Throughput sparkline
        result.append("\n  THROUGHPUT ", style="white")
        result.append(self._throughput_buffer.render(40, "bright_green"))
        result.append(
            f"  avg: {self._payload_rate:.1f}/s  "
            f"peak: {self._peak_rate:.1f}/s  "
            f"total: {self._total_payloads}",
            style="bright_cyan",
        )

        return Panel(
            result,
            title="[bright_green]\U0001F9EA LIVE PAYLOAD FEED[/]",
            border_style="bright_green",
            box=box.ROUNDED,
        )
