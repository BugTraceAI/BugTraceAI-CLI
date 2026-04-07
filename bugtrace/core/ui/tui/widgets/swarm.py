"""Agent swarm widget for BugTraceAI TUI.

Displays the status of all specialist agents with queue/progress info.
"""

from __future__ import annotations

import random
from typing import Dict, Any

from rich.panel import Panel
from rich.text import Text
from rich import box
from textual.reactive import reactive
from textual.widgets import Static


class AgentSwarm(Static):
    """Agent swarm status widget.

    Shows all specialist agents with their status, queue depth,
    processed count, and vulnerability findings.
    Matches the legacy _render_specialist_swarm() appearance.

    Attributes:
        agents: Dict of agent states with status, queue, processed, vulns.
        current_agent: Name of currently active agent.
        demo_mode: When True, generates random demo data.
    """

    # Agent display configuration
    AGENT_DISPLAY = {
        "sqli": "SQLi",
        "xss": "XSS",
        "csti": "CSTI",
        "ssrf": "SSRF",
        "xxe": "XXE",
        "idor": "IDOR",
        "lfi": "LFI",
        "rce": "RCE",
        "openredirect": "Redirect",
    }

    # Status indicators
    STATUS_ICONS = {
        "IDLE": ("\u25cb", "bright_black"),
        "ACTIVE": ("\u25cf", "bright_green"),
        "WAITING": ("\u25cf", "bright_yellow"),
        "ERROR": ("\u2717", "bright_red"),
        "DONE": ("\u2713", "bright_cyan"),
    }

    # Spinner frames for active agents
    SPINNER_FRAMES = "\u280b\u2819\u2839\u2838\u283c\u2834\u2826\u2827\u2807\u280f"

    # Reactive attributes
    agents: reactive[Dict[str, Dict[str, Any]]] = reactive({})
    current_agent = reactive("")
    demo_mode = reactive(False)

    def __init__(self, *args, **kwargs):
        """Initialize the agent swarm widget."""
        super().__init__(*args, **kwargs)
        self._spinner_idx = 0
        # Initialize agents with default state
        self._agents_data: Dict[str, Dict[str, Any]] = {}
        for key in self.AGENT_DISPLAY:
            self._agents_data[key] = {
                "status": "IDLE",
                "queue": 0,
                "processed": 0,
                "vulns": 0,
            }

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
        """Generate demo data for testing."""
        agents = list(self.AGENT_DISPLAY.keys())

        # Randomly select an active agent
        active_idx = (self._spinner_idx // 10) % len(agents)
        self.current_agent = agents[active_idx]

        for i, key in enumerate(agents):
            if i == active_idx:
                status = "ACTIVE"
                queue = random.randint(1, 10)
                processed = random.randint(0, 50)
            elif i < active_idx:
                status = "DONE"
                queue = 0
                processed = random.randint(20, 100)
            else:
                status = "IDLE"
                queue = random.randint(0, 5)
                processed = 0

            self._agents_data[key] = {
                "status": status,
                "queue": queue,
                "processed": processed,
                "vulns": random.randint(0, 3) if status == "DONE" else 0,
            }

    def update_agent(self, name: str, status: str = None, **kwargs) -> None:
        """Update an agent's status.

        Thread-safe update of agent metrics.

        Args:
            name: Agent name (e.g., "sqli", "xss", "SQLiAgent").
            status: New status (IDLE, ACTIVE, WAITING, ERROR, DONE).
            **kwargs: Additional metrics (queue, processed, vulns).
        """
        # Normalize agent name
        key = name.lower()
        for suffix in ("_agent", "agent"):
            key = key.replace(suffix, "")
        key = key.strip("_")

        if key not in self._agents_data:
            self._agents_data[key] = {
                "status": "IDLE",
                "queue": 0,
                "processed": 0,
                "vulns": 0,
            }

        if status:
            self._agents_data[key]["status"] = status

        for k, v in kwargs.items():
            if k in self._agents_data[key]:
                self._agents_data[key][k] = v

        self.refresh()

    def _get_spinner(self) -> str:
        """Get current spinner frame."""
        return self.SPINNER_FRAMES[self._spinner_idx]

    def _make_progress_bar(self, value: float, width: int = 25) -> Text:
        """Create a progress bar with gradient colors.

        Args:
            value: Progress percentage (0-100).
            width: Bar width in characters.

        Returns:
            Rich Text with the progress bar.
        """
        filled = int((value / 100) * width)
        empty = width - filled

        result = Text()
        for i in range(filled):
            pct = i / width
            if pct < 0.5:
                color = "bright_green"
            elif pct < 0.75:
                color = "bright_yellow"
            else:
                color = "bright_red"
            result.append("\u2588", style=color)

        result.append("\u2591" * empty, style="bright_black")
        return result

    def render(self) -> Panel:
        """Render the agent swarm panel.

        Returns:
            Rich Panel containing agent status grid.
        """
        result = Text()

        for key, label in self.AGENT_DISPLAY.items():
            data = self._agents_data.get(key, {})
            status = data.get("status", "IDLE")
            queue = data.get("queue", 0)
            processed = data.get("processed", 0)
            vulns = data.get("vulns", 0)

            total = queue + processed
            progress = (processed / total * 100) if total > 0 else 0

            # Determine if this is the active agent
            is_active = key.lower() == self.current_agent.lower().replace("agent", "").strip("_")

            # Get status indicator
            if is_active and status == "ACTIVE":
                indicator = self._get_spinner()
                name_style = "bright_green bold"
            else:
                indicator, color = self.STATUS_ICONS.get(status, ("\u25cf", "white"))
                name_style = color

            # Build the line
            result.append(f"  {label:12} ", style=name_style)
            result.append(f"{indicator} ", style=name_style if is_active else "bright_cyan")

            # Progress bar
            result.append(self._make_progress_bar(progress))

            # Stats
            result.append(f" {progress:3.0f}%", style="bright_cyan")
            result.append(f"  {queue:2} queued", style="bright_yellow" if queue > 0 else "bright_black")

            # Vulns indicator
            if vulns > 0:
                result.append(f"  \U0001F534{vulns}", style="bright_red bold")

            # Active marker
            if is_active:
                result.append("  \u2190 ACTIVE", style="bright_green bold")

            result.append("\n")

        return Panel(
            result,
            title="[bright_yellow]\u26a1 SPECIALIST SWARM[/]",
            border_style="bright_yellow",
            box=box.ROUNDED,
        )
