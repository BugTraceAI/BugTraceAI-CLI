"""Pipeline status widget for BugTraceAI TUI.

Displays the current phase of the security scan pipeline with
progress visualization matching the legacy Rich dashboard.
"""

from __future__ import annotations

import random
from typing import List, Tuple

from rich.align import Align
from rich.panel import Panel
from rich.text import Text
from rich import box
from textual.reactive import reactive
from textual.widgets import Static


class PipelineStatus(Static):
    """Pipeline progress visualization widget.

    Displays the current scan phase with visual progress indicators.
    Matches the legacy _render_phase_pipeline() appearance.

    Attributes:
        phase: Current phase name (e.g., "DISCOVERY", "ANALYSIS").
        progress: Progress percentage (0.0 to 100.0).
        status_msg: Current status message.
        urls_analyzed: Number of URLs analyzed.
        urls_total: Total URLs to analyze.
        payloads_tested: Number of payloads tested.
        demo_mode: When True, generates random demo data.
    """

    # Phase definitions: (name, keywords for detection)
    PHASES: List[Tuple[str, List[str]]] = [
        ("RECON", ["recon", "init", "warm", "assembl", "start"]),
        ("DISCOVER", ["discover", "spider", "crawl", "gospider", "endpoint"]),
        ("ANALYZE", ["analy", "dast", "hunt", "think", "process"]),
        ("EXPLOIT", ["exploit", "attack", "specialist", "test", "payload"]),
        ("REPORT", ["report", "generat", "complete", "done", "mission", "finish"]),
    ]

    # Reactive attributes for real-time updates
    phase = reactive("INITIALIZING")
    progress = reactive(0.0)
    status_msg = reactive("Starting...")
    urls_analyzed = reactive(0)
    urls_total = reactive(0)
    payloads_tested = reactive(0)
    demo_mode = reactive(False)

    def __init__(self, *args, **kwargs):
        """Initialize the pipeline status widget."""
        super().__init__(*args, **kwargs)
        self._demo_phase_idx = 0
        self._demo_progress = 0.0

    def on_mount(self) -> None:
        """Set up demo mode interval if enabled."""
        self.set_interval(1.0, self._demo_tick)

    def _demo_tick(self) -> None:
        """Update demo data on each tick."""
        if not self.demo_mode:
            return

        # Cycle through phases
        self._demo_progress += random.uniform(5, 15)
        if self._demo_progress >= 100:
            self._demo_progress = 0
            self._demo_phase_idx = (self._demo_phase_idx + 1) % len(self.PHASES)

        phase_name = self.PHASES[self._demo_phase_idx][0]
        self.phase = phase_name
        self.progress = self._demo_progress
        self.urls_analyzed = int(self._demo_progress)
        self.urls_total = 100
        self.payloads_tested = self._demo_phase_idx * 50 + int(self._demo_progress)
        self.status_msg = f"Phase {phase_name} in progress..."

    def _get_phase_index(self) -> int:
        """Determine current phase index based on state.

        Returns:
            Index of current phase (0-4).
        """
        current_phase = self.phase.lower()
        payloads = self.payloads_tested
        urls_analyzed = self.urls_analyzed
        urls_total = self.urls_total

        # Determine phase based on progress metrics
        if payloads > 0 or "exploit" in current_phase or "specialist" in current_phase:
            return 3  # EXPLOIT
        elif urls_analyzed > 0 or "analy" in current_phase or "dast" in current_phase:
            return 2  # ANALYZE
        elif urls_total > 0 or "discover" in current_phase or "spider" in current_phase:
            return 1  # DISCOVER
        elif "report" in current_phase or "complete" in current_phase:
            return 4  # REPORT
        else:
            return 0  # RECON

    def _calculate_progress(self, phase_idx: int) -> int:
        """Calculate progress percentage for current phase.

        Args:
            phase_idx: Current phase index.

        Returns:
            Progress percentage (0-100).
        """
        if phase_idx == 0:
            return 50
        elif phase_idx == 1:
            return min(100, self.urls_total * 2) if self.urls_total > 0 else 10
        elif phase_idx == 2:
            return int((self.urls_analyzed / max(self.urls_total, 1)) * 100)
        elif phase_idx == 3:
            return min(100, self.payloads_tested) if self.payloads_tested > 0 else 10
        elif phase_idx == 4:
            return 100
        return 0

    def render(self) -> Panel:
        """Render the pipeline status panel.

        Returns:
            Rich Panel containing the pipeline visualization.
        """
        phase_idx = self._get_phase_index()
        progress_pct = self._calculate_progress(phase_idx)

        # Build pipeline visualization
        pipeline = Text()

        for i, (name, _) in enumerate(self.PHASES):
            if i < phase_idx:
                # Completed phase
                pipeline.append(f"[green]\u2705{name}[/]", style="bright_green")
            elif i == phase_idx:
                # Current phase
                pipeline.append(f"\u23f5{name}", style="bright_yellow bold")
            else:
                # Future phase
                pipeline.append(f"\u25cb{name}", style="bright_black")

            if i < len(self.PHASES) - 1:
                arrow_style = "bright_green" if i < phase_idx else "bright_black"
                pipeline.append("\u2192", style=arrow_style)

        pipeline.append(f"  [{progress_pct}%]", style="bright_cyan")

        return Panel(
            Align.center(pipeline),
            title="[bright_cyan]PROGRESS[/]",
            border_style="bright_cyan",
            box=box.ROUNDED,
        )
