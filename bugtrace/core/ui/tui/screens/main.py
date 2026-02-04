"""Main dashboard screen for BugTraceAI TUI.

This screen displays the primary dashboard view with:
- Phase pipeline progress
- Activity graph and system metrics
- Agent swarm status
- Payload feed
- Findings summary and activity log
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container
from textual.screen import Screen
from textual.widgets import Footer, Header

from bugtrace.core.ui.tui.widgets.pipeline import PipelineStatus
from bugtrace.core.ui.tui.widgets.activity import ActivityGraph
from bugtrace.core.ui.tui.widgets.metrics import SystemMetrics
from bugtrace.core.ui.tui.widgets.swarm import AgentSwarm
from bugtrace.core.ui.tui.widgets.payload_feed import PayloadFeed
from bugtrace.core.ui.tui.widgets.findings import FindingsSummary
from bugtrace.core.ui.tui.widgets.log_panel import LogPanel


class MainScreen(Screen):
    """Main dashboard screen.

    Displays the primary interface with all widgets for real-time
    scan monitoring and control.

    Attributes:
        demo_mode: When True, all widgets show demo data.
    """

    BINDINGS = [
        ("f", "findings", "Findings"),
        ("l", "logs", "Logs"),
        ("s", "stats", "Stats"),
        ("a", "agents", "Agents"),
    ]

    def __init__(self, demo_mode: bool = False, *args, **kwargs):
        """Initialize the main screen.

        Args:
            demo_mode: Enable demo mode for all widgets.
            *args: Positional arguments for Screen.
            **kwargs: Keyword arguments for Screen.
        """
        super().__init__(*args, **kwargs)
        self._demo_mode = demo_mode

    def compose(self) -> ComposeResult:
        """Compose the main screen layout.

        Yields widgets in a structured layout matching the legacy
        Rich dashboard appearance.

        Yields:
            Widget: The composed widgets for this screen.
        """
        yield Header(show_clock=True)
        yield Container(
            PipelineStatus(id="pipeline"),
            Container(
                ActivityGraph(id="activity"),
                SystemMetrics(id="metrics"),
                classes="metrics-row",
            ),
            Container(
                AgentSwarm(id="swarm"),
                PayloadFeed(id="payload-feed"),
                classes="middle-row",
            ),
            Container(
                FindingsSummary(id="findings"),
                LogPanel(id="logs"),
                classes="bottom-row",
            ),
            id="main-content",
        )
        yield Footer()

    def on_mount(self) -> None:
        """Enable demo mode on widgets if configured."""
        if self._demo_mode:
            self.enable_demo_mode()

    def enable_demo_mode(self) -> None:
        """Enable demo mode on all widgets."""
        try:
            self.query_one("#pipeline", PipelineStatus).demo_mode = True
            self.query_one("#activity", ActivityGraph).demo_mode = True
            self.query_one("#metrics", SystemMetrics).demo_mode = True
            self.query_one("#swarm", AgentSwarm).demo_mode = True
            self.query_one("#payload-feed", PayloadFeed).demo_mode = True
            self.query_one("#findings", FindingsSummary).demo_mode = True
            self.query_one("#logs", LogPanel).demo_mode = True
        except Exception:
            pass

    def disable_demo_mode(self) -> None:
        """Disable demo mode on all widgets."""
        try:
            self.query_one("#pipeline", PipelineStatus).demo_mode = False
            self.query_one("#activity", ActivityGraph).demo_mode = False
            self.query_one("#metrics", SystemMetrics).demo_mode = False
            self.query_one("#swarm", AgentSwarm).demo_mode = False
            self.query_one("#payload-feed", PayloadFeed).demo_mode = False
            self.query_one("#findings", FindingsSummary).demo_mode = False
            self.query_one("#logs", LogPanel).demo_mode = False
        except Exception:
            pass

    def action_findings(self) -> None:
        """Show findings view (placeholder for Phase 3)."""
        self.notify("Findings view - Coming in Phase 3")

    def action_logs(self) -> None:
        """Show logs view (placeholder for Phase 3)."""
        self.notify("Logs view - Coming in Phase 3")

    def action_stats(self) -> None:
        """Show statistics view (placeholder for Phase 3)."""
        self.notify("Statistics view - Coming in Phase 3")

    def action_agents(self) -> None:
        """Show agents view (placeholder for Phase 3)."""
        self.notify("Agents view - Coming in Phase 3")
