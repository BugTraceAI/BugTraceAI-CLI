"""Main dashboard screen for BugTraceAI TUI.

This screen displays the primary dashboard view with:
- Phase pipeline progress
- Activity graph and system metrics
- Agent swarm status
- Findings table with interactive selection
- Payload feed and log inspector
- Command input bar
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header

from bugtrace.core.ui.tui.widgets.pipeline import PipelineStatus
from bugtrace.core.ui.tui.widgets.activity import ActivityGraph
from bugtrace.core.ui.tui.widgets.metrics import SystemMetrics
from bugtrace.core.ui.tui.widgets.swarm import AgentSwarm
from bugtrace.core.ui.tui.widgets.payload_feed import PayloadFeed
from bugtrace.core.ui.tui.widgets.findings import FindingsSummary
from bugtrace.core.ui.tui.widgets.log_panel import LogPanel
from bugtrace.core.ui.tui.widgets.findings_table import FindingsTable
from bugtrace.core.ui.tui.widgets.log_inspector import LogInspector
from bugtrace.core.ui.tui.widgets.command_input import CommandInput


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

        Yields widgets in a structured grid layout:
        - Top: Pipeline status
        - Row 1: Activity + Metrics | Agent Swarm
        - Row 2: Findings Table (full width)
        - Row 3: Payload Feed | Log Inspector
        - Bottom: Command Input bar

        Yields:
            Widget: The composed widgets for this screen.
        """
        yield Header(show_clock=True)

        with Container(id="main-content"):
            # Top: Pipeline status
            yield PipelineStatus(id="pipeline")

            # Row 1: Activity + Metrics | Swarm
            with Horizontal(classes="dashboard-row"):
                with Vertical(classes="left-panel"):
                    yield ActivityGraph(id="activity")
                    yield SystemMetrics(id="metrics")
                yield AgentSwarm(id="swarm")

            # Row 2: Findings Table (full width)
            yield FindingsTable(id="findings-table")

            # Row 3: Payload Feed | Log Inspector
            with Horizontal(classes="dashboard-row"):
                yield PayloadFeed(id="payload-feed")
                yield LogInspector(id="log-inspector")

            # Legacy widgets hidden but kept for backward compatibility
            # Kept in compose for demo mode to work
            with Container(classes="hidden-legacy"):
                yield FindingsSummary(id="findings")
                yield LogPanel(id="logs")

        yield CommandInput(id="command-input")
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

        # Add demo findings to FindingsTable
        try:
            table = self.query_one("#findings-table", FindingsTable)
            demo_findings = [
                ("XSS", "Reflected XSS in search", "HIGH", "q", "<script>alert(1)</script>"),
                ("SQLi", "SQL Injection in login", "CRITICAL", "username", "' OR 1=1--"),
                ("SSRF", "SSRF via image URL", "MEDIUM", "image_url", "http://169.254.169.254/"),
                ("Open Redirect", "Unvalidated redirect", "LOW", "next", "//evil.com"),
            ]
            for finding_type, details, severity, param, payload in demo_findings:
                table.add_finding(
                    finding_type=finding_type,
                    details=details,
                    severity=severity,
                    param=param,
                    payload=payload,
                )
        except Exception:
            pass

        # Add demo logs to LogInspector
        try:
            inspector = self.query_one("#log-inspector", LogInspector)
            demo_logs = [
                ("INFO", "[XSSAgent] Starting scan..."),
                ("INFO", "[XSSAgent] Testing 42 payloads on /search"),
                ("WARNING", "[XSSAgent] Possible reflection detected"),
                ("SUCCESS", "[XSSAgent] Confirmed XSS in 'q' parameter"),
                ("ERROR", "[SQLiAgent] Connection timeout"),
            ]
            for level, message in demo_logs:
                inspector.log(message, level=level)
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
