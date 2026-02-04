"""Main dashboard screen for BugTraceAI TUI.

This screen displays the primary dashboard view with:
- Phase pipeline progress
- Activity graph
- System metrics
- Agent swarm status
"""

from __future__ import annotations

from textual.app import ComposeResult
from textual.containers import Container, Grid
from textual.screen import Screen
from textual.widgets import Footer, Header, Static


class MainScreen(Screen):
    """Main dashboard screen.

    Displays the primary interface with placeholder panels that will be
    replaced with real widgets in Phase 2.
    """

    BINDINGS = [
        ("f", "findings", "Findings"),
        ("l", "logs", "Logs"),
        ("s", "stats", "Stats"),
        ("a", "agents", "Agents"),
    ]

    def compose(self) -> ComposeResult:
        """Compose the main screen layout.

        Uses Textual's built-in Header and Footer initially.
        Custom widgets will be added in Phase 2.

        Yields:
            Widget: The composed widgets for this screen.
        """
        yield Header(show_clock=True)
        yield Container(
            Static(
                "[bold cyan]PROGRESS[/bold cyan]  "
                "[dim]DISCOVERY[/dim] -> [dim]ANALYSIS[/dim] -> [dim]EXPLOITATION[/dim] -> [dim]VALIDATION[/dim] -> [dim]REPORTING[/dim]  "
                "[cyan][0%][/cyan]",
                id="pipeline",
            ),
            Grid(
                Static(
                    "[bold cyan]ACTIVITY[/bold cyan]\n\n"
                    "[dim]Awaiting scan start...[/dim]\n\n"
                    "Sparkline: [dim]________________[/dim]",
                    id="activity",
                ),
                Static(
                    "[bold cyan]SYSTEM[/bold cyan]\n\n"
                    "CPU: [green]0%[/green]  "
                    "MEM: [green]0%[/green]\n"
                    "Network: [dim]0 req/s[/dim]",
                    id="metrics",
                ),
                id="metrics-row",
            ),
            Static(
                "[bold magenta]AGENT SWARM[/bold magenta]\n\n"
                "[dim]No active agents. Run a scan to activate the swarm.[/dim]\n\n"
                "Agents: [cyan]0[/cyan] active  |  "
                "Queue: [yellow]0[/yellow] pending  |  "
                "Findings: [green]0[/green] total",
                id="swarm",
            ),
            id="main-content",
        )
        yield Footer()

    def action_findings(self) -> None:
        """Show findings view (placeholder for Phase 2)."""
        self.notify("Findings view - Coming in Phase 2")

    def action_logs(self) -> None:
        """Show logs view (placeholder for Phase 2)."""
        self.notify("Logs view - Coming in Phase 2")

    def action_stats(self) -> None:
        """Show statistics view (placeholder for Phase 2)."""
        self.notify("Statistics view - Coming in Phase 2")

    def action_agents(self) -> None:
        """Show agents view (placeholder for Phase 2)."""
        self.notify("Agents view - Coming in Phase 2")
