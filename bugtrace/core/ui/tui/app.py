"""BugTraceAI Textual Application.

Main application class that manages screens, bindings, and lifecycle.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from textual import work
from textual.app import App
from textual.binding import Binding
from textual.widgets import DataTable
from textual.worker import Worker, WorkerState

from .messages import (
    AgentUpdate,
    LogEntry,
    MetricsUpdate,
    NewFinding,
    PayloadTested,
    PipelineProgress,
    ScanComplete,
)
from .widgets.activity import ActivityGraph
from .widgets.findings import FindingsSummary
from .widgets.findings_table import FindingsTable
from .widgets.log_panel import LogPanel
from .widgets.log_inspector import LogInspector
from .widgets.metrics import SystemMetrics
from .widgets.payload_feed import PayloadFeed
from .widgets.pipeline import PipelineStatus
from .widgets.swarm import AgentSwarm
from .widgets.command_input import CommandInput, COMMANDS
from .workers import TUILoggingHandler, UICallback
from .screens.modals import FindingDetailsModal

if TYPE_CHECKING:
    from textual.screen import Screen


class BugTraceApp(App):
    """BugTraceAI Terminal User Interface Application.

    A Textual-based TUI for monitoring and controlling security scans.
    Replaces the legacy Rich-based dashboard with a modern, reactive interface.

    Attributes:
        target: The target URL for scanning (optional, can be set after init).
        scan_worker: Reference to the current scan worker (if running).
    """

    # Load stylesheet from same directory
    CSS_PATH = Path(__file__).parent / "styles.tcss"

    TITLE = "BugTraceAI Reactor"
    SUB_TITLE = "Advanced Security Scanner"

    BINDINGS = [
        Binding("q", "quit", "Quit", priority=True),
        Binding("d", "toggle_dark", "Toggle Dark"),
        Binding("escape", "unfocus", "Unfocus", show=False),
        Binding("?", "show_help", "Help"),
        Binding("s", "start_scan", "Start Scan", show=False),
        Binding("f", "focus_findings", "Findings"),
        Binding("l", "focus_logs", "Logs"),
        Binding(":", "focus_command", "Command"),
    ]

    def __init__(
        self,
        target: Optional[str] = None,
        demo_mode: bool = False,
        *args,
        **kwargs,
    ) -> None:
        """Initialize BugTraceApp.

        Args:
            target: Optional target URL for scanning.
            demo_mode: When True, widgets show animated demo data.
            *args: Positional arguments passed to parent App.
            **kwargs: Keyword arguments passed to parent App.
        """
        super().__init__(*args, **kwargs)
        self.target = target
        self.demo_mode = demo_mode
        self.scan_worker: Optional[Worker] = None
        self._shutdown_event = asyncio.Event()
        self._scan_start_time: Optional[float] = None
        self._logging_handler: Optional[TUILoggingHandler] = None
        self._total_findings = 0

    def on_mount(self) -> None:
        """Called when app is mounted.

        Shows the loader screen initially, which transitions to MainScreen
        after initialization completes. In demo mode, skips loader and goes
        straight to demo dashboard.
        """
        from bugtrace.core.ui.tui.screens.loader import LoaderScreen

        if self.demo_mode:
            # Skip loader in demo mode, go straight to main screen with demo data
            from bugtrace.core.ui.tui.screens.main import MainScreen
            self.push_screen(MainScreen(demo_mode=True))
        else:
            self.push_screen(LoaderScreen())

        # Install TUI logging handler
        self._install_logging_handler()

        # Auto-start scan if target provided (not in demo mode)
        if self.target and not self.demo_mode:
            # Defer scan start until after screens are mounted
            self.set_timer(0.5, self._auto_start_scan)

    def _install_logging_handler(self) -> None:
        """Install the TUI logging handler to capture logs."""
        self._logging_handler = TUILoggingHandler(self)
        self._logging_handler.setLevel(logging.INFO)
        logging.getLogger().addHandler(self._logging_handler)

    def _remove_logging_handler(self) -> None:
        """Remove the TUI logging handler."""
        if self._logging_handler:
            logging.getLogger().removeHandler(self._logging_handler)
            self._logging_handler = None

    def _auto_start_scan(self) -> None:
        """Auto-start scan after screens are mounted."""
        if self.target and not self.scan_worker:
            self.scan_worker = self.run_scan(self.target)

    async def on_shutdown_request(self) -> None:
        """Handle shutdown request gracefully.

        Ensures all workers and resources are cleaned up before exit.
        """
        self._shutdown_event.set()

    @work(thread=True, exclusive=True)
    def run_scan(self, target: str) -> None:
        """Execute scan in background thread.

        Uses thread=True because the pipeline has blocking I/O operations.
        The exclusive=True ensures only one scan runs at a time.

        Args:
            target: The target URL to scan.
        """
        # Import here to avoid circular imports and heavy startup
        from bugtrace.core.conductor import conductor
        from bugtrace.core.team import TeamOrchestrator

        # Create UI callback and register with conductor
        callback = UICallback(self)
        conductor.set_ui_callback(callback)

        self._scan_start_time = time.time()
        self._total_findings = 0

        try:
            callback.on_phase_change("discovery", 0.0, "Initializing scan...")

            # Create orchestrator with TUI-compatible settings
            orchestrator = TeamOrchestrator(
                target,
                resume=False,
                use_vertical_agents=True,
            )

            # Run the scan (this is blocking, but we're in a thread)
            import asyncio as _asyncio

            loop = _asyncio.new_event_loop()
            _asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(orchestrator.start())
            finally:
                loop.close()

            # Scan completed successfully
            duration = time.time() - self._scan_start_time
            callback.on_complete(self._total_findings, duration)

        except Exception as e:
            callback.on_log("ERROR", f"Scan error: {e}")
            import traceback

            callback.on_log("ERROR", traceback.format_exc())
        finally:
            # Unregister callback
            conductor.set_ui_callback(None)

    def action_start_scan(self) -> None:
        """Start a scan if target is set and no scan is running."""
        if not self.target:
            self.notify("No target set. Use --target or enter URL.", severity="warning")
            return

        if self.scan_worker and self.scan_worker.state == WorkerState.RUNNING:
            self.notify("Scan already in progress.", severity="warning")
            return

        self.scan_worker = self.run_scan(self.target)

    def action_quit(self) -> None:
        """Quit the application cleanly.

        If a scan is running, cancels it before exiting.
        Note: Confirmation dialog will be added in Phase 3.
        """
        # Cancel any running scan
        if self.scan_worker and self.scan_worker.state == WorkerState.RUNNING:
            self.notify("Cancelling scan...", severity="warning")
            self.scan_worker.cancel()
            # Small delay to allow cancellation to propagate
            self.set_timer(0.5, self.exit)
        else:
            self.exit()

    def action_toggle_dark(self) -> None:
        """Toggle dark mode on/off."""
        self.dark = not self.dark

    def action_focus_findings(self) -> None:
        """Focus the findings table."""
        try:
            self.query_one("#findings-table").focus()
        except Exception:
            pass

    def action_focus_logs(self) -> None:
        """Focus the log inspector."""
        try:
            self.query_one("#log-inspector").focus()
        except Exception:
            pass

    def action_focus_command(self) -> None:
        """Focus the command input."""
        try:
            self.query_one("#command-input").focus()
        except Exception:
            pass

    def action_show_help(self) -> None:
        """Show help via command handler."""
        self._show_help()

    def action_unfocus(self) -> None:
        """Remove focus from current widget."""
        self.screen.set_focus(None)

    @property
    def is_shutting_down(self) -> bool:
        """Check if the app is in shutdown state."""
        return self._shutdown_event.is_set()

    @property
    def is_scan_running(self) -> bool:
        """Check if a scan is currently running."""
        return (
            self.scan_worker is not None
            and self.scan_worker.state == WorkerState.RUNNING
        )

    async def on_unmount(self) -> None:
        """Clean up on app exit."""
        # Cancel any running scan worker
        if self.scan_worker and self.scan_worker.state == WorkerState.RUNNING:
            self.scan_worker.cancel()

        # Remove logging handler
        self._remove_logging_handler()

    # =========================================================
    # MESSAGE HANDLERS: React to pipeline events
    # =========================================================

    def on_agent_update(self, message: AgentUpdate) -> None:
        """Handle agent status update.

        Updates the AgentSwarm widget with new agent status.
        """
        try:
            swarm = self.query_one("#swarm", AgentSwarm)
            swarm.update_agent(
                message.agent_name,
                message.status,
                queue=message.queue,
                processed=message.processed,
                vulns=message.vulns,
            )
        except Exception:
            pass  # Widget may not be mounted yet

    def on_pipeline_progress(self, message: PipelineProgress) -> None:
        """Handle pipeline progress update.

        Updates the PipelineStatus widget with new progress.
        """
        try:
            pipeline = self.query_one("#pipeline", PipelineStatus)
            pipeline.phase = message.phase
            pipeline.progress = message.progress * 100  # Convert 0-1 to 0-100
            if message.status_msg:
                pipeline.status_msg = message.status_msg
        except Exception:
            pass  # Widget may not be mounted yet

        # Also update app subtitle for visibility
        self.sub_title = f"{message.phase}: {int(message.progress * 100)}%"

    def on_new_finding(self, message: NewFinding) -> None:
        """Handle new vulnerability finding.

        Updates both FindingsSummary (legacy) and FindingsTable (new) widgets.
        """
        self._total_findings += 1

        # Update FindingsSummary (legacy widget)
        try:
            findings = self.query_one("#findings", FindingsSummary)
            findings.add_finding(
                finding_type=message.finding_type,
                details=message.details,
                severity=message.severity.upper(),
            )
        except Exception:
            pass  # Widget may not be mounted yet

        # Also add to FindingsTable (new interactive widget)
        try:
            table = self.query_one("#findings-table", FindingsTable)
            table.add_finding(
                finding_type=message.finding_type,
                details=message.details,
                severity=message.severity,
                param=message.param,
                payload=message.payload,
            )
        except Exception:
            pass  # Widget may not be mounted yet

        # Show notification for findings
        severity_colors = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }
        color = severity_colors.get(message.severity.lower(), "white")
        self.notify(
            f"[{color}][{message.severity.upper()}][/{color}] {message.finding_type}",
            severity="warning" if message.severity.lower() in ("critical", "high") else "information",
        )

    def on_payload_tested(self, message: PayloadTested) -> None:
        """Handle payload tested notification.

        Updates the PayloadFeed widget with test result.
        """
        try:
            feed = self.query_one("#payload-feed", PayloadFeed)
            # Map result to status
            status_map = {"success": "confirmed", "fail": "failed", "blocked": "blocked"}
            status = status_map.get(message.result, "testing")
            feed.add_payload(
                payload=message.payload,
                agent=message.agent,
                status=status,
            )
        except Exception:
            pass  # Widget may not be mounted yet

    def on_log_entry(self, message: LogEntry) -> None:
        """Handle log entry.

        Routes to both LogPanel (legacy) and LogInspector (new) widgets.
        """
        # Update LogPanel (legacy widget)
        try:
            logs = self.query_one("#logs", LogPanel)
            logs.log(message.message, level=message.level)
        except Exception:
            pass  # Widget may not be mounted yet

        # Also add to LogInspector (new filterable widget)
        try:
            inspector = self.query_one("#log-inspector", LogInspector)
            inspector.log(message.message, level=message.level)
        except Exception:
            pass  # Widget may not be mounted yet

    def on_metrics_update(self, message: MetricsUpdate) -> None:
        """Handle system metrics update.

        Updates SystemMetrics and ActivityGraph widgets.
        """
        try:
            metrics = self.query_one("#metrics", SystemMetrics)
            metrics.cpu_usage = message.cpu
            metrics.ram_usage = message.ram
        except Exception:
            pass  # Widget may not be mounted yet

        try:
            activity = self.query_one("#activity", ActivityGraph)
            activity.req_rate = message.req_rate
            if message.req_rate > activity.peak_rate:
                activity.peak_rate = message.req_rate
        except Exception:
            pass  # Widget may not be mounted yet

    def on_scan_complete(self, message: ScanComplete) -> None:
        """Handle scan completion.

        Shows completion notification with summary.
        """
        self.notify(
            f"Scan complete: {message.total_findings} findings in {message.duration:.1f}s",
            severity="information",
            timeout=10,
        )
        self.sub_title = f"Complete: {message.total_findings} findings"

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Open finding details when row selected in findings table.

        Only handles selections from the FindingsTable widget.
        """
        # Only handle findings table
        if not isinstance(event.data_table, FindingsTable):
            return

        table = event.data_table
        finding = table.get_finding(event.row_key.value)

        if finding:
            self.push_screen(FindingDetailsModal(finding))

    # =========================================================
    # COMMAND HANDLERS: Process ChatOps commands
    # =========================================================

    def on_command_input_command_submitted(
        self, message: CommandInput.CommandSubmitted
    ) -> None:
        """Handle commands from the command input bar."""
        cmd = message.command.strip()

        # Parse command and arguments
        parts = cmd.split(maxsplit=1)
        command = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""

        if command in ("/stop", "stop"):
            self._handle_stop()

        elif command in ("/pause", "pause"):
            self._handle_pause()

        elif command in ("/resume", "resume"):
            self._handle_resume()

        elif command in ("/help", "help", "?"):
            self._show_help()

        elif command in ("/filter", "filter"):
            self._apply_filter(args)

        elif command in ("/show", "show"):
            self._show_agent(args)

        elif command in ("/clear", "clear"):
            self._clear_logs()

        elif command in ("/export", "export"):
            self._export_findings()

        else:
            self.notify(f"Unknown command: {command}", severity="warning")
            self.notify("Type /help for available commands")

    def _handle_stop(self) -> None:
        """Stop the current scan."""
        if self.scan_worker and self.scan_worker.state == WorkerState.RUNNING:
            self.scan_worker.cancel()
            self.notify("Scan stopped")
        else:
            self.notify("No scan running", severity="warning")

    def _handle_pause(self) -> None:
        """Pause the scan (placeholder)."""
        self.notify("Pause not implemented yet", severity="warning")

    def _handle_resume(self) -> None:
        """Resume the scan (placeholder)."""
        self.notify("Resume not implemented yet", severity="warning")

    def _show_help(self) -> None:
        """Show help for available commands."""
        help_lines = ["Available commands:"]
        for cmd, desc in COMMANDS.items():
            help_lines.append(f"  {cmd}: {desc}")

        # Write to log inspector if available
        try:
            inspector = self.query_one("#log-inspector", LogInspector)
            for line in help_lines:
                inspector.log(line, level="INFO")
        except Exception:
            pass

        self.notify("Help written to log panel")

    def _apply_filter(self, filter_text: str) -> None:
        """Apply filter to log inspector."""
        try:
            inspector = self.query_one("#log-inspector", LogInspector)
            filter_input = inspector.query_one("#log-filter")
            filter_input.value = filter_text
            self.notify(f"Filter applied: {filter_text}")
        except Exception as e:
            self.notify(f"Filter failed: {e}", severity="error")

    def _show_agent(self, agent_name: str) -> None:
        """Filter to show only specific agent."""
        if not agent_name:
            self.notify("Usage: /show <agent-name>", severity="warning")
            return
        self._apply_filter(agent_name)

    def _clear_logs(self) -> None:
        """Clear the log inspector."""
        try:
            inspector = self.query_one("#log-inspector", LogInspector)
            inspector.clear()
            self.notify("Logs cleared")
        except Exception:
            pass

    def _export_findings(self) -> None:
        """Export findings to file (placeholder)."""
        self.notify("Export not implemented yet", severity="warning")
