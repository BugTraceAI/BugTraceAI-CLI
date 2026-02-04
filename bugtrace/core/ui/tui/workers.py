"""Worker classes and callbacks for BugTraceAI TUI.

This module provides the bridge between the scanning pipeline and the Textual UI.
The UICallback class translates pipeline events into Textual messages.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from .messages import (
    AgentUpdate,
    LogEntry,
    MetricsUpdate,
    NewFinding,
    PayloadTested,
    PipelineProgress,
    ScanComplete,
)

if TYPE_CHECKING:
    from textual.app import App


class UICallback:
    """Bridge between pipeline and Textual app via messages.

    This class provides callback methods that the scanning pipeline can invoke.
    Each callback posts the appropriate Textual message to update the UI.

    The callback interface is designed to be injected into the Conductor
    and other pipeline components without tight coupling to Textual.
    """

    def __init__(self, app: App) -> None:
        """Initialize the callback with a reference to the Textual app.

        Args:
            app: The Textual App instance to post messages to.
        """
        self.app = app

    def on_phase_change(self, phase: str, progress: float, status: str = "") -> None:
        """Called when the pipeline phase or progress changes.

        Args:
            phase: Current phase name.
            progress: Progress percentage (0.0 to 1.0).
            status: Optional status message.
        """
        self.app.post_message(PipelineProgress(phase, progress, status))

    def on_agent_update(
        self,
        agent: str,
        status: str,
        queue: int = 0,
        processed: int = 0,
        vulns: int = 0,
        **kwargs,
    ) -> None:
        """Called when an agent's status changes.

        Args:
            agent: Name of the agent.
            status: Current status.
            queue: Items in queue.
            processed: Items processed.
            vulns: Vulnerabilities found.
            **kwargs: Additional keyword arguments (ignored for forward compatibility).
        """
        self.app.post_message(
            AgentUpdate(agent, status, queue=queue, processed=processed, vulns=vulns)
        )

    def on_finding(
        self,
        finding_type: str,
        details: str,
        severity: str,
        param: str | None = None,
        payload: str | None = None,
        **kwargs,
    ) -> None:
        """Called when a vulnerability is discovered.

        Args:
            finding_type: Type of vulnerability.
            details: Description of the finding.
            severity: Severity level.
            param: Optional vulnerable parameter.
            payload: Optional triggering payload.
            **kwargs: Additional keyword arguments (ignored for forward compatibility).
        """
        self.app.post_message(
            NewFinding(finding_type, details, severity, param=param, payload=payload)
        )

    def on_payload_tested(self, payload: str, result: str, agent: str) -> None:
        """Called when a payload is tested.

        Args:
            payload: The payload that was tested.
            result: Result of the test ("success", "fail", "blocked").
            agent: Name of the agent.
        """
        self.app.post_message(PayloadTested(payload, result, agent))

    def on_log(self, level: str, message: str) -> None:
        """Called for logging messages.

        Args:
            level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL).
            message: Log message text.
        """
        self.app.post_message(LogEntry(level, message))

    def on_metrics(
        self,
        cpu: float = 0,
        ram: float = 0,
        req_rate: float = 0,
        urls_discovered: int = 0,
        urls_analyzed: int = 0,
        **kwargs,
    ) -> None:
        """Called periodically with system metrics.

        Args:
            cpu: CPU usage percentage.
            ram: RAM usage percentage.
            req_rate: Request rate (req/s).
            urls_discovered: Total URLs discovered.
            urls_analyzed: Total URLs analyzed.
            **kwargs: Additional keyword arguments (ignored for forward compatibility).
        """
        self.app.post_message(
            MetricsUpdate(
                cpu=cpu,
                ram=ram,
                req_rate=req_rate,
                urls_discovered=urls_discovered,
                urls_analyzed=urls_analyzed,
            )
        )

    def on_complete(self, total_findings: int, duration: float) -> None:
        """Called when the scan completes.

        Args:
            total_findings: Total vulnerabilities found.
            duration: Scan duration in seconds.
        """
        self.app.post_message(ScanComplete(total_findings, duration))


class TUILoggingHandler(logging.Handler):
    """Routes Python logging to TUI LogPanel via messages.

    This handler integrates with Python's standard logging system to capture
    log messages from any part of the application and forward them to the
    TUI's log panel.

    Usage:
        handler = TUILoggingHandler(app)
        logging.getLogger().addHandler(handler)
    """

    def __init__(self, app: App) -> None:
        """Initialize the handler with a reference to the Textual app.

        Args:
            app: The Textual App instance to post messages to.
        """
        super().__init__()
        self.app = app
        # Set a reasonable default format
        self.setFormatter(logging.Formatter("%(name)s: %(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record as a Textual message.

        Args:
            record: The log record to emit.
        """
        try:
            msg = self.format(record)
            self.app.post_message(LogEntry(record.levelname, msg))
        except Exception:
            self.handleError(record)
