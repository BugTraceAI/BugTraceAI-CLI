"""Textual Message types for BugTraceAI TUI.

These messages enable event-driven communication between the scanning pipeline
and the Textual UI. The pipeline posts messages, and the App handles them to
update widgets reactively.
"""

from __future__ import annotations

from typing import Optional

from textual.message import Message


class AgentUpdate(Message):
    """Sent when an agent's status changes.

    Attributes:
        agent_name: Name of the agent (e.g., "XSSAgent", "SQLiAgent").
        status: Current status ("idle", "running", "complete", "error").
        queue: Number of items in agent's queue.
        processed: Number of items processed.
        vulns: Number of vulnerabilities found.
    """

    def __init__(
        self,
        agent_name: str,
        status: str,
        queue: int = 0,
        processed: int = 0,
        vulns: int = 0,
    ) -> None:
        super().__init__()
        self.agent_name = agent_name
        self.status = status
        self.queue = queue
        self.processed = processed
        self.vulns = vulns


class PipelineProgress(Message):
    """Sent when pipeline phase/progress changes.

    Attributes:
        phase: Current phase name ("discovery", "analysis", "exploitation", etc.).
        progress: Progress percentage (0.0 to 1.0).
        status_msg: Optional status message for display.
    """

    def __init__(
        self,
        phase: str,
        progress: float,
        status_msg: str = "",
    ) -> None:
        super().__init__()
        self.phase = phase
        self.progress = progress
        self.status_msg = status_msg


class NewFinding(Message):
    """Sent when a vulnerability is discovered.

    Attributes:
        finding_type: Type of vulnerability (e.g., "XSS", "SQLi", "SSRF").
        details: Description of the finding.
        severity: Severity level ("critical", "high", "medium", "low", "info").
        param: Optional vulnerable parameter name.
        payload: Optional payload that triggered the vulnerability.
    """

    def __init__(
        self,
        finding_type: str,
        details: str,
        severity: str,
        param: Optional[str] = None,
        payload: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.finding_type = finding_type
        self.details = details
        self.severity = severity
        self.param = param
        self.payload = payload


class PayloadTested(Message):
    """Sent when a payload is tested.

    Attributes:
        payload: The payload string that was tested.
        result: Result of the test ("success", "fail", "blocked").
        agent: Name of the agent that tested the payload.
    """

    def __init__(
        self,
        payload: str,
        result: str,
        agent: str,
    ) -> None:
        super().__init__()
        self.payload = payload
        self.result = result
        self.agent = agent


class LogEntry(Message):
    """Sent for logging to the TUI log panel.

    Attributes:
        level: Log level ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL").
        message: The log message text.
    """

    def __init__(
        self,
        level: str,
        message: str,
    ) -> None:
        super().__init__()
        self.level = level
        self.message = message


class MetricsUpdate(Message):
    """Sent periodically with system/scan metrics.

    Attributes:
        cpu: CPU usage percentage (0-100).
        ram: RAM usage percentage (0-100).
        req_rate: Request rate (requests per second).
        urls_discovered: Total URLs discovered.
        urls_analyzed: Total URLs analyzed.
    """

    def __init__(
        self,
        cpu: float = 0,
        ram: float = 0,
        req_rate: float = 0,
        urls_discovered: int = 0,
        urls_analyzed: int = 0,
    ) -> None:
        super().__init__()
        self.cpu = cpu
        self.ram = ram
        self.req_rate = req_rate
        self.urls_discovered = urls_discovered
        self.urls_analyzed = urls_analyzed


class ScanComplete(Message):
    """Sent when the scan finishes.

    Attributes:
        total_findings: Total number of vulnerabilities found.
        duration: Scan duration in seconds.
    """

    def __init__(
        self,
        total_findings: int,
        duration: float,
    ) -> None:
        super().__init__()
        self.total_findings = total_findings
        self.duration = duration
