"""Interactive findings table with sorting and selection."""

from textual.widgets import DataTable
from textual.reactive import reactive
from rich.text import Text
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    severity: str
    finding_type: str
    param: Optional[str]
    payload: Optional[str]
    request: Optional[str]
    response_excerpt: Optional[str]
    time: str
    status: str = "new"


class FindingsTable(DataTable):
    """Interactive findings table with sorting and selection."""

    # Store findings for lookup when row selected
    _findings: reactive[Dict[str, Finding]] = reactive({})

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.cursor_type = "row"
        self.zebra_stripes = True
        self._findings = {}

    def on_mount(self) -> None:
        """Set up table columns on mount."""
        self.add_columns("Severity", "Type", "Parameter", "Time", "Status")

    def add_finding(
        self,
        finding_type: str,
        details: str,
        severity: str,
        param: Optional[str] = None,
        payload: Optional[str] = None,
        request: Optional[str] = None,
        response_excerpt: Optional[str] = None,
    ) -> None:
        """Add a finding row with severity-based styling."""
        # Generate unique ID
        finding_id = f"finding_{len(self._findings)}_{datetime.now().timestamp()}"

        # Create finding object
        finding = Finding(
            id=finding_id,
            severity=severity.upper(),
            finding_type=finding_type,
            param=param,
            payload=payload or details,
            request=request,
            response_excerpt=response_excerpt,
            time=datetime.now().strftime("%H:%M:%S"),
            status="new",
        )

        # Store for later lookup
        self._findings[finding_id] = finding

        # Style severity text
        severity_styles = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "green",
            "INFO": "dim",
        }
        style = severity_styles.get(finding.severity, "white")
        severity_text = Text(finding.severity, style=style)

        # Add row with finding_id as key for lookup
        self.add_row(
            severity_text,
            finding.finding_type,
            finding.param or "-",
            finding.time,
            finding.status,
            key=finding_id,
        )

    def get_finding(self, row_key: str) -> Optional[Finding]:
        """Get finding by row key."""
        return self._findings.get(str(row_key))

    def action_sort_by_severity(self) -> None:
        """Sort table by severity (Critical first)."""
        self.sort("Severity", reverse=True)

    def action_sort_by_type(self) -> None:
        """Sort table by finding type."""
        self.sort("Type")

    def action_sort_by_time(self) -> None:
        """Sort table by time (newest first)."""
        self.sort("Time", reverse=True)
