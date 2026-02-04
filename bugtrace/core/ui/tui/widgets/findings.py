"""Findings summary widget for BugTraceAI TUI.

Displays vulnerability findings grouped by severity.
"""

from __future__ import annotations

import random
from typing import List, Tuple, Dict, Any

from rich.panel import Panel
from rich.text import Text
from rich import box
from textual.reactive import reactive
from textual.widgets import Static


class FindingsSummary(Static):
    """Findings summary widget.

    Shows findings count by severity with preview list.
    Matches the legacy _render_findings_summary() appearance.

    Attributes:
        findings: List of finding tuples (type, details, severity, time, status).
        demo_mode: When True, generates random demo data.
    """

    # Severity configuration: (emoji, style)
    SEVERITY_CONFIG: Dict[str, Tuple[str, str]] = {
        "CRITICAL": ("\U0001F6A8", "bright_red bold"),
        "HIGH": ("\U0001F534", "bright_red"),
        "MEDIUM": ("\U0001F7E1", "bright_yellow"),
        "LOW": ("\u26aa", "white"),
        "INFO": ("\u2139\ufe0f", "bright_blue"),
    }

    # Sample findings for demo mode
    DEMO_FINDINGS = [
        ("XSS", "Reflected XSS in search param", "HIGH"),
        ("SQLi", "SQL Injection in login form", "CRITICAL"),
        ("SSRF", "Internal IP disclosure via img src", "MEDIUM"),
        ("LFI", "Path traversal in file param", "HIGH"),
        ("IDOR", "User ID enumeration in /api/user", "MEDIUM"),
        ("XXE", "XML parser vulnerable to XXE", "CRITICAL"),
        ("RCE", "Command injection in ping utility", "CRITICAL"),
        ("Redirect", "Open redirect in return_url", "LOW"),
    ]

    # Reactive attributes
    findings: reactive[List[Tuple[str, str, str, str, str]]] = reactive([])
    demo_mode = reactive(False)

    def __init__(self, *args, **kwargs):
        """Initialize the findings summary widget."""
        super().__init__(*args, **kwargs)
        self._findings_list: List[Tuple[str, str, str, str, str]] = []

    def on_mount(self) -> None:
        """Set up demo mode interval if needed."""
        self.set_interval(2.0, self._demo_tick)

    def _demo_tick(self) -> None:
        """Generate demo findings periodically."""
        if not self.demo_mode:
            return

        # Add a random finding every tick
        if len(self._findings_list) < 15 and random.random() > 0.3:
            finding_type, details, severity = random.choice(self.DEMO_FINDINGS)
            timestamp = f"{random.randint(0, 23):02d}:{random.randint(0, 59):02d}:{random.randint(0, 59):02d}"
            self._findings_list.append(
                (finding_type, details, severity, timestamp, "confirmed")
            )
            self.refresh()

    def add_finding(
        self,
        finding_type: str,
        details: str,
        severity: str = "INFO",
        timestamp: str = "",
        status: str = "confirmed",
    ) -> None:
        """Add a finding to the list.

        Args:
            finding_type: Type of vulnerability (XSS, SQLi, etc.).
            details: Description of the finding.
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
            timestamp: Time of finding (optional).
            status: Status (confirmed, potential, etc.).
        """
        if not timestamp:
            from datetime import datetime
            timestamp = datetime.now().strftime("%H:%M:%S")

        self._findings_list.append((finding_type, details, severity, timestamp, status))
        self.refresh()

    def clear(self) -> None:
        """Clear all findings."""
        self._findings_list = []
        self.refresh()

    def get_counts(self) -> Dict[str, int]:
        """Get counts by severity.

        Returns:
            Dict mapping severity to count.
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self._findings_list:
            severity = f[2] if len(f) > 2 else "INFO"
            if severity in counts:
                counts[severity] += 1
        return counts

    def render(self) -> Panel:
        """Render the findings summary panel.

        Returns:
            Rich Panel containing findings summary.
        """
        total = len(self._findings_list)
        result = Text()

        # Sort findings by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(
            self._findings_list,
            key=lambda x: severity_order.get(x[2], 99)
        )[:6]

        for finding in sorted_findings:
            finding_type = finding[0]
            details = finding[1]
            severity = finding[2]

            emoji, style = self.SEVERITY_CONFIG.get(severity, ("\u2022", "white"))

            result.append(f" {emoji} ", style=style)
            result.append(f"{severity:6} ", style=style)
            result.append(f"{finding_type:12} ", style="white")
            result.append(f"{details[:35]}\n", style="bright_black")

        # Pad to 6 lines
        for _ in range(6 - len(sorted_findings)):
            result.append("\n")

        # Summary line
        remaining = total - 6
        if remaining > 0:
            result.append(f" +{remaining} more", style="bright_black")

        return Panel(
            result,
            title="[bright_red]\U0001F6A8 FINDINGS[/]",
            border_style="bright_red",
            box=box.ROUNDED,
        )
