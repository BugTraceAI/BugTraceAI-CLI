"""Dashboard shell mixin — extracted from ui_legacy for size policy."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Dict, Tuple
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import ROUNDED, HEAVY, DOUBLE, SIMPLE, MINIMAL
from rich.style import Style
from rich.align import Align
from rich import box
import threading
import time
import logging
import sys
import os

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False



class DashboardChromeMixin:
    def _render_logo(self) -> Text:
        """Render the logo with gradient effect."""
        gradient_colors = ["bright_red", "red", "yellow", "bright_yellow"]
        result = Text()

        for line in self.LOGO_LINES:
            gradient_line = self._make_gradient_text(line, gradient_colors)
            result.append(gradient_line)
            result.append("\n")

        return result

    def _render_header_bar(self) -> Text:
        """Render the header info bar."""
        with self._lock:
            target = self.target[:60] + "..." if len(self.target) > 60 else self.target
            balance = self.credits
            cost = self.session_cost
            reqs = self.total_requests
            elapsed = self._format_elapsed()
            spinner = self._get_spinner()
            paused = self.paused

        # Balance display
        if balance >= 900.0:
            balance_str = "∞"
            balance_color = "bright_green"
        else:
            balance_str = f"${balance:.2f}"
            balance_color = "bright_green" if balance > 2 else ("bright_yellow" if balance > 1 else "bright_red")

        # Status
        if paused:
            status = "⏸ PAUSED"
            status_color = "bright_yellow"
        else:
            status = f"{spinner} LIVE"
            status_color = "bright_green"

        return Text.assemble(
            ("🎯 ", "white"),
            (target, "bright_cyan bold"),
            ("  │  ", "bright_black"),
            ("💰 ", "white"),
            (balance_str, balance_color),
            (" │ ", "bright_black"),
            (f"-${cost:.4f}", "white"),
            (" │ ", "bright_black"),
            (f"{reqs} reqs", "white"),
            (" │ ", "bright_black"),
            ("⏱ ", "white"),
            (elapsed, "bright_cyan"),
            ("  │  ", "bright_black"),
            (status, status_color),
        )

    def _render_metrics_row(self) -> Layout:
        """Render the three-column metrics row using Layout for fixed height."""
        row = Layout()
        row.split_row(
            Layout(name="activity", ratio=1),
            Layout(name="system", ratio=1),
            Layout(name="severity", ratio=1),
        )

        # Column 1: Activity Graph
        row["activity"].update(Panel(
            self._render_activity_graph(),
            title="[bright_cyan]📈 ACTIVITY[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
        ))

        # Column 2: System Metrics
        row["system"].update(Panel(
            self._render_system_metrics(),
            title="[bright_cyan]🔥 SYSTEM[/]",
            border_style="bright_magenta",
            box=box.ROUNDED,
        ))

        # Column 3: Severity Breakdown
        row["severity"].update(Panel(
            self._render_severity_breakdown(),
            title="[bright_cyan]🚨 SEVERITY[/]",
            border_style="bright_red",
            box=box.ROUNDED,
        ))

        return row

    def _render_activity_graph(self) -> Text:
        """Render ASCII activity graph using sparkline characters."""
        data = self.requests_sparkline.get_ordered()[-20:]

        result = Text()
        result.append("req/s\n", style="bright_black")

        # Use sparkline for compact display
        chars = "▁▂▃▄▅▆▇█"
        max_val = max(data) if max(data) > 0 else 1

        for val in data:
            idx = int((val / max_val) * (len(chars) - 1)) if max_val > 0 else 0
            result.append(chars[idx], style="bright_green")

        result.append(f"\n\nRate: {self.payload_rate:.1f}/s", style="bright_cyan")
        result.append(f"\nPeak: {self.payload_peak_rate:.1f}/s", style="bright_yellow")

        return result

    def _render_system_metrics(self) -> Text:
        """Render system metrics with sparklines."""
        with self._lock:
            cpu = self.cpu_usage
            ram = self.ram_usage
            threads = self.threads_count

        result = Text()

        # CPU
        result.append("CPU ", style="white")
        result.append(self.cpu_sparkline.render(15, "bright_green" if cpu < 70 else "bright_red"))
        result.append(f" {cpu:.0f}%\n", style="bright_green" if cpu < 70 else "bright_red")

        # RAM
        result.append("RAM ", style="white")
        result.append(self.ram_sparkline.render(15, "bright_cyan" if ram < 80 else "bright_yellow"))
        result.append(f" {ram:.0f}%\n", style="bright_cyan" if ram < 80 else "bright_yellow")

        result.append(f"\nThreads: {threads}", style="bright_black")

        return result

    def _render_severity_breakdown(self) -> Text:
        """Render findings by severity - numbers only."""
        with self._lock:
            findings = list(self.findings)

        # Count by severity
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f[2] if len(f) > 2 else "INFO"
            if sev in counts:
                counts[sev] += 1

        total = len(findings)

        result = Text()
        result.append("🚨 CRIT: ", style="bright_red bold")
        result.append(f"{counts['CRITICAL']}\n", style="bright_red bold")
        result.append("🔴 HIGH: ", style="bright_red")
        result.append(f"{counts['HIGH']}\n", style="bright_red")
        result.append("🟡 MED:  ", style="bright_yellow")
        result.append(f"{counts['MEDIUM']}\n", style="bright_yellow")
        result.append("⚪ LOW:  ", style="white")
        result.append(f"{counts['LOW']}\n", style="white")
        result.append("\n")
        result.append(f"TOTAL: {total}", style="bright_white bold")

        return result

    def _render_activity_log_panel(self) -> Panel:
        """Render activity log panel (replaces specialist swarm position)."""
        with self._lock:
            logs = list(self.logs[-5:])  # 5 logs fit in 8-row slot (8 - 2 border - 1 padding)

        result = Text()

        for timestamp, level, msg in logs:
            # Icon based on level/content
            if "SUCCESS" in level or "✓" in str(msg) or "CONFIRMED" in str(msg).upper():
                icon, color = "✓", "bright_green"
            elif "WARN" in level or "⚠" in str(msg):
                icon, color = "⚠", "bright_yellow"
            elif "ERROR" in level:
                icon, color = "✗", "bright_red"
            else:
                icon, color = "●", "bright_cyan"

            result.append(f"  {timestamp} ", style="bright_black")
            result.append(f"{icon} ", style=color)
            result.append(f"{str(msg)[:90]}\n", style="white")

        # Pad to 5 lines
        for _ in range(5 - len(logs)):
            result.append("\n")

        return Panel(
            result,
            title="[bright_blue]📋 ACTIVITY LOG[/]",
            border_style="bright_blue",
            box=box.ROUNDED,
        )

    def _render_bottom_row(self) -> Layout:
        """Render bottom row with findings and specialists using Layout for fixed height."""
        row = Layout()
        row.split_row(
            Layout(name="findings", ratio=1),
            Layout(name="specialists", ratio=1),
        )

        # Findings panel
        row["findings"].update(Panel(
            self._render_findings_summary(),
            title="[bright_red]🚨 FINDINGS[/]",
            border_style="bright_red",
            box=box.ROUNDED,
        ))

        # Specialists panel (compact version)
        row["specialists"].update(Panel(
            self._render_specialists_compact(),
            title="[bright_yellow]⚡ SPECIALISTS[/]",
            border_style="bright_yellow",
            box=box.ROUNDED,
        ))

        return row

    def _render_findings_summary(self) -> Text:
        """Render findings summary for main page (fits in 7 lines)."""
        with self._lock:
            findings = list(self.findings)
            total = len(findings)

        result = Text()

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x[2], 99))[:6]

        for finding in sorted_findings:
            f_type, details, severity = finding[0], finding[1], finding[2]
            emoji, style = self._get_severity_style(severity)

            result.append(f" {emoji} ", style=style)
            result.append(f"{severity:6} ", style=style)
            result.append(f"{f_type:12} ", style="white")
            result.append(f"{details[:35]}\n", style="bright_black")

        # Pad to 6 lines
        for _ in range(6 - len(sorted_findings)):
            result.append("\n")

        # Summary line
        remaining = total - 6
        if remaining > 0:
            result.append(f" +{remaining} more", style="bright_black")

        return result

    def _render_log_summary(self) -> Text:
        """Render log summary for main page."""
        with self._lock:
            logs = list(self.logs[-6:])

        result = Text()

        for timestamp, level, msg in logs:
            # Icon based on level/content
            if "SUCCESS" in level or "✓" in str(msg) or "CONFIRMED" in str(msg).upper():
                icon, color = "✓", "bright_green"
            elif "WARN" in level or "⚠" in str(msg):
                icon, color = "⚠", "bright_yellow"
            elif "ERROR" in level:
                icon, color = "✗", "bright_red"
            else:
                icon, color = "●", "bright_cyan"

            # Extract agent name if present
            agent = ""
            if "[" in str(msg) and "]" in str(msg):
                try:
                    agent = str(msg).split("[")[1].split("]")[0][:10]
                    msg = str(msg).split("]", 1)[1].strip() if "]" in str(msg) else msg
                except:
                    pass

            result.append(f"  {timestamp} ", style="bright_black")
            result.append(f"{icon} ", style=color)
            if agent:
                result.append(f"{agent:10} ", style="bright_magenta")
            result.append(f"{str(msg)[:45]}\n", style="white")

        # Pad
        for _ in range(6 - len(logs)):
            result.append("\n")

        return result

    def _render_footer(self) -> Text:
        """Render the footer with page navigation and controls."""
        with self._lock:
            current = self.current_page

        pages = ["MAIN", "FINDINGS", "LOGS", "STATS", "AGENTS", "QUEUES", "CONFIG"]

        result = Text()
        result.append("  ", style="white")

        for i, name in enumerate(pages):
            if i == current:
                result.append(f"[{i}] {name}", style="bright_cyan bold underline")
            else:
                result.append(f"[{i}] {name}", style="bright_black")
            result.append("  ", style="white")

        result.append(" │  ", style="bright_black")
        result.append("[P] Pause  ", style="bright_yellow")
        result.append("[Q] Quit  ", style="bright_red")
        result.append("[R] Report  ", style="bright_green")
        result.append("[?] Help", style="white")

        return result
