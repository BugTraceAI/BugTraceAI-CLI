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



class DashboardPagesMixin:
    def _render_page_main(self) -> Layout:
        """Render the main overview page (Page 0) with fixed layout."""
        layout = Layout()

        # Fixed layout: header(3) + progress(3) + metrics(9) + activity(8) + bottom(10) + footer(1) = 34
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="progress", size=3),
            Layout(name="metrics", size=9),
            Layout(name="activity", size=8),
            Layout(name="bottom", size=10),
            Layout(name="footer", size=1),
        )

        # Header
        layout["header"].update(Panel(
            Align.center(self._render_header_bar()),
            title="[bright_red bold]🔥 BUGTRACE AI[/]",
            border_style="bright_cyan",
            box=box.ROUNDED,
        ))

        # Progress pipeline
        layout["progress"].update(self._render_phase_pipeline())

        # Metrics row
        layout["metrics"].update(self._render_metrics_row())

        # Activity log
        layout["activity"].update(self._render_activity_log_panel())

        # Bottom row (findings + specialists)
        layout["bottom"].update(self._render_bottom_row())

        # Footer
        layout["footer"].update(self._render_footer())

        return layout

    def _render_page_findings(self) -> Layout:
        """Render detailed findings page with fixed layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="content", size=30),
            Layout(name="footer", size=1),
        )

        with self._lock:
            findings = list(self.findings)

        # Header
        layout["header"].update(Panel(
            Text.assemble(
                ("🚨 FINDINGS DETAIL", "bright_red bold"),
                ("  │  ", "bright_black"),
                (f"Total: {len(findings)} findings", "white"),
            ),
            border_style="bright_red",
            box=box.ROUNDED,
        ))

        # Content - compact list
        content = Text()
        if findings:
            for i, finding in enumerate(findings[:12]):
                f_type, details, severity = finding[0], finding[1], finding[2]
                emoji, style = self._get_severity_style(severity)
                content.append(f" {emoji} ", style=style)
                content.append(f"#{i+1:2} {severity:8} ", style=style)
                content.append(f"{f_type:15} ", style="white")
                content.append(f"{details[:50]}\n", style="bright_black")
        else:
            content.append("No findings yet...", style="bright_black")

        layout["content"].update(Panel(content, border_style="bright_red", box=box.ROUNDED))
        layout["footer"].update(self._render_footer())

        return layout

    def _render_page_logs(self) -> Layout:
        """Render full logs page with fixed layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="content", size=30),
            Layout(name="footer", size=1),
        )

        with self._lock:
            logs = list(self.logs[-25:])

        # Header
        layout["header"].update(Panel(
            Text.assemble(
                ("📋 FULL LOG VIEW", "bright_blue bold"),
                ("  │  ", "bright_black"),
                (f"{len(self.logs)} total entries", "white"),
            ),
            border_style="bright_blue",
            box=box.ROUNDED,
        ))

        # Logs content
        log_content = Text()
        for timestamp, level, msg in logs:
            if "SUCCESS" in level or "CONFIRMED" in str(msg).upper():
                icon, color = "✓", "bright_green"
            elif "WARN" in level:
                icon, color = "⚠", "bright_yellow"
            elif "ERROR" in level:
                icon, color = "✗", "bright_red"
            else:
                icon, color = "●", "bright_cyan"

            log_content.append(f" {timestamp} {icon} {str(msg)[:95]}\n", style=color if "ERROR" in level else "white")

        layout["content"].update(Panel(log_content, border_style="bright_blue", box=box.ROUNDED))
        layout["footer"].update(self._render_footer())

        return layout

    def _render_page_stats(self) -> Layout:
        """Render detailed statistics page with fixed layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="content", size=30),
            Layout(name="footer", size=1),
        )

        with self._lock:
            urls_disc = self.urls_discovered
            urls_analyzed = self.urls_analyzed
            urls_total = self.urls_total
            tested = self.payloads_tested
            success = self.payloads_success
            failed = self.payloads_failed
            blocked = self.payloads_blocked
            cost = self.session_cost
            reqs = self.total_requests
            rate = self.payload_rate

        # Header
        layout["header"].update(Panel(
            Text.assemble(
                ("📊 DETAILED STATISTICS", "bright_cyan bold"),
                ("  │  ", "bright_black"),
                (f"Runtime: {self._format_elapsed()}", "white"),
            ),
            border_style="bright_cyan",
            box=box.ROUNDED,
        ))

        # Stats grid
        stats_table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
        stats_table.add_column(ratio=1)
        stats_table.add_column(ratio=1)

        # Discovery stats
        disc_content = Text()
        disc_content.append(f"URLs discovered:     {urls_disc}\n", style="white")
        disc_content.append(f"URLs analyzed:       {urls_analyzed}/{urls_total}\n", style="white")
        disc_content.append(f"Analysis progress:   {(urls_analyzed/urls_total*100) if urls_total > 0 else 0:.1f}%\n", style="bright_cyan")
        disc_content.append(f"\nDedup effectiveness: {self.dedup_effectiveness:.1f}%\n", style="bright_magenta")

        # Testing stats
        test_content = Text()
        test_content.append(f"Payloads tested:     {tested}\n", style="white")
        test_content.append(f"Successful:          {success} ({(success/tested*100) if tested > 0 else 0:.1f}%)\n", style="bright_green")
        test_content.append(f"Failed:              {failed}\n", style="bright_red")
        test_content.append(f"Blocked (WAF):       {blocked}\n", style="bright_yellow")
        test_content.append(f"Rate:                {rate:.1f}/s\n", style="bright_cyan")

        # Cost stats
        cost_content = Text()
        cost_content.append(f"Session cost:        ${cost:.4f}\n", style="white")
        cost_content.append(f"API requests:        {reqs}\n", style="white")
        cost_content.append(f"Cost per request:    ${(cost/reqs) if reqs > 0 else 0:.6f}\n", style="bright_cyan")

        # Timing stats
        timing_content = Text()
        timing_content.append(f"Total runtime:       {self._format_elapsed()}\n", style="white")
        timing_content.append(f"Peak rate:           {self.payload_peak_rate:.1f}/s\n", style="bright_cyan")
        timing_content.append(f"Threads:             {self.threads_count}\n", style="white")

        stats_table.add_row(
            Panel(disc_content, title="[bright_cyan]DISCOVERY[/]", border_style="bright_cyan", box=box.ROUNDED),
            Panel(test_content, title="[bright_green]TESTING[/]", border_style="bright_green", box=box.ROUNDED),
        )
        stats_table.add_row(
            Panel(cost_content, title="[bright_yellow]COST[/]", border_style="bright_yellow", box=box.ROUNDED),
            Panel(timing_content, title="[bright_magenta]TIMING[/]", border_style="bright_magenta", box=box.ROUNDED),
        )

        layout["content"].update(stats_table)
        layout["footer"].update(self._render_footer())

        return layout

    def _render_page_agents(self) -> Layout:
        """Render agent monitor page with fixed layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="content", size=30),
            Layout(name="footer", size=1),
        )

        agents = ["SQLiAgent", "XSSAgent", "CSTIAgent", "SSRFAgent", "XXEAgent", "IDORAgent", "LFIAgent", "RCEAgent", "OpenRedirect"]

        with self._lock:
            queue_stats = dict(self.queue_stats)
            current = self.current_agent

        # Header
        layout["header"].update(Panel(
            Text.assemble(
                ("🤖 AGENT MONITOR", "bright_magenta bold"),
                ("  │  ", "bright_black"),
                ("Live refresh", "white"),
            ),
            border_style="bright_magenta",
            box=box.ROUNDED,
        ))

        # Content - compact table
        content = Text()
        content.append(" AGENT          STATUS      QUEUE   DONE    PROGRESS\n", style="bright_cyan bold")
        content.append("─" * 60 + "\n", style="bright_black")

        for agent in agents:
            stats = queue_stats.get(agent, {})
            depth = stats.get('depth', 0)
            processed = stats.get('processed', 0)
            total = depth + processed
            progress = int((processed / total * 100)) if total > 0 else 0

            is_active = agent == current
            if is_active:
                status = "⏵ ACTIVE"
                style = "bright_green bold"
            elif depth > 0:
                status = "● QUEUED"
                style = "bright_yellow"
            else:
                status = "○ IDLE"
                style = "bright_black"

            # Progress bar mini
            bar_filled = int(progress / 10)
            bar = "█" * bar_filled + "░" * (10 - bar_filled)

            content.append(f" {agent:14} ", style=style)
            content.append(f"{status:10} ", style=style)
            content.append(f"{depth:5}   ", style="bright_yellow" if depth > 0 else "bright_black")
            content.append(f"{processed:5}   ", style="bright_green" if processed > 0 else "bright_black")
            content.append(f"{bar} {progress:3}%\n", style="bright_cyan")

        layout["content"].update(Panel(content, border_style="bright_magenta", box=box.ROUNDED))
        layout["footer"].update(self._render_footer())

        return layout

    def _render_page_queues(self) -> Layout:
        """Render queue monitor page with fixed layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="content", size=30),
            Layout(name="footer", size=1),
        )

        with self._lock:
            queue_stats = dict(self.queue_stats)

        # Header
        total_queued = sum(s.get('depth', 0) for s in queue_stats.values())
        total_processed = sum(s.get('processed', 0) for s in queue_stats.values())
        layout["header"].update(Panel(
            Text.assemble(
                ("📬 QUEUE MONITOR", "bright_yellow bold"),
                ("  │  ", "bright_black"),
                (f"Queued: {total_queued}", "bright_yellow"),
                ("  │  ", "bright_black"),
                (f"Processed: {total_processed}", "bright_green"),
            ),
            border_style="bright_yellow",
            box=box.ROUNDED,
        ))

        # Content - compact queue list
        content = Text()
        content.append(" QUEUE           DEPTH   PROCESSED   PROGRESS                    RATE\n", style="bright_cyan bold")
        content.append("─" * 75 + "\n", style="bright_black")

        agents = ["SQLiAgent", "XSSAgent", "CSTIAgent", "SSRFAgent", "XXEAgent", "IDORAgent", "LFIAgent", "RCEAgent", "OpenRedirect"]

        for agent in agents:
            stats = queue_stats.get(agent, {})
            depth = stats.get('depth', 0)
            processed = stats.get('processed', 0)
            total = depth + processed
            progress = int((processed / total * 100)) if total > 0 else 0
            rate = stats.get('rate', 0)

            # Progress bar
            bar_filled = int(progress / 5)
            bar = "█" * bar_filled + "░" * (20 - bar_filled)

            depth_style = "bright_yellow" if depth > 0 else "bright_black"
            proc_style = "bright_green" if processed > 0 else "bright_black"

            content.append(f" {agent:14} ", style="white")
            content.append(f"{depth:5}   ", style=depth_style)
            content.append(f"{processed:8}   ", style=proc_style)
            content.append(f"{bar} ", style="bright_cyan")
            content.append(f"{progress:3}%  ", style="bright_cyan")
            content.append(f"{rate:.1f}/s\n", style="bright_magenta")

        layout["content"].update(Panel(content, border_style="bright_yellow", box=box.ROUNDED))
        layout["footer"].update(self._render_footer())

        return layout

    def _render_page_config(self) -> Layout:
        """Render configuration page with fixed layout."""
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="content", size=30),
            Layout(name="footer", size=1),
        )

        # Header
        layout["header"].update(Panel(
            Text.assemble(
                ("⚙️ RUNTIME CONFIGURATION", "bright_white bold"),
                ("  │  ", "bright_black"),
                ("Read from bugtraceaicli.conf", "bright_cyan"),
            ),
            border_style="bright_white",
            box=box.ROUNDED,
        ))

        # Config content with actual info
        config_content = Text()
        config_content.append(" CURRENT SESSION\n", style="bright_cyan bold")
        config_content.append("─" * 50 + "\n", style="bright_black")
        config_content.append(f" Target:           {self.target[:60]}\n", style="white")
        config_content.append(f" Phase:            {self.phase}\n", style="bright_yellow")
        config_content.append(f" Runtime:          {self._format_elapsed()}\n", style="white")
        config_content.append(f" Active threads:   {self.threads_count}\n", style="white")
        config_content.append("\n")
        config_content.append(" KEYBOARD SHORTCUTS\n", style="bright_cyan bold")
        config_content.append("─" * 50 + "\n", style="bright_black")
        config_content.append(" [0-6]  Switch pages\n", style="white")
        config_content.append(" [P]    Pause/Resume scan\n", style="bright_yellow")
        config_content.append(" [Q]    Quit application\n", style="bright_red")
        config_content.append(" [R]    Generate report\n", style="bright_green")
        config_content.append("\n")
        config_content.append(" SYSTEM STATUS\n", style="bright_cyan bold")
        config_content.append("─" * 50 + "\n", style="bright_black")
        config_content.append(f" CPU:              {self.cpu_usage:.1f}%\n", style="bright_green" if self.cpu_usage < 70 else "bright_red")
        config_content.append(f" RAM:              {self.ram_usage:.1f}%\n", style="bright_cyan" if self.ram_usage < 80 else "bright_yellow")
        config_content.append(f" Paused:           {'Yes' if self.paused else 'No'}\n", style="bright_yellow" if self.paused else "white")

        layout["content"].update(Panel(config_content, border_style="bright_white", box=box.ROUNDED))
        layout["footer"].update(self._render_footer())

        return layout
