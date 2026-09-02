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



class DashboardPipelineMixin:
    def _render_phase_pipeline(self) -> Panel:
        """Render the mission phase pipeline."""
        phases = [
            ("RECON", ["recon", "init", "warm", "assembl", "start"]),
            ("DISCOVER", ["discover", "spider", "crawl", "gospider", "endpoint"]),
            ("ANALYZE", ["analy", "dast", "hunt", "think", "process"]),
            ("EXPLOIT", ["exploit", "attack", "specialist", "test", "payload"]),
            ("REPORT", ["report", "generat", "complete", "done", "mission", "finish"]),
        ]

        with self._lock:
            current_phase = self.phase.lower()
            urls_analyzed = self.urls_analyzed
            urls_total = self.urls_total
            payloads = self.payloads_tested
            findings_count = len(self.findings)

        # Determine current phase index based on actual progress
        if payloads > 0 or "exploit" in current_phase or "specialist" in current_phase:
            phase_idx = 3  # EXPLOIT
        elif urls_analyzed > 0 or "analy" in current_phase or "dast" in current_phase:
            phase_idx = 2  # ANALYZE
        elif urls_total > 0 or "discover" in current_phase or "spider" in current_phase:
            phase_idx = 1  # DISCOVER
        elif "report" in current_phase or "complete" in current_phase:
            phase_idx = 4  # REPORT
        else:
            phase_idx = 0  # RECON

        # Calculate progress percentage
        if phase_idx == 0:
            progress_pct = 50
        elif phase_idx == 1:
            progress_pct = min(100, urls_total * 2) if urls_total > 0 else 10
        elif phase_idx == 2:
            progress_pct = int((urls_analyzed / max(urls_total, 1)) * 100)
        elif phase_idx == 3:
            progress_pct = min(100, payloads) if payloads > 0 else 10
        elif phase_idx == 4:
            progress_pct = 100
        else:
            progress_pct = 0

        # Build compact pipeline visualization
        pipeline = Text()

        for i, (name, _) in enumerate(phases):
            if i < phase_idx:
                pipeline.append(f"✅{name}", style="bright_green")
            elif i == phase_idx:
                pipeline.append(f"⏵{name}", style="bright_yellow bold")
            else:
                pipeline.append(f"○{name}", style="bright_black")

            if i < len(phases) - 1:
                pipeline.append("→", style="bright_green" if i < phase_idx else "bright_black")

        pipeline.append(f"  [{progress_pct}%]", style="bright_cyan")

        return Panel(
            Align.center(pipeline),
            title="[bright_cyan]PROGRESS[/]",
            border_style="bright_cyan",
            box=box.ROUNDED,
        )

    def _render_specialist_swarm(self) -> Panel:
        """Render the specialist agents with progress."""
        agents = [
            "SQLiAgent", "XSSAgent", "CSTIAgent",
            "SSRFAgent", "XXEAgent", "IDORAgent",
            "LFIAgent", "RCEAgent", "OpenRedirect"
        ]

        with self._lock:
            queue_stats = dict(self.queue_stats)
            current_agent = self.current_agent
            agent_stats = dict(self.agent_stats)

        result = Text()

        for agent in agents[:6]:  # Show top 6
            stats = queue_stats.get(agent, {})
            agent_info = agent_stats.get(agent, {})

            depth = stats.get('depth', 0)
            processed = stats.get('processed', 0)
            total = depth + processed
            progress = (processed / total * 100) if total > 0 else 0

            current_payload = agent_info.get('current_payload', '')[:45]
            status = agent_info.get('status', 'idle')

            # Spinner for active agents
            spinner = self._get_spinner() if agent == current_agent else " "

            # Agent name
            is_active = agent == current_agent
            name_style = "bright_yellow bold" if is_active else "white"
            result.append(f"  {agent:12} ", style=name_style)

            # Spinner
            result.append(f"{spinner} ", style="bright_cyan")

            # Progress bar
            result.append(self._make_progress_bar(progress, width=25))

            # Stats
            result.append(f" {progress:3.0f}%", style="bright_cyan")
            result.append(f"  {depth:2} queued", style="bright_yellow" if depth > 0 else "bright_black")

            # Current action
            if current_payload:
                result.append(f"   {current_payload}", style="bright_black")

            # Active marker
            if is_active:
                result.append("  ← ACTIVE", style="bright_green bold")

            result.append("\n")

        return Panel(
            result,
            title="[bright_yellow]⚡ SPECIALIST SWARM[/]",
            border_style="bright_yellow",
            box=box.ROUNDED,
        )

    def _render_payload_feed(self) -> Panel:
        """Render the live payload testing feed."""
        with self._lock:
            history = list(self.payload_history[-6:])
            rate = self.payload_rate
            peak = self.payload_peak_rate
            total = self.payloads_tested

        result = Text()

        for entry in reversed(history):
            num = entry.get('num', 0)
            agent = entry.get('agent', 'Unknown')[:10]
            vector = entry.get('vector', '')[:12]
            payload = entry.get('payload', '')[:50]
            status = entry.get('status', 'testing')

            # Status indicator
            if status == 'testing':
                indicator = self._get_spinner()
                style = "bright_yellow"
                status_text = "● TESTING"
            elif status == 'confirmed':
                indicator = "✓"
                style = "bright_green"
                status_text = "✓ CONFIRMED!"
            elif status == 'blocked':
                indicator = "✗"
                style = "bright_red"
                status_text = "✗ BLOCKED"
            elif status == 'waiting':
                indicator = "⏳"
                style = "bright_cyan"
                status_text = "⏳ WAITING"
            else:
                indicator = "✗"
                style = "bright_red"
                status_text = "✗ FAILED"

            result.append(f"  {indicator} ", style=style)
            result.append(f"#{num:4} ", style="bright_black")
            result.append("│ ", style="bright_black")
            result.append(f"{agent:10} ", style="bright_magenta")
            result.append("│ ", style="bright_black")
            result.append(f"{vector:12} ", style="bright_cyan")
            result.append("│ ", style="bright_black")
            result.append(f"{payload:50} ", style="white")
            result.append("│ ", style="bright_black")
            result.append(f"{status_text:12}\n", style=style)

        # Pad if needed
        for _ in range(6 - len(history)):
            result.append("  " + " " * 110 + "\n", style="bright_black")

        # Throughput sparkline
        result.append("\n  THROUGHPUT ", style="white")
        result.append(self.throughput_sparkline.render(40, "bright_green"))
        result.append(f"  avg: {rate:.1f}/s  peak: {peak:.1f}/s  total: {total}", style="bright_cyan")

        return Panel(
            result,
            title="[bright_green]🧪 LIVE PAYLOAD FEED[/]",
            border_style="bright_green",
            box=box.ROUNDED,
        )

    def _render_specialists_compact(self) -> Text:
        """Render compact specialist status using visual telemetry (7 lines)."""
        # Display mapping: short_key -> display_label
        display_map = {
            "sqli": "SQLi",
            "xss": "XSS",
            "csti": "CSTI",
            "ssrf": "SSRF",
            "xxe": "XXE",
            "idor": "IDOR",
            "lfi": "LFI",
        }

        with self._lock:
            specialist_metrics = dict(self.specialist_metrics)
            queue_stats = dict(self.queue_stats)
            current_agent = self.current_agent

        result = Text()

        for key, label in display_map.items():
            # Prefer specialist_metrics (visual telemetry) if available
            metrics = specialist_metrics.get(key, {})

            # Fallback to queue_stats for backwards compatibility
            full_name = f"{label}Agent"
            fallback_stats = queue_stats.get(full_name, {})

            # Get values with fallback chain
            queue_depth = metrics.get("queue", fallback_stats.get('depth', 0))
            processed = metrics.get("processed", fallback_stats.get('processed', 0))
            status = metrics.get("status", "IDLE")
            vulns = metrics.get("vulns", 0)
            is_active = status == "ACTIVE" or full_name == current_agent

            # Dynamic styling based on status
            if is_active:
                indicator = self._get_spinner()
                name_style = "bright_green bold"
            elif queue_depth > 0:
                indicator = "●"
                name_style = "bright_yellow"
            elif status == "DONE":
                indicator = "✓"
                name_style = "bright_cyan"
            else:
                indicator = "○"
                name_style = "bright_black"

            # Queue count styling
            q_style = "bright_yellow" if queue_depth > 0 else "bright_black"
            # Processed count styling
            done_style = "bright_green" if processed > 0 else "bright_black"
            # Vuln count styling (highlight if found)
            vuln_style = "bright_red bold" if vulns > 0 else "bright_black"

            result.append(f" {indicator} ", style=name_style)
            result.append(f"{label:5}", style=name_style)
            result.append(f" Q:", style="bright_black")
            result.append(f"{queue_depth:2}", style=q_style)
            result.append(f" ✓:", style="bright_black")
            result.append(f"{processed:2}", style=done_style)
            # Show vulns if any found
            if vulns > 0:
                result.append(f" 🔴{vulns}", style=vuln_style)
            result.append("\n")

        return result
