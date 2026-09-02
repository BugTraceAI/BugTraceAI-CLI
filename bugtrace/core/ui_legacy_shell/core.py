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

from bugtrace.core.ui_legacy_shell.widgets import SparklineBuffer, DashboardHandler


class DashboardCoreMixin:
    def __init__(self):
        self.console = Console()
        self._lock = threading.RLock()
        self.active = False

        # Page system
        self.current_page = self.PAGE_MAIN

        # Initialize state
        self._init_state()
        self._init_metrics()
        self._init_sparklines()

        # Force terminal size
        self._disable_mouse_reporting()
        self._resize_terminal()

    def _disable_mouse_reporting(self):
        """Disable terminal mouse reporting to prevent input flood."""
        try:
            # Disable multiple mouse tracking modes
            # 1000: Normal tracking
            # 1002: Button-event tracking
            # 1003: Any-event tracking
            # 1006: SGR extension
            # 1015: URXVT extension
            sys.stdout.write("\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?1015l")
            sys.stdout.flush()
        except Exception:
            pass

    def _resize_terminal(self):
        """Force terminal to 35 rows x 113 cols."""
        try:
            # ANSI escape: ESC[8;rows;colst
            sys.stdout.write("\033[8;35;113t")
            sys.stdout.flush()
        except Exception:
            pass

    def _init_state(self):
        """Initialize dashboard state."""
        self.target: str = "Waiting for target..."
        self.phase: str = "INITIALIZING"
        self.status_msg: str = "Starting..."
        self.progress_msg: str = "Ready"
        self.logs: List[Tuple[str, str, str]] = []
        self.findings: List[Tuple[str, str, str, str, str]] = []  # type, details, severity, time, status
        self.active_tasks: Dict[str, Dict] = {}
        self.start_time = datetime.now()

        # Spinner state
        self._spinner_idx = 0
        self._last_activity = time.time()

        # Cost tracking
        self.credits: float = 0.0
        self.total_requests: int = 0
        self.session_cost: float = 0.0

        # Control flags
        self.paused: bool = False
        self.stop_requested: bool = False

        # Keyboard listener
        self._keyboard_thread: Optional[threading.Thread] = None
        self._keyboard_cleanup_done = threading.Event()

        # Payload tracking
        self.current_payload: str = ""
        self.current_vector: str = ""
        self.current_payload_status: str = "Idle"
        self.current_agent: str = ""
        self._last_agent: str = ""
        self.payload_retry_count: int = 0
        self.payloads_tested: int = 0
        self.payloads_success: int = 0
        self.payloads_failed: int = 0
        self.payloads_blocked: int = 0
        self.payload_rate: float = 0.0
        self.payload_peak_rate: float = 0.0
        self._rate_window: List[float] = []  # timestamps of recent payloads
        self._rate_window_seconds: float = 3.0  # sliding window size

        # Payload history for live feed
        self.payload_history: List[Dict] = []

        # Progress metrics
        self.urls_discovered: int = 0
        self.urls_analyzed: int = 0
        self.urls_total: int = 0
        self.findings_before_dedup: int = 0
        self.findings_after_dedup: int = 0
        self.findings_distributed: int = 0
        self.dedup_effectiveness: float = 0.0
        self.queue_stats: Dict[str, Dict] = {}

        # Phase timing
        self.phase_times: Dict[str, float] = {}
        self.phase_start_time: Optional[datetime] = None

        # Agent stats
        self.agent_stats: Dict[str, Dict] = {}

        # Specialist telemetry metrics (visual telemetry v4.2)
        # Format: { 'sqli': {'queue': 0, 'processed': 0, 'vulns': 0, 'status': 'IDLE'} }
        self.specialist_metrics: Dict[str, Dict] = {}

    def _init_metrics(self):
        """Initialize system metrics tracking."""
        self.cpu_usage: float = 0.0
        self.ram_usage: float = 0.0
        self.threads_count: int = 0
        self.network_download: float = 0.0
        self.network_upload: float = 0.0

        if PSUTIL_AVAILABLE:
            self._metrics_thread = threading.Thread(target=self._update_system_metrics_loop, daemon=True)
            self._metrics_thread.start()

    def _init_sparklines(self):
        """Initialize sparkline buffers."""
        self.cpu_sparkline = SparklineBuffer(30)
        self.ram_sparkline = SparklineBuffer(30)
        self.requests_sparkline = SparklineBuffer(60)
        self.throughput_sparkline = SparklineBuffer(40)

    def reset(self):
        """Reset dashboard state for a clean new scan."""
        with self._lock:
            self.findings = []
            self.logs = []
            self.active_tasks = {}
            self.payload_history = []
            self.payloads_tested = 0
            self.payloads_success = 0
            self.payloads_failed = 0
            self.payloads_blocked = 0
            self.session_cost = 0.0
            self.total_requests = 0
            self.stop_requested = False
            self.paused = False
            self.current_payload = ""
            self.current_agent = ""
            self._last_agent = ""
            self.phase = "INITIALIZING"
            self.status_msg = "Starting..."
            self.start_time = datetime.now()
            self._spinner_idx = 0
            self._last_activity = time.time()
            self.urls_discovered = 0
            self.urls_analyzed = 0
            self.urls_total = 0
            self.findings_before_dedup = 0
            self.findings_after_dedup = 0
            self.findings_distributed = 0
            self.dedup_effectiveness = 0.0
            self.queue_stats = {}
            self.phase_times = {}
            self.agent_stats = {}
            self.specialist_metrics = {}
            self._rate_window = []
            self._init_sparklines()

    def reset_controls(self):
        """Reset per-run control flags without clearing rendered scan state.

        Only the shared control flags are cleared here so a stale stop/pause from
        a previous scan can't abort a new one; the full metric/sparkline reset
        stays in reset() (called at scan start) to avoid wiping rendered state."""
        with self._lock:
            self.stop_requested = False
            self.paused = False

    def start_keyboard_listener(self):
        """Start background keyboard listener."""
        self._keyboard_cleanup_done.clear()
        listener = threading.Thread(target=self._keyboard_loop, daemon=True)
        self._keyboard_thread = listener
        listener.start()

    def stop_keyboard_listener(self, timeout: float = 0.5):
        """Stop keyboard listener and restore terminal."""
        self.active = False  # Signal keyboard loop to stop
        if self._keyboard_thread is not None and self._keyboard_thread.is_alive():
            self._keyboard_cleanup_done.wait(timeout=timeout)
        self._keyboard_thread = None
        # Force restore terminal settings
        self._restore_terminal()

    def _restore_terminal(self):
        """Force restore terminal to normal mode."""
        try:
            import termios
            import sys
            if sys.stdin.isatty():
                fd = sys.stdin.fileno()
                # Get current settings and restore to cooked mode
                try:
                    settings = termios.tcgetattr(fd)
                    settings[3] = settings[3] | termios.ECHO | termios.ICANON
                    termios.tcsetattr(fd, termios.TCSANOW, settings)
                except Exception:
                    pass
        except ImportError:
            pass

    def _keyboard_loop(self):
        """Non-blocking keyboard listener with page navigation."""
        try:
            import tty
            import termios
            import select
        except ImportError:
            self._keyboard_cleanup_done.set()
            return

        # Wait for dashboard to become active
        for _ in range(100):
            if self.active:
                break
            time.sleep(0.1)
        else:
            self._keyboard_cleanup_done.set()
            return

        if not sys.stdin.isatty():
            self._keyboard_cleanup_done.set()
            return

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)

        try:
            tty.setcbreak(fd)
            while self.active:
                dr, _, _ = select.select([sys.stdin], [], [], 0.1)
                if dr:
                    char = sys.stdin.read(1)
                    self._handle_key_press(char)
                if self.stop_requested:
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, old_settings)
            self._keyboard_cleanup_done.set()

    def _handle_key_press(self, char: str):
        """Handle keyboard input including page navigation."""
        with self._lock:
            # Page navigation (0-6)
            if char in "0123456":
                self.current_page = int(char)
                # Force terminal size on page change
                self._resize_terminal()
            # Control keys
            elif char.lower() == 'q':
                self.stop_requested = True
            elif char.lower() == 'p':
                self.paused = not self.paused
            elif char.lower() == 'r':
                # Trigger report generation
                pass

    def _update_system_metrics_loop(self):
        """Background thread to update system metrics."""
        while True:
            try:
                cpu = psutil.cpu_percent(interval=None)
                mem = psutil.virtual_memory()
                ram = mem.percent

                process = psutil.Process()
                threads = process.num_threads()

                net_io = psutil.net_io_counters()
                dl = net_io.bytes_recv / 1024 / 1024
                ul = net_io.bytes_sent / 1024 / 1024

                with self._lock:
                    self.cpu_usage = cpu
                    self.ram_usage = ram
                    self.threads_count = threads
                    self.network_download = dl
                    self.network_upload = ul

                    # Update sparklines
                    self.cpu_sparkline.add(cpu)
                    self.ram_sparkline.add(ram)

                time.sleep(1)
            except Exception:
                time.sleep(2)

    def _get_spinner(self) -> str:
        """Get current spinner frame and advance."""
        self._spinner_idx = (self._spinner_idx + 1) % len(self.SPINNER_FRAMES)
        return self.SPINNER_FRAMES[self._spinner_idx]

    def render(self):
        """Render the current page."""
        with self._lock:
            page = self.current_page

        if page == self.PAGE_MAIN:
            return self._render_page_main()
        elif page == self.PAGE_FINDINGS:
            return self._render_page_findings()
        elif page == self.PAGE_LOGS:
            return self._render_page_logs()
        elif page == self.PAGE_STATS:
            return self._render_page_stats()
        elif page == self.PAGE_AGENTS:
            return self._render_page_agents()
        elif page == self.PAGE_QUEUES:
            return self._render_page_queues()
        elif page == self.PAGE_CONFIG:
            return self._render_page_config()
        else:
            return self._render_page_main()

    def _make_gradient_text(self, text: str, colors: List[str]) -> Text:
        """Create text with gradient effect."""
        result = Text()
        if not text:
            return result

        step = len(text) / max(len(colors) - 1, 1)
        for i, char in enumerate(text):
            color_idx = min(int(i / step), len(colors) - 1)
            result.append(char, style=colors[color_idx])
        return result

    def _make_progress_bar(self, value: float, width: int = 30,
                           filled_char: str = "█", empty_char: str = "░",
                           gradient: bool = True) -> Text:
        """Create a progress bar with optional gradient."""
        filled = int((value / 100) * width)
        empty = width - filled

        result = Text()
        if gradient:
            # Green -> Yellow -> Red gradient based on position
            for i in range(filled):
                pct = i / width
                if pct < 0.5:
                    color = "bright_green"
                elif pct < 0.75:
                    color = "bright_yellow"
                else:
                    color = "bright_red"
                result.append(filled_char, style=color)
        else:
            result.append(filled_char * filled, style="bright_green")

        result.append(empty_char * empty, style="bright_black")
        return result

    def _format_elapsed(self) -> str:
        """Format elapsed time as HH:MM:SS."""
        elapsed = datetime.now() - self.start_time
        return str(elapsed).split('.')[0]

    def _get_severity_style(self, severity: str) -> Tuple[str, str]:
        """Get emoji and style for severity level."""
        styles = {
            "CRITICAL": ("🚨", "bright_red bold"),
            "HIGH": ("🔴", "bright_red"),
            "MEDIUM": ("🟡", "bright_yellow"),
            "LOW": ("⚪", "white"),
            "INFO": ("ℹ️", "bright_blue"),
        }
        return styles.get(severity, ("•", "white"))

    def __rich__(self):
        return self.render()

    def log(self, message: str, level: str = "INFO"):
        """Add a log entry.

        Rate-limited to prevent UI freeze from log flooding.
        Max 20 messages/second (drops messages if rate exceeded).
        """
        # Rate limiting: prevent freeze from log flooding
        now = time.time()
        if not hasattr(self, '_last_log_time'):
            self._last_log_time = 0.0

        if now - self._last_log_time < 0.05:  # Max 20 logs/second
            return  # Throttled - skip this message

        self._last_log_time = now

        timestamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append((timestamp, level, message))
            # Keep last 500 logs
            if len(self.logs) > 500:
                self.logs = self.logs[-500:]

    def add_finding(self, finding_type: str, details: str, severity: str = "INFO"):
        """Add a finding."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.findings.append((finding_type, details, severity, timestamp, "confirmed"))

    def update_task(self, task_id: str, name: str = None, status: str = None, payload: str = None):
        """Update task status."""
        with self._lock:
            if task_id not in self.active_tasks:
                self.active_tasks[task_id] = {"name": name or task_id, "status": "Initializing", "payload": ""}
            if name:
                self.active_tasks[task_id]["name"] = name
            if status:
                self.active_tasks[task_id]["status"] = status
            if payload:
                self.active_tasks[task_id]["payload"] = payload

    def set_target(self, target: str):
        with self._lock:
            self.target = target

    def set_phase(self, phase: str):
        with self._lock:
            self.phase = phase

    def set_status(self, status: str, progress: str = None):
        with self._lock:
            self.status_msg = status
            if progress:
                self.progress_msg = progress

    def set_current_payload(self, payload: str, vector: str = "", status: str = "Testing", agent: str = ""):
        """Set current payload being tested and add to history."""
        with self._lock:
            self.current_payload = payload
            self.current_vector = vector
            self.current_payload_status = status
            self.current_agent = agent
            if agent:
                self._last_agent = agent

            # Add to history
            self.payloads_tested += 1
            self.payload_history.append({
                'num': self.payloads_tested,
                'agent': agent,
                'vector': vector,
                'payload': payload,
                'status': 'testing',
            })

            # Keep last 50
            if len(self.payload_history) > 50:
                self.payload_history = self.payload_history[-50:]

            # Calculate real payload rate using sliding window
            now = time.time()
            self._rate_window.append(now)
            cutoff = now - self._rate_window_seconds
            self._rate_window = [t for t in self._rate_window if t > cutoff]
            self.payload_rate = len(self._rate_window) / self._rate_window_seconds
            if self.payload_rate > self.payload_peak_rate:
                self.payload_peak_rate = self.payload_rate

            # Update sparklines
            self.throughput_sparkline.add(self.payload_rate)
            self.requests_sparkline.add(self.payload_rate)

    def update_payload_status(self, status: str):
        """Update the status of the current payload."""
        with self._lock:
            self.current_payload_status = status
            if self.payload_history:
                self.payload_history[-1]['status'] = status

            if status == 'confirmed':
                self.payloads_success += 1
            elif status == 'blocked':
                self.payloads_blocked += 1
            elif status in ('failed', 'error'):
                self.payloads_failed += 1

    def set_progress_metrics(
        self,
        urls_discovered: int = None,
        urls_analyzed: int = None,
        urls_total: int = None,
        findings_before_dedup: int = None,
        findings_after_dedup: int = None,
        findings_distributed: int = None,
        dedup_effectiveness: float = None,
        queue_stats: Dict[str, Dict] = None,
        scan_id: int = None,
    ):
        """Update progress metrics."""
        with self._lock:
            if urls_discovered is not None:
                self.urls_discovered = urls_discovered
            if urls_analyzed is not None:
                self.urls_analyzed = urls_analyzed
            if urls_total is not None:
                self.urls_total = urls_total
            if findings_before_dedup is not None:
                self.findings_before_dedup = findings_before_dedup
            if findings_after_dedup is not None:
                self.findings_after_dedup = findings_after_dedup
            if findings_distributed is not None:
                self.findings_distributed = findings_distributed
            if dedup_effectiveness is not None:
                self.dedup_effectiveness = dedup_effectiveness
            if queue_stats is not None:
                self.queue_stats = queue_stats

        # WebSocket broadcast if scan_id provided
        if scan_id is not None:
            self._broadcast_progress_update(scan_id, urls_discovered, urls_analyzed, urls_total,
                                           findings_before_dedup, findings_after_dedup,
                                           findings_distributed, dedup_effectiveness, queue_stats)

    def update_agent_stats(self, agent: str, current_payload: str = None, status: str = None):
        """Update agent-specific stats."""
        with self._lock:
            if agent not in self.agent_stats:
                self.agent_stats[agent] = {}
            if current_payload is not None:
                self.agent_stats[agent]['current_payload'] = current_payload
            if status is not None:
                self.agent_stats[agent]['status'] = status

    def update_specialist_status(self, agent_name: str, **kwargs):
        """
        Update specialist telemetry metrics for visual dashboard.

        Called by specialist agents during queue consumption to report:
        - queue: Current items in queue
        - processed: Total items processed
        - vulns: Vulnerabilities found
        - status: 'IDLE', 'ACTIVE', 'DONE'

        Args:
            agent_name: Agent name (e.g., 'SQLiAgent', 'xss_agent', 'XSS')
            **kwargs: Metrics to update (queue, processed, vulns, status)
        """
        # Normalize agent name to short form (sqli, xss, csti, etc.)
        name = agent_name.lower()
        for suffix in ("_agent", "agent"):
            name = name.replace(suffix, "")
        name = name.strip("_")

        with self._lock:
            if name not in self.specialist_metrics:
                self.specialist_metrics[name] = {
                    "queue": 0,
                    "processed": 0,
                    "vulns": 0,
                    "status": "IDLE"
                }

            # Update only provided values
            for key, value in kwargs.items():
                if key in self.specialist_metrics[name]:
                    self.specialist_metrics[name][key] = value

    def _broadcast_progress_update(
        self, scan_id: int, urls_discovered: int, urls_analyzed: int, urls_total: int,
        findings_before_dedup: int, findings_after_dedup: int, findings_distributed: int,
        dedup_effectiveness: float, queue_stats: Dict[str, Dict],
    ):
        """Broadcast progress update to WebSocket clients."""
        try:
            from bugtrace.api.websocket import ws_manager
            import asyncio

            try:
                loop = asyncio.get_running_loop()
                loop.create_task(ws_manager.send_progress_update(
                    scan_id=scan_id,
                    urls_discovered=urls_discovered,
                    urls_analyzed=urls_analyzed,
                    urls_total=urls_total,
                    findings_before_dedup=findings_before_dedup,
                    findings_after_dedup=findings_after_dedup,
                    findings_distributed=findings_distributed,
                    dedup_effectiveness=dedup_effectiveness,
                    queue_stats=queue_stats,
                ))
            except RuntimeError:
                pass
        except ImportError:
            pass

    def save_report(self):
        """Generate a simple Markdown report of findings."""
        from bugtrace.core.config import settings
        from pathlib import Path

        report_dir = Path(settings.REPORT_DIR)
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        content = f"# BugTraceAI v4.1 - Scan Report\n"
        content += f"**Date:** {datetime.now()}\n"
        content += f"**Target:** {self.target}\n\n"
        content += f"## Executive Summary\n"
        content += f"- Total Findings: {len(self.findings)}\n"
        content += f"- Payloads Tested: {self.payloads_tested}\n"
        content += f"- Success Rate: {(self.payloads_success/self.payloads_tested*100) if self.payloads_tested > 0 else 0:.1f}%\n\n"

        content += "## Findings\n"
        for f_type, details, severity, time_str, status in self.findings:
            emoji = "🚨" if severity == "CRITICAL" else ("🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "⚪")
            content += f"### {emoji} {severity} - {f_type}\n"
            content += f"- **Location:** {details}\n"
            content += f"- **Time:** {time_str}\n\n"

        with open(report_path, "w") as f:
            f.write(content)

        return str(report_path)
