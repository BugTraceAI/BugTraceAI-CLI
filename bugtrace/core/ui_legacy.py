"""
BugTraceAI v4.1 - Advanced Terminal Dashboard
Multi-page UI with animations, sparklines, gradients and real-time metrics
"""

from datetime import datetime
from typing import List, Optional, Dict, Tuple
from rich.console import Console, Group
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.box import ROUNDED, HEAVY, DOUBLE, SIMPLE, MINIMAL
from rich.style import Style
from rich.traceback import install
from rich.align import Align
from rich import box
import threading
import time
import logging
import sys
import os

# Install rich traceback handler
install(show_locals=True)

# Lazy import psutil
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False


class DashboardHandler(logging.Handler):
    """Custom logging handler that sends logs to the dashboard."""
    def __init__(self, dashboard):
        super().__init__()
        self.dashboard = dashboard

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname
            self.dashboard.log(msg, level)
        except Exception:
            self.handleError(record)


class SparklineBuffer:
    """Circular buffer for sparkline data."""
    def __init__(self, size: int = 30):
        self.size = size
        self.data: List[float] = [0.0] * size
        self.index = 0

    def add(self, value: float):
        self.data[self.index] = value
        self.index = (self.index + 1) % self.size

    def get_ordered(self) -> List[float]:
        """Return data in chronological order."""
        return self.data[self.index:] + self.data[:self.index]

    def render(self, width: int = 20, color: str = "bright_cyan") -> Text:
        """Render sparkline as Text with blocks."""
        chars = "▁▂▃▄▅▆▇█"
        data = self.get_ordered()[-width:]
        max_val = max(data) if max(data) > 0 else 1

        result = Text()
        for val in data:
            idx = int((val / max_val) * (len(chars) - 1)) if max_val > 0 else 0
            result.append(chars[idx], style=color)
        return result


class Dashboard:
    """Advanced multi-page terminal dashboard with animations and graphics."""

    # Page constants
    PAGE_MAIN = 0
    PAGE_FINDINGS = 1
    PAGE_LOGS = 2
    PAGE_STATS = 3
    PAGE_AGENTS = 4
    PAGE_QUEUES = 5
    PAGE_CONFIG = 6

    # Spinner frames
    SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    # Logo ASCII art with gradient colors
    LOGO_LINES = [
        "██████╗ ██╗   ██╗ ██████╗ ████████╗██████╗  █████╗  ██████╗███████╗     █████╗ ██╗",
        "██╔══██╗██║   ██║██╔════╝ ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝    ██╔══██╗██║",
        "██████╔╝██║   ██║██║  ███╗   ██║   ██████╔╝███████║██║     █████╗      ███████║██║",
        "██╔══██╗██║   ██║██║   ██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝      ██╔══██║██║",
        "██████╔╝╚██████╔╝╚██████╔╝   ██║   ██║  ██║██║  ██║╚██████╗███████╗    ██║  ██║██║",
        "╚═════╝  ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝╚═╝",
    ]

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

    # ═══════════════════════════════════════════════════════════════════════════
    # KEYBOARD HANDLING
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # SYSTEM METRICS
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # RENDERING HELPERS
    # ═══════════════════════════════════════════════════════════════════════════

    def _get_spinner(self) -> str:
        """Get current spinner frame and advance."""
        self._spinner_idx = (self._spinner_idx + 1) % len(self.SPINNER_FRAMES)
        return self.SPINNER_FRAMES[self._spinner_idx]

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

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 0: MAIN OVERVIEW
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 1: FINDINGS DETAIL
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 2: LOGS
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 3: STATS
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 4: AGENTS
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 5: QUEUES
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # PAGE 6: CONFIG
    # ═══════════════════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════════════════
    # MAIN RENDER
    # ═══════════════════════════════════════════════════════════════════════════

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

    def __rich__(self):
        return self.render()

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════════════════════════

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


# Global singleton
dashboard = Dashboard()
