from datetime import datetime
from typing import List, Optional, Dict
from rich.console import Console
from rich.spinner import Spinner
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.traceback import install
from rich.columns import Columns
from rich.table import Table
from rich.box import ROUNDED, SIMPLE
import threading
import time
import logging  # Added missing import

# Install rich traceback handler
install(show_locals=True)

# Lazy import psutil to avoid dependency issues
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

class DashboardHandler(logging.Handler):
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

class Dashboard:
    def __init__(self):
        self.console = Console()
        self.layout = Layout()
        self._lock = threading.RLock()
        self.active = False

        self._init_layout()
        self._init_state()
        self._init_metrics()

    def _init_layout(self):
        """Initialize dashboard layout."""
        self.layout.split(
            Layout(name="header1", size=1),
            Layout(name="header2", size=1),
            Layout(name="payloads", ratio=1, minimum_size=5),
            Layout(name="tasks", ratio=1, minimum_size=3),
            Layout(name="log", ratio=2, minimum_size=6),
            Layout(name="findings", ratio=1, minimum_size=5),
            Layout(name="footer", size=1)
        )

    def _init_state(self):
        """Initialize dashboard state."""
        self.target: str = "Unknown"
        self.phase: str = "🚀 WARMING UP"
        self.status_msg: str = "Starting..."
        self.progress_msg: str = "Ready"
        self.logs: List[tuple] = []
        self.findings: List[tuple] = []
        self.active_tasks: Dict[str, Dict] = {}
        self.start_time = datetime.now()

        # Animated spinner for activity indicator
        self._spinner_frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        self._spinner_idx = 0
        self._last_activity = time.time()

        self.credits: float = 0.0
        self.total_requests: int = 0
        self.session_cost: float = 0.0
        self.paused: bool = False
        self.stop_requested: bool = False

        self.current_payload: str = ""
        self.current_vector: str = ""
        self.current_payload_status: str = "Idle"
        self.current_agent: str = ""
        self._last_agent: str = ""  # Track last active agent for display fallback
        self.payload_retry_count: int = 0
        self.payloads_tested: int = 0
        self.payloads_success: int = 0
        self.payloads_failed: int = 0
        self.payload_rate: float = 0.0

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

    def reset(self):
        """Reset dashboard state for a clean new scan."""
        with self._lock:
            self.findings = []
            self.logs = []
            self.active_tasks = {}
            self.payloads_tested = 0
            self.payloads_success = 0
            self.payloads_failed = 0
            self.session_cost = 0.0
            self.total_requests = 0
            self.stop_requested = False
            self.paused = False
            self.current_payload = ""
            self.current_agent = ""
            self._last_agent = ""
            self.phase = "🚀 WARMING UP"
            self.status_msg = "Starting..."
            self.start_time = datetime.now()
            self._spinner_idx = 0
            self._last_activity = time.time()

    def start_keyboard_listener(self):
        """Start a background thread to listen for q/p keys."""
        listener = threading.Thread(target=self._keyboard_loop, daemon=True)
        listener.start()

    def _keyboard_loop(self):
        """Non-blocking keyboard listener."""
        import sys
        import time as _time

        try:
            import tty
            import termios
        except ImportError:
            return

        if not self._wait_for_active(_time):
            return

        try:
            fd = sys.stdin.fileno()
            if not sys.stdin.isatty():
                self._keyboard_loop_non_tty(sys.stdin, _time)
            else:
                self._keyboard_loop_tty(sys.stdin, termios, tty)
        except Exception:
            pass

    def _wait_for_active(self, time_module) -> bool:
        """Wait for dashboard to become active."""
        for _ in range(100):
            if self.active:
                return True
            time_module.sleep(0.1)
        return False

    def _keyboard_loop_non_tty(self, stdin, time_module):
        """Handle keyboard input for non-TTY environments."""
        while self.active:
            char = stdin.read(1)
            if not char:
                time_module.sleep(0.5)
                continue

            if char.lower() == 'q':
                with self._lock:
                    self.stop_requested = True
                break

            if char.lower() == 'p':
                with self._lock:
                    self.paused = not self.paused

    def _keyboard_loop_tty(self, stdin, termios, tty):
        """Handle keyboard input for TTY environments."""
        import select
        import sys

        fd = stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while self.active:
                dr, dw, de = select.select([stdin], [], [], 0.1)
                if dr:
                    char = stdin.read(1)
                    self._handle_key_press(char)
                if self.stop_requested:
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, old_settings)

    def _handle_key_press(self, char: str):
        """Handle single key press."""
        if char.lower() == 'q':
            with self._lock:
                self.stop_requested = True
        elif char.lower() == 'p':
            with self._lock:
                self.paused = not self.paused

    def _update_system_metrics_loop(self):
        """Background thread to update system metrics safely"""
        while True:
            try:
                cpu = psutil.cpu_percent(interval=None) # Non-blocking first
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
                
                time.sleep(2)
            except Exception:
                time.sleep(2)

    def _get_cpu_ram_bar(self, percentage: float, width: int = 10) -> str:
        filled = int(percentage / 10)
        empty = width - filled
        return "█" * filled + "░" * empty

    def _get_color_for_percentage(self, percentage: float) -> str:
        if percentage < 60: return "bright_green"
        elif percentage < 85: return "bright_yellow"
        else: return "bright_red"

    def update_header1(self):
        with self._lock:
             cost = self.session_cost
             reqs = self.total_requests
             balance = self.credits
             target_raw = self.target

        # Dynamic Sizing for Robustness
        try:
            width = self.console.size.width
        except Exception:
            width = 80
            
        # Fixed length parts approx: Title (40) + Metrics (~30) = 70
        # Available for target
        available = max(10, width - 75)
        target = target_raw[:available] + "..." if len(target_raw) > available else target_raw

        cost_per_req = cost / reqs if reqs > 0 else 0.0
        if balance >= 900.0:
             balance_str = " NoLimit "
             balance_color = "bright_green"
        else:
             balance_str = f"{balance:.2f}"
             balance_color = "bright_green" if balance > 2.0 else ("bright_yellow" if balance > 1.0 else "bright_red bold blink")
        
        from bugtrace.core.config import settings
        # New Order: Title | Balance | Cost | Target (Last so it truncates first)
        text = Text.assemble(
            (f"🔥 BugtraceAI v{settings.VERSION}", "bright_yellow bold"),
            (" | 💰 $", "white"),
            (balance_str, balance_color),
            (" | Cost: $", "white"),
            (f"{cost:.4f}", "white"),
            (" | T: ", "white dim"), # Shortened label
            (target, "white bold")
        )
        self.layout["header1"].update(text)

    def update_header2(self):
        with self._lock:
            agent = self.current_agent
            # Track last active agent for fallback display
            if agent:
                self._last_agent = agent
            last_agent = self._last_agent
            phase = self.phase
            cpu = self.cpu_usage
            ram = self.ram_usage
            paused = self.paused
            # Advance spinner
            self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_frames)
            spinner_char = self._spinner_frames[self._spinner_idx]

        # Calculate elapsed time
        elapsed = datetime.now() - self.start_time
        elapsed_str = str(elapsed).split('.')[0]  # HH:MM:SS without microseconds

        if paused:
            status_text, status_color = "⏸ PAUSED", "white dim"
            spinner_char = "⏸"
        elif "ERROR" in phase:
            status_text, status_color = "ERROR", "bright_red bold"
            spinner_char = "✗"
        elif "COMPLETE" in phase or "MISSION" in phase:
            status_text, status_color = "DONE", "bright_green bold"
            spinner_char = "✓"
        else:
            status_text, status_color = "ACTIVE", "bright_green bold"

        cpu_bar = self._get_cpu_ram_bar(cpu)
        ram_bar = self._get_cpu_ram_bar(ram)
        cpu_color = self._get_color_for_percentage(cpu)
        ram_color = self._get_color_for_percentage(ram)

        # Show agent name, or fall back to last agent, or phase-based status
        if agent:
            agent_display = agent
        elif last_agent:
            agent_display = f"({last_agent})"  # Parentheses indicate "was running"
        elif phase and "WARMING" not in phase:
            agent_display = f"[{phase}]"
        else:
            agent_display = "Initializing..."

        text = Text.assemble(
            ("Agent: ", "white"),
            (agent_display, "bright_magenta bold"),
            (" | Phase: ", "white"),
            (phase or "BOOT", "bright_magenta"),
            (" | ", "white"),
            (spinner_char, "bright_cyan bold"),
            (" ", "white"),
            (status_text, status_color),
            (" | ⏱ ", "white"),
            (elapsed_str, "bright_cyan"),
            (" | CPU: ", "white"),
            (f"{cpu:.0f}%", cpu_color),
            (cpu_bar, cpu_color),
            (" | RAM: ", "white"),
            (f"{ram:.0f}%", ram_color),
            (ram_bar, ram_color)
        )
        self.layout["header2"].update(text)

    def update_status_bar(self):
        # Status bar removed - info now shown in header2 and status panel
        pass

    def update_payload_section(self):
        with self._lock:
             payload_data = self._capture_payload_data()

        panel_width = self._get_panel_width()
        status_content = self._build_status_content(payload_data)
        payload_content = self._build_payload_content(payload_data, panel_width)

        combined_table = self._build_payload_table(status_content, payload_content)
        self.layout["payloads"].update(combined_table)

    def _capture_payload_data(self) -> dict:
        """Capture current payload state."""
        return {
            "payload": self.current_payload,
            "vector": self.current_vector,
            "tested": self.payloads_tested,
            "status": self.current_payload_status,
            "agent": self.current_agent,
            "retry": self.payload_retry_count,
            "success": self.payloads_success,
            "failed": self.payloads_failed,
            "rate": self.payload_rate,
            "phase": self.phase,
            "status_msg": self.status_msg,
            "progress_msg": self.progress_msg
        }

    def _get_panel_width(self) -> int:
        """Calculate panel width for proper alignment."""
        try:
            total_width = self.console.size.width
        except Exception:
            total_width = 120
        return max(30, (total_width - 4) // 2)

    def _build_status_content(self, data: dict) -> Text:
        """Build status column content."""
        # Show progress_msg if available, otherwise status_msg
        status_display = data.get("progress_msg") or data["status_msg"] or "Ready"
        status_display = status_display[:35] if len(status_display) > 35 else status_display

        lines = [
            Text.assemble(("📍 Phase: ", "white"), (data["phase"] or "IDLE", "bright_cyan bold")),
            Text.assemble(("🤖 Agent: ", "white"), (data["agent"] or "Idle", "bright_magenta bold")),
            Text.assemble(("📊 Status: ", "white"), (status_display, "bright_yellow")),
            Text.assemble(("⏱️  Progress: ", "white"), (f"{data['tested']} tested | {data['success']}✓ | {data['failed']}✗", "white dim"))
        ]
        return Text("\n").join(lines)

    def _build_payload_content(self, data: dict, panel_width: int) -> Text:
        """Build payload column content."""
        lines = []
        if data["payload"]:
            test_num = f"[#{data['tested']}]" if data['tested'] > 0 else "[#0]"
            lines.append(Text.assemble((test_num, "white dim"), (" ", "white"), (data["vector"] or "unknown", "bright_yellow bold")))

            max_len = panel_width - 10
            display = data["payload"][:max_len] + "..." if len(data["payload"]) > max_len else data["payload"]
            lines.append(Text(display, style="white"))

            style = "bright_green" if "Success" in data["status"] else ("bright_red" if "Failed" in data["status"] else "bright_yellow")
            lines.append(Text.assemble(("Result: ", "white"), (data["status"], style)))
        else:
            lines.extend([Text("No active payload", style="white dim"), Text("Waiting for tasks...", style="white dim"), Text("", style="white")])

        lines.append(Text.assemble(("Rate: ", "white"), (f"{data['rate']:.1f}/s", "bright_green")))
        return Text("\n").join(lines)

    def _build_payload_table(self, status_content: Text, payload_content: Text) -> Table:
        """Build combined payload section table."""
        table = Table(show_header=True, header_style="bold", box=ROUNDED, expand=True,
                     border_style="bright_cyan", padding=(0, 1))
        table.add_column("📌 STATUS", style="bright_cyan", ratio=1)
        table.add_column("🧪 PAYLOAD", style="bright_yellow", ratio=1)
        table.add_row(status_content, payload_content)
        return table

    def update_log_section(self):
        # Calculate available lines based on terminal height
        try:
            term_height = self.console.size.height
            term_width = self.console.size.width
        except Exception:
            term_height = 24
            term_width = 120

        # Estimate available lines for log section
        # Layout: header1(1) + header2(1) + payloads(~5) + tasks(~3) + findings(~5) + footer(1) = ~16 fixed
        # Remaining goes to log with ratio=2, subtract 2 for panel borders
        available_lines = max(5, term_height - 18)

        with self._lock:
            recent_logs = self.logs[-available_lines:] if len(self.logs) >= available_lines else self.logs

        # Calculate max message width based on terminal width (account for timestamp, icon, panel borders)
        max_msg_width = max(40, term_width - 25)

        lines = []
        for timestamp, level, msg in recent_logs:
            icon, color = self._get_log_icon_and_color(level, msg)
            display_msg = str(msg)[:max_msg_width] + "..." if len(str(msg)) > max_msg_width else str(msg)
            lines.append(Text.assemble((f"[{timestamp}] ", "white dim"), (f"{icon} " if icon else "", color), (display_msg, "white")))

        # Pad to fill available space
        while len(lines) < available_lines:
            lines.append(Text("", style="white"))
        content = Text("\n").join(lines)
        panel = Panel(content, title="[bright_yellow bold]📋 LOG[/bright_yellow bold]", border_style="cyan", padding=(0, 1))
        self.layout["log"].update(panel)

    def _get_log_icon_and_color(self, level: str, msg) -> tuple:
        """Get icon and color for log message."""
        if "SUCCESS" in level or "✓" in str(msg):
            return "✓", "bright_green"
        if "WARN" in level or "⚠" in str(msg):
            return "⚠", "bright_yellow"
        if "ERROR" in level or "CRITICAL" in level:
            return "✗", "bright_red"
        return "", "white"

    def update_tasks_section(self):
        """Render active tasks with spinner for running tasks."""
        with self._lock:
            tasks = list(self.active_tasks.items())
        lines = []
        if tasks:
            for task_id, info in tasks:
                name = info.get("name", task_id)
                status = info.get("status", "")
                payload = info.get("payload", "")
                # Use text instead of Spinner inside Text.assemble
                if status.lower() in ("running", "active", "initializing"):
                    status_text = f"● {status}"
                    status_style = "bright_green"
                else:
                    status_text = status
                    status_style = "bright_yellow"

                line = Text.assemble(
                    (f"{name}: ", "bright_cyan"),
                    (status_text, status_style),
                    (f" | payload: {payload}" if payload else "", "white dim")
                )
                lines.append(line)
        else:
            lines.append(Text("No active tasks", style="white dim"))
        # Pad to fixed height (3 lines)
        while len(lines) < 3:
            lines.append(Text("", style="white"))
        content = Text("\n").join(lines)
        panel = Panel(content, title="[bright_yellow bold]⚙️ TASKS[/bright_yellow bold]", border_style="bright_cyan", padding=(0,1))
        self.layout["tasks"].update(panel)

    def update_findings_section(self):
        with self._lock:
            # Sort copy
            current_findings = list(self.findings)

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(current_findings, key=lambda x: severity_order.get(x[2], 99))[:4]

        lines = []
        if sorted_findings:
            for finding_type, details, severity in sorted_findings:
                emoji, color = self._get_severity_icon_and_color(severity)
                details_display = details[:45] + "..." if len(details) > 45 else details
                lines.append(Text.assemble((emoji + " ", color), (f"[{severity}] ", color), (f"{finding_type} @ ", "white"), (details_display, "white")))
        else:
            lines.append(Text("No findings yet...", style="white dim"))

        while len(lines) < 4: lines.append(Text("", style="white"))
        content = Text("\n").join(lines)
        panel = Panel(content, title=f"[bright_yellow bold]🔍 FINDINGS ({len(current_findings)} total)[/bright_yellow bold]", border_style="magenta", padding=(0, 1))
        self.layout["findings"].update(panel)

    def _get_severity_icon_and_color(self, severity: str) -> tuple:
        """Get icon and color for severity level."""
        if severity == "CRITICAL":
            return "🚨", "bright_red bold blink"
        if severity == "HIGH":
            return "🔴", "bright_red bold"
        if severity == "MEDIUM":
            return "🟡", "bright_yellow"
        return "⚪", "white dim"

    def update_footer(self):
        text = Text.assemble(("[p] Pause", "bright_yellow"), (" | ", "white dim"), ("[q] Quit", "bright_red"), (" | ", "white dim"), ("[h] Help", "white"))
        self.layout["footer"].update(text)

    def update_separators(self):
        # Separators removed for cleaner design
        pass

    def render(self) -> Layout:
        self.update_header1()
        self.update_header2()
        self.update_payload_section()
        self.update_tasks_section()
        self.update_log_section()
        self.update_findings_section()
        self.update_footer()
        return self.layout

    def __rich__(self) -> Layout:
        return self.render()

    def log(self, message: str, level: str = "INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append((timestamp, level, message))
        
    def add_finding(self, finding_type: str, details: str, severity: str = "INFO"):
        with self._lock:
            self.findings.append((finding_type, details, severity))

    def update_task(self, task_id: str, name: str = None, status: str = None, payload: str = None):
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
        with self._lock: self.target = target

    def set_phase(self, phase: str):
        with self._lock: self.phase = phase
        
    def set_status(self, status: str, progress: str = None):
        with self._lock:
            self.status_msg = status
            if progress:
                self.progress_msg = progress
    
    def set_current_payload(self, payload: str, vector: str = "", status: str = "Testing", agent: str = ""):
        with self._lock:
            self.current_payload = payload
            self.current_vector = vector
            self.current_payload_status = status
            self.current_agent = agent

    def save_report(self):
        """Generates a simple Markdown report of findings."""
        from bugtrace.core.config import settings
        from pathlib import Path
        
        report_dir = Path(settings.REPORT_DIR)
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        content = f"# BugTraceAI V4 - Final Scan Report\n"
        content += f"**Date:** {datetime.now()}\n"
        content += f"**Target:** {self.target}\n\n"
        content += f"## Executive Summary\n"
        content += f"- Total Findings: {len(self.findings)}\n\n"
        
        content += "## Detailed Findings\n"
        for f_type, details, severity in self.findings:
            icon = "🚨" if severity == "CRITICAL" else ("🔴" if severity == "HIGH" else "⚪")
            content += f"### {icon} {severity} - {f_type}\n"
            content += f"- **Details:** {details}\n\n"
            
        with open(report_path, "w") as f:
            f.write(content)
            
        return str(report_path)


# Global singleton
dashboard = Dashboard()
