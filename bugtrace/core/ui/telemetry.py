"""Passive scan telemetry shared by agents, the API and the TUI runner.

Importing this module creates no threads, renders no screen and never reads or
changes the terminal. Textual owns interactive terminal input and rendering.
"""
from collections import deque
from datetime import datetime
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple


class DashboardHandler(logging.Handler):
    """Compatibility logging sink for the passive telemetry model."""

    def __init__(self, dashboard):
        super().__init__()
        self.dashboard = dashboard

    def emit(self, record):
        try:
            self.dashboard.log(self.format(record), record.levelname)
        except Exception:
            self.handleError(record)


class ScanTelemetry:
    """Bounded logs, findings, metrics and cooperative scan control flags."""

    def __init__(self):
        self._lock = threading.RLock()
        self._init_state()

    def _init_state(self):
        """Initialize scan telemetry."""
        self.target: str = "Waiting for target..."
        self.phase: str = "INITIALIZING"
        self.status_msg: str = "Starting..."
        self.progress_msg: str = "Ready"
        self.logs: List[Tuple[str, str, str]] = []
        self.findings: List[Tuple[str, str, str, str, str]] = []  # type, details, severity, time, status
        self.active_tasks: Dict[str, Dict] = {}
        self.start_time = datetime.now()

        # Cost tracking
        self.credits: float = 0.0
        self.total_requests: int = 0
        self.session_cost: float = 0.0

        # Control flags
        self.paused: bool = False
        self.stop_requested: bool = False

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
        self._rate_window = deque()  # monotonic timestamps in the rate window
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

        # Specialist telemetry metrics (shared by the TUI and API)
        # Format: { 'sqli': {'queue': 0, 'processed': 0, 'vulns': 0, 'status': 'IDLE'} }
        self.specialist_metrics: Dict[str, Dict] = {}

    def reset(self):
        """Clear per-scan state while preserving the configured target and balance."""
        with self._lock:
            target, credits = self.target, self.credits
            self._init_state()
            self.target, self.credits = target, credits

    def reset_controls(self):
        """Clear stale stop/pause flags without discarding the current scan data."""
        with self._lock:
            self.stop_requested = False
            self.paused = False

    def log(self, message: str, level: str = "INFO"):
        """Keep the latest 500 messages, including errors during log bursts."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        with self._lock:
            self.logs.append((timestamp, level, message))
            if len(self.logs) > 500:
                del self.logs[:-500]

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
            now = time.monotonic()
            self._rate_window.append(now)
            cutoff = now - self._rate_window_seconds
            while self._rate_window and self._rate_window[0] <= cutoff:
                self._rate_window.popleft()
            self.payload_rate = len(self._rate_window) / self._rate_window_seconds
            if self.payload_rate > self.payload_peak_rate:
                self.payload_peak_rate = self.payload_rate

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
        Update specialist telemetry metrics for the TUI and API.

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



# Preserve the historical agent-facing names without retaining a renderer.
Dashboard = ScanTelemetry
dashboard = ScanTelemetry()
