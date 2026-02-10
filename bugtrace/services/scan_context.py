"""
Scan Context - Per-scan isolated state container.

Solves the critical state isolation blocker (INF-02) by providing each concurrent
scan with its own frozen settings snapshot, stop event, and status tracking.

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel


class ScanOptions(BaseModel):
    """
    Options for a scan request.

    These options define what the scan should do and how it should behave.
    They are immutable once the scan starts.
    """
    target_url: str
    scan_type: str = "full"  # full, hunter, manager, or focused agent names
    safe_mode: Optional[bool] = None  # override global setting
    max_depth: int = 2
    max_urls: int = 20
    resume: bool = False
    use_vertical: bool = True
    focused_agents: List[str] = []  # for --xss, --sqli etc.
    param: Optional[str] = None  # for focused mode parameter targeting


class ScanContext:
    """
    Per-scan isolated state container.

    Each concurrent scan gets its own ScanContext instance with:
    - Immutable settings snapshot (no global singleton mutation)
    - Per-scan stop event (not shared across scans)
    - Isolated findings buffer and progress tracking
    - Reference to the running asyncio task

    This solves INF-02 (state isolation) by ensuring scans never share mutable state.
    """

    def __init__(self, scan_id: int, options: ScanOptions, event_bus):
        """
        Initialize a new scan context.

        Args:
            scan_id: Database scan ID
            options: Scan configuration
            event_bus: Event bus instance for scan-scoped events
        """
        self.scan_id = scan_id
        self.options = options
        self.event_bus = event_bus

        # Status tracking
        self.status: str = "initializing"  # maps to ScanStatus enum values
        self.progress: int = 0
        self.start_time = datetime.utcnow()

        # Per-scan isolation primitives
        self.stop_event = asyncio.Event()  # asyncio.Event for single-loop safety (INF-01)
        self._resume_event = asyncio.Event()  # Cleared when paused, set when running
        self._resume_event.set()  # Start in "not paused" state
        self.settings_snapshot: Dict[str, Any] = {}  # frozen copy at scan start

        # Findings tracking
        self.findings_count: int = 0

        # Agent tracking
        self.active_agent: str = "System"
        self.phase: str = "BOOT"

        # Task reference
        self._task: Optional[asyncio.Task] = None

    def freeze_settings(self) -> "ScanContext":
        """
        Capture an immutable snapshot of current global settings.

        This prevents the scan from being affected by settings changes during execution.
        Solves INF-02 by ensuring each scan has isolated configuration.

        Returns:
            self for method chaining
        """
        from bugtrace.core.config import settings
        self.settings_snapshot = settings.model_dump()
        return self

    def request_stop(self):
        """
        Request the scan to stop gracefully.

        Sets the stop_event that the scan loop should check periodically.
        Updates status to "stopping" to indicate shutdown is in progress.
        """
        self.stop_event.set()
        self._resume_event.set()  # Unblock if paused so it can stop
        self.status = "stopping"

    def request_pause(self):
        """Pause the scan. Pipeline will block at next checkpoint."""
        self._resume_event.clear()
        self.status = "paused"

    def request_resume(self):
        """Resume a paused scan."""
        self._resume_event.set()
        self.status = "running"

    async def wait_if_paused(self):
        """Call at pipeline checkpoints. Blocks until resumed if paused."""
        await self._resume_event.wait()

    @property
    def is_paused(self) -> bool:
        return self.status == "paused"

    @property
    def is_running(self) -> bool:
        """Check if scan is in an active state."""
        return self.status in ("initializing", "running", "paused")

    @property
    def uptime_seconds(self) -> float:
        """Calculate scan uptime in seconds."""
        return (datetime.utcnow() - self.start_time).total_seconds()

    def to_status_dict(self) -> Dict[str, Any]:
        """
        Export scan status as a dictionary.

        Used for API responses and WebSocket status broadcasts.

        Returns:
            Dictionary with scan_id, target, status, progress, uptime, etc.
        """
        return {
            "scan_id": self.scan_id,
            "target": self.options.target_url,
            "status": self.status.upper(),
            "progress": self.progress,
            "uptime_seconds": self.uptime_seconds,
            "findings_count": self.findings_count,
            "active_agent": self.active_agent,
            "phase": self.phase,
        }
