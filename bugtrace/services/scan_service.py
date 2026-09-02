"""
Scan Service - Scan lifecycle management with asyncio-based concurrency.

Wraps TeamOrchestrator with concurrent scan management, enforces scan limits,
and provides status/stop/list operations. This is the core service that CLI,
API, and MCP will all invoke.

Solves:
- SVC-01: Shared ScanService for all interfaces
- INF-02: SQLite pooling via existing DatabaseManager
- INF-03: Concurrent scan limit enforcement

Author: BugtraceAI Team
Date: 2026-01-27
Version: 2.0.0
"""

import asyncio
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse

from bugtrace.services.scan_context import ScanContext, ScanOptions
from bugtrace.services.event_bus import service_event_bus
from bugtrace.core.database import get_db_manager
from bugtrace.schemas.db_models import ScanStatus, FindingStatus
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger

logger = get_logger("services.scan_service")


from bugtrace.services.scan_shell.lifecycle_flow import ScanLifecycleMixin
from bugtrace.services.scan_shell.misc_flow import ScanMiscMixin
from bugtrace.services.scan_shell.orchestrate_flow import ScanOrchestrateMixin
from bugtrace.services.scan_shell.auth_flow import ScanAuthMixin
from bugtrace.services.scan_shell.report_flow import ScanReportMixin

class ScanService(ScanLifecycleMixin, ScanMiscMixin, ScanOrchestrateMixin, ScanAuthMixin, ScanReportMixin):
    """
    Manages scan lifecycle with asyncio-based concurrent execution.

    Key responsibilities:
    - Create and start scans with create_scan()
    - Enforce concurrent scan limit (default 1)
    - Track active scans in memory
    - Provide status queries for active and completed scans
    - Stop running scans gracefully
    - List paginated scan history

    CRITICAL: Uses asyncio.create_task (NOT threading.Thread) to avoid event loop conflicts.
    """

    EVENT_HISTORY_CLEANUP_GRACE_SECONDS = 3600.0
    REPEATER_REFRESH_MARKER = ".repeater-refresh-pending.json"

    def __init__(self, max_concurrent: int = 1):
        """
        Initialize ScanService.

        Args:
            max_concurrent: Maximum number of concurrent scans (default 1)
        """
        from bugtrace.core.lifecycle_policy import normalize_max_concurrent

        self.db = get_db_manager()
        self.event_bus = service_event_bus
        self.max_concurrent = normalize_max_concurrent(max_concurrent)

        # Active scans: {scan_id: ScanContext}
        self._active_scans: Dict[int, ScanContext] = {}

        # Concurrency control primitives
        self._lock = asyncio.Lock()  # Protects _active_scans dict
        self._semaphore = asyncio.Semaphore(self.max_concurrent)  # Limits concurrent executions
        self._repeater_persistence_lock = asyncio.Lock()
        self._repeater_report_refresh_tasks: Dict[str, asyncio.Task] = {}

        logger.info(f"ScanService initialized (max_concurrent={self.max_concurrent})")
