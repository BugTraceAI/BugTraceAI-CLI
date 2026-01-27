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


class ScanService:
    """
    Manages scan lifecycle with asyncio-based concurrent execution.

    Key responsibilities:
    - Create and start scans with create_scan()
    - Enforce concurrent scan limit (default 5)
    - Track active scans in memory
    - Provide status queries for active and completed scans
    - Stop running scans gracefully
    - List paginated scan history

    CRITICAL: Uses asyncio.create_task (NOT threading.Thread) to avoid event loop conflicts.
    """

    def __init__(self, max_concurrent: int = 5):
        """
        Initialize ScanService.

        Args:
            max_concurrent: Maximum number of concurrent scans (default 5)
        """
        self.db = get_db_manager()
        self.event_bus = service_event_bus
        self.max_concurrent = max_concurrent

        # Active scans: {scan_id: ScanContext}
        self._active_scans: Dict[int, ScanContext] = {}

        # Concurrency control primitives
        self._lock = asyncio.Lock()  # Protects _active_scans dict
        self._semaphore = asyncio.Semaphore(max_concurrent)  # Limits concurrent executions

        logger.info(f"ScanService initialized (max_concurrent={max_concurrent})")

    async def create_scan(self, options: ScanOptions) -> int:
        """
        Create and start a new scan.

        Args:
            options: Scan configuration (target_url, scan_type, etc.)

        Returns:
            scan_id: Database ID for tracking this scan

        Process:
            1. Check if at concurrent limit (raise error if so)
            2. Create database scan record
            3. Create ScanContext with frozen settings
            4. Launch background task via asyncio.create_task
            5. Emit scan.created event

        Raises:
            RuntimeError: If max concurrent scans already running
        """
        async with self._lock:
            # Check concurrent limit
            if len(self._active_scans) >= self.max_concurrent:
                raise RuntimeError(
                    f"Maximum concurrent scans ({self.max_concurrent}) already running. "
                    f"Wait for a scan to complete or stop one."
                )

            # Create database scan record
            scan_id = self.db.create_new_scan(options.target_url)
            logger.info(f"Created scan {scan_id} for target: {options.target_url}")

            # Create scan context
            ctx = ScanContext(scan_id, options, self.event_bus)
            ctx.freeze_settings()  # Capture immutable settings snapshot

            # Add to active scans before starting task
            self._active_scans[scan_id] = ctx

            # Start scan in background task
            task = asyncio.create_task(self._run_scan(ctx))
            ctx._task = task

            # Emit event
            await self.event_bus.emit("scan.created", {
                "scan_id": scan_id,
                "target": options.target_url,
                "scan_type": options.scan_type,
            })

            logger.info(f"Scan {scan_id} task started (active: {len(self._active_scans)})")

            return scan_id

    async def _run_scan(self, ctx: ScanContext):
        """
        Background task to execute a scan.

        Args:
            ctx: ScanContext for this scan

        Process:
            1. Acquire semaphore (enforces concurrent limit)
            2. Update status to RUNNING
            3. Compute output_dir from settings.REPORT_DIR
            4. Create TeamOrchestrator with ctx settings
            5. Monkey-patch orchestrator._stop_event to ctx.stop_event
            6. Execute orchestrator.start()
            7. Handle completion/errors
            8. Cleanup: release semaphore, remove from active_scans

        CRITICAL: Uses asyncio.Semaphore to enforce max_concurrent limit.
        CRITICAL: Does NOT mutate global settings singleton.
        """
        scan_id = ctx.scan_id

        try:
            # Acquire semaphore - blocks if at concurrent limit
            async with self._semaphore:
                logger.info(f"Scan {scan_id} acquired semaphore, starting execution")

                # Update status
                ctx.status = "running"
                ctx.phase = "INIT"
                self.db.update_scan_status(scan_id, ScanStatus.RUNNING)

                await self.event_bus.emit("scan.started", {
                    "scan_id": scan_id,
                    "target": ctx.options.target_url,
                })

                # Compute output directory (pattern: {REPORT_DIR}/{domain}_{timestamp})
                domain = urlparse(ctx.options.target_url).netloc.replace(":", "_")
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                output_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
                output_dir.mkdir(parents=True, exist_ok=True)

                # Create TeamOrchestrator using settings from context snapshot
                from bugtrace.core.team import TeamOrchestrator

                orchestrator = TeamOrchestrator(
                    target=ctx.options.target_url,
                    resume=ctx.options.resume,
                    max_depth=ctx.options.max_depth,
                    max_urls=ctx.options.max_urls,
                    use_vertical_agents=ctx.options.use_vertical,
                    output_dir=output_dir,
                )

                # CRITICAL: Monkey-patch orchestrator's stop_event to use our context's stop_event
                # This ensures stop_scan() can signal the orchestrator
                orchestrator._stop_event = ctx.stop_event
                orchestrator.scan_id = scan_id  # Already set by TeamOrchestrator.__init__ but be explicit

                # Execute scan (blocks until complete or stopped)
                logger.info(f"Scan {scan_id} starting TeamOrchestrator")
                await orchestrator.start()

                # Scan completed successfully
                ctx.status = "completed"
                ctx.progress = 100
                self.db.update_scan_status(scan_id, ScanStatus.COMPLETED)

                await self.event_bus.emit("scan.completed", {
                    "scan_id": scan_id,
                    "target": ctx.options.target_url,
                    "findings_count": ctx.findings_count,
                })

                logger.success(f"Scan {scan_id} completed successfully")

        except asyncio.CancelledError:
            # Task was cancelled (stop_scan called)
            ctx.status = "stopped"
            self.db.update_scan_status(scan_id, ScanStatus.STOPPED)

            await self.event_bus.emit("scan.stopped", {
                "scan_id": scan_id,
                "target": ctx.options.target_url,
            })

            logger.warning(f"Scan {scan_id} was cancelled")
            raise  # Re-raise to properly cancel the task

        except Exception as e:
            # Scan failed with error
            ctx.status = "failed"
            self.db.update_scan_status(scan_id, ScanStatus.FAILED)

            await self.event_bus.emit("scan.failed", {
                "scan_id": scan_id,
                "target": ctx.options.target_url,
                "error": str(e),
            })

            logger.error(f"Scan {scan_id} failed: {e}")

        finally:
            # Cleanup: remove from active scans
            async with self._lock:
                if scan_id in self._active_scans:
                    del self._active_scans[scan_id]
                    logger.info(f"Scan {scan_id} removed from active scans (remaining: {len(self._active_scans)})")

    async def get_scan_status(self, scan_id: int) -> Dict[str, Any]:
        """
        Get status for a scan (active or completed).

        Args:
            scan_id: Scan ID to query

        Returns:
            Dictionary with scan_id, target, status, progress, findings_count, etc.

        Process:
            - If scan is active: return from ScanContext
            - If scan is completed: query database
        """
        # Check if scan is active
        async with self._lock:
            if scan_id in self._active_scans:
                ctx = self._active_scans[scan_id]
                return ctx.to_status_dict()

        # Query database for completed/stopped/failed scans
        with self.db.get_session() as session:
            from sqlmodel import select
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            statement = select(ScanTable).where(ScanTable.id == scan_id)
            scan = session.exec(statement).first()

            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            # Get target info
            target = session.get(TargetTable, scan.target_id)

            # Count findings
            from bugtrace.schemas.db_models import FindingTable
            findings_statement = select(FindingTable).where(FindingTable.scan_id == scan_id)
            findings = session.exec(findings_statement).all()

            return {
                "scan_id": scan_id,
                "target": target.url if target else "unknown",
                "status": scan.status.value,
                "progress": scan.progress_percent,
                "uptime_seconds": None,  # No longer running
                "findings_count": len(findings),
                "active_agent": None,
                "phase": None,
            }

    async def stop_scan(self, scan_id: int) -> Dict[str, Any]:
        """
        Stop a running scan gracefully.

        Args:
            scan_id: Scan ID to stop

        Returns:
            Dictionary with scan_id, status, message

        Process:
            1. Check if scan is active
            2. Set stop_event (orchestrator checks this)
            3. Cancel the task
            4. Return status

        Raises:
            ValueError: If scan is not active
        """
        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not currently running")

            ctx = self._active_scans[scan_id]

            # Request stop
            ctx.request_stop()

            # Cancel the task
            if ctx._task and not ctx._task.done():
                ctx._task.cancel()

            logger.info(f"Scan {scan_id} stop requested")

            return {
                "scan_id": scan_id,
                "status": "stopping",
                "message": "Stop signal sent to scan",
            }

    async def list_scans(
        self,
        page: int = 1,
        per_page: int = 20,
        status_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List scans with pagination.

        Args:
            page: Page number (1-indexed)
            per_page: Results per page
            status_filter: Optional status filter (RUNNING, COMPLETED, STOPPED, FAILED)

        Returns:
            Dictionary with scans, total, page, per_page
        """
        offset = (page - 1) * per_page

        with self.db.get_session() as session:
            from sqlmodel import select, func
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            # Build query
            statement = select(ScanTable).order_by(ScanTable.id.desc())

            if status_filter:
                statement = statement.where(ScanTable.status == ScanStatus[status_filter.upper()])

            # Count total
            count_statement = select(func.count()).select_from(ScanTable)
            if status_filter:
                count_statement = count_statement.where(ScanTable.status == ScanStatus[status_filter.upper()])
            total = session.exec(count_statement).one()

            # Paginate
            statement = statement.offset(offset).limit(per_page)
            scans = session.exec(statement).all()

            # Format results
            results = []
            for scan in scans:
                target = session.get(TargetTable, scan.target_id)
                results.append({
                    "scan_id": scan.id,
                    "target": target.url if target else "unknown",
                    "status": scan.status.value,
                    "progress": scan.progress_percent,
                    "timestamp": scan.timestamp.isoformat(),
                })

            return {
                "scans": results,
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    async def get_findings(
        self,
        scan_id: int,
        severity: Optional[str] = None,
        vuln_type: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> Dict[str, Any]:
        """
        Get findings for a scan with filtering and pagination.

        Args:
            scan_id: Scan ID to get findings for
            severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            vuln_type: Optional vulnerability type filter (XSS, SQLi, etc.)
            page: Page number (1-indexed)
            per_page: Results per page

        Returns:
            Dictionary with findings, total, page, per_page
        """
        offset = (page - 1) * per_page

        with self.db.get_session() as session:
            from sqlmodel import select, func
            from bugtrace.schemas.db_models import FindingTable

            # Build query
            statement = select(FindingTable).where(FindingTable.scan_id == scan_id)

            if severity:
                statement = statement.where(FindingTable.severity == severity.upper())

            if vuln_type:
                statement = statement.where(FindingTable.type == vuln_type.upper())

            # Count total
            count_statement = select(func.count()).select_from(FindingTable).where(
                FindingTable.scan_id == scan_id
            )
            if severity:
                count_statement = count_statement.where(FindingTable.severity == severity.upper())
            if vuln_type:
                count_statement = count_statement.where(FindingTable.type == vuln_type.upper())

            total = session.exec(count_statement).one()

            # Paginate
            statement = statement.offset(offset).limit(per_page)
            findings = session.exec(statement).all()

            # Format results
            results = []
            for finding in findings:
                results.append({
                    "finding_id": finding.id,
                    "type": finding.type.value if hasattr(finding.type, 'value') else str(finding.type),
                    "severity": finding.severity,
                    "details": finding.details,
                    "payload": finding.payload_used,
                    "url": finding.attack_url,
                    "parameter": finding.vuln_parameter,
                    "validated": finding.visual_validated,
                    "status": finding.status.value,
                    "confidence": finding.confidence_score,
                })

            return {
                "findings": results,
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    @property
    def active_scan_count(self) -> int:
        """Get count of currently running scans."""
        return len(self._active_scans)

    def get_active_scan_ids(self) -> List[int]:
        """Get list of active scan IDs."""
        return list(self._active_scans.keys())
