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


class ScanService:
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

    def __init__(self, max_concurrent: int = 1):
        """
        Initialize ScanService.

        Args:
            max_concurrent: Maximum number of concurrent scans (default 1)
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

    async def create_scan(self, options: ScanOptions, origin: str = "cli") -> int:
        """
        Create and start a new scan.

        Args:
            options: Scan configuration (target_url, scan_type, etc.)
            origin: Where the scan was launched from ('cli' or 'web')

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
            scan_id = self.db.create_new_scan(options.target_url, origin=origin)
            logger.info(f"Created scan {scan_id} for target: {options.target_url} (origin={origin})")

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
                "origin": getattr(scan, "origin", "cli"),
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
                    "origin": getattr(scan, "origin", "cli"),
                })

            return {
                "scans": results,
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    async def delete_scan(self, scan_id: int, force: bool = False) -> Dict[str, Any]:
        """
        Delete a scan and its associated findings from the database,
        and remove report files from disk.

        Args:
            scan_id: Scan ID to delete
            force: If True, bypass origin check (used by CLI delete command)

        Returns:
            Dictionary with scan_id and message

        Raises:
            ValueError: If scan not found or is currently running
            PermissionError: If scan origin is 'cli' and force=False (web cannot delete CLI scans)
        """
        with self.db.get_session() as session:
            from sqlmodel import select
            from bugtrace.schemas.db_models import ScanTable, FindingTable, ScanStateTable, TargetTable

            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

            if scan.status == ScanStatus.RUNNING:
                raise ValueError(f"Cannot delete scan {scan_id}: scan is still running")

            # Origin check: web UI cannot delete CLI-originated scans
            scan_origin = getattr(scan, "origin", "cli")
            if scan_origin == "cli" and not force:
                raise PermissionError(
                    f"Cannot delete scan {scan_id} from web: scan was launched from CLI. "
                    f"Use 'bugtrace delete {scan_id}' from the command line."
                )

            # Resolve target URL and timestamp for report directory cleanup
            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else None
            scan_timestamp = scan.timestamp

            # Delete associated findings first (FK constraint)
            findings = session.exec(
                select(FindingTable).where(FindingTable.scan_id == scan_id)
            ).all()
            for finding in findings:
                session.delete(finding)

            # Delete associated scan state (FK constraint)
            scan_states = session.exec(
                select(ScanStateTable).where(ScanStateTable.scan_id == scan_id)
            ).all()
            for state in scan_states:
                session.delete(state)

            # Delete the scan
            session.delete(scan)
            session.commit()

            logger.info(f"Deleted scan {scan_id} with {len(findings)} findings")

        # Delete report files from disk (outside DB session)
        deleted_dirs = self._delete_report_dirs(scan_id, target_url, scan_timestamp)

        parts = [f"Scan {scan_id} deleted ({len(findings)} findings removed)"]
        if deleted_dirs:
            parts.append(f"{len(deleted_dirs)} report folder(s) removed")

        return {
            "scan_id": scan_id,
            "message": ", ".join(parts),
        }

    def _delete_report_dirs(
        self,
        scan_id: int,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime] = None,
    ) -> List[Path]:
        """
        Find and delete report directories associated with a scan.

        Searches two patterns:
        1. scan_{scan_id}/ (created by ReportService API)
        2. {domain}_{YYYYMMDD}_{HHMMSS}/ (created by scan pipeline)

        Uses the scan's timestamp to precisely match the pipeline directory
        and avoid deleting reports from other scans of the same target.

        Args:
            scan_id: Scan ID
            target_url: Target URL for domain extraction
            scan_timestamp: Scan creation timestamp for precise directory matching

        Returns:
            List of deleted directory paths
        """
        report_base = settings.REPORT_DIR
        deleted = []

        # Pattern 1: API-generated reports (scan_{id}/)
        api_dir = report_base / f"scan_{scan_id}"
        if api_dir.is_dir():
            try:
                shutil.rmtree(api_dir)
                deleted.append(api_dir)
                logger.info(f"Deleted report directory: {api_dir}")
            except OSError as e:
                logger.warning(f"Failed to delete report directory {api_dir}: {e}")

        # Pattern 2: Pipeline-generated reports ({domain}_{timestamp}/)
        if target_url:
            try:
                hostname = urlparse(target_url).hostname or ""
                if hostname:
                    if scan_timestamp:
                        # Precise match: {domain}_{YYYYMMDD}_{HHMMSS}
                        ts_prefix = scan_timestamp.strftime("%Y%m%d_%H%M")
                        for match in report_base.glob(f"{hostname}_{ts_prefix}*"):
                            if match.is_dir():
                                try:
                                    shutil.rmtree(match)
                                    deleted.append(match)
                                    logger.info(f"Deleted report directory: {match}")
                                except OSError as e:
                                    logger.warning(f"Failed to delete report directory {match}: {e}")
                    else:
                        # Fallback: match all dirs for this domain (less precise)
                        for match in report_base.glob(f"{hostname}_*"):
                            if match.is_dir():
                                try:
                                    shutil.rmtree(match)
                                    deleted.append(match)
                                    logger.info(f"Deleted report directory: {match}")
                                except OSError as e:
                                    logger.warning(f"Failed to delete report directory {match}: {e}")
            except Exception as e:
                logger.warning(f"Error finding report dirs for {target_url}: {e}")

        return deleted

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
