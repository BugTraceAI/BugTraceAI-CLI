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

    async def create_scan(self, options: ScanOptions, origin: str = "unknown") -> int:
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
            self._check_concurrent_limit()

            try:
                scan_id = self._create_scan_record(options, origin)
            except Exception as e:
                logger.error(f"Failed to create scan record: {e}", exc_info=True)
                raise RuntimeError(f"Failed to create scan in database: {e}")

            try:
                ctx = self._build_scan_context(scan_id, options)
                self._active_scans[scan_id] = ctx

                await self._emit_scan_created_event(scan_id, options)
                ctx._task = asyncio.create_task(self._run_scan(ctx))
                logger.info(f"Scan {scan_id} task started (active: {len(self._active_scans)})")
            except Exception as e:
                logger.error(f"Scan {scan_id} created in DB but failed to start: {e}", exc_info=True)
                self._active_scans.pop(scan_id, None)
                self.db.update_scan_progress(scan_id, 0, ScanStatus.FAILED)
                raise

            return scan_id

    def _check_concurrent_limit(self):
        """Check if at concurrent scan limit."""
        if len(self._active_scans) >= self.max_concurrent:
            raise RuntimeError(
                f"Maximum concurrent scans ({self.max_concurrent}) already running. "
                f"Wait for a scan to complete or stop one."
            )

    def _create_scan_record(self, options: ScanOptions, origin: str) -> int:
        """Create database scan record."""
        scan_id = self.db.create_new_scan(options.target_url, origin=origin)
        logger.info(f"Created scan {scan_id} for target: {options.target_url} (origin={origin})")
        return scan_id

    def _build_scan_context(self, scan_id: int, options: ScanOptions) -> ScanContext:
        """Build and freeze scan context."""
        ctx = ScanContext(scan_id, options, self.event_bus)
        ctx.freeze_settings()
        return ctx

    async def _emit_scan_created_event(self, scan_id: int, options: ScanOptions):
        """Emit scan.created event."""
        await self.event_bus.emit("scan.created", {
            "scan_id": scan_id,
            "target": options.target_url,
            "scan_type": options.scan_type,
        })

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
            async with self._semaphore:
                await self._execute_scan(ctx)
        except asyncio.CancelledError:
            await self._handle_scan_cancellation(ctx)
            raise
        except Exception as e:
            await self._handle_scan_failure(ctx, e)
        finally:
            await self._cleanup_scan(scan_id)

    async def _execute_scan(self, ctx: ScanContext):
        """Execute scan with orchestrator."""
        scan_id = ctx.scan_id
        logger.info(f"Scan {scan_id} acquired semaphore, starting execution")

        # Update status
        ctx.status = "running"
        ctx.phase = "INIT"
        self.db.update_scan_status(scan_id, ScanStatus.RUNNING)

        await self.event_bus.emit("scan.started", {
            "scan_id": scan_id,
            "target": ctx.options.target_url,
        })

        # Compute output directory
        output_dir = self._compute_output_dir(ctx.options.target_url)

        # Create and configure orchestrator
        orchestrator = self._create_orchestrator(ctx, output_dir)

        # Execute scan
        logger.info(f"Scan {scan_id} starting TeamOrchestrator")
        await orchestrator.start()

        # Mark as completed
        await self._mark_scan_completed(ctx)

    def _compute_output_dir(self, target_url: str) -> Path:
        """Compute output directory for scan reports."""
        domain = urlparse(target_url).netloc.replace(":", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        output_dir = settings.REPORT_DIR / f"{domain}_{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _create_orchestrator(self, ctx: ScanContext, output_dir: Path):
        """Create and configure TeamOrchestrator."""
        from bugtrace.core.team import TeamOrchestrator

        orchestrator = TeamOrchestrator(
            target=ctx.options.target_url,
            resume=ctx.options.resume,
            max_depth=ctx.options.max_depth,
            max_urls=ctx.options.max_urls,
            use_vertical_agents=ctx.options.use_vertical,
            output_dir=output_dir,
            scan_id=ctx.scan_id,  # Pass existing scan_id to avoid duplicate creation
            scan_depth=ctx.options.scan_depth or settings.SCAN_DEPTH,
        )

        # CRITICAL: Monkey-patch stop_event for graceful shutdown
        orchestrator._stop_event = ctx.stop_event
        # Pause support: orchestrator checks this at phase boundaries
        orchestrator._scan_context = ctx

        return orchestrator

    async def _mark_scan_completed(self, ctx: ScanContext):
        """Mark scan as completed with success event."""
        ctx.status = "completed"
        ctx.progress = 100
        self.db.update_scan_status(ctx.scan_id, ScanStatus.COMPLETED)

        await self.event_bus.emit("scan.completed", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
            "findings_count": ctx.findings_count,
        })

        logger.info(f"Scan {ctx.scan_id} completed successfully")

    async def _handle_scan_cancellation(self, ctx: ScanContext):
        """Handle scan cancellation."""
        ctx.status = "stopped"
        self.db.update_scan_status(ctx.scan_id, ScanStatus.STOPPED)

        await self.event_bus.emit("scan.stopped", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
        })

        logger.warning(f"Scan {ctx.scan_id} was cancelled")

    async def _handle_scan_failure(self, ctx: ScanContext, error: Exception):
        """Handle scan failure."""
        ctx.status = "failed"
        self.db.update_scan_status(ctx.scan_id, ScanStatus.FAILED)

        await self.event_bus.emit("scan.failed", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
            "error": str(error),
        })

        logger.error(f"Scan {ctx.scan_id} failed: {error}")

    async def _cleanup_scan(self, scan_id: int):
        """Remove scan from active scans."""
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
                "enrichment_status": getattr(scan, "enrichment_status", None),
            }

    async def stop_scan(self, scan_id: int) -> Dict[str, Any]:
        """Stop a running or paused scan gracefully."""
        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not currently running")

            ctx = self._active_scans[scan_id]
            ctx.request_stop()

            if ctx._task and not ctx._task.done():
                ctx._task.cancel()

            logger.info(f"Scan {scan_id} stop requested")

            return {
                "scan_id": scan_id,
                "status": "stopping",
                "message": "Stop signal sent to scan",
            }

    async def pause_scan(self, scan_id: int) -> Dict[str, Any]:
        """Pause a running scan. Pipeline blocks at next checkpoint."""
        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not currently running")

            ctx = self._active_scans[scan_id]
            if ctx.status != "running":
                raise ValueError(f"Scan {scan_id} is not running (status: {ctx.status})")

            ctx.request_pause()
            self.db.update_scan_status(scan_id, ScanStatus.PAUSED)

            await self.event_bus.emit("scan.paused", {
                "scan_id": scan_id,
                "target": ctx.options.target_url,
            })

            logger.info(f"Scan {scan_id} paused")

            return {
                "scan_id": scan_id,
                "status": "paused",
                "message": "Scan paused",
            }

    async def resume_scan(self, scan_id: int) -> Dict[str, Any]:
        """Resume a paused scan."""
        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not active")

            ctx = self._active_scans[scan_id]
            if ctx.status != "paused":
                raise ValueError(f"Scan {scan_id} is not paused (status: {ctx.status})")

            ctx.request_resume()
            self.db.update_scan_status(scan_id, ScanStatus.RUNNING)

            await self.event_bus.emit("scan.resumed", {
                "scan_id": scan_id,
                "target": ctx.options.target_url,
            })

            logger.info(f"Scan {scan_id} resumed")

            return {
                "scan_id": scan_id,
                "status": "running",
                "message": "Scan resumed",
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

            statement = self._build_scans_query(status_filter)
            total = self._count_scans(session, status_filter, func)
            scans = session.exec(statement.offset(offset).limit(per_page)).all()
            results = self._format_scan_results(session, scans)

            return {
                "scans": results,
                "total": total,
                "page": page,
                "per_page": per_page,
            }

    def _build_scans_query(self, status_filter: Optional[str]):
        """Build scans query with optional status filter and eager-loaded target."""
        from sqlmodel import select
        from sqlalchemy.orm import selectinload
        from bugtrace.schemas.db_models import ScanTable

        # Use selectinload to prevent N+1 queries when accessing scan.target
        statement = (
            select(ScanTable)
            .options(selectinload(ScanTable.target))
            .order_by(ScanTable.id.desc())
        )
        if status_filter:
            statement = statement.where(ScanTable.status == ScanStatus[status_filter.upper()])
        return statement

    def _count_scans(self, session, status_filter: Optional[str], func) -> int:
        """Count total scans matching filter."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanTable

        count_statement = select(func.count()).select_from(ScanTable)
        if status_filter:
            count_statement = count_statement.where(ScanTable.status == ScanStatus[status_filter.upper()])
        return session.exec(count_statement).one()

    def _format_scan_results(self, session, scans) -> List[Dict[str, Any]]:
        """Format scan results with report status.

        Note: Assumes scans were loaded with selectinload(ScanTable.target)
        to prevent N+1 queries.
        """
        report_base = settings.REPORT_DIR
        results = []
        for scan in scans:
            # Use already-loaded relationship (no extra query due to selectinload)
            target_url = scan.target.url if scan.target else None
            has_report = self._has_report_dir(report_base, scan.id, target_url, scan.timestamp)

            results.append({
                "scan_id": scan.id,
                "target": target_url or "unknown",
                "status": scan.status.value,
                "progress": scan.progress_percent,
                "timestamp": scan.timestamp.isoformat(),
                "origin": getattr(scan, "origin", "cli"),
                "enrichment_status": getattr(scan, "enrichment_status", None),
                "has_report": has_report,
            })
        return results

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
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status == ScanStatus.RUNNING:
                raise ValueError(f"Cannot delete scan {scan_id}: scan is still running")

            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else None
            scan_timestamp = scan.timestamp

            findings_count = self._delete_scan_findings(session, scan_id)
            self._delete_scan_states(session, scan_id)

            session.delete(scan)
            session.commit()
            logger.info(f"Deleted scan {scan_id} with {findings_count} findings")

        deleted_dirs = self._delete_report_dirs(scan_id, target_url, scan_timestamp)
        return self._build_delete_response(scan_id, findings_count, deleted_dirs)

    def _delete_scan_findings(self, session, scan_id: int) -> int:
        """Delete all findings associated with a scan."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import FindingTable

        findings = session.exec(select(FindingTable).where(FindingTable.scan_id == scan_id)).all()
        for finding in findings:
            session.delete(finding)
        return len(findings)

    def _delete_scan_states(self, session, scan_id: int):
        """Delete all scan states associated with a scan."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanStateTable

        scan_states = session.exec(select(ScanStateTable).where(ScanStateTable.scan_id == scan_id)).all()
        for state in scan_states:
            session.delete(state)

    def _build_delete_response(self, scan_id: int, findings_count: int, deleted_dirs: List[Path]) -> Dict[str, Any]:
        """Build delete scan response message."""
        parts = [f"Scan {scan_id} deleted ({findings_count} findings removed)"]
        if deleted_dirs:
            parts.append(f"{len(deleted_dirs)} report folder(s) removed")

        return {
            "scan_id": scan_id,
            "message": ", ".join(parts),
            "files_cleaned": len(deleted_dirs) > 0,
        }

    @staticmethod
    def _has_report_dir(
        report_base: Path,
        scan_id: int,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime] = None,
    ) -> bool:
        """Check if a report directory with actual report files exists for this scan."""
        report_files = {"final_report.md", "validated_findings.json", "raw_findings.json"}

        def _has_files(d: Path) -> bool:
            """Check if directory contains at least one known report file."""
            return d.is_dir() and any((d / f).is_file() for f in report_files)

        # Pattern 1: API-generated (scan_{id}/)
        if _has_files(report_base / f"scan_{scan_id}"):
            return True

        # Pattern 2: Pipeline-generated ({domain}_{timestamp}/)
        return ScanService._check_pipeline_report_dir(
            report_base, target_url, scan_timestamp, _has_files
        )

    @staticmethod
    def _check_pipeline_report_dir(
        report_base: Path,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime],
        has_files_check
    ) -> bool:
        """Check for pipeline-generated report directories."""
        if not target_url:
            return False

        hostname = urlparse(target_url).hostname or ""
        if not hostname:
            return False

        return ScanService._check_hostname_reports(
            report_base, hostname, scan_timestamp, has_files_check
        )

    @staticmethod
    def _check_hostname_reports(
        report_base: Path,
        hostname: str,
        scan_timestamp: Optional[datetime],
        has_files_check
    ) -> bool:
        """Check for report directories matching hostname."""
        # Precise match using scan timestamp (minute-level)
        if scan_timestamp:
            ts_prefix = scan_timestamp.strftime("%Y%m%d_%H%M")
            for match in report_base.glob(f"{hostname}_{ts_prefix}*"):
                if has_files_check(match):
                    return True

        # Fallback: any dir for this domain that contains report files
        for match in report_base.glob(f"{hostname}_*"):
            if has_files_check(match):
                return True

        return False

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

        self._delete_api_report_dir(report_base, scan_id, deleted)
        if target_url:
            self._delete_pipeline_report_dirs(report_base, target_url, scan_timestamp, deleted)

        return deleted

    def _delete_api_report_dir(self, report_base: Path, scan_id: int, deleted: List[Path]):
        """Delete API-generated report directory (scan_{id}/)."""
        api_dir = report_base / f"scan_{scan_id}"
        if api_dir.is_dir():
            try:
                shutil.rmtree(api_dir)
                deleted.append(api_dir)
                logger.info(f"Deleted report directory: {api_dir}")
            except OSError as e:
                logger.warning(f"Failed to delete report directory {api_dir}: {e}")

    def _delete_pipeline_report_dirs(
        self,
        report_base: Path,
        target_url: str,
        scan_timestamp: Optional[datetime],
        deleted: List[Path]
    ):
        """Delete pipeline-generated report directories ({domain}_{timestamp}/)."""
        try:
            hostname = urlparse(target_url).hostname or ""
            if not hostname:
                return

            if scan_timestamp:
                self._delete_timestamped_reports(report_base, hostname, scan_timestamp, deleted)
            else:
                self._delete_all_domain_reports(report_base, hostname, deleted)
        except Exception as e:
            logger.warning(f"Error finding report dirs for {target_url}: {e}")

    def _delete_timestamped_reports(
        self,
        report_base: Path,
        hostname: str,
        scan_timestamp: datetime,
        deleted: List[Path]
    ):
        """Delete reports matching precise timestamp."""
        ts_prefix = scan_timestamp.strftime("%Y%m%d_%H%M")
        for match in report_base.glob(f"{hostname}_{ts_prefix}*"):
            if match.is_dir():
                self._try_delete_dir(match, deleted)

    def _delete_all_domain_reports(self, report_base: Path, hostname: str, deleted: List[Path]):
        """Delete all reports for a domain (fallback when no timestamp)."""
        for match in report_base.glob(f"{hostname}_*"):
            if match.is_dir():
                self._try_delete_dir(match, deleted)

    def _try_delete_dir(self, path: Path, deleted: List[Path]):
        """Attempt to delete a directory and track success."""
        try:
            shutil.rmtree(path)
            deleted.append(path)
            logger.info(f"Deleted report directory: {path}")
        except OSError as e:
            logger.warning(f"Failed to delete report directory {path}: {e}")

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

        V3.2: Reads from FILES (source of truth) instead of database.
        Files: specialists/wet/*.json, specialists/dry/*.json, specialists/results/*.json

        Args:
            scan_id: Scan ID to get findings for
            severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            vuln_type: Optional vulnerability type filter (XSS, SQLi, etc.)
            page: Page number (1-indexed)
            per_page: Results per page

        Returns:
            Dictionary with findings, total, page, per_page
        """
        # Verify scan exists before loading findings
        with self.db.get_session() as session:
            from sqlmodel import select
            from bugtrace.schemas.db_models import ScanTable
            scan = session.exec(select(ScanTable).where(ScanTable.id == scan_id)).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")

        # Load all findings from files (source of truth)
        all_findings = self._load_findings_from_files(scan_id)

        # Apply filters
        filtered = self._filter_findings(all_findings, severity, vuln_type)

        # Paginate
        total = len(filtered)
        offset = (page - 1) * per_page
        paginated = filtered[offset:offset + per_page]

        # Format for API response
        results = self._format_file_findings(paginated)

        return {
            "findings": results,
            "total": total,
            "page": page,
            "per_page": per_page,
        }

    def _find_report_dir_for_scan(self, scan_id: int) -> Optional[Path]:
        """
        Find the report directory for a scan_id.

        Searches two patterns:
        1. scan_{id}/ (created by ReportService API)
        2. {domain}_{timestamp}/ (created by scan pipeline)
        """
        report_base = settings.REPORT_DIR

        # Pattern 1: API-generated reports
        api_dir = report_base / f"scan_{scan_id}"
        if api_dir.is_dir():
            return api_dir

        # Pattern 2: Pipeline-generated reports ({domain}_{timestamp})
        try:
            with self.db.get_session() as session:
                from bugtrace.schemas.db_models import ScanTable, TargetTable
                scan = session.get(ScanTable, scan_id)
                if not scan:
                    return None
                target = session.get(TargetTable, scan.target_id)
                if not target:
                    return None

                # Extract domain from URL
                domain = urlparse(target.url).hostname or ""

                # Find matching report directories, sorted newest first
                matches = sorted(
                    report_base.glob(f"{domain}_*"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                if matches:
                    return matches[0]
        except Exception as e:
            logger.warning(f"Error resolving report dir for scan {scan_id}: {e}")

        return None

    def _load_findings_from_files(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Load all findings from files for a scan.

        Reads from (in priority order):
        1. specialists/results/*.json (validated findings)
        2. specialists/dry/*.json (deduplicated findings)
        3. specialists/wet/*.json (raw findings)

        Returns:
            List of finding dictionaries
        """
        import json
        from bugtrace.core.payload_format import decode_finding_payloads

        report_dir = self._find_report_dir_for_scan(scan_id)
        if not report_dir:
            logger.debug(f"No report directory found for scan {scan_id}")
            return []

        specialists_dir = report_dir / "specialists"
        if not specialists_dir.exists():
            logger.debug(f"No specialists dir in {report_dir}")
            return []

        all_findings = []
        finding_id_counter = 1

        # Priority: results > dry > wet
        for subdir in ["results", "dry", "wet"]:
            subdir_path = specialists_dir / subdir
            if not subdir_path.exists():
                continue

            for json_file in subdir_path.glob("*.json"):
                try:
                    findings_from_file = self._read_findings_file(json_file)
                    for finding in findings_from_file:
                        # Decode base64 payloads if present
                        finding = decode_finding_payloads(finding)
                        finding["_source_file"] = str(json_file)
                        finding["_source_dir"] = subdir
                        finding["_id"] = finding_id_counter
                        finding_id_counter += 1
                        all_findings.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to read {json_file}: {e}")

            # If we found findings in results/, don't look in dry/wet
            if all_findings and subdir == "results":
                break
            # If we found findings in dry/, don't look in wet
            if all_findings and subdir == "dry":
                break

        logger.debug(f"Loaded {len(all_findings)} findings from files for scan {scan_id}")
        return all_findings

    def _read_findings_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Read findings from a JSON or JSON Lines file.

        Supports both formats:
        - JSON Lines: One JSON object per line (v3.2 format)
        - JSON Array: Array of finding objects
        """
        import json

        findings = []
        content = file_path.read_text(encoding="utf-8").strip()

        if not content:
            return []

        # Try JSON Lines first (one object per line)
        if content.startswith("{"):
            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    # Handle v3.2 format with nested "finding" key
                    if "finding" in entry:
                        findings.append(entry["finding"])
                    else:
                        findings.append(entry)
                except json.JSONDecodeError:
                    continue
        # Try JSON Array
        elif content.startswith("["):
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    findings = data
            except json.JSONDecodeError:
                pass

        return findings

    def _filter_findings(
        self,
        findings: List[Dict[str, Any]],
        severity: Optional[str],
        vuln_type: Optional[str]
    ) -> List[Dict[str, Any]]:
        """Filter findings by severity and/or vulnerability type."""
        filtered = findings

        if severity:
            sev_upper = severity.upper()
            filtered = [f for f in filtered if f.get("severity", "").upper() == sev_upper]

        if vuln_type:
            type_upper = vuln_type.upper()
            filtered = [
                f for f in filtered
                if type_upper in (f.get("type", "") or "").upper()
            ]

        return filtered

    def _format_file_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Format file-based findings for API response."""
        results = []
        for finding in findings:
            # Determine status: respect finding's own status from specialist,
            # only fall back to directory-based inference if no explicit status
            source_dir = finding.get("_source_dir", "wet")
            explicit_status = finding.get("status")
            if explicit_status and explicit_status not in ("", "PENDING_VALIDATION"):
                status = explicit_status
            elif source_dir == "results":
                status = "VALIDATED_CONFIRMED"
            elif source_dir == "dry":
                status = "PENDING_VALIDATION"
            else:
                status = "PENDING_VALIDATION"

            results.append({
                "finding_id": finding.get("_id", 0),
                "type": finding.get("type", "Unknown"),
                "severity": finding.get("severity", "MEDIUM"),
                "details": finding.get("evidence") or finding.get("description") or finding.get("note", ""),
                "payload": finding.get("payload", ""),
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "validated": status == "VALIDATED_CONFIRMED",
                "status": status,
                "confidence": finding.get("confidence", 0.0),
            })
        return results

    @property
    def active_scan_count(self) -> int:
        """Get count of currently running scans."""
        return len(self._active_scans)

    def get_active_scan_ids(self) -> List[int]:
        """Get list of active scan IDs."""
        return list(self._active_scans.keys())

    def cleanup_orphaned_scans(self) -> int:
        """Mark any RUNNING/PENDING scans as FAILED on startup.

        When the backend restarts, no scans are actually running in-process.
        Any scan still marked RUNNING in the DB is orphaned (process died).
        """
        from bugtrace.schemas.db_models import ScanTable, ScanStatus
        from sqlmodel import select

        count = 0
        with self.db.get_session() as session:
            stmt = select(ScanTable).where(
                ScanTable.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING])
            )
            orphans = session.exec(stmt).all()
            for scan in orphans:
                scan.status = ScanStatus.FAILED
                session.add(scan)
                count += 1
            if count:
                session.commit()
                logger.info(f"Cleaned up {count} orphaned scan(s) → FAILED")
        return count

    async def re_enrich_scan(self, scan_id: int) -> Dict[str, Any]:
        """
        Re-enrich a completed scan whose LLM enrichment failed.

        Reads engagement_data.json, identifies unenriched findings,
        runs LLM enrichment on them, and writes updated files back.

        Args:
            scan_id: Scan ID to re-enrich

        Returns:
            Dictionary with status and message

        Raises:
            ValueError: If scan not found or not completed
            RuntimeError: If LLM unavailable or no report dir found
        """
        from bugtrace.core.llm_client import llm_client

        # 1. Verify LLM health
        health = llm_client.get_health_status()
        if health["state"] == "CRITICAL":
            raise RuntimeError("LLM unavailable (circuit breaker OPEN). Try again later.")

        # 2. Verify scan exists and is completed
        with self.db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable
            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status != ScanStatus.COMPLETED:
                raise RuntimeError(f"Scan {scan_id} is not completed (status: {scan.status.value})")

            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else "unknown"

        # 3. Find report directory
        report_dir = self._find_report_dir_for_scan(scan_id)
        if not report_dir:
            raise RuntimeError(f"No report directory found for scan {scan_id}")

        # 4. Mark enrichment as pending
        self.db.update_scan_enrichment_status(scan_id, "pending")

        # 5. Launch background task
        asyncio.create_task(
            self._run_re_enrichment(scan_id, target_url, report_dir)
        )

        return {
            "scan_id": scan_id,
            "status": "re_enriching",
            "message": f"Re-enrichment started for scan {scan_id}. Check enrichment_status for progress.",
        }

    async def _run_re_enrichment(self, scan_id: int, target_url: str, report_dir: Path):
        """Background task: re-enrich unenriched findings in engagement_data.json."""
        import json
        from bugtrace.agents.reporting import ReportingAgent

        try:
            logger.info(f"Re-enrichment started for scan {scan_id}")

            # 1. Load engagement_data.json
            engagement_path = report_dir / "engagement_data.json"
            if not engagement_path.is_file():
                logger.error(f"engagement_data.json not found in {report_dir}")
                self.db.update_scan_enrichment_status(scan_id, "none")
                return

            with open(engagement_path, "r") as f:
                engagement_data = json.load(f)

            findings = engagement_data.get("findings", [])
            if not findings:
                logger.info(f"No findings to re-enrich for scan {scan_id}")
                self.db.update_scan_enrichment_status(scan_id, "full")
                return

            # 2. Identify unenriched findings (explicit flag or heuristic for legacy scans)
            unenriched = []
            for finding in findings:
                if finding.get("enriched") is False:
                    unenriched.append(finding)
                elif "enriched" not in finding:
                    # Legacy scan: detect by heuristic
                    has_null_cvss = finding.get("cvss_score") is None
                    has_fallback_text = False
                    details = finding.get("exploitation_details", "")
                    if isinstance(details, str) and ("LLM unavailable" in details or "fail open" in details):
                        has_fallback_text = True
                    if has_null_cvss or has_fallback_text:
                        unenriched.append(finding)

            if not unenriched:
                logger.info(f"All findings already enriched for scan {scan_id}")
                self.db.update_scan_enrichment_status(scan_id, "full")
                return

            logger.info(f"Re-enriching {len(unenriched)}/{len(findings)} findings for scan {scan_id}")

            # 3. Create a ReportingAgent instance for enrichment only
            agent = ReportingAgent(
                scan_id=scan_id,
                target_url=target_url,
                output_dir=report_dir,
            )

            # 4. Run enrichment on unenriched findings
            await agent._enrich_findings_batch(unenriched)

            # 5. Merge enriched results back into engagement_data
            # Build lookup by finding id
            enriched_lookup = {f.get("id"): f for f in unenriched if f.get("id")}
            for i, finding in enumerate(findings):
                fid = finding.get("id")
                if fid and fid in enriched_lookup:
                    enriched = enriched_lookup[fid]
                    # Update fields that enrichment populates
                    if enriched.get("cvss_score") is not None:
                        finding["cvss_score"] = enriched["cvss_score"]
                    if enriched.get("cvss_vector") is not None:
                        finding["cvss_vector"] = enriched["cvss_vector"]
                    if enriched.get("cvss_rationale") is not None:
                        finding["cvss_rationale"] = enriched["cvss_rationale"]
                    if enriched.get("exploitation_details"):
                        finding["exploitation_details"] = enriched["exploitation_details"]
                    finding["enriched"] = enriched.get("enriched", True)

            # 6. Update meta with new enrichment status
            meta = engagement_data.get("meta", {})
            meta["enrichment_status"] = agent._compute_enrichment_status()
            meta["enrichment_stats"] = {
                "total": agent._enrichment_total,
                "enriched": agent._enrichment_total - agent._enrichment_failures,
                "failed": agent._enrichment_failures,
            }
            engagement_data["meta"] = meta

            # 7. Write updated engagement_data.json
            with open(engagement_path, "w") as f:
                json.dump(engagement_data, f, indent=2, default=str)

            # 8. Write engagement_data.js (for HTML report viewer)
            js_path = report_dir / "engagement_data.js"
            if js_path.is_file():
                with open(js_path, "w") as f:
                    f.write("const ENGAGEMENT_DATA = ")
                    json.dump(engagement_data, f, indent=2, default=str)
                    f.write(";")

            # 9. Persist final enrichment status
            final_status = agent._compute_enrichment_status()
            self.db.update_scan_enrichment_status(scan_id, final_status)

            logger.info(f"Re-enrichment completed for scan {scan_id}: status={final_status}")

        except Exception as e:
            logger.error(f"Re-enrichment failed for scan {scan_id}: {e}", exc_info=True)
            self.db.update_scan_enrichment_status(scan_id, "none")
