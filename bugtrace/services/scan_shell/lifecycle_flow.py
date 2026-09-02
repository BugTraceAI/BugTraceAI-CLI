"""ScanService shell mixin (lifecycle). Hard max 2000 LOC."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.services.scan_context import ScanContext, ScanOptions
from bugtrace.schemas.db_models import ScanStatus

logger = get_logger(__name__)

from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.database import get_db_manager
from bugtrace.agents.reporting import ReportingAgent
from bugtrace.core.http_manager import http_manager

class ScanLifecycleMixin:
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

    def _create_scan_record(self, options: ScanOptions, origin: str) -> int:
        """Create database scan record with config."""
        from bugtrace.core.config import settings as _settings
        scan_id = self.db.create_new_scan(
            options.target_url,
            origin=origin,
            scan_type=options.scan_type,
            max_depth=options.max_depth,
            max_urls=options.max_urls,
            provider=getattr(_settings, 'PROVIDER', None),
        )
        logger.info(f"Created scan {scan_id} for target: {options.target_url} (origin={origin})")
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
            async with self._semaphore:
                await self._execute_scan(ctx)
        except asyncio.CancelledError:
            await self._handle_scan_cancellation(ctx)
            raise
        except Exception as e:
            await self._handle_scan_failure(ctx, e)
        finally:
            await self._cleanup_scan(scan_id)

    async def _handle_scan_cancellation(self, ctx: ScanContext):
        """Handle scan cancellation."""
        ctx.status = "stopped"
        self.db.update_scan_status(ctx.scan_id, ScanStatus.STOPPED)

        from bugtrace.services.scan_context import clear_scan_tokens
        clear_scan_tokens(getattr(ctx, '_auth_token_key', str(ctx.scan_id)))

        await self.event_bus.emit("scan.stopped", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
        })
        self._schedule_event_history_cleanup(ctx.scan_id)

        logger.warning(f"Scan {ctx.scan_id} was cancelled")

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
            from bugtrace.services.scan_status_policy import (
                findings_count_for_status,
                project_db_scan_status,
            )

            findings_statement = select(FindingTable).where(FindingTable.scan_id == scan_id)
            findings = session.exec(findings_statement).all()
            report_counts = self._load_report_counts(scan_id)
            detections_count = findings_count_for_status(
                report_counts, db_findings_fallback=len(findings)
            )

            return project_db_scan_status(
                scan_id=scan_id,
                target_url=target.url if target else "unknown",
                status=scan.status,
                progress=scan.progress_percent,
                origin=getattr(scan, "origin", None),
                enrichment_status=getattr(scan, "enrichment_status", None),
                scan_type=scan.scan_type,
                max_depth=scan.max_depth,
                max_urls=scan.max_urls,
                provider=getattr(scan, "provider", None),
                detections_count=detections_count,
                uptime_seconds=None,
                active_agent=None,
                phase=None,
            )

    @staticmethod
    def _memory_status_to_policy(status: str | None) -> str:
        """Thin adapter: pure owner is lifecycle_policy.memory_status_to_policy."""
        from bugtrace.core import lifecycle_policy as lp

        return lp.memory_status_to_policy(status)

    async def stop_scan(self, scan_id: int) -> Dict[str, Any]:
        """Stop a running or paused scan gracefully."""
        from bugtrace.core import lifecycle_policy as lp

        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not currently running")

            ctx = self._active_scans[scan_id]
            decision = lp.decide_stop(
                self._memory_status_to_policy(getattr(ctx, "status", None)),
                scan_id=scan_id,
            )
            if not decision.allowed:
                raise ValueError(
                    decision.error or f"Scan {scan_id} cannot be stopped"
                )

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
        from bugtrace.core import lifecycle_policy as lp

        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not currently running")

            ctx = self._active_scans[scan_id]
            decision = lp.decide_pause(
                self._memory_status_to_policy(getattr(ctx, "status", None)),
                scan_id=scan_id,
            )
            if not decision.allowed:
                raise ValueError(
                    decision.error
                    or f"Scan {scan_id} is not running (status: {ctx.status})"
                )

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

    async def _resume_paused_scan(self, scan_id: int) -> Dict[str, Any]:
        """Resume an in-memory paused scan."""
        from bugtrace.core import lifecycle_policy as lp

        async with self._lock:
            if scan_id not in self._active_scans:
                raise ValueError(f"Scan {scan_id} is not active")

            ctx = self._active_scans[scan_id]
            decision = lp.decide_resume(
                self._memory_status_to_policy(getattr(ctx, "status", None)),
                scan_id=scan_id,
            )
            if not decision.allowed:
                raise ValueError(
                    decision.error
                    or f"Scan {scan_id} is not paused (status: {ctx.status})"
                )

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

    async def resume_scan(self, scan_id: int) -> Dict[str, Any]:
        """Resume either a paused in-memory scan or recreate a recoverable failed scan."""
        async with self._lock:
            ctx = self._active_scans.get(scan_id)

        if ctx is not None:
            return await self._resume_paused_scan(scan_id)

        return await self._resume_recoverable_scan(scan_id)

    def _start_recovered_repeater_refresh(
        self, scan_id: int, target_url: str, report_dir: Path,
    ) -> None:
        key = self._report_refresh_key(report_dir)
        current = self._repeater_report_refresh_tasks.get(key)
        if current and not current.done():
            return
        task = asyncio.create_task(
            self._run_queued_repeater_report_refresh(report_dir)
        )
        self._repeater_report_refresh_tasks[key] = task

    async def _resume_recoverable_scan(self, original_scan_id: int) -> Dict[str, Any]:
        """Resume a failed scan with preserved recovery artifacts using stored scan config."""
        from bugtrace.schemas.db_models import ScanTable, TargetTable, ScanStatus
        from sqlmodel import select

        with self.db.get_session() as session:
            original = session.exec(
                select(ScanTable).where(ScanTable.id == original_scan_id)
            ).first()
            if not original:
                raise ValueError(f"Scan {original_scan_id} not found")
            if original.status != ScanStatus.FAILED:
                raise ValueError(
                    f"Scan {original_scan_id} is not resumable (status: {original.status.value})"
                )

            target = session.exec(
                select(TargetTable).where(TargetTable.id == original.target_id)
            ).first()
            if not target:
                raise ValueError(f"Target for scan {original_scan_id} not found")

            if not self._has_recovery_artifacts(
                Path(settings.REPORT_DIR),
                original.id,
                target.url,
                original.timestamp,
                original.report_dir,
            ):
                raise ValueError(f"Scan {original_scan_id} has no recovery artifacts to resume")

            options = ScanOptions(
                target_url=target.url,
                scan_type=original.scan_type or "full",
                max_depth=original.max_depth or 2,
                max_urls=original.max_urls or 20,
                resume=True,
            )
            origin = original.origin or "unknown"

        new_scan_id = await self._start_resumed_scan(original_scan_id, options, origin=origin)
        return {
            "scan_id": new_scan_id,
            "status": "running",
            "message": f"Resumed scan {original_scan_id} as new scan {new_scan_id}",
        }

    async def _start_resumed_scan(self, original_scan_id: int, options: ScanOptions, origin: str = "unknown") -> int:
        """
        Create a new scan that resumes from an incomplete previous scan.
        
        Args:
            original_scan_id: ID of the failed scan to resume from
            options: Updated scan configuration
            origin: Where the resume was initiated from
            
        Returns:
            New scan_id for the resumed scan
        """
        from bugtrace.schemas.db_models import ScanTable
        from sqlmodel import select
        
        new_scan_id = None
        original_report_dir = None
        retry_count = 0

        # Get original scan metadata
        with self.db.get_session() as session:
            original = session.exec(
                select(ScanTable).where(ScanTable.id == original_scan_id)
            ).first()
            if not original:
                raise ValueError(f"Original scan {original_scan_id} not found")
            
            # Increment retry count
            original.retry_count += 1
            retry_count = original.retry_count
            original_report_dir = original.report_dir
            session.add(original)
            session.commit()
        
        logger.info(
            f"Resuming scan {original_scan_id} (retry #{retry_count})",
            extra={"scan_id": original_scan_id}
        )
        
        # Create new scan record marked as resumed
        async with self._lock:
            self._check_concurrent_limit()
            new_scan_id = self._create_scan_record(options, origin)
            
        # Update new scan to reference original
        with self.db.get_session() as session:
            new_scan = session.exec(
                select(ScanTable).where(ScanTable.id == new_scan_id)
            ).first()
            new_scan.resumed_from_id = original_scan_id
            new_scan.report_dir = original_report_dir  # Reuse same report dir
            session.add(new_scan)
            session.commit()
        
        # Start the resumed scan
        try:
            ctx = self._build_scan_context(new_scan_id, options)
            ctx._output_dir = (
                Path(original_report_dir)
                if original_report_dir
                else self._compute_output_dir(options.target_url)
            )
            
            async with self._lock:
                self._active_scans[new_scan_id] = ctx

            ctx._task = asyncio.create_task(self._run_scan(ctx))
            await self.event_bus.emit("scan.resumed", {
                "scan_id": new_scan_id,
                "parent_scan_id": original_scan_id,
                "target": options.target_url,
            })
            
            logger.info(f"Resumed scan started: {new_scan_id} (parent: {original_scan_id})")
            return new_scan_id
        except Exception as e:
            logger.error(f"Failed to start resumed scan {new_scan_id}: {e}", exc_info=True)
            if new_scan_id is not None:
                with self.db.get_session() as session:
                    failed_scan = session.exec(
                        select(ScanTable).where(ScanTable.id == new_scan_id)
                    ).first()
                    if failed_scan:
                        failed_scan.status = ScanStatus.FAILED
                        session.add(failed_scan)
                        session.commit()
            raise

    def _update_enrichment_status_from_artifacts(
        self, scan_id: int, report_dir: Path, agent,
    ) -> None:
        status = "none"
        try:
            data = self._load_artifact_document(report_dir / "validated_findings.json")
            confirmed = [
                finding for finding in data.get("findings", [])
                if isinstance(finding, dict)
            ]
            status = agent._audit_enrichment_completeness(confirmed)["status"]
        except Exception:
            pass
        self.db.update_scan_enrichment_status(scan_id, status)

