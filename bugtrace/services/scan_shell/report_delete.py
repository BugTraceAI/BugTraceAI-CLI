"""ScanService shell mixin (report). Hard max 2000 LOC."""

from __future__ import annotations

import asyncio
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.schemas.db_models import ScanStatus

logger = get_logger(__name__)

from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.database import get_db_manager
from bugtrace.agents.reporting import ReportingAgent
from bugtrace.core.http_manager import http_manager


class ScanReportDeleteMixin:
    """Report dir cleanup/delete."""

    def _find_or_create_report_dir_for_scan(
        self, scan_id: int, target_url: str, finding_data: dict
    ) -> Optional[Path]:
        """Find the scan's report directory or create one."""
        report_dir = self._find_report_dir_for_scan(scan_id)
        if report_dir:
            return report_dir

        domain = urlparse(target_url).netloc.replace(":", "_")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        report_dir = settings.REPORT_DIR / f"scan_{scan_id}"
        report_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"Created report directory for scan {scan_id}: {report_dir}")
        return report_dir

    @staticmethod
    def _assert_report_not_shared_with_active_scan(session, scan) -> None:
        """Reject writes unless this is the sole/latest owner of its artifacts."""
        if not scan.report_dir:
            return
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanTable

        active = session.exec(
            select(ScanTable).where(
                ScanTable.id != scan.id,
                ScanTable.report_dir == scan.report_dir,
                ScanTable.status.in_([
                    ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.PAUSED,
                ]),
            )
        ).first()
        if active:
            raise ValueError(
                f"Report artifacts are in use by active resumed scan {active.id}"
            )
        newer = session.exec(
            select(ScanTable).where(
                ScanTable.id > scan.id,
                ScanTable.report_dir == scan.report_dir,
            ).order_by(ScanTable.id.desc())
        ).first()
        if newer:
            raise ValueError(
                f"Report artifacts belong to newer resumed scan {newer.id}"
            )

    def _load_report_counts(self, scan_id: int) -> Dict[str, int]:
        """Read user-facing counters from canonical report artifacts.

        Count math: pure ``scan_status_policy.report_counts_from_artifacts``.
        """
        import json

        from bugtrace.services.scan_status_policy import report_counts_from_artifacts

        report_dir = self._find_report_dir_for_scan(scan_id)
        if not report_dir:
            return {}

        raw_doc = None
        validated_doc = None
        try:
            raw_doc = json.loads(
                (report_dir / "raw_findings.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError, TypeError):
            pass
        try:
            validated_doc = json.loads(
                (report_dir / "validated_findings.json").read_text(encoding="utf-8")
            )
        except (OSError, ValueError, TypeError):
            pass

        return report_counts_from_artifacts(raw_doc, validated_doc)

    def _delete_scan_findings(self, session, scan_id: int) -> int:
        """Delete all findings associated with a scan."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import FindingTable

        findings = session.exec(select(FindingTable).where(FindingTable.scan_id == scan_id)).all()
        for finding in findings:
            session.delete(finding)
        return len(findings)

    @staticmethod
    def _has_report_dir(
        report_base: Path,
        scan_id: int,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime] = None,
        report_dir: Optional[str] = None,
    ) -> bool:
        """Check if a report directory with actual report files exists for this scan."""
        report_files = {"final_report.md", "validated_findings.json", "raw_findings.json"}

        def _has_files(d: Path) -> bool:
            """Check if directory contains at least one known report file."""
            return d.is_dir() and any((d / f).is_file() for f in report_files)

        if report_dir and _has_files(Path(report_dir)):
            return True

        # Pattern 1: API-generated (scan_{id}/)
        if _has_files(report_base / f"scan_{scan_id}"):
            return True

        # Pattern 2: Pipeline-generated ({domain}_{timestamp}/)
        return ScanReportDeleteMixin._check_pipeline_report_dir(
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

        return ScanReportDeleteMixin._check_hostname_reports(
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

