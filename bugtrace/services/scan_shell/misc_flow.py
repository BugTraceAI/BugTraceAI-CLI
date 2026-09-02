"""ScanService shell mixin (misc). Hard max 2000 LOC."""

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
from bugtrace.services.scan_context import ScanContext, ScanOptions
from bugtrace.schemas.db_models import ScanStatus

logger = get_logger(__name__)

from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.database import get_db_manager
from bugtrace.agents.reporting import ReportingAgent
from bugtrace.core.http_manager import http_manager

class ScanMiscMixin:
    def _check_concurrent_limit(self):
        """Check if at concurrent scan limit. Pure gate: lifecycle_policy."""
        from bugtrace.core import lifecycle_policy as lp

        decision = lp.decide_accept_scan(
            len(self._active_scans), self.max_concurrent
        )
        if not decision.allowed:
            raise RuntimeError(decision.error or lp.concurrent_limit_message(self.max_concurrent))

    def _build_scan_context(self, scan_id: int, options: ScanOptions) -> ScanContext:
        """Build scan context for in-memory lifecycle state."""
        return ScanContext(scan_id, options, self.event_bus)

    async def _emit_scan_created_event(self, scan_id: int, options: ScanOptions):
        """Emit scan.created event."""
        await self.event_bus.emit("scan.created", {
            "scan_id": scan_id,
            "target": options.target_url,
            "scan_type": options.scan_type,
        })

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

        # Resumed scans continue in the parent's directory so specialist state,
        # sidecars, and the canonical report remain one coherent artifact set.
        output_dir = getattr(ctx, "_output_dir", None)
        if output_dir is None:
            output_dir = self._compute_output_dir(ctx.options.target_url)

        # Create and configure orchestrator
        orchestrator = self._create_orchestrator(ctx, output_dir)

        # Setup auth tokens (Level 1: pass-through, Level 2: auto-login)
        # Store the orchestrator's scan_context key on ctx so cleanup uses the same key
        ctx._auth_token_key = orchestrator.scan_context
        auth_session = await self._setup_auth_tokens(
            ctx.options,
            orchestrator.scan_context,
        )
        if auth_session["cookies"] or auth_session["headers"]:
            orchestrator.captured_session = auth_session
            orchestrator._auth_required = bool(auth_session["cookies"])

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

    @staticmethod
    def _extract_jwt_from_response(resp) -> Optional[str]:
        """Extract JWT token from an HTTP login response."""
        import re
        jwt_pattern = re.compile(
            r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)'
        )

        # Try JSON body first
        try:
            body = resp.json()
            if isinstance(body, dict):
                for key in ("access_token", "token", "jwt", "auth_token", "id_token",
                            "accessToken", "authToken", "idToken"):
                    val = body.get(key, "")
                    if val and jwt_pattern.match(val):
                        return val
                # Check nested: body.data.token, body.user.token, etc.
                for outer_key in ("data", "user", "result", "response"):
                    nested = body.get(outer_key, {})
                    if isinstance(nested, dict):
                        for key in ("access_token", "token", "jwt"):
                            val = nested.get(key, "")
                            if val and jwt_pattern.match(val):
                                return val
        except Exception:
            pass

        # Fallback: regex scan on raw text
        text = resp.text
        match = jwt_pattern.search(text)
        if match:
            return match.group(1)

        # Check Authorization header in response (some APIs echo it)
        auth_header = resp.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if jwt_pattern.match(token):
                return token

        return None

    async def _mark_scan_completed(self, ctx: ScanContext):
        """Mark scan as completed with success event."""
        ctx.status = "completed"
        ctx.progress = 100
        self.db.update_scan_status(ctx.scan_id, ScanStatus.COMPLETED)

        # Clean up auth tokens stored during this scan
        from bugtrace.services.scan_context import clear_scan_tokens
        clear_scan_tokens(getattr(ctx, '_auth_token_key', str(ctx.scan_id)))

        await self.event_bus.emit("scan.completed", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
            "findings_count": ctx.findings_count,
        })
        self._schedule_event_history_cleanup(ctx.scan_id)

        logger.info(f"Scan {ctx.scan_id} completed successfully")

    async def _handle_scan_failure(self, ctx: ScanContext, error: Exception):
        """Handle scan failure."""
        ctx.status = "failed"
        self.db.update_scan_status(ctx.scan_id, ScanStatus.FAILED)

        from bugtrace.services.scan_context import clear_scan_tokens
        clear_scan_tokens(getattr(ctx, '_auth_token_key', str(ctx.scan_id)))

        await self.event_bus.emit("scan.failed", {
            "scan_id": ctx.scan_id,
            "target": ctx.options.target_url,
            "error": str(error),
        })
        self._schedule_event_history_cleanup(ctx.scan_id)

        logger.error(f"Scan {ctx.scan_id} failed: {error}")

    def _schedule_event_history_cleanup(self, scan_id: int) -> None:
        """Schedule delayed event-bus cleanup after terminal scan states."""
        asyncio.create_task(self._clear_event_history_after_grace(scan_id))

    async def _clear_event_history_after_grace(self, scan_id: int) -> None:
        await asyncio.sleep(self.EVENT_HISTORY_CLEANUP_GRACE_SECONDS)
        self.event_bus.clear_scan(scan_id)

    async def _cleanup_scan(self, scan_id: int):
        """Remove scan from active scans."""
        async with self._lock:
            if scan_id in self._active_scans:
                del self._active_scans[scan_id]
                logger.info(f"Scan {scan_id} removed from active scans (remaining: {len(self._active_scans)})")

    @staticmethod
    def _exposed_progress(status: ScanStatus, progress: int) -> int:
        """Pure owner: scan_status_policy.exposed_progress."""
        from bugtrace.services.scan_status_policy import exposed_progress

        return exposed_progress(status, progress)

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
        from bugtrace.services.scan_status_policy import (
            normalize_pagination,
            project_list_response,
        )

        page, per_page, offset = normalize_pagination(page, per_page)

        with self.db.get_session() as session:
            from sqlmodel import select, func
            from bugtrace.schemas.db_models import ScanTable, TargetTable

            statement = self._build_scans_query(status_filter)
            total = self._count_scans(session, status_filter, func)
            scans = session.exec(statement.offset(offset).limit(per_page)).all()
            results = self._format_scan_results(session, scans)

            return project_list_response(
                results, total=total, page=page, per_page=per_page
            )

    def _build_scans_query(self, status_filter: Optional[str]):
        """Build scans query with optional status filter and eager-loaded target."""
        from sqlmodel import select
        from sqlalchemy.orm import selectinload
        from bugtrace.schemas.db_models import ScanTable

        # Use selectinload to prevent N+1 queries when accessing scan.target and scan.findings
        statement = (
            select(ScanTable)
            .options(selectinload(ScanTable.target), selectinload(ScanTable.findings))
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

    def _write_repeater_refresh_marker(
        self, scan_id: int, target_url: str, report_dir: Path,
    ) -> None:
        """Persist refresh intent so an API restart cannot lose queued work."""
        import os
        import uuid

        marker = report_dir / self.REPEATER_REFRESH_MARKER
        temp = self._stage_artifact(marker, {
            "scan_id": scan_id,
            "target_url": target_url,
            "token": uuid.uuid4().hex,
        })
        os.replace(temp, marker)
        self._fsync_directory(report_dir)

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        import os

        directory = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def recover_pending_repeater_refreshes(self) -> int:
        """Resume durable post-Repeater refresh markers after an API restart."""
        import json

        recovered = 0
        if not settings.REPORT_DIR.is_dir():
            return recovered
        for marker in settings.REPORT_DIR.glob(f"*/{self.REPEATER_REFRESH_MARKER}"):
            try:
                data = json.loads(marker.read_text(encoding="utf-8"))
                scan_id = int(data["scan_id"])
                target_url = str(data["target_url"])
                with self.db.get_session() as session:
                    from sqlmodel import select
                    from bugtrace.schemas.db_models import ScanTable, TargetTable

                    marked_scan = session.get(ScanTable, scan_id)
                    if not marked_scan:
                        raise ValueError(f"Marker references missing scan {scan_id}")
                    owner = marked_scan
                    if marked_scan.report_dir and (
                        Path(marked_scan.report_dir).resolve() == marker.parent.resolve()
                    ):
                        owner = session.exec(
                            select(ScanTable).where(
                                ScanTable.report_dir == marked_scan.report_dir,
                            ).order_by(ScanTable.id.desc())
                        ).first() or marked_scan
                    if owner.id != scan_id:
                        target = session.get(TargetTable, owner.target_id)
                        scan_id = owner.id
                        target_url = target.url if target else target_url
                        self._write_repeater_refresh_marker(
                            scan_id, target_url, marker.parent,
                        )
                        logger.info(
                            f"Migrated stale report refresh marker to canonical scan {scan_id}"
                        )
                try:
                    self.db.update_scan_enrichment_status(scan_id, "pending")
                except Exception as exc:
                    logger.warning(f"Could not mark recovered scan {scan_id} pending: {exc}")
                self._start_recovered_repeater_refresh(scan_id, target_url, marker.parent)
                recovered += 1
            except Exception as exc:
                logger.error(f"Could not recover Repeater refresh marker {marker}: {exc}")
        return recovered

    @staticmethod
    def _async_repeater_artifact_lock(report_dir: Path):
        """Acquire the cross-process report lock without blocking the event loop."""
        import fcntl
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def lock():
            report_dir.mkdir(parents=True, exist_ok=True)
            handle = (report_dir / ".report-artifacts.lock").open("a+b")
            await asyncio.to_thread(fcntl.flock, handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                await asyncio.to_thread(fcntl.flock, handle.fileno(), fcntl.LOCK_UN)
                handle.close()

        return lock()

    @staticmethod
    def _repeater_artifact_lock(report_dir: Path):
        """Serialize Repeater artifact transactions across API worker processes."""
        import fcntl
        from contextlib import contextmanager

        @contextmanager
        def lock():
            report_dir.mkdir(parents=True, exist_ok=True)
            with (report_dir / ".report-artifacts.lock").open("a+b") as handle:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

        return lock()

    @staticmethod
    def _normalized_origin(url: str) -> tuple:
        """Pure owner: repeater_policy.normalized_origin."""
        from bugtrace.services.repeater_policy import normalized_origin

        return normalized_origin(url)

    @classmethod
    def _validate_repeater_exchange(
        cls, target_url: str, finding_url: str, raw_request: str,
    ) -> None:
        """Pure owner: repeater_policy.validate_repeater_exchange."""
        from bugtrace.services.repeater_policy import validate_repeater_exchange

        validate_repeater_exchange(target_url, finding_url, raw_request)

    @staticmethod
    def _load_artifact_document(path: Path) -> dict:
        """Load a canonical artifact without silently discarding invalid data."""
        import json

        if not path.is_file():
            return {"findings": []}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise RuntimeError(f"Cannot read valid JSON from {path.name}") from exc
        if isinstance(data, list):
            return {"findings": list(data)}
        if not isinstance(data, dict):
            raise RuntimeError(f"Unsupported JSON structure in {path.name}")
        result = dict(data)
        findings = result.get("findings", [])
        if not isinstance(findings, list):
            raise RuntimeError(f"Invalid findings collection in {path.name}")
        result["findings"] = list(findings)
        return result

    @staticmethod
    def _stage_artifact(path: Path, document: dict) -> Path:
        """Write and fsync a unique temporary artifact beside its destination."""
        import json
        import os
        import tempfile

        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            json.dump(document, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
            return Path(handle.name)

    @classmethod
    def _restore_artifact(cls, path: Path, snapshot: Optional[bytes]) -> None:
        """Restore exact prior bytes, or remove a file that did not exist."""
        import os
        import tempfile

        if snapshot is None:
            path.unlink(missing_ok=True)
            return
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.restore.",
            suffix=".tmp", delete=False,
        ) as handle:
            handle.write(snapshot)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        os.replace(temp_path, path)

    @staticmethod
    def _artifact_matches_snapshot(path: Path, snapshot: Optional[bytes]) -> bool:
        """Detect report changes made outside this service before replacement."""
        if snapshot is None:
            return not path.exists()
        return path.is_file() and path.read_bytes() == snapshot

    async def _update_canonical_artifacts(
        self,
        report_dir: Path,
        finding_data: dict,
        vuln_type: str,
        parameter: str,
        url: str,
        is_new: bool,
    ):
        """Atomically update raw_findings.json and validated_findings.json."""
        import json, tempfile, os
        from bugtrace.core.payload_format import decode_finding_payloads

        raw_path = report_dir / "raw_findings.json"
        validated_path = report_dir / "validated_findings.json"

        canonical_finding = {
            "type": vuln_type,
            "severity": finding_data.get("severity", "MEDIUM"),
            "url": url,
            "parameter": parameter or "",
            "status": "VALIDATED_CONFIRMED",
            "confidence": finding_data.get("confidence", 0.95),
            "source": "ai_repeater",
            "summary": finding_data.get("summary", ""),
            "scan_id": str(finding_data.get("scan_id", "")),
        }

        if is_new:
            self._append_to_json_file(raw_path, canonical_finding)
            self._append_to_json_file(validated_path, canonical_finding)
        else:
            self._upsert_in_json_file(raw_path, canonical_finding, vuln_type, parameter, url)
            self._upsert_in_json_file(validated_path, canonical_finding, vuln_type, parameter, url)

    def _load_json_file(self, path: Path) -> dict:
        """Load a JSON file preserving all metadata fields, or return empty dict."""
        import json
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return dict(data)
            except Exception:
                pass
        return {}

    def _append_to_json_file(self, path: Path, finding: dict):
        """Append a finding to a JSON findings file atomically, preserving all top-level metadata."""
        import json, os

        data = self._load_json_file(path)
        existing_findings = data.get("findings", [])
        if isinstance(existing_findings, list):
            pass
        elif isinstance(data, list):
            existing_findings = data
            data = {}
        else:
            existing_findings = []

        if any(
            f.get("type") == finding["type"]
            and f.get("url") == finding["url"]
            and f.get("parameter", "") == finding.get("parameter", "")
            for f in existing_findings
        ):
            return

        existing_findings.append(finding)
        data["findings"] = existing_findings
        if "scan_id" not in data:
            data["scan_id"] = finding.get("scan_id", "")

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)

    def _upsert_in_json_file(self, path: Path, finding: dict, vuln_type: str, parameter: str, url: str):
        """Update or insert a finding in a JSON findings file atomically, preserving all top-level metadata."""
        import json, os

        data = self._load_json_file(path)
        existing_findings = data.get("findings", [])
        if isinstance(existing_findings, list):
            pass
        elif isinstance(data, list):
            existing_findings = data
            data = {}
        else:
            existing_findings = []

        found = False
        for i, f in enumerate(existing_findings):
            if (
                f.get("type") == vuln_type
                and f.get("url") == url
                and f.get("parameter", "") == parameter
            ):
                existing_findings[i] = {**f, **finding}
                found = True
                break

        if not found:
            existing_findings.append(finding)

        data["findings"] = existing_findings
        if "scan_id" not in data:
            data["scan_id"] = finding.get("scan_id", "")

        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, path)

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
    def _has_recovery_artifacts(
        report_base: Path,
        scan_id: int,
        target_url: Optional[str],
        scan_timestamp: Optional[datetime] = None,
        report_dir: Optional[str] = None,
    ) -> bool:
        """Check whether a scan has any persisted artifacts, even without final deliverables."""
        candidate_dirs: List[Path] = []

        if report_dir:
            candidate_dirs.append(Path(report_dir))

        candidate_dirs.append(report_base / f"scan_{scan_id}")

        if target_url:
            hostname = urlparse(target_url).hostname or ""
            if hostname:
                if scan_timestamp:
                    ts_prefix = scan_timestamp.strftime("%Y%m%d_%H%M")
                    candidate_dirs.extend(report_base.glob(f"{hostname}_{ts_prefix}*"))
                candidate_dirs.extend(report_base.glob(f"{hostname}_*"))

        seen = set()
        for directory in candidate_dirs:
            if directory in seen:
                continue
            seen.add(directory)

            if not directory.is_dir():
                continue

            try:
                if any(path.is_file() for path in directory.rglob("*")):
                    return True
            except OSError as e:
                logger.debug(f"Error inspecting recovery artifacts in {directory}: {e}")

        return False

    def _try_delete_dir(self, path: Path, deleted: List[Path]):
        """Attempt to delete a directory and track success."""
        try:
            shutil.rmtree(path)
            deleted.append(path)
            logger.info(f"Deleted report directory: {path}")
        except OSError as e:
            logger.warning(f"Failed to delete report directory {path}: {e}")

    @staticmethod
    def _dir_belongs_to_scan(directory: Path, scan_id: int) -> bool:
        """Return True only when report metadata clearly names this scan."""
        import json

        candidates = (
            directory / "validated_findings.json",
            directory / "raw_findings.json",
        )
        for path in candidates:
            if not path.is_file():
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue

            if ScanMiscMixin._json_names_scan(data, scan_id):
                return True

        return False

    @staticmethod
    def _json_names_scan(data: Any, scan_id: int) -> bool:
        """Inspect common report JSON shapes for scan_id."""
        if isinstance(data, dict):
            if str(data.get("scan_id", "")) == str(scan_id):
                return True
            findings = data.get("findings")
            if isinstance(findings, list):
                return any(ScanMiscMixin._json_names_scan(item, scan_id) for item in findings)
            finding = data.get("finding")
            if isinstance(finding, dict):
                return ScanMiscMixin._json_names_scan(finding, scan_id)
            return False
        if isinstance(data, list):
            return any(ScanMiscMixin._json_names_scan(item, scan_id) for item in data)
        return False

    @staticmethod
    def _normalize_details(finding: Dict[str, Any]) -> str:
        """Extract details from a finding, converting dicts to JSON strings."""
        value = (
            finding.get("exploitation_details")
            or finding.get("description")
            or finding.get("details")
            or finding.get("reasoning")
            or finding.get("evidence")
            or finding.get("note", "")
        )
        if isinstance(value, dict):
            import json
            return json.dumps(value)
        return str(value) if value else ""

    @staticmethod
    def _finding_description_for_api(finding: Dict[str, Any]) -> str:
        """Human narrative for WEB report viewer (needs description/exploitation text)."""
        for key in (
            "exploitation_details",
            "description",
            "reasoning",
            "validator_notes",
            "summary",
        ):
            val = finding.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        details = ScanMiscMixin._normalize_details(finding)
        if details:
            return details
        # Minimal synthesis so UI never shows an empty description panel.
        parts = []
        vtype = finding.get("type") or "Finding"
        parts.append(f"**{vtype}**")
        if finding.get("parameter"):
            parts.append(f"Parameter: `{finding.get('parameter')}`")
        if finding.get("url"):
            parts.append(f"URL: {finding.get('url')}")
        if finding.get("payload"):
            parts.append(f"Payload: `{finding.get('payload')}`")
        return "\n\n".join(parts)

    @property
    def active_scan_count(self) -> int:
        """Get count of currently running scans."""
        return len(self._active_scans)

    def get_active_scan_ids(self) -> List[int]:
        """Get list of active scan IDs."""
        return list(self._active_scans.keys())

    def find_incomplete_scan(self, target_url: str, scan_type: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Find the most recent FAILED scan with recovery artifacts for resumption.
        
        Args:
            target_url: URL to find incomplete scan for
            scan_type: Optional scan type filter ("full", "hunter", etc)
            
        Returns:
            Dict with scan metadata if incomplete scan found, None otherwise
        """
        from bugtrace.schemas.db_models import ScanTable, TargetTable, ScanStatus
        from sqlmodel import select
        
        with self.db.get_session() as session:
            # Find target first
            target_stmt = select(TargetTable).where(TargetTable.url == target_url)
            target = session.exec(target_stmt).first()
            if not target:
                return None
            
            # Find most recent FAILED scan with recovery artifacts
            query = select(ScanTable).where(
                (ScanTable.target_id == target.id) &
                (ScanTable.status == ScanStatus.FAILED)
            ).order_by(ScanTable.timestamp.desc())
            
            if scan_type:
                query = query.where(ScanTable.scan_type == scan_type)
            
            scan = session.exec(query).first()
            if not scan:
                return None
            
            # Verify it has recovery artifacts
            if not self._has_recovery_artifacts(
                Path(settings.REPORT_DIR),
                scan.id,
                target_url,
                scan.timestamp,
                scan.report_dir
            ):
                return None
            
            return {
                "scan_id": scan.id,
                "target_url": target_url,
                "scan_type": scan.scan_type,
                "last_phase": scan.last_phase_completed,
                "report_dir": scan.report_dir,
                "retry_count": scan.retry_count,
            }

    def cleanup_orphaned_scans(self) -> int:
        """Mark any RUNNING/PENDING/PAUSED scans as FAILED on startup.

        When the backend restarts, no scans are actually running in-process.
        Any scan still marked RUNNING/PAUSED in the DB is orphaned (process died).
        """
        from bugtrace.schemas.db_models import ScanTable, ScanStatus
        from sqlmodel import select

        count = 0
        with self.db.get_session() as session:
            stmt = select(ScanTable).where(
                ScanTable.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING, ScanStatus.PAUSED])
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
        health = llm_client.get_health_status() or {}
        if health.get("state") == "CRITICAL":
            raise RuntimeError("LLM unavailable (circuit breaker OPEN). Try again later.")

        # 2. Verify scan exists and is completed
        with self.db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable
            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status != ScanStatus.COMPLETED:
                raise RuntimeError(f"Scan {scan_id} is not completed (status: {scan.status.value})")
            self._assert_report_not_shared_with_active_scan(session, scan)

            target = session.get(TargetTable, scan.target_id)
            target_url = target.url if target else "unknown"

        # 3. Find report directory
        report_dir = self._find_report_dir_for_scan(scan_id)
        if not report_dir:
            raise RuntimeError(f"No report directory found for scan {scan_id}")

        # 4. Coalesce manual and Repeater regeneration by report directory.
        key = self._report_refresh_key(report_dir)
        current = self._repeater_report_refresh_tasks.get(key)
        if current and not current.done():
            marker = report_dir / self.REPEATER_REFRESH_MARKER
            marker_scan_id = None
            try:
                import json
                marker_scan_id = int(json.loads(marker.read_text(encoding="utf-8"))["scan_id"])
            except Exception:
                pass
            if marker_scan_id != scan_id:
                raise RuntimeError(
                    f"Report refresh already belongs to scan {marker_scan_id}"
                )
            return {
                "scan_id": scan_id,
                "status": "re_enriching",
                "message": f"Re-enrichment already running for scan {scan_id}.",
            }

        # 5. Use the same durable marker and queue as post-Repeater refreshes.
        self._queue_repeater_report_refresh(
            scan_id, target_url, report_dir, write_marker=True,
        )

        return {
            "scan_id": scan_id,
            "status": "re_enriching",
            "message": f"Re-enrichment started for scan {scan_id}. Check enrichment_status for progress.",
        }

    async def _run_re_enrichment(
        self,
        scan_id: int,
        target_url: str,
        report_dir: Path,
        *,
        acquire_artifact_lock: bool = True,
    ) -> bool:
        """Background task: fully regenerate a scan's report with fresh LLM enrichment.

        Re-runs the ReportingAgent end-to-end (re-collect from specialist results → enrich →
        render ALL deliverables → truth-based enrichment_status) instead of patching
        engagement_data.json in place. The old in-place patch decided what to re-enrich from
        each finding's `enriched` flag — but that flag can read True while cvss_score is None
        (enrichment interrupted mid-way), so it skipped everything and falsely reported
        "full", and it left final_report.md / report.html / validated_findings.json stale.
        generate_all_deliverables redoes the work from source and rewrites every deliverable
        consistently, and its completeness audit persists the honest status.
        """
        if acquire_artifact_lock:
            async with self._async_repeater_artifact_lock(report_dir):
                return await self._run_re_enrichment(
                    scan_id, target_url, report_dir, acquire_artifact_lock=False,
                )

        from bugtrace.agents.reporting import ReportingAgent

        agent = ReportingAgent(
            scan_id=scan_id,
            target_url=target_url,
            output_dir=report_dir,
        )
        try:
            logger.info(f"Re-enrichment started for scan {scan_id}")
            await agent.generate_all_deliverables()
            # generate_all_deliverables persists the truth-based enrichment_status itself.
            logger.info(f"Re-enrichment completed for scan {scan_id}")
            return True

        except asyncio.CancelledError:
            self._update_enrichment_status_from_artifacts(scan_id, report_dir, agent)
            raise
        except Exception as e:
            logger.error(f"Re-enrichment failed for scan {scan_id}: {e}", exc_info=True)
            self._update_enrichment_status_from_artifacts(scan_id, report_dir, agent)
            return False
