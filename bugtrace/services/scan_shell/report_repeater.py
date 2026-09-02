"""ScanService shell mixin (report). Hard max 2000 LOC."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.schemas.db_models import ScanStatus, FindingStatus

logger = get_logger(__name__)

from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.database import get_db_manager
from bugtrace.agents.reporting import ReportingAgent
from bugtrace.core.http_manager import http_manager


class ScanReportRepeaterMixin:
    """Repeater finding persistence."""

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
            report_dir = getattr(scan, "report_dir", None)
            has_report = self._has_report_dir(report_base, scan.id, target_url, scan.timestamp, report_dir)
            recovery_available = self._has_recovery_artifacts(
                report_base,
                scan.id,
                target_url,
                scan.timestamp,
                report_dir,
            )
            report_counts = self._load_report_counts(scan.id) if has_report else {}
            detections_count = report_counts.get(
                "detections_count",
                len(scan.findings) if scan.findings else 0,
            )

            results.append({
                "scan_id": scan.id,
                "target": target_url or "unknown",
                "status": scan.status.value,
                "progress": self._exposed_progress(scan.status, scan.progress_percent),
                "timestamp": scan.timestamp.isoformat(),
                "origin": getattr(scan, "origin", None) or "unknown",
                "enrichment_status": getattr(scan, "enrichment_status", None),
                "has_report": has_report,
                "recovery_available": recovery_available,
                "scan_type": scan.scan_type,
                "max_depth": scan.max_depth,
                "max_urls": scan.max_urls,
                "provider": getattr(scan, "provider", None),
                # Compatibility alias: this is the deduplicated detection count,
                # never the number of physical persistence rows.
                "findings_count": detections_count,
                "detections_count": detections_count,
                "confirmed_count": report_counts.get("confirmed_count", 0),
                "manual_review_count": report_counts.get("manual_review_count", 0),
                "reportable_count": report_counts.get("reportable_count", 0),
            })
        return results

    async def persist_repeater_finding(
        self, scan_id: int, finding_data: dict
    ) -> dict:
        """Persist a confirmed AI Repeater finding to SQLite and canonical artifacts.

        Transactional compensation: under a lock, validates input, resolves paths,
        captures artifact byte snapshots, writes temp files + fsyncs, commits DB,
        replaces artifacts. On any exception: rolls back DB AND restores artifact bytes.
        Never returns 2xx with success=false.

        Returns dict with finding_id, created, success, message.
        """
        import json, tempfile, os

        target_url = finding_data.get("target_url") or finding_data.get("scan_target")
        vuln_url = finding_data.get("url", "")
        vuln_type = finding_data.get("type", "").upper()
        severity = finding_data.get("severity", "MEDIUM").upper()
        summary = finding_data.get("summary", "")
        parameter = finding_data.get("parameter", "")
        confidence = finding_data.get("confidence", 0.95)
        request_raw = finding_data.get("request", "")
        response_status = finding_data.get("response_status")
        response_excerpt = finding_data.get("response_excerpt", "")
        request_ok = finding_data.get("request_ok")

        if not vuln_type or not summary:
            raise ValueError("type and summary are required")
        if not request_raw or not request_raw.strip():
            raise ValueError("request is required and must not be empty")
        if response_status is None or response_status < 100 or response_status > 599:
            raise ValueError("response_status must be between 100 and 599")
        if request_ok is not True:
            raise ValueError("request_ok must be true")

        with self.db.get_session() as session:
            from bugtrace.schemas.db_models import ScanTable, TargetTable
            scan = session.get(ScanTable, scan_id)
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
            if scan.status in {ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.PAUSED}:
                raise ValueError("Repeater findings cannot be persisted while the scan is active")
            target = session.get(TargetTable, scan.target_id)
            if not target:
                raise ValueError(f"Target for scan {scan_id} not found")
            actual_target_url = target.url
            self._assert_report_not_shared_with_active_scan(session, scan)

        if target_url and target_url != actual_target_url:
            raise ValueError("Scan target mismatch")

        self._validate_repeater_exchange(actual_target_url, vuln_url, request_raw)

        report_dir = self._find_or_create_report_dir_for_scan(
            scan_id, actual_target_url, finding_data,
        )
        async with self._repeater_persistence_lock:
            async with self._async_repeater_artifact_lock(report_dir):
                result = await self._persist_repeater_finding_locked(
                    scan_id, actual_target_url, vuln_url, vuln_type, severity,
                    parameter, summary, confidence, request_raw, response_status,
                    response_excerpt, finding_data, report_dir,
                )
        report_dir = result.pop("_report_dir")
        try:
            self._queue_repeater_report_refresh(
                scan_id, actual_target_url, report_dir, write_marker=False,
            )
            result["report_refresh"] = "queued"
        except Exception as exc:
            logger.error(f"Could not queue report refresh for scan {scan_id}: {exc}", exc_info=True)
            result["report_refresh"] = "failed"
        return result

    def _queue_repeater_report_refresh(
        self, scan_id: int, target_url: str, report_dir: Path,
        *, write_marker: bool = True,
    ) -> None:
        """Coalesce post-Repeater report regeneration per scan."""
        key = self._report_refresh_key(report_dir)
        current = self._repeater_report_refresh_tasks.get(key)
        if current and not current.done():
            marker = report_dir / self.REPEATER_REFRESH_MARKER
            try:
                import json
                marker_scan_id = int(json.loads(marker.read_text(encoding="utf-8"))["scan_id"])
            except Exception:
                marker_scan_id = scan_id
            if marker_scan_id != scan_id:
                raise RuntimeError(
                    f"Report refresh already belongs to scan {marker_scan_id}"
                )
            try:
                self.db.update_scan_enrichment_status(scan_id, "pending")
            except Exception as exc:
                logger.warning(f"Could not mark scan {scan_id} enrichment pending: {exc}")
            return
        if write_marker:
            self._write_repeater_refresh_marker(scan_id, target_url, report_dir)
        try:
            self.db.update_scan_enrichment_status(scan_id, "pending")
        except Exception as exc:
            logger.warning(f"Could not mark scan {scan_id} enrichment pending: {exc}")
        task = asyncio.create_task(
            self._run_queued_repeater_report_refresh(report_dir)
        )
        self._repeater_report_refresh_tasks[key] = task

    async def _run_queued_repeater_report_refresh(
        self, report_dir: Path,
    ) -> None:
        """Regenerate all products until the report directory's marker is consumed."""
        import json

        key = self._report_refresh_key(report_dir)
        marker = report_dir / self.REPEATER_REFRESH_MARKER
        refresh_succeeded = False
        try:
            while marker.is_file():
                # Brief debounce lets rapid Repeater saves share one regeneration.
                await asyncio.sleep(0.5)
                if not marker.is_file():
                    break
                async with self._async_repeater_artifact_lock(report_dir):
                    if not marker.is_file():
                        break
                    marker_token = marker.read_text(encoding="utf-8")
                    marker_data = json.loads(marker_token)
                    marker_scan_id = int(marker_data["scan_id"])
                    marker_target_url = str(marker_data["target_url"])
                    refresh_succeeded = await self._run_re_enrichment(
                        marker_scan_id, marker_target_url, report_dir,
                        acquire_artifact_lock=False,
                    )
                    if (
                        refresh_succeeded
                        and marker.is_file()
                        and marker.read_text(encoding="utf-8") == marker_token
                    ):
                        marker.unlink(missing_ok=True)
                        self._fsync_directory(report_dir)
                if not refresh_succeeded or not marker.is_file():
                    break
        finally:
            current = self._repeater_report_refresh_tasks.get(key)
            if current is asyncio.current_task():
                self._repeater_report_refresh_tasks.pop(key, None)

    @staticmethod
    def _report_refresh_key(report_dir: Path) -> str:
        return str(report_dir.resolve())

    async def _persist_repeater_finding_locked(
        self, scan_id, actual_target_url, vuln_url, vuln_type, severity,
        parameter, summary, confidence, request_raw, response_status,
        response_excerpt, finding_data, report_dir,
    ):
        """Transactional persistence under lock. Never returns success=false on 2xx."""
        import os
        import uuid

        finding_payload = {
            "type": vuln_type,
            "severity": severity,
            "url": vuln_url or actual_target_url,
            "parameter": parameter or "",
            "summary": summary,
            "details": summary,
            "confidence": confidence,
            "validated": True,
            "status": FindingStatus.VALIDATED_CONFIRMED.value,
            "source": "ai_repeater",
            "validator_notes": f"Confirmed by AI Repeater. {summary}",
            "reproduction": request_raw,
            "response_status": response_status,
            "response_excerpt": response_excerpt or "",
            "source_finding_id": finding_data.get("source_finding_id"),
        }

        if not report_dir:
            raise RuntimeError(f"No report directory available for scan {scan_id}")
        raw_path = report_dir / "raw_findings.json"
        validated_path = report_dir / "validated_findings.json"
        marker_path = report_dir / self.REPEATER_REFRESH_MARKER

        raw_snapshot = raw_path.read_bytes() if raw_path.is_file() else None
        validated_snapshot = validated_path.read_bytes() if validated_path.is_file() else None
        marker_snapshot = marker_path.read_bytes() if marker_path.is_file() else None
        raw_tmp = None
        validated_tmp = None
        marker_tmp = None
        raw_replaced = False
        validated_replaced = False
        marker_replaced = False
        raw_staged_bytes = None
        validated_staged_bytes = None
        marker_staged_bytes = None

        with self.db.get_session() as session:
            try:
                from bugtrace.schemas.models import normalize_vuln_type
                vuln_type_enum = normalize_vuln_type(vuln_type)
            except Exception:
                from bugtrace.schemas.db_models import VulnType
                vuln_type_enum = VulnType.MISCONFIG
            finding_payload["reported_type"] = finding_payload["type"]
            finding_payload["type"] = vuln_type_enum.value

            existing = self.db._find_existing_finding(
                session, scan_id, vuln_type_enum,
                {"url": vuln_url or actual_target_url, "parameter": parameter},
                actual_target_url,
            )
            created = existing is None

            try:
                raw_doc = self._load_artifact_document(raw_path)
                val_doc = self._load_artifact_document(validated_path)
                canonical = self._build_canonical_finding(finding_payload, scan_id)
                self._upsert_finding_in_list(
                    raw_doc["findings"], canonical, vuln_type, parameter,
                    vuln_url or actual_target_url,
                )
                self._upsert_finding_in_list(
                    val_doc["findings"], canonical, vuln_type, parameter,
                    vuln_url or actual_target_url,
                )
                raw_doc.setdefault("scan_id", str(scan_id))
                val_doc.setdefault("scan_id", str(scan_id))
                raw_tmp = self._stage_artifact(raw_path, raw_doc)
                validated_tmp = self._stage_artifact(validated_path, val_doc)
                marker_tmp = self._stage_artifact(marker_path, {
                    "scan_id": scan_id,
                    "target_url": actual_target_url,
                    "token": uuid.uuid4().hex,
                })
                raw_staged_bytes = raw_tmp.read_bytes()
                validated_staged_bytes = validated_tmp.read_bytes()
                marker_staged_bytes = marker_tmp.read_bytes()

                if existing:
                    # Repeater is authoritative for its own canonical record;
                    # corrections may lower severity/confidence or shorten text.
                    existing.severity = severity
                    existing.details = summary
                    existing.confidence_score = confidence
                    existing.visual_validated = True
                    existing.status = FindingStatus.VALIDATED_CONFIRMED
                    existing.attack_url = vuln_url or actual_target_url
                    existing.vuln_parameter = parameter or ""
                    existing.reproduction_command = request_raw
                    existing.validator_notes = finding_payload["validator_notes"]
                    session.add(existing)
                else:
                    new_finding = self.db._create_new_finding(scan_id, vuln_type_enum, finding_payload, actual_target_url)
                    new_finding.validator_notes = finding_payload["validator_notes"]
                    session.add(new_finding)

                session.flush()
                finding_id = existing.id if existing else new_finding.id

                if not self._artifact_matches_snapshot(raw_path, raw_snapshot):
                    raise RuntimeError(f"{raw_path.name} changed concurrently")
                os.replace(raw_tmp, raw_path)
                raw_replaced = True
                raw_tmp = None
                if not self._artifact_matches_snapshot(validated_path, validated_snapshot):
                    raise RuntimeError(f"{validated_path.name} changed concurrently")
                os.replace(validated_tmp, validated_path)
                validated_replaced = True
                validated_tmp = None
                if not self._artifact_matches_snapshot(marker_path, marker_snapshot):
                    raise RuntimeError(f"{marker_path.name} changed concurrently")
                os.replace(marker_tmp, marker_path)
                marker_replaced = True
                marker_tmp = None
                self._fsync_directory(report_dir)
                session.commit()

            except Exception as exc:
                session.rollback()
                restore_errors = []
                for path, snapshot, replaced, staged_bytes in (
                    (raw_path, raw_snapshot, raw_replaced, raw_staged_bytes),
                    (validated_path, validated_snapshot, validated_replaced, validated_staged_bytes),
                    (marker_path, marker_snapshot, marker_replaced, marker_staged_bytes),
                ):
                    if not replaced:
                        continue
                    try:
                        if path.read_bytes() != staged_bytes:
                            raise RuntimeError("artifact changed after replacement")
                        self._restore_artifact(path, snapshot)
                    except Exception as restore_exc:
                        restore_errors.append(f"{path.name}: {restore_exc}")
                if restore_errors:
                    logger.critical(
                        "Repeater persistence compensation failed: "
                        + "; ".join(restore_errors)
                    )
                detail = f"Repeater persistence rolled back: {exc}"
                if restore_errors:
                    detail += "; artifact restore errors: " + "; ".join(restore_errors)
                raise RuntimeError(detail) from exc
            finally:
                for tmp in (raw_tmp, validated_tmp, marker_tmp):
                    if tmp and tmp.exists():
                        try:
                            tmp.unlink(missing_ok=True)
                        except Exception:
                            pass

        logger.info(
            f"{'Created' if created else 'Updated'} Repeater finding id={finding_id} in scan {scan_id}"
        )
        return {
            "finding_id": finding_id,
            "created": created,
            "success": True,
            "message": f"{'Created' if created else 'Updated'} finding {finding_id} in scan {scan_id}",
            "_report_dir": report_dir,
        }

    def _build_canonical_finding(self, finding_payload: dict, scan_id: int) -> dict:
        import hashlib

        proof = "\0".join(str(finding_payload.get(field, "")) for field in (
            "url", "reproduction", "response_status", "response_excerpt",
        ))
        canonical = {
            "type": finding_payload.get("type", ""),
            "reported_type": finding_payload.get("reported_type", finding_payload.get("type", "")),
            "severity": finding_payload.get("severity", "MEDIUM"),
            "url": finding_payload.get("url", ""),
            "parameter": finding_payload.get("parameter", ""),
            "status": "VALIDATED_CONFIRMED",
            "confidence": finding_payload.get("confidence", 0.95),
            "source": "ai_repeater",
            "summary": finding_payload.get("summary", ""),
            "description": finding_payload.get("summary", ""),
            "reproduction": finding_payload.get("reproduction", ""),
            "http_request": finding_payload.get("reproduction", ""),
            "http_response": finding_payload.get("response_excerpt", "")[:4000],
            "response_status": finding_payload.get("response_status"),
            "response_excerpt": finding_payload.get("response_excerpt", "")[:4000],
            "evidence": {
                "response_status": finding_payload.get("response_status"),
                "response_excerpt": finding_payload.get("response_excerpt", "")[:4000],
                "source": "ai_repeater",
            },
            "source_finding_id": finding_payload.get("source_finding_id"),
            "validator_notes": finding_payload.get("validator_notes", ""),
            "scan_id": str(scan_id),
            "evidence_fingerprint": hashlib.sha256(proof.encode("utf-8")).hexdigest(),
        }
        from bugtrace.agents.reporting_mod.finding_processor import apply_deterministic_baseline
        return apply_deterministic_baseline([canonical])[0]

    @staticmethod
    def _upsert_finding_in_list(findings: list, canonical: dict, vuln_type: str, parameter: str, url: str):
        for i, f in enumerate(findings):
            existing_reported_type = str(f.get("reported_type") or f.get("type") or "").upper()
            if (
                (f.get("type") == canonical["type"] or existing_reported_type == vuln_type.upper())
                and f.get("url") == canonical["url"]
                and f.get("parameter", "") == canonical.get("parameter", "")
            ):
                merged = {**f, **canonical}
                old_fingerprint = f.get("evidence_fingerprint")
                if not old_fingerprint:
                    import hashlib
                    old_proof = "\0".join(str(value) for value in (
                        f.get("url", ""),
                        f.get("http_request") or f.get("reproduction") or "",
                        f.get("response_status", ""),
                        f.get("http_response") or f.get("response_excerpt") or "",
                    ))
                    old_fingerprint = hashlib.sha256(old_proof.encode("utf-8")).hexdigest()
                new_fingerprint = canonical.get("evidence_fingerprint")
                enrichment_inputs_changed = (
                    old_fingerprint != new_fingerprint
                    or str(f.get("severity", "")).upper() != str(canonical.get("severity", "")).upper()
                    or (f.get("summary") or f.get("description") or "") != canonical.get("summary", "")
                    or f.get("confidence") != canonical.get("confidence")
                )
                if enrichment_inputs_changed:
                    for field in (
                        "cvss_score", "cvss_vector", "cvss_rationale", "cve",
                        "exploitation_details", "llm_reproduction_steps", "enriched",
                    ):
                        merged.pop(field, None)
                findings[i] = merged
                return
        findings.append(canonical)

    async def _find_existing_repeater_finding(
        self, scan_id: int, vuln_type: str, parameter: str, url: str
    ):
        """Find an existing AI Repeater finding matching type+url+parameter."""
        from bugtrace.schemas.db_models import FindingTable, VulnType
        from sqlmodel import select

        try:
            from bugtrace.schemas.models import normalize_vuln_type
            vuln_type_enum = normalize_vuln_type(vuln_type)
        except Exception:
            vuln_type_enum = VulnType.MISCONFIG

        with self.db.get_session() as session:
            results = session.exec(
                select(FindingTable).where(
                    FindingTable.scan_id == scan_id,
                    FindingTable.type == vuln_type_enum,
                    FindingTable.attack_url == url,
                )
            ).all()
            for r in results:
                if (r.vuln_parameter or "") == (parameter or ""):
                    return r
            return None

    def _get_last_inserted_finding_id(
        self, scan_id: int, vuln_type: str, parameter: str, url: str
    ) -> int:
        """Get the ID of the most recently inserted matching finding."""
        from bugtrace.schemas.db_models import FindingTable, VulnType
        from sqlmodel import select

        try:
            from bugtrace.schemas.models import normalize_vuln_type
            vuln_type_enum = normalize_vuln_type(vuln_type)
        except Exception:
            vuln_type_enum = VulnType.MISCONFIG

        with self.db.get_session() as session:
            results = session.exec(
                select(FindingTable).where(
                    FindingTable.scan_id == scan_id,
                    FindingTable.type == vuln_type_enum,
                ).order_by(FindingTable.id.desc())
            ).all()
            for r in results:
                if (r.vuln_parameter or "") == (parameter or "") and (r.attack_url or "") == (url or ""):
                    return r.id
            if results:
                return results[0].id
            return 0

