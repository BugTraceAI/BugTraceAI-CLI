"""ScanService shell mixin (report). Hard max 2000 LOC."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime
from urllib.parse import urlparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard

logger = get_logger(__name__)

from bugtrace.core.team import TeamOrchestrator
from bugtrace.core.event_bus import event_bus, EventType
from bugtrace.core.database import get_db_manager
from bugtrace.agents.reporting import ReportingAgent
from bugtrace.core.http_manager import http_manager


class ScanReportLoadMixin:
    """Load/filter findings from reports."""

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

        # Present like the reporting agent (pure): dedup + header consolidation
        from bugtrace.agents.reporting_mod.finding_quality import present_findings_for_api

        all_findings = present_findings_for_api(all_findings)

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

    @staticmethod
    def _dir_has_report_files(directory: Path) -> bool:
        """Check if a directory contains actual report deliverables."""
        key_files = ("final_report.md", "validated_findings.json", "raw_findings.json")
        return any((directory / f).is_file() for f in key_files)

    def _find_report_dir_for_scan(self, scan_id: int) -> Optional[Path]:
        """
        Find the report directory for a scan_id.

        Priority order:
        0. scan.report_dir from DB (v5.1 architecture)
        1. scan_{id}/ (created by ReportService API, fallback)
        2. {domain}_{timestamp}/ (created by scan pipeline, verified by scan_id)

        Validates directories contain actual report files before returning.
        """
        report_base = settings.REPORT_DIR

        try:
            with self.db.get_session() as session:
                from bugtrace.schemas.db_models import ScanTable, TargetTable
                scan = session.get(ScanTable, scan_id)
                if not scan:
                    return None
                target = session.get(TargetTable, scan.target_id)
                if not target:
                    return None

                # Pattern 0: Direct DB match (v5.1 architecture)
                if hasattr(scan, 'report_dir') and scan.report_dir:
                    db_dir = Path(scan.report_dir)
                    if db_dir.is_dir() and self._dir_has_report_files(db_dir):
                        return db_dir

                # Pattern 1: API-generated reports (scan-specific fallback)
                api_dir = report_base / f"scan_{scan_id}"
                if api_dir.is_dir() and self._dir_has_report_files(api_dir):
                    return api_dir

                # Pattern 2: Pipeline-generated reports ({domain}_{timestamp})
                # Only accept hostname matches that prove scan_id ownership.
                domain = urlparse(target.url).hostname or ""
                matches = sorted(
                    report_base.glob(f"{domain}_*"),
                    key=lambda p: p.stat().st_mtime,
                    reverse=True,
                )
                for match in matches:
                    if (
                        self._dir_has_report_files(match)
                        and self._dir_belongs_to_scan(match, scan_id)
                    ):
                        return match

        except Exception as e:
            logger.warning(f"Error resolving report dir for scan {scan_id}: {e}")

        # Last resort without DB
        api_dir = report_base / f"scan_{scan_id}"
        if api_dir.is_dir() and self._dir_has_report_files(api_dir):
            return api_dir

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

        # Completed reports expose the ReportingAgent's canonical, deduplicated
        # detection set. Specialist stage files remain a recovery fallback.
        raw_path = report_dir / "raw_findings.json"
        if raw_path.is_file():
            try:
                raw_findings = self._read_findings_file(raw_path)
                canonical = []
                for finding_id, finding in enumerate(raw_findings, 1):
                    finding = decode_finding_payloads(finding)
                    finding["_source_file"] = str(raw_path)
                    finding["_source_dir"] = "raw"
                    finding["_id"] = finding_id
                    canonical.append(finding)
                logger.debug(f"Loaded {len(canonical)} canonical detections for scan {scan_id}")
                return canonical
            except Exception as e:
                logger.warning(f"Failed to read canonical findings from {raw_path}: {e}")

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

        Supports three formats:
        - Wrapped JSON: {"findings": [...]} (nuclei_misconfig, bac_detection)
        - JSON Lines: One JSON object per line (v3.2 format)
        - JSON Array: Array of finding objects
        """
        import json

        findings = []
        content = file_path.read_text(encoding="utf-8").strip()

        if not content:
            return []

        if content.startswith("{"):
            # Try as single wrapped JSON object first (e.g. nuclei_misconfig_results.json)
            try:
                data = json.loads(content)
                if "findings" in data and isinstance(data["findings"], list):
                    return data["findings"]
                # Single finding object (one JSON object, not wrapped)
                if "finding" in data:
                    return [data["finding"]]
                # Could be a single finding dict itself
                if any(k in data for k in ("vulnerability_type", "vuln_type", "type", "severity")):
                    return [data]
            except json.JSONDecodeError:
                pass

            # Fall through to JSON Lines (one object per line)
            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
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
            explicit_status = str(finding.get("status") or "").strip().upper()
            status_aliases = {
                "VALIDATED": "VALIDATED_CONFIRMED",
                "FINDING_VALIDATED": "VALIDATED_CONFIRMED",
                "NEEDS_VALIDATION": "MANUAL_REVIEW_RECOMMENDED",
                "VALIDATION_ERROR": "MANUAL_REVIEW_RECOMMENDED",
                "NEEDS_CDP_VALIDATION": "MANUAL_REVIEW_RECOMMENDED",
            }
            canonical_statuses = {
                "PENDING_VALIDATION", "VALIDATED_CONFIRMED",
                "VALIDATED_FALSE_POSITIVE", "MANUAL_REVIEW_RECOMMENDED",
                "SKIPPED", "ERROR",
            }
            normalized_status = status_aliases.get(explicit_status, explicit_status)
            if normalized_status in canonical_statuses:
                status = normalized_status
            elif source_dir == "results":
                status = "VALIDATED_CONFIRMED"
            elif source_dir == "dry":
                status = "PENDING_VALIDATION"
            else:
                status = "PENDING_VALIDATION"

            description = self._finding_description_for_api(finding)
            details = self._normalize_details(finding)
            results.append({
                "finding_id": finding.get("_id", 0),
                "type": finding.get("type", "Unknown"),
                "severity": finding.get("severity", "MEDIUM"),
                # WEB ReportMarkdownViewer reads description / exploitation_details /
                # llm_reproduction_steps; raw specialist dumps often only have evidence.
                "description": description,
                "details": details or description,
                "exploitation_details": finding.get("exploitation_details") or description,
                "reasoning": finding.get("reasoning") or "",
                "validator_notes": finding.get("validator_notes") or "",
                "evidence": finding.get("evidence") if isinstance(finding.get("evidence"), (dict, str)) else details,
                "llm_reproduction_steps": finding.get("llm_reproduction_steps")
                or finding.get("reproduction_steps")
                or [],
                "reproduction": finding.get("reproduction") or "",
                "payload": finding.get("payload", ""),
                "url": finding.get("url", ""),
                "parameter": finding.get("parameter", ""),
                "validated": status == "VALIDATED_CONFIRMED",
                "status": status,
                "confidence": finding.get("confidence", 0.0),
                # Seed enrichment: the real request(s) that confirmed the finding,
                # auth already masked at capture time. Consumed by the WEB AI Repeater.
                "repro": finding.get("repro"),
                "http_request": finding.get("http_request"),
                "http_response": finding.get("http_response") or finding.get("response_excerpt") or "",
            })
        return results

