"""
ValidationEngine v3 - FILE-BASED

Reads findings from specialist JSON files (source of truth).
Only validates genuinely PENDING findings via CDP.
Writes results to DB in bulk at the end (DB = write-only from CLI).
"""

import asyncio
import json
import time
from loguru import logger
from typing import Optional, List, Dict, Any
from pathlib import Path

from bugtrace.core.database import get_db_manager
from bugtrace.agents.agentic_validator import AgenticValidator
from bugtrace.core.ui import dashboard
from rich.live import Live
from bugtrace.core.config import settings
from bugtrace.agents.reporting import ReportingAgent


class ValidationEngine:
    """
    The 'Auditor' role in V3 - FILE-BASED.

    Architecture: DB is WRITE-ONLY from CLI.
    - Reads findings from specialist JSON files (source of truth)
    - Only CDP-validates findings with PENDING_VALIDATION status
    - Bulk-writes all findings to DB at the end (for API/WEB to read)
    """

    BATCH_SIZE = 10
    USE_BATCH_VALIDATION = True

    def __init__(
        self,
        scan_id: Optional[int] = None,
        output_dir: Optional[Path] = None,
        scan_dir: Optional[Path] = None,
        target_url: Optional[str] = None,
    ):
        self.scan_id = scan_id
        self.output_dir = output_dir
        self.scan_dir = scan_dir or output_dir
        self.target_url = target_url
        self.db = get_db_manager()

        self._cancellation_token = {"cancelled": False}
        self.validator = AgenticValidator(cancellation_token=self._cancellation_token)
        self.is_running = False

    # ── Loading findings from files ─────────────────────────────────

    def _load_findings_from_files(self) -> List[Dict[str, Any]]:
        """
        Load findings from specialist JSON files (source of truth).

        Priority: results/ > dry/ > wet/
        Deduplicates by (url, parameter, type, payload).
        """
        if not self.scan_dir:
            logger.warning("ValidationEngine: no scan_dir set, cannot load findings")
            return []

        specialists_dir = self.scan_dir / "specialists"
        if not specialists_dir.exists():
            logger.debug(f"No specialists dir in {self.scan_dir}")
            return []

        results = []
        seen_keys = set()

        for subdir in ["results", "dry", "wet"]:
            subdir_path = specialists_dir / subdir
            if not subdir_path.exists():
                continue

            for json_file in sorted(subdir_path.glob("*.json")):
                try:
                    findings = self._read_findings_file(json_file, subdir)
                    for finding in findings:
                        dedup_key = (
                            finding.get("url", ""),
                            finding.get("parameter", ""),
                            finding.get("type", ""),
                            finding.get("payload", ""),
                        )
                        if dedup_key in seen_keys:
                            continue
                        seen_keys.add(dedup_key)
                        results.append(finding)
                except Exception as e:
                    logger.warning(f"Failed to read {json_file}: {e}")

        logger.info(f"ValidationEngine loaded {len(results)} findings from files")
        return results

    def _read_findings_file(self, file_path: Path, source_dir: str) -> List[Dict]:
        """Read findings from a specialist JSON file."""
        try:
            content = file_path.read_text(encoding="utf-8").strip()
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            return []

        if not content:
            return []

        findings = []

        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # FIX (2026-02-10): WET files are JSON Lines (one JSON per line).
            # json.loads fails on multi-line JSONL — parse line-by-line instead.
            data = None

        raw_findings = []

        if data is not None:
            # Single JSON object or array
            if isinstance(data, dict) and "findings" in data:
                raw_findings = data["findings"]
            elif isinstance(data, list):
                raw_findings = data
            elif isinstance(data, dict):
                raw_findings = [data]
        else:
            # JSON Lines fallback (WET files)
            for line in content.split("\n"):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if "finding" in entry:
                        raw_findings.append(entry["finding"])
                    else:
                        raw_findings.append(entry)
                except json.JSONDecodeError:
                    continue
            if not raw_findings:
                logger.warning(f"Invalid JSON in {file_path}")
                return []

        for f in raw_findings:
            if not isinstance(f, dict):
                continue

            # Decode base64 payloads if present
            if "payload_b64" in f and f.get("payload_b64"):
                try:
                    import base64
                    f["payload"] = base64.b64decode(f["payload_b64"]).decode("utf-8", errors="replace")
                except Exception:
                    pass

            findings.append({
                "type": f.get("type", "Unknown"),
                "url": f.get("url", ""),
                "parameter": f.get("parameter", ""),
                "payload": f.get("payload", ""),
                "severity": f.get("severity", "HIGH"),
                "status": f.get("status", "PENDING_VALIDATION"),
                "evidence": f.get("evidence") or f.get("description", ""),
                "confidence": f.get("confidence", 0.85),
                "validated": f.get("validated", False),
                "reproduction_command": f.get("reproduction_command") or f.get("reproduction", ""),
                "screenshot_path": f.get("screenshot_path") or f.get("screenshot"),
                "successful_payloads": f.get("successful_payloads"),
                "_source": source_dir,
            })

        return findings

    # ── Triage (works with dicts) ───────────────────────────────────

    def _triage_findings(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Triage finding dicts into categories."""
        already_confirmed = []
        needs_cdp = []
        specialist_authority = []
        unvalidated_sqli = []

        for f in findings:
            status = f.get("status", "")

            if status == "VALIDATED_CONFIRMED":
                already_confirmed.append(f)
                continue

            if status == "PENDING_CDP_VALIDATION":
                needs_cdp.append(f)
                continue

            if status not in ["PENDING_VALIDATION", "PENDING"]:
                continue

            # Categorize pending findings by vuln type
            vuln_type = str(f.get("type", "")).upper()

            if vuln_type in ["XSS", "CSTI", "SSTI"]:
                needs_cdp.append(f)
            elif vuln_type in ["SQLI", "SQL"]:
                self._classify_sqli_finding(f, specialist_authority, unvalidated_sqli)
            else:
                specialist_authority.append(f)

        return {
            "already_confirmed": already_confirmed,
            "needs_cdp": needs_cdp,
            "specialist_authority": specialist_authority,
            "unvalidated_sqli": unvalidated_sqli,
        }

    def _classify_sqli_finding(self, f: Dict, specialist_authority: List, unvalidated_sqli: List):
        """Classify SQLi finding based on validation evidence."""
        reproduction = str(f.get("reproduction_command", "")).lower()
        has_evidence = "sqlmap" in reproduction or "[probe-validated]" in reproduction

        if has_evidence:
            specialist_authority.append(f)
            if "[probe-validated]" in reproduction:
                dashboard.log(
                    f"✅ SQLi on Cookie: {f.get('parameter', 'N/A')} - probe-validated",
                    "SUCCESS",
                )
        else:
            unvalidated_sqli.append(f)

    # ── Main run loop ───────────────────────────────────────────────

    async def run(self, continuous: bool = False):
        """Main validation entry point."""
        self.is_running = True
        total_start = time.time()

        def dashboard_sink(message):
            try:
                record = message.record
                level = record["level"].name
                text = record["message"]
                if level in ["INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]:
                    dashboard.log(text, level)
            except Exception:
                pass

        sink_id = None
        if not dashboard.active:
            sink_id = logger.add(dashboard_sink, level="INFO")

        dashboard.log("🛡️  Validation Engine v3 (FILE-BASED) initialized.", "INFO")

        if not dashboard.active:
            with Live(dashboard, refresh_per_second=4, screen=True):
                dashboard.active = True
                await self._run_validation_core(continuous)
                dashboard.active = False
        else:
            await self._run_validation_core(continuous)

        total_elapsed = time.time() - total_start
        stats = self.validator.get_stats()
        dashboard.log(f"⏱️  Total validation time: {total_elapsed:.1f}s", "INFO")
        logger.info(f"Validator stats: {stats}")

        # FIX (2026-02-10): Report generation removed from validator.
        # Reports are generated ONCE by team.py Phase 6 (_phase_4_reporting).
        # Having it here caused double execution.

        if sink_id:
            logger.remove(sink_id)

    async def _run_validation_core(self, continuous: bool):
        """Core validation logic - reads from files, validates pending, bulk-writes to DB."""
        while self.is_running:
            if dashboard.stop_requested:
                self._cancellation_token["cancelled"] = True
                dashboard.log("🛑 Audit stop requested. Exiting...", "WARN")
                break

            # Read findings from files (NOT from DB)
            all_findings = self._load_findings_from_files()

            if not all_findings:
                if not continuous:
                    dashboard.log("✅ No findings to validate. Audit complete.", "SUCCESS")
                    break
                dashboard.log("⏳ Waiting for new findings...", "DEBUG")
                await asyncio.sleep(5)
                continue

            dashboard.log(f"🔎 Audit: {len(all_findings)} total findings loaded from files.", "INFO")

            # Triage
            categories = self._triage_findings(all_findings)

            dashboard.log(
                f"📊 Triage: {len(categories['already_confirmed'])} confirmed, "
                f"{len(categories['needs_cdp'])} need CDP, "
                f"{len(categories['specialist_authority'])} specialist authority, "
                f"{len(categories['unvalidated_sqli'])} SQLi without evidence",
                "INFO",
            )

            # Mark unvalidated SQLi as false positive (in dict)
            for f in categories["unvalidated_sqli"]:
                f["status"] = "VALIDATED_FALSE_POSITIVE"
                f["validator_notes"] = "SQLi hypothesis rejected: No SQLMap validation evidence."
                dashboard.log(f"❌ SQLi on {f.get('parameter', 'N/A')} - rejected (no SQLMap evidence)", "WARN")

            # Mark specialist authority as confirmed (in dict)
            for f in categories["specialist_authority"]:
                f["status"] = "VALIDATED_CONFIRMED"
                f["validated"] = True
                dashboard.log(f"✅ {f.get('type')} on {f.get('parameter', 'N/A')} - specialist authority", "SUCCESS")

            if categories["already_confirmed"]:
                dashboard.log(
                    f"✅ {len(categories['already_confirmed'])} findings already validated (fast-path).",
                    "SUCCESS",
                )

            # CDP validation for genuinely pending findings
            needs_cdp = categories["needs_cdp"]
            if needs_cdp:
                dashboard.log(f"🔬 Sending {len(needs_cdp)} findings to CDP validator...", "INFO")
                if self.USE_BATCH_VALIDATION:
                    await self._validate_batch(needs_cdp)
                else:
                    await self._validate_sequential(needs_cdp)

            # Bulk write ALL findings to DB (write-only)
            self._bulk_write_to_db(all_findings)

            if not continuous:
                break

    # ── CDP Validation ──────────────────────────────────────────────

    async def _validate_batch(self, findings: List[Dict]):
        """Validate findings via CDP in batches."""
        total = len(findings)
        processed = 0

        for i in range(0, total, self.BATCH_SIZE):
            if dashboard.stop_requested:
                self._cancellation_token["cancelled"] = True
                break

            batch = findings[i : i + self.BATCH_SIZE]
            batch_num = (i // self.BATCH_SIZE) + 1
            total_batches = (total + self.BATCH_SIZE - 1) // self.BATCH_SIZE

            dashboard.log(
                f"🚀 Processing batch {batch_num}/{total_batches} ({len(batch)} findings)...",
                "INFO",
            )

            try:
                results = await asyncio.wait_for(
                    self.validator.validate_batch(batch),
                    timeout=300.0,
                )
                self._apply_cdp_results(batch, results)
                processed += len(batch)
            except Exception as e:
                logger.error(f"Batch {batch_num} failed: {e}", exc_info=True)
                for f in batch:
                    f["status"] = "ERROR"
                    f["validator_notes"] = f"Batch error: {str(e)}"
                processed += len(batch)

            dashboard.log(f"📊 Progress: {processed}/{total} findings processed", "INFO")

    async def _validate_sequential(self, findings: List[Dict]):
        """Fallback sequential CDP validation."""
        for f in findings:
            dashboard.log(f"🕵️  Auditing {f.get('type')}...", "INFO")

            try:
                timeout = getattr(settings, "VALIDATION_TIMEOUT", 60)
                result = await asyncio.wait_for(
                    self.validator.validate_finding_agentically(f),
                    timeout=timeout,
                )
                self._apply_single_cdp_result(f, result)
            except asyncio.TimeoutError:
                dashboard.log(f"⏰ TIMEOUT: {f.get('type')}", "WARN")
                f["status"] = "ERROR"
                f["validator_notes"] = f"Timeout ({timeout}s)"
            except Exception as e:
                logger.error(f"Validation crash: {e}", exc_info=True)
                f["status"] = "ERROR"
                f["validator_notes"] = str(e)

    def _apply_cdp_results(self, batch: List[Dict], results: List[Dict]):
        """Apply CDP validation results to finding dicts."""
        result_map = {}
        for r in results:
            # Match by url+parameter+type since findings don't have DB ids
            key = (r.get("url", ""), r.get("parameter", ""), r.get("type", ""))
            result_map[key] = r

        for f in batch:
            key = (f.get("url", ""), f.get("parameter", ""), f.get("type", ""))
            result = result_map.get(key, {})
            self._apply_single_cdp_result(f, result)

    def _apply_single_cdp_result(self, finding: Dict, result: Dict):
        """Apply a single CDP result to a finding dict."""
        if result.get("validated"):
            dashboard.log(f"✅ CONFIRMED: {finding.get('type')} on {finding.get('parameter')}", "SUCCESS")
            finding["status"] = "VALIDATED_CONFIRMED"
            finding["validated"] = True
            finding["validator_notes"] = result.get("reasoning", "Validated by CDP")
            if result.get("screenshot_path"):
                finding["screenshot_path"] = result["screenshot_path"]
        elif result.get("needs_manual_review"):
            dashboard.log(f"⚠️ NEEDS REVIEW: {finding.get('type')} on {finding.get('parameter')}", "WARN")
            finding["status"] = "MANUAL_REVIEW_RECOMMENDED"
            finding["validator_notes"] = result.get("reasoning", "Manual review needed")
        else:
            dashboard.log(f"❌ FALSE POSITIVE: {finding.get('type')} on {finding.get('parameter')}", "WARN")
            finding["status"] = "VALIDATED_FALSE_POSITIVE"
            finding["validator_notes"] = result.get("reasoning", "No evidence of exploitation")

    # ── DB Bulk Write ───────────────────────────────────────────────

    def _bulk_write_to_db(self, findings: List[Dict]):
        """
        Bulk write all findings to DB (write-only).
        Uses save_scan_result() which handles create/update automatically.
        """
        if not self.target_url or not self.scan_id:
            logger.warning("Cannot bulk-write to DB: missing target_url or scan_id")
            return

        # Filter to findings worth persisting (skip empty/invalid)
        valid_findings = [f for f in findings if f.get("url") and f.get("type")]

        if not valid_findings:
            return

        try:
            self.db.save_scan_result(self.target_url, valid_findings, scan_id=self.scan_id)
            dashboard.log(f"💾 Bulk-wrote {len(valid_findings)} findings to DB", "INFO")
        except Exception as e:
            logger.error(f"Failed to bulk-write findings to DB: {e}", exc_info=True)

    # ── Report Generation ───────────────────────────────────────────

    async def generate_final_reports(self, output_dir: Path):
        """Generate all report deliverables after validation."""
        if not self.scan_id or not self.target_url:
            logger.error("Cannot generate reports: no scan_id or target_url")
            return

        reporter = ReportingAgent(
            scan_id=self.scan_id,
            target_url=self.target_url,
            output_dir=output_dir,
        )

        return await reporter.generate_all_deliverables()

    def stop(self):
        self.is_running = False


# Singleton helper
async def run_audit(scan_id: Optional[int] = None):
    engine = ValidationEngine(scan_id)
    await engine.run()
