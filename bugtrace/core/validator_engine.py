"""
ValidationEngine v2 - OPTIMIZED

Uses AgenticValidator's batch processing for parallel validation.
Typical speedup: 3-5x over sequential processing.
"""

import asyncio
import time
from loguru import logger
from typing import Optional, List, Dict, Any
from pathlib import Path

from bugtrace.core.database import get_db_manager
from bugtrace.schemas.db_models import FindingStatus
from bugtrace.agents.agentic_validator import AgenticValidator
from bugtrace.core.ui import dashboard
from rich.live import Live
from bugtrace.core.config import settings
from bugtrace.agents.reporting import ReportingAgent


class ValidationEngine:
    """
    The 'Auditor' role in V3 - OPTIMIZED for batch processing.

    Key optimizations:
    - Uses AgenticValidator's parallel batch validation
    - Configurable batch sizes for memory management
    - Reduced per-finding timeout (30s default vs 120s)
    - Smart batching by vulnerability type
    """

    # Configuration
    BATCH_SIZE = 10  # Process in batches to manage memory
    USE_BATCH_VALIDATION = True  # Enable parallel batch processing

    def __init__(self, scan_id: Optional[int] = None, output_dir: Optional[Path] = None):
        self.scan_id = scan_id
        self.output_dir = output_dir
        self.db = get_db_manager()
        
        # Create cancellation token that will be updated by the main loop
        self._cancellation_token = {"cancelled": False}
        self.validator = AgenticValidator(cancellation_token=self._cancellation_token)
        self.is_running = False

    async def run(self, continuous: bool = False):
        """
        Main loop for validation - OPTIMIZED for batch processing.
        If continuous=True, it will keep polling the DB for new findings.
        """
        self.is_running = True
        total_start = time.time()
        
        # Setup logging redirection for dashboard
        def dashboard_sink(message):
            try:
                record = message.record
                level = record["level"].name
                text = record["message"]
                if level in ["INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"]:
                    dashboard.log(text, level)
            except Exception as e:
                logger.debug(f"Dashboard sink error: {e}")
        
        # Add sink only if it's the standalone run (avoid duplicates)
        sink_id = None
        if not dashboard.active:
            sink_id = logger.add(dashboard_sink, level="INFO")
            
        dashboard.log("🛡️  Validation Engine v2 (OPTIMIZED) initialized.", "INFO")

        if not dashboard.active:
            with Live(dashboard, refresh_per_second=4, screen=True):
                dashboard.active = True
                await self._run_validation_core(continuous)
                dashboard.active = False
        else:
            await self._run_validation_core(continuous)

        # Log total time
        total_elapsed = time.time() - total_start
        stats = self.validator.get_stats()
        dashboard.log(f"⏱️  Total validation time: {total_elapsed:.1f}s", "INFO")
        logger.info(f"Validator stats: {stats}")

        # After validation completes, generate final reports
        if not continuous:
            dashboard.log("📊 Generating final reports...", "INFO")
            output_dir = self.output_dir or self._get_default_output_dir()
            await self.generate_final_reports(output_dir)
            dashboard.log(f"✅ Reports generated in {output_dir}", "SUCCESS")
            
        if sink_id:
            logger.remove(sink_id)

    def _check_stop_requested(self) -> bool:
        """Check if user requested stop."""
        if dashboard.stop_requested:
            self._cancellation_token["cancelled"] = True
            dashboard.log("🛑 Audit stop requested. Exiting...", "WARN")
            return True
        return False

    def _handle_no_pending_findings(self, continuous: bool) -> bool:
        """Handle case when no pending findings. Returns True if should break loop."""
        if not continuous:
            dashboard.log("✅ No pending findings to validate. Audit complete.", "SUCCESS")
            return True
        dashboard.log("⏳ Waiting for new findings...", "DEBUG")
        return False

    def _get_vuln_type_str(self, finding) -> str:
        """Extract vulnerability type as uppercase string."""
        vuln_type_raw = finding.type
        if hasattr(vuln_type_raw, 'value'):
            return str(vuln_type_raw.value).upper()
        return str(vuln_type_raw or "").upper()

    def _classify_sqli_finding(self, finding, specialist_authority: List, unvalidated_sqli: List):
        """Classify SQLi finding based on SQLMap evidence or probe validation."""
        reproduction = str(finding.reproduction_command or "").lower()
        # Accept SQLMap validated OR probe-validated findings
        has_validation_evidence = (
            "sqlmap" in reproduction or
            "[probe-validated]" in reproduction
        )
        if has_validation_evidence:
            specialist_authority.append(finding)
            if "[probe-validated]" in reproduction:
                dashboard.log(f"✅ SQLi on Cookie: {finding.vuln_parameter or 'N/A'} - probe-validated (active HTTP testing)", "SUCCESS")
        else:
            unvalidated_sqli.append(finding)

    def _triage_findings(self, pending: List) -> Dict[str, List]:
        """Triage findings into categories for processing."""
        already_confirmed = []
        needs_cdp = []
        specialist_authority = []
        unvalidated_sqli = []

        for f in pending:
            self._categorize_finding(
                f, already_confirmed, needs_cdp, specialist_authority, unvalidated_sqli
            )

        return {
            "already_confirmed": already_confirmed,
            "needs_cdp": needs_cdp,
            "specialist_authority": specialist_authority,
            "unvalidated_sqli": unvalidated_sqli
        }

    def _categorize_finding(
        self,
        f,
        already_confirmed: List,
        needs_cdp: List,
        specialist_authority: List,
        unvalidated_sqli: List
    ):
        """Categorize a single finding based on status and type."""
        if f.status == "VALIDATED_CONFIRMED":
            already_confirmed.append(f)
            return

        if f.status == "PENDING_CDP_VALIDATION":
            needs_cdp.append(f)
            return

        if f.status not in ["PENDING_VALIDATION", "PENDING"]:
            return

        self._categorize_pending_finding(f, needs_cdp, specialist_authority, unvalidated_sqli)

    def _categorize_pending_finding(
        self,
        f,
        needs_cdp: List,
        specialist_authority: List,
        unvalidated_sqli: List
    ):
        """Categorize a pending finding by vulnerability type."""
        vuln_type = self._get_vuln_type_str(f)

        if vuln_type in ["XSS", "CSTI", "SSTI"]:
            needs_cdp.append(f)
        elif vuln_type in ["SQLI", "SQL"]:
            self._classify_sqli_finding(f, specialist_authority, unvalidated_sqli)
        else:
            specialist_authority.append(f)

    def _process_unvalidated_sqli(self, unvalidated_sqli: List):
        """Mark unvalidated SQLi findings as false positives."""
        for f in unvalidated_sqli:
            self.db.update_finding_status(
                f.id,
                FindingStatus.VALIDATED_FALSE_POSITIVE,
                notes="SQLi hypothesis rejected: No SQLMap validation evidence. LLM-only finding."
            )
            dashboard.log(f"❌ SQLi on {f.vuln_parameter or 'N/A'} - rejected (no SQLMap evidence)", "WARN")

    def _process_specialist_authority(self, specialist_authority: List):
        """Mark specialist authority findings as confirmed."""
        for f in specialist_authority:
            self.db.update_finding_status(
                f.id,
                FindingStatus.VALIDATED_CONFIRMED,
                notes="Confirmed by specialist agent (CDP not required)"
            )
            dashboard.log(f"✅ {f.type} on {f.vuln_parameter or 'N/A'} - specialist authority", "SUCCESS")

    async def _run_validation_core(self, continuous: bool):
        """Core validation logic separated from UI lifecycle."""
        while self.is_running:
            if self._check_stop_requested():
                break

            pending = self.db.get_pending_findings(self.scan_id)

            if not pending:
                if self._handle_no_pending_findings(continuous):
                    break
                await asyncio.sleep(5)
                continue

            dashboard.log(f"🔎 Audit: {len(pending)} findings queued for validation.", "INFO")

            # Triage findings
            categories = self._triage_findings(pending)

            # Log triage results
            dashboard.log(
                f"📊 Triage: {len(categories['already_confirmed'])} confirmed, {len(categories['needs_cdp'])} need CDP, "
                f"{len(categories['specialist_authority'])} specialist authority, {len(categories['unvalidated_sqli'])} SQLi without evidence",
                "INFO"
            )

            # Process categorized findings
            self._process_unvalidated_sqli(categories["unvalidated_sqli"])
            self._process_specialist_authority(categories["specialist_authority"])

            if categories["already_confirmed"]:
                dashboard.log(f"✅ {len(categories['already_confirmed'])} findings already validated (fast-path).", "SUCCESS")

            # Validate CDP-needed findings
            needs_cdp = categories["needs_cdp"]
            if self.USE_BATCH_VALIDATION and needs_cdp:
                dashboard.log(f"🔬 Sending {len(needs_cdp)} findings to CDP validator...", "INFO")
                await self._validate_batch_optimized(needs_cdp)
            elif needs_cdp:
                await self._validate_sequential(needs_cdp)

            if not continuous:
                break

    async def _validate_batch_optimized(self, findings_objects: List):
        """
        OPTIMIZED: Process findings in parallel batches.
        """
        # Convert DB objects to dicts
        findings_dicts = [self._table_to_dict(f) for f in findings_objects]
        finding_map = {f.id: f for f in findings_objects}  # For DB updates

        total = len(findings_dicts)
        processed = 0

        # Process in batches to manage memory
        for i in range(0, total, self.BATCH_SIZE):
            if dashboard.stop_requested:
                self._cancellation_token["cancelled"] = True
                break

            processed = await self._process_single_batch(
                findings_dicts, i, total, processed
            )

    async def _process_single_batch(
        self,
        findings_dicts: List[Dict],
        batch_start: int,
        total: int,
        processed: int
    ) -> int:
        """Process a single batch of findings."""
        batch = findings_dicts[batch_start:batch_start + self.BATCH_SIZE]
        batch_num = (batch_start // self.BATCH_SIZE) + 1
        total_batches = (total + self.BATCH_SIZE - 1) // self.BATCH_SIZE

        dashboard.log(f"🚀 Processing batch {batch_num}/{total_batches} ({len(batch)} findings)...", "INFO")

        try:
            # 5 minutes max per batch (individual findings have their own timeouts)
            results = await asyncio.wait_for(
                self.validator.validate_batch(batch),
                timeout=300.0
            )

            processed = self._update_batch_results(results, processed)
        except Exception as e:
            logger.error(f"Batch {batch_num} failed: {e}", exc_info=True)
            processed = self._mark_batch_as_error(batch, processed, e)

        dashboard.log(f"📊 Progress: {processed}/{total} findings processed", "INFO")
        return processed

    def _update_batch_results(self, results: List[Dict], processed: int) -> int:
        """Update database with batch validation results."""
        for result in results:
            finding_id = result.get("id")
            if not finding_id:
                continue

            self._update_db_from_result(finding_id, result)
            processed += 1
        return processed

    def _mark_batch_as_error(self, batch: List[Dict], processed: int, error: Exception) -> int:
        """Mark all findings in a failed batch as errors."""
        for f in batch:
            if f.get("id"):
                self.db.update_finding_status(
                    f["id"], FindingStatus.ERROR, notes=f"Batch error: {str(error)}"
                )
        return processed + len(batch)

    async def _validate_sequential(self, findings_objects: List):
        """
        Fallback sequential validation (original behavior).
        """
        for finding_obj in findings_objects:
            finding_dict = self._table_to_dict(finding_obj)
            dashboard.log(f"🕵️  Auditing {finding_dict['type']}...", "INFO")

            try:
                timeout = getattr(settings, "VALIDATION_TIMEOUT", 60)  # Reduced default
                result = await asyncio.wait_for(
                    self.validator.validate_finding_agentically(finding_dict),
                    timeout=timeout
                )
                self._update_db_from_result(finding_obj.id, result)

            except asyncio.TimeoutError:
                dashboard.log(f"⏰ TIMEOUT: {finding_dict['type']}", "WARN")
                self.db.update_finding_status(finding_obj.id, FindingStatus.ERROR, notes=f"Timeout ({timeout}s)")
            except Exception as e:
                logger.error(f"Validation crash for {finding_obj.id}: {e}", exc_info=True)
                self.db.update_finding_status(finding_obj.id, FindingStatus.ERROR, notes=str(e))

    def _update_db_from_result(self, finding_id: int, result: Dict[str, Any]):
        """Update DB based on validation result."""
        if result.get("validated"):
            dashboard.log(f"✅ CONFIRMED: Finding #{finding_id}", "SUCCESS")
            self.db.update_finding_status(
                finding_id,
                FindingStatus.VALIDATED_CONFIRMED,
                notes=result.get("reasoning", "Validated"),
                screenshot=result.get("screenshot_path")
            )
        elif result.get("needs_manual_review"):
            dashboard.log(f"⚠️ NEEDS REVIEW: Finding #{finding_id}", "WARN")
            self.db.update_finding_status(
                finding_id,
                FindingStatus.MANUAL_REVIEW_RECOMMENDED,
                notes=result.get("reasoning", "Manual review needed"),
                screenshot=result.get("screenshot_path")
            )
        else:
            dashboard.log(f"❌ FALSE POSITIVE: Finding #{finding_id}", "WARN")
            self.db.update_finding_status(
                finding_id,
                FindingStatus.VALIDATED_FALSE_POSITIVE,
                notes=result.get("reasoning", "No evidence of exploitation")
            )

    def _get_default_output_dir(self) -> Path:
        """Get default output directory for reports."""
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return settings.REPORT_DIR / f"scan_{self.scan_id}_{timestamp}"

    def _table_to_dict(self, obj):
        """Helper to convert SQLModel object to dict for agents."""
        return {
            "id": obj.id,
            "type": obj.type,
            "url": obj.attack_url,
            "parameter": obj.vuln_parameter,
            "payload": obj.payload_used,
            "severity": obj.severity
        }

    async def generate_final_reports(self, output_dir: Path):
        """Generate all report deliverables after validation is complete."""
        if not self.scan_id:
            logger.error("Cannot generate reports: no scan_id")
            return

        # Get target URL from DB
        target_url = self._get_target_url()
        if not target_url:
            logger.error("Cannot generate reports: target URL not found")
            return

        reporter = ReportingAgent(
            scan_id=self.scan_id,
            target_url=target_url,
            output_dir=output_dir
        )

        return await reporter.generate_all_deliverables()

    def _get_target_url(self) -> Optional[str]:
        """Get target URL for this scan from DB."""
        from sqlmodel import select
        from bugtrace.schemas.db_models import ScanTable, TargetTable

        with self.db.get_session() as session:
            scan = session.get(ScanTable, self.scan_id)
            if scan and scan.target_id:
                target = session.get(TargetTable, scan.target_id)
                if target:
                    return target.url
        return None

    def stop(self):
        self.is_running = False

# Singleton helper
async def run_audit(scan_id: Optional[int] = None):
    engine = ValidationEngine(scan_id)
    await engine.run()
