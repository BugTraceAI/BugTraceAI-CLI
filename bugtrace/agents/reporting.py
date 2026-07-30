"""
ReportingAgent: Generates all 4 deliverables for a scan.

Deliverables:
1. raw_findings.json - Pre-AgenticValidator findings (for manual review)
2. validated_findings.json - Only VALIDATED_CONFIRMED findings
3. final_report.md - Triager-ready markdown with all findings
4. engagement_data.json - Structured JSON for HTML viewer
5. report.html - Static HTML that loads engagement_data.json
"""

import json
import hashlib
import math
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.database import get_db_manager
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.json_parser import safe_json_loads, extract_json_list
# ScanTable import removed: DB is write-only from CLI
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    get_reference_cve,
    normalize_severity,
    format_cve,
)
from bugtrace.agents.lfi.detection import LFI_SIGNATURES
from bugtrace.reporting.poc_format import (
    build_query_url,
    curl_form_field,
    curl_get,
    curl_raw_body,
    curl_header,
    evidence_pairs,
    md_code_block,
    md_evidence_block,
    md_injection_point,
    md_labeled_block,
    md_document_with_values,
    md_step_with_block,
    md_step_with_value,
    plain_evidence_block,
    shell_word,
    template_expression_result,
    truncate_marked,
)
import asyncio
import re

logger = get_logger("agents.reporting")


def _normalize_markdown_document(content: str) -> str:
    """Remove an accidental outer LLM fence while preserving inner code blocks."""
    lines = content.strip().splitlines()
    if not lines or not re.fullmatch(r"```(?:markdown|md|plaintext|text)?[ \t]*", lines[0], re.IGNORECASE):
        return content

    closing_index = next(
        (index for index in range(len(lines) - 1, 0, -1) if re.fullmatch(r"```[ \t]*", lines[index])),
        -1,
    )
    if closing_index < 0:
        return content

    wrapped_body = "\n".join(lines[1:closing_index])
    if not re.search(
        r"(^|\n)(?:#{1,6}\s+\S|(?:[-*+]|\d+\.)\s+\S|>\s+\S|\|.+\|\s*$)|\*\*[^*\n]+\*\*",
        wrapped_body,
    ):
        return content

    return "\n".join(lines[1:closing_index] + lines[closing_index + 1:]).strip()


class ReportingAgent(BaseAgent):
    """
    Final Agent responsible for generating all report deliverables.
    """

    def __init__(self, scan_id: int, target_url: str, output_dir: Path, tech_profile: Dict = None):
        super().__init__("ReportingAgent", "Reporting Specialist", agent_id="reporting_agent")
        self.scan_id = scan_id
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.tech_profile = tech_profile or {}
        self.db = get_db_manager()

        # Event-driven finding accumulation
        self._validated_findings: List[Dict] = []
        self._event_bus = event_bus
        self._subscribed = False

        # Enrichment tracking
        self._enrichment_failures = 0
        self._enrichment_total = 0
        self._reporting_failover_count = 0   # reporting/enrichment calls recovered via scoped provider failover
        self._nuclei_state_lock = asyncio.Lock()

    def subscribe_to_events(self) -> None:
        """
        Subscribe to validation events from the pipeline.

        Subscribes to:
        - VULNERABILITY_DETECTED: Specialist self-validated findings (VALIDATED_CONFIRMED)
        - FINDING_VALIDATED: AgenticValidator CDP-validated findings

        Call this during scan startup to enable event-driven report generation.
        """
        if self._subscribed:
            logger.warning(f"[{self.name}] Already subscribed to events")
            return

        self._event_bus.subscribe(
            EventType.VULNERABILITY_DETECTED.value,
            self._handle_vulnerability_detected
        )
        self._event_bus.subscribe(
            EventType.FINDING_VALIDATED.value,
            self._handle_finding_validated
        )

        self._subscribed = True
        logger.info(f"[{self.name}] Subscribed to vulnerability_detected and finding_validated events")

    def unsubscribe_from_events(self) -> None:
        """
        Unsubscribe from validation events.

        Call this during scan cleanup to prevent memory leaks.
        """
        if not self._subscribed:
            logger.debug(f"[{self.name}] Not subscribed, nothing to unsubscribe")
            return

        self._event_bus.unsubscribe(
            EventType.VULNERABILITY_DETECTED.value,
            self._handle_vulnerability_detected
        )
        self._event_bus.unsubscribe(
            EventType.FINDING_VALIDATED.value,
            self._handle_finding_validated
        )

        self._subscribed = False
        logger.info(f"[{self.name}] Unsubscribed from validation events")

    async def _handle_vulnerability_detected(self, data: Dict[str, Any]) -> None:
        """
        Handle vulnerability_detected events from specialist agents.

        Only processes findings with VALIDATED_CONFIRMED status (specialist self-validated).
        These are high-confidence findings that don't require CDP validation.

        Args:
            data: Event payload containing:
                - status: ValidationStatus string
                - finding: Finding dictionary
                - specialist: Specialist agent name
                - scan_context: Scan context identifier
                - validation_requires_cdp: Whether CDP validation was needed
        """
        try:
            status = data.get("status", "")

            # Only collect VALIDATED_CONFIRMED findings (skip PENDING_VALIDATION)
            if status != ValidationStatus.VALIDATED_CONFIRMED.value:
                return

            finding = data.get("finding", {}).copy()
            specialist = data.get("specialist", "unknown")

            # Enrich finding with event metadata
            finding["scan_context"] = data.get("scan_context", "")
            finding["specialist"] = specialist
            finding["validation_requires_cdp"] = data.get("validation_requires_cdp", False)
            finding["status"] = status
            finding["event_source"] = "vulnerability_detected"

            self._validated_findings.append(finding)
            logger.info(f"[{self.name}] Collected VALIDATED_CONFIRMED finding from {specialist}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to handle vulnerability_detected: {e}")

    async def _handle_finding_validated(self, data: Dict[str, Any]) -> None:
        """
        Handle finding_validated events from AgenticValidator.

        These are findings that required CDP validation and were confirmed.

        Args:
            data: Event payload containing:
                - finding: Original finding dictionary
                - validation_result: CDP validation result with reasoning/confidence
                - scan_context: Scan context identifier
        """
        try:
            finding = data.get("finding", {}).copy()
            validation_result = data.get("validation_result", {})
            specialist = finding.get("specialist", data.get("specialist", "unknown"))

            # Mark as CDP-validated
            finding["status"] = "VALIDATED"
            finding["cdp_validated"] = True
            finding["cdp_reasoning"] = validation_result.get("reasoning", "")
            finding["cdp_confidence"] = validation_result.get("confidence", 0.0)
            finding["scan_context"] = data.get("scan_context", "")
            finding["event_source"] = "finding_validated"

            self._validated_findings.append(finding)
            logger.info(f"[{self.name}] Collected CDP-VALIDATED finding from {specialist}")
        except Exception as e:
            logger.error(f"[{self.name}] Failed to handle finding_validated: {e}")

    def get_validated_findings(self) -> List[Dict]:
        """
        Get a copy of all accumulated validated findings.

        Returns:
            List of validated finding dictionaries (copy to prevent mutation)
        """
        return self._validated_findings.copy()

    def clear_validated_findings(self) -> None:
        """
        Clear all accumulated validated findings.

        Useful for testing or multi-scan scenarios where the same
        ReportingAgent instance is reused.
        """
        self._validated_findings.clear()
        logger.debug(f"[{self.name}] Cleared validated findings")

    async def run_loop(self):
        """Not used - call generate_all_deliverables() directly."""
        pass

    async def generate_all_deliverables(self) -> Dict[str, Path]:
        """
        Main entry point. Generates all 4 deliverables.

        Returns dict with paths to each deliverable.
        """
        dashboard.update_task("reporting", name="Reporting Agent", status="Generating deliverables...")
        logger.info(f"[{self.name}] Starting report generation for scan {self.scan_id}")

        # Phase 1: Setup and data collection
        self._setup_output_directories()
        all_findings, tech_stack = await self._collect_all_findings()
        self._apply_deterministic_validation_rules(all_findings)

        # Phase 2: Categorize findings
        categorized = self._categorize_findings(all_findings)

        # Consolidate and deduplicate before enrichment so LLM work matches the
        # final report population instead of spending calls on rows later merged.
        for _bucket in ("validated", "manual_review", "pending"):
            categorized[_bucket] = self._deduplicate_findings(
                self._consolidate_informational(categorized.get(_bucket, []))
            )

        # Re-enrichment is additive: preserve successful fields from the previous
        # report and request only what is still missing.
        self._restore_existing_enrichment(categorized["validated"])

        # FIX (large-scan reliability): Write raw_findings.json BEFORE enrichment
        # This ensures users always have data even if enrichment times out or crashes
        # on large scans (100+ findings). The file will be overwritten below with
        # the final version, but this acts as a safety checkpoint.
        try:
            raw_path = self.output_dir / "raw_findings.json"
            self._write_json_document_atomic(raw_path, {"findings": all_findings})
            logger.info(f"[{self.name}] Safety checkpoint: wrote {len(all_findings)} raw findings before enrichment")
        except Exception as e:
            logger.warning(f"[{self.name}] Could not write safety checkpoint: {e}")

        # Safety checkpoint #2 (stop / crash reliability): write the FULL set of downloadable
        # deliverables — final_report.md, validated_findings.json, engagement_data.json/js,
        # report.html — from the UN-enriched findings, BEFORE the slow LLM enrichment below.
        # A hard stop (STOP MISSION → task.cancel) or a crash during enrichment would otherwise
        # leave a scan with findings in the DB but NO downloadable report (404 on report.md / empty
        # ZIP). This writes a coherent (if un-enriched) report to the SAME report dir up front;
        # Phase 4 overwrites it with the fully-enriched version on a normal completion. Cheap +
        # idempotent (formatters only, no LLM); fail-open so it can never break a normal scan.
        try:
            _base_stats = self._calculate_scan_stats(all_findings)
            _base_paths = self._generate_json_reports(all_findings, categorized)
            _base_paths.update(self._generate_markdown_reports(categorized))
            _base_paths.update(self._generate_data_files(all_findings, categorized, _base_stats, tech_stack))
            _base_paths.update(self._generate_html_report(_base_paths))
            logger.info(f"[{self.name}] Safety checkpoint: wrote base deliverables (report.md/json/html) before enrichment")
        except Exception as e:
            logger.warning(f"[{self.name}] Could not write base-deliverables checkpoint: {e}")

        # Phase 2.1: Enrich findings — wrapped in a global timeout to prevent
        # infinite hangs on large scans when LLM responses are slow.
        # 20 minutes is generous but protects against truly stuck LLM calls.
        ENRICHMENT_TIMEOUT = 1200  # 20 minutes
        enriched_list = categorized["validated"] + categorized["manual_review"]
        # Track a genuine cancellation so it can be honored AFTER the report is rendered.
        # Root cause (scan 62): the hourly HTTP-session recycle (max_session_age=3600s)
        # closed the LLM connector mid-enrichment, aborting an in-flight request as a
        # CancelledError. CancelledError is a BaseException, so it slips past `except
        # Exception`, propagates out of reporting, and gets mislabeled as a scan
        # cancellation — Phase 4 never runs and the on-disk report stays at the un-enriched
        # base checkpoint (empty CVSS/PoC). We now catch it at EVERY await in this section,
        # ALWAYS render (Phase 4 is synchronous) below, then re-raise a real cancellation
        # after the report is written. (Fix A stops the recycle from cancelling in-flight
        # requests in the first place; this is the reporting-side safety net.)
        _interrupted: Optional[asyncio.CancelledError] = None
        try:
            await asyncio.wait_for(
                self._enrich_findings_batch(enriched_list),
                timeout=ENRICHMENT_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.error(
                f"[{self.name}] Enrichment timed out after {ENRICHMENT_TIMEOUT}s for scan {self.scan_id}. "
                f"Proceeding with partial enrichment ({self._enrichment_total - self._enrichment_failures} enriched)."
            )
            dashboard.log(
                f"[Reporting] Enrichment timed out — report will use partial CVSS/PoC data.",
                "WARN"
            )
        except asyncio.CancelledError as e:
            _interrupted = e
            logger.warning(
                f"[{self.name}] Enrichment interrupted (cancelled) for scan {self.scan_id}; "
                f"rendering report with partial data before honoring cancellation."
            )
        except Exception as e:
            logger.error(f"[{self.name}] Enrichment failed with unexpected error: {e}. Proceeding anyway.")

        # Apply deterministic class rules before persistence and rendering.
        self._apply_deterministic_severity_rules(enriched_list)
        self._apply_severity_floor(categorized["validated"])
        self._normalize_cvss_severities(enriched_list)

        # Phase 2.2: Persist enriched severity/confidence back to DB
        self.db.update_findings_from_enrichment(self.scan_id, enriched_list)

        # Phase 2.5b: LLM-enrich the GROUPED Nuclei findings — analyze the consolidated entry
        # (template + evidence + affected endpoints) into a grounded description/impact/
        # remediation. Runs on the ~10 grouped entries, NOT the 50 raw hits (cheap), and is
        # fail-open: any error/LLM-outage leaves the deterministic synthesis from
        # _synthesize_description/_render_evidence_dict intact. Skipped if enrichment was
        # already interrupted, so a STOP goes straight to render instead of doing more LLM work.
        if _interrupted is None:
            try:
                await asyncio.wait_for(
                    self._enrich_nuclei_findings_llm(
                        categorized["validated"] + categorized["manual_review"] + categorized["pending"]
                    ),
                    timeout=300,
                )
            except asyncio.CancelledError as e:
                _interrupted = e
                logger.warning(
                    f"[{self.name}] Nuclei enrichment interrupted (cancelled) for scan {self.scan_id}; "
                    f"rendering report with partial data before honoring cancellation."
                )
            except Exception as e:
                logger.warning(f"[{self.name}] Nuclei LLM enrichment skipped ({e}); using deterministic descriptions.")

        # Phase 2.6: Upgrade silent payloads to visual PoC for report quality
        from bugtrace.agents.reporting_mod.finding_processor import upgrade_finding_payloads
        categorized["validated"] = upgrade_finding_payloads(categorized["validated"])
        categorized["manual_review"] = upgrade_finding_payloads(categorized["manual_review"])

        # Phase 2.7: make the narrative's quoted values survive the markdown renderer.
        #
        # This runs HERE, after the upgrade, and not inside the enrichment producers,
        # because enrichment happens BEFORE Phase 2.6: the payload the model quoted is
        # not the payload the report finally ships, so protecting it at write time
        # protects a string that is about to be replaced. This is the first point where
        # the prose and the payload are both final, and doing it once covers all three
        # producers (batch, individual, deterministic fallback) instead of three copies.
        self._protect_narrative_values(categorized["validated"] + categorized["manual_review"])

        # LLM output cannot override evidence-backed classifications or introduce
        # unsupported RCE/CVE claims into client-facing narratives.
        report_findings = categorized["validated"] + categorized["manual_review"] + categorized["pending"]
        self._apply_deterministic_severity_rules(report_findings)
        self._apply_deterministic_content_rules(report_findings)
        self._sanitize_manual_review_findings(categorized["manual_review"])

        # Phase 2.7: Severity floor (authoritative, POST-enrichment). The LLM PoC
        # enrichment above can reset severity back to the specialist's value,
        # deflating proven RCE/SQLi/Deser/SSTI/CSTI to MEDIUM. Re-apply the floor
        # here as the LAST severity authority before any deliverable is generated,
        # so JSON + Markdown + data files all agree. (Also applied pre-enrichment in
        # _categorize_findings, but that gets overwritten by enrichment.)
        self._apply_severity_floor(categorized["validated"])
        self._normalize_cvss_severities(report_findings)

        # Compute the artifact status before rendering so JSON/JS, DB, and events
        # all expose the same truth-based result.
        pre_render_audit = self._audit_enrichment_completeness(categorized["validated"])
        self._audited_enrichment_status = pre_render_audit["status"]

        # Phase 3: Calculate statistics
        stats = self._calculate_scan_stats(all_findings)

        # Phase 4: Generate all report deliverables
        paths = self._generate_json_reports(all_findings, categorized)
        paths.update(self._generate_markdown_reports(categorized))
        paths.update(self._generate_data_files(all_findings, categorized, stats, tech_stack))
        paths.update(self._generate_html_report(paths))

        # Phase 5: Organize artifacts
        self._copy_screenshots(all_findings, self.output_dir / "captures")

        # Completeness audit (truth-based) — the last-line detector for "the report came
        # out empty". It inspects the ACTUAL cvss_score/exploitation fields of the confirmed
        # findings that were just written, NOT the _enrichment_failures counter (which a
        # mid-enrichment cancellation can bypass, leaving it falsely reading "full"). Runs
        # here because Phase 4 always runs, so it can never be skipped.
        audit = self._audit_enrichment_completeness(categorized.get("validated", []))
        enrichment_status = audit["status"]
        if enrichment_status != "full":
            logger.warning(
                f"[{self.name}] Completeness audit for scan {self.scan_id}: "
                f"{audit['missing_cvss']}/{audit['confirmed']} confirmed findings missing CVSS, "
                f"{audit['missing_exploitation']} missing exploitation "
                f"→ enrichment_status={enrichment_status}. Report is downloadable but "
                f"under-enriched; re-enrich when the LLM is available."
            )
            dashboard.log(
                f"[Reporting] {audit['missing_cvss']}/{audit['confirmed']} confirmed findings "
                f"lack CVSS/PoC — report under-enriched (status={enrichment_status}). Use re-enrich.",
                "WARN",
            )

        # Persist the TRUTH-based status (supersedes the bypassable counter)
        self.db.update_scan_enrichment_status(self.scan_id, enrichment_status)

        # Best-effort live signal for the UI (skipped on a genuine cancel, where awaiting
        # the emit could re-raise; the DB status above is the durable record either way).
        if enrichment_status != "full" and _interrupted is None:
            try:
                await self._event_bus.emit(EventType.ENRICHMENT_DEGRADED, {
                    "scan_id": self.scan_id,
                    "total": audit["confirmed"],
                    "enriched": max(0, audit["confirmed"] - max(
                        audit["missing_cvss"], audit["missing_exploitation"],
                    )),
                    "failed": max(audit["missing_cvss"], audit["missing_exploitation"]),
                    "enrichment_status": enrichment_status,
                    "message": (
                        f"{audit['missing_cvss']} missing CVSS and "
                        f"{audit['missing_exploitation']} missing PoC out of "
                        f"{audit['confirmed']} confirmed findings."
                    ),
                })
            except Exception:
                pass

        dashboard.log(f"[{self.name}] Generated {len(paths)} deliverables in {self.output_dir}", "SUCCESS")

        # If enrichment was genuinely cancelled (a real STOP), honor it now — AFTER the
        # report is on disk — so the scan is still marked stopped, but with a complete,
        # enriched deliverable set instead of losing the report entirely. Everything from
        # Phase 3 down is synchronous, so it always completes before this re-raise.
        if _interrupted is not None:
            raise _interrupted

        return paths

    def _setup_output_directories(self):
        """Create necessary output directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "captures").mkdir(exist_ok=True)

    async def _collect_all_findings(self) -> tuple[List[Dict], Dict]:
        """
        Collect all findings from specialist result files.

        v3.2: Files are the source of truth, not the database.
        - specialists/results/*.json = validated findings from each specialist
        - Database is only for process tracking/resume

        Returns:
            (all_findings, tech_stack) tuple
        """
        # Primary source: specialist result files
        all_findings = self._load_specialist_results()
        logger.info(f"[{self.name}] Loaded {len(all_findings)} findings from specialists/results/")

        # Repeater findings are created after specialists and reporting finish.
        # Re-import only these persisted rows so re-enrichment cannot erase them.
        repeater_findings = self._load_persisted_repeater_findings()
        if repeater_findings:
            all_findings.extend(repeater_findings)
            all_findings = self._deduplicate_exact(all_findings)
            logger.info(f"[{self.name}] Added {len(repeater_findings)} persisted AI Repeater findings")

        # Fallback to DB if no files found (backward compatibility)
        if not all_findings:
            logger.warning(f"[{self.name}] No specialist results found, falling back to DB")
            all_findings = self._get_findings_from_db()
            logger.info(f"[{self.name}] Retrieved {len(all_findings)} findings from DB (fallback)")

        # Add Nuclei findings
        nuclei_findings, tech_stack = self._load_nuclei_findings()
        if nuclei_findings:
            all_findings.extend(nuclei_findings)
            logger.info(f"[{self.name}] Added {len(nuclei_findings)} Nuclei findings")

        return all_findings, tech_stack

    def _load_persisted_repeater_findings(self) -> List[Dict]:
        """Load post-scan Repeater findings from the canonical validated artifact."""
        path = self.output_dir / "validated_findings.json"
        if not path.is_file():
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning(f"[{self.name}] Could not load persisted Repeater findings: {exc}")
            return []
        if not isinstance(data, dict):
            return []
        rows = list(data.get("findings", [])) + list(data.get("manual_review", []))
        return [
            dict(finding)
            for finding in rows
            if isinstance(finding, dict) and finding.get("source") == "ai_repeater"
        ]

    def _load_specialist_results(self) -> List[Dict]:
        """
        Load findings from specialist report files.

        v3.2: Reads from MULTIPLE sources (in priority order):
        1. specialists/*_report.json - REAL exploitation results from specialist agents
        2. specialists/results/*_results.json - Generated by team.py from wet/ files

        Returns:
            List of findings from all specialist files
        """
        from bugtrace.core.payload_format import decode_finding_payloads

        all_findings = []
        specialists_dir = self.output_dir / "specialists"

        if not specialists_dir.exists():
            logger.debug(f"[{self.name}] specialists/ directory not found")
            return []

        # Priority 1: Load from specialist *_report.json files (REAL exploitation results)
        # These are written by specialist agents (xss_agent, sqli_agent, etc.) after exploitation
        for report_file in specialists_dir.glob("*_report.json"):
            findings = self._load_findings_from_report_file(report_file, decode_finding_payloads)
            all_findings.extend(findings)

        # Priority 2: Load from results/*_results.json (team.py generated from wet/)
        results_dir = specialists_dir / "results"
        if results_dir.exists():
            for result_file in results_dir.glob("*_results.json"):
                findings = self._load_findings_from_results_file(result_file, decode_finding_payloads)
                all_findings.extend(findings)

        # Priority 3: Load from wet/*.json (raw findings from ThinkingAgent)
        wet_dir = specialists_dir / "wet"
        if wet_dir.exists() and not all_findings:
            for wet_file in wet_dir.glob("*.json"):
                findings = self._load_findings_from_wet_file(wet_file, decode_finding_payloads)
                all_findings.extend(findings)
            logger.info(f"[{self.name}] Loaded {len(all_findings)} findings from wet/ (fallback)")

        # Deduplicate by exact (url, parameter, payload) match
        all_findings = self._deduplicate_exact(all_findings)

        logger.info(f"[{self.name}] Loaded {len(all_findings)} total findings from specialist files")
        return all_findings

    def _load_findings_from_report_file(self, report_file: Path, decode_fn) -> List[Dict]:
        """Load findings from specialist *_report.json file."""
        findings = []
        try:
            with open(report_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Specialist reports have various structures
            report_findings = data.get("validated_findings", []) or data.get("findings", []) or data.get("results", [])
            specialist = data.get("specialist", report_file.stem.replace("_report", ""))

            for finding in report_findings:
                finding = decode_fn(finding)
                finding["source"] = f"specialist_report:{specialist}"
                # Mark as validated if from specialist report (they self-validate)
                if not finding.get("status"):
                    finding["status"] = "VALIDATED_CONFIRMED"
                findings.append(finding)

            if findings:
                logger.debug(f"[{self.name}] Loaded {len(findings)} from {report_file.name}")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load {report_file}: {e}")

        return findings

    def _load_findings_from_results_file(self, result_file: Path, decode_fn) -> List[Dict]:
        """Load findings from results/*_results.json file."""
        findings = []
        try:
            with open(result_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            result_findings = data.get("findings", [])
            specialist = data.get("specialist", result_file.stem.replace("_results", ""))

            for i, finding in enumerate(result_findings):
                try:
                    finding = decode_fn(finding)
                    finding["source"] = f"specialist:{specialist}"
                    # Add status fallback for findings from specialist results (they self-validate)
                    if not finding.get("status"):
                        finding["status"] = "VALIDATED_CONFIRMED"
                    findings.append(finding)
                except Exception as e:
                    logger.warning(
                        f"[{self.name}] Skipping corrupt finding #{i} in {result_file.name}: {e}"
                    )

            if findings:
                logger.debug(f"[{self.name}] Loaded {len(findings)} from {result_file.name}")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load {result_file}: {e}")

        return findings

    def _load_findings_from_wet_file(self, wet_file: Path, decode_fn) -> List[Dict]:
        """Load findings from wet/*.json file (JSON Lines format)."""
        findings = []
        try:
            with open(wet_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        finding = entry.get("finding", entry)
                        finding = decode_fn(finding)
                        specialist = entry.get("specialist", wet_file.stem)
                        finding["source"] = f"wet:{specialist}"
                        # WET files are raw observations, not validation verdicts.
                        if not finding.get("status"):
                            finding["status"] = "PENDING_VALIDATION"
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load {wet_file}: {e}")

        return findings

    def _deduplicate_exact(self, findings: List[Dict]) -> List[Dict]:
        """Deduplicate findings by exact (url, parameter, payload) key."""
        positions = {}
        unique = []
        for f in findings:
            key = (
                self._normalize_type_for_dedup(f.get("type", "Unknown")),
                f.get("url"), f.get("parameter"), f.get("payload"),
            )
            if key not in positions:
                positions[key] = len(unique)
                unique.append(f)
            else:
                index = positions[key]
                unique[index] = self._merge_duplicate_finding_records(unique[index], f)
        return unique

    @staticmethod
    def _merge_duplicate_finding_records(first: Dict, second: Dict) -> Dict:
        """Merge duplicates while treating Repeater HTTP proof as authoritative."""
        first_repeater = first.get("source") == "ai_repeater"
        second_repeater = second.get("source") == "ai_repeater"
        if second_repeater and not first_repeater:
            merged = {**first, **second}
            authoritative = second
        elif first_repeater and not second_repeater:
            merged = {**second, **first}
            authoritative = first
        else:
            merged = dict(first)
            for key, value in second.items():
                if merged.get(key) in (None, "", [], {}):
                    merged[key] = value
            return merged

        # Never borrow CVSS/PoC from a specialist row for fresh Repeater proof.
        for field in (
            "cvss_score", "cvss_vector", "cvss_rationale", "cve",
            "exploitation_details", "llm_reproduction_steps", "enriched",
        ):
            if authoritative.get(field) in (None, "", []):
                merged.pop(field, None)
        return merged

    def _merge_event_findings(self, db_findings: List[Dict]) -> List[Dict]:
        """
        Merge event-sourced validated findings with database findings.

        NOTE: Currently unused — all specialists now write *_results.json files
        that are picked up by _load_specialist_results(). Kept for potential
        future use if an agent needs event-bus-only reporting.

        Deduplicates based on (url, parameter, payload) to prevent duplicates.
        Event findings are marked with source='event_bus'.
        """
        event_findings = self.get_validated_findings()
        if not event_findings:
            return db_findings

        # Build deduplication key function
        def dedup_key(f: Dict) -> tuple:
            return (f.get("url"), f.get("parameter"), f.get("payload"))

        # Create seen keys set from DB findings
        seen_keys = set(dedup_key(f) for f in db_findings)

        # Mark DB findings with source
        for f in db_findings:
            if "source" not in f:
                f["source"] = "database"

        # Merge non-duplicate event findings
        merged = list(db_findings)
        added_count = 0

        for event_finding in event_findings:
            key = dedup_key(event_finding)
            if key not in seen_keys:
                # Convert to DB-compatible format
                formatted = self._event_finding_to_db_format(event_finding)
                merged.append(formatted)
                seen_keys.add(key)
                added_count += 1

        logger.info(f"[{self.name}] Merged {added_count} event findings with {len(db_findings)} DB findings")
        return merged

    def _event_finding_to_db_format(self, event_finding: Dict) -> Dict:
        """
        Convert event finding structure to DB-compatible structure.

        Args:
            event_finding: Finding from event bus accumulator

        Returns:
            Dictionary with DB-compatible field names
        """
        evidence = event_finding.get("evidence", {})
        if not isinstance(evidence, dict):
            evidence = {}

        return {
            "id": None,  # Event findings don't have DB IDs
            "type": event_finding.get("type") or event_finding.get("vuln_type", "Unknown"),
            "severity": event_finding.get("severity", "HIGH"),
            "url": event_finding.get("url", ""),
            "parameter": event_finding.get("parameter", ""),
            "payload": event_finding.get("payload", ""),
            "description": event_finding.get("description") or evidence.get("description", ""),
            "status": event_finding.get("status", "VALIDATED_CONFIRMED"),
            "validator_notes": event_finding.get("cdp_reasoning") or event_finding.get("reasoning", ""),
            "screenshot_path": event_finding.get("screenshot_path"),
            "validation_method": event_finding.get("validation_method", "event_bus"),
            "source": "event_bus",
            # Preserve event-specific metadata
            "specialist": event_finding.get("specialist"),
            "scan_context": event_finding.get("scan_context"),
            "cdp_validated": event_finding.get("cdp_validated", False),
            "cdp_confidence": event_finding.get("cdp_confidence"),
        }

    def _categorize_findings(self, all_findings: List[Dict]) -> Dict[str, List[Dict]]:
        """
        Categorize findings by validation status.

        Handles both:
        - VALIDATED_CONFIRMED: Specialist self-validated (no CDP needed)
        - VALIDATED: CDP-validated findings from AgenticValidator
        """
        # Define validated status values (both specialist and CDP confirmed)
        validated_statuses = {
            "VALIDATED_CONFIRMED",  # Specialist self-validated
            "VALIDATED",  # CDP validated (from finding_validated events)
            ValidationStatus.VALIDATED_CONFIRMED.value,
            ValidationStatus.FINDING_VALIDATED.value if hasattr(ValidationStatus, 'FINDING_VALIDATED') else "FINDING_VALIDATED",
        }

        categorized = {
            "raw": [f for f in all_findings],
            "validated": [
                f for f in all_findings
                if f.get("status") in validated_statuses
                and self._has_minimum_evidence(f)
                and self._meets_report_quality(f)
            ],
            "manual_review": [
                f for f in all_findings
                if self._is_manual_review_status(f)
                or (f.get("status") in validated_statuses
                    and (not self._has_minimum_evidence(f)
                         or not self._meets_report_quality(f)))
            ],
            "false_positives": [f for f in all_findings if f.get("status") == "VALIDATED_FALSE_POSITIVE"],
            "pending": [f for f in all_findings if f.get("status") == "PENDING_VALIDATION"]
        }
        # Quality-gate routing is a classification decision, not only a display
        # bucket. Persist it on the finding so raw JSON and API consumers agree.
        for finding in categorized["manual_review"]:
            if finding.get("status") in validated_statuses:
                finding["status"] = "MANUAL_REVIEW_RECOMMENDED"
                finding["validated"] = False
                finding.setdefault(
                    "manual_review_reason",
                    "The finding did not meet the report evidence quality gate.",
                )
        # Backfill a default severity on any REPORTED finding that arrives without one (XSS/IDOR/
        # SSRF leave it to enrichment/CVSS). Runs before the floor so pre-enrichment reports
        # (stopped/crashed scan, base-deliverables checkpoint) never show blank severity badges.
        for _bucket in ("validated", "manual_review", "pending"):
            self._fill_missing_severity(categorized[_bucket])
        # Severity floor: confirmed high-impact classes (RCE/SQLi/Deserialization/
        # SSTI/CSTI/XXE) must never be reported below their floor. The skeptic/
        # validation pass was deflating proven criticals to MEDIUM, burying them
        # under header noise. Applied centrally so JSON + Markdown + HTML agree.
        self._apply_severity_floor(categorized["validated"])
        return categorized

    _MANUAL_REVIEW_STATUSES = {
        "MANUAL_REVIEW_RECOMMENDED", "NEEDS_VALIDATION",
        "VALIDATION_ERROR", "NEEDS_CDP_VALIDATION",
    }
    _CONFIRMED_STATUSES = {
        "VALIDATED_CONFIRMED", "VALIDATED", "FINDING_VALIDATED",
    }

    @classmethod
    def _is_manual_review_status(cls, finding: Dict) -> bool:
        return str(finding.get("status", "")).upper() in cls._MANUAL_REVIEW_STATUSES

    @classmethod
    def _is_confirmed_status(cls, finding: Dict) -> bool:
        return str(finding.get("status", "")).upper() in cls._CONFIRMED_STATUSES

    @staticmethod
    def _sanitize_manual_review_findings(findings: List[Dict]) -> None:
        """Manual-review rows may show evidence, never generated exploit claims."""
        for finding in findings:
            for field in (
                "exploitation_details", "llm_reproduction_steps",
                "poc_enrichment_provenance",
            ):
                finding.pop(field, None)
            finding["enriched"] = False

    # Confirmed high-impact vuln classes must never be reported below this floor
    # (type substring -> minimum severity). Generic and target-independent.
    _SEVERITY_FLOOR = {
        "rce": "Critical", "remote code": "Critical", "command inj": "Critical",
        "deserial": "Critical",
        "sqli": "High", "sql injection": "High",
        "ssti": "High", "template injection": "High", "csti": "High",
        "xxe": "High",
    }
    _SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    # CVSS band minimums — keep the numeric score consistent when the floor raises
    # severity. A HIGH badge next to a MEDIUM-band CVSS reads as a self-contradicting
    # row; raise the score to the band floor (only ever upward) so both agree.
    _SEVERITY_CVSS_FLOOR = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "info": 0.0}

    # Default severity for confirmed findings whose specialist leaves severity to the
    # enrichment/CVSS pass (XSS/IDOR/SSRF/open-redirect arrive with severity=None). Used ONLY to
    # backfill a MISSING severity — never to override an assigned one. (type substring -> default)
    _DEFAULT_SEVERITY = {
        "xss": "Medium",
        "idor": "Medium",
        "ssrf": "Medium",
        "open redirect": "Low", "openredirect": "Low", "open_redirect": "Low",
        "prototype pollution": "Medium",
    }

    def _fill_missing_severity(self, findings: List[Dict]) -> None:
        """Backfill a sensible default severity on reported findings that arrive WITHOUT one.
        Some specialists (XSS/IDOR/SSRF) leave severity to the enrichment/CVSS pass, so a report
        written BEFORE enrichment — a stopped/crashed scan, or the pre-enrichment safety
        checkpoint — would otherwise render blank severity badges. Only fills None/empty; never
        overrides an existing value (a completed/enriched report is unchanged). Mutates in place."""
        for f in findings:
            sev = f.get("severity")
            if sev is not None and str(sev).strip():
                continue
            ftype = str(f.get("type", "")).lower()
            default = "Medium"
            for key, dv in self._DEFAULT_SEVERITY.items():
                if key in ftype:
                    default = dv
                    break
            f["severity"] = default
            f["_severity_defaulted"] = True

    def _apply_severity_floor(self, findings: List[Dict]) -> None:
        """Raise (never lower) the severity of confirmed high-impact findings to
        their type floor. Fixes the skeptic deflating proven RCE/SQLi/deser to
        MEDIUM and burying crown-jewel findings under header noise. Mutates in
        place; only raises, never lowers."""
        for f in findings:
            ftype = str(f.get("type", "")).lower()
            engine_type = str(
                f.get("engine_type")
                or (f.get("csti_metadata") or {}).get("type", "")
            ).lower()
            # Client-side template injection has reflected/DOM-XSS semantics and
            # requires victim interaction. It must not inherit the server-side floor.
            if ("csti" in ftype or "template injection" in ftype) and engine_type == "client-side":
                continue
            cur_rank = self._SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 2)
            for key, floor in self._SEVERITY_FLOOR.items():
                if key in ftype:
                    if cur_rank < self._SEVERITY_RANK.get(floor.lower(), 3):
                        f["_severity_floored_from"] = f.get("severity")
                        f["severity"] = floor
                        # Keep CVSS consistent with the raised severity (never lower it).
                        band_min = self._SEVERITY_CVSS_FLOOR.get(floor.lower())
                        cur_cvss = f.get("cvss_score")
                        if band_min is not None and (
                            not isinstance(cur_cvss, (int, float)) or cur_cvss < band_min
                        ):
                            f["cvss_score"] = band_min
                    break

    @staticmethod
    def _get_js_component_policy(finding: Dict) -> Optional[Dict]:
        """Resolve a detected JS component through the scanner's advisory registry."""
        identifiers = " ".join(str(finding.get(key, "")) for key in (
            "parameter", "payload", "nuclei_template", "template_id"
        )).lower()
        match = re.search(r"js-vulnerable-([a-z0-9_-]+)", identifiers)
        if not match:
            return None

        from bugtrace.agents.nuclei.core import KNOWN_VULNERABLE_JS
        return KNOWN_VULNERABLE_JS.get(match.group(1))

    def _apply_deterministic_severity_rules(self, findings: List[Dict]) -> None:
        """Apply evidence-backed rules where generic LLM scoring is ambiguous."""
        for finding in findings:
            finding_type = str(finding.get("type", "")).lower()
            engine_type = str(
                finding.get("engine_type")
                or (finding.get("csti_metadata") or {}).get("type", "")
            ).lower()
            component_policy = self._get_js_component_policy(finding)

            if component_policy:
                severity = str(component_policy.get("severity", "low")).upper()
                representative_cvss = {
                    "INFO": 0.0,
                    "LOW": 3.1,
                    "MEDIUM": 5.4,
                    "HIGH": 7.5,
                    "CRITICAL": 9.8,
                }[severity]
                cves = component_policy.get("cves", [])
                finding.update({
                    "severity": severity,
                    "cvss_score": representative_cvss,
                    "cvss_rationale": (
                        "Severity comes from the vulnerable JavaScript component registry. "
                        "Version detection alone does not prove an exploitable application path."
                    ),
                    "cve": cves[0] if cves else None,
                    "cve_id": cves[0] if cves else "N/A",
                })
                finding.pop("cvss_vector", None)
            elif ("csti" in finding_type or "template injection" in finding_type) and engine_type == "client-side":
                finding.update({
                    "severity": "MEDIUM",
                    "cvss_score": 6.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "cvss_rationale": (
                        "Confirmed client-side template injection executes in the victim's "
                        "browser and requires user interaction; it is not server-side RCE."
                    ),
                })
            elif ("csti" in finding_type or "template injection" in finding_type) and engine_type == "server-side":
                if not self._has_template_code_execution_proof(finding):
                    finding.update({
                        "severity": "HIGH",
                        "cvss_score": 8.1,
                        "cvss_rationale": (
                            "Server-side expression evaluation is confirmed, but no file access, "
                            "command output, callback, or code execution was demonstrated."
                        ),
                    })
                    finding.pop("cvss_vector", None)
            elif "deserial" in finding_type and finding.get("status") == "MANUAL_REVIEW_RECOMMENDED":
                finding.update({
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cvss_rationale": (
                        "A reachable unsafe deserialization sink is present, but the probe "
                        "did not demonstrate a gadget chain or code execution. Manual review is required."
                    ),
                })

    @staticmethod
    def _has_deserialization_execution_proof(finding: Dict) -> bool:
        """Require structured proof before treating an unsafe sink as executed RCE."""
        proof_flags = (
            "rce_confirmed",
            "code_execution_confirmed",
            "oob_confirmed",
            "gadget_chain_confirmed",
        )
        if any(finding.get(flag) is True for flag in proof_flags):
            return True

        method = str(finding.get("validation_method", "")).lower()
        evidence = " ".join(str(finding.get(key, "")) for key in (
            "evidence", "http_response", "validator_notes", "execution_evidence"
        )).lower()
        return (
            ("oob" in method and ("callback" in evidence or "interaction" in evidence))
            or "gadget chain executed" in evidence
            or "code execution confirmed" in evidence
            or "command output captured" in evidence
        )

    @staticmethod
    def _has_template_code_execution_proof(finding: Dict) -> bool:
        """Distinguish expression evaluation from demonstrated server-side execution."""
        if any(finding.get(flag) is True for flag in (
            "rce_confirmed", "code_execution_confirmed", "oob_confirmed"
        )):
            return True
        evidence = " ".join(str(finding.get(key, "")) for key in (
            "evidence", "http_response", "validator_notes", "execution_evidence"
        )).lower()
        return any(marker in evidence for marker in (
            "command output captured",
            "code execution confirmed",
            "file read confirmed",
            "oob callback received",
        ))

    @staticmethod
    def _is_unresolved_lfi_probe(finding: Dict) -> bool:
        """Identify a scanner traversal probe that lacks an injectable sink."""
        finding_type = str(finding.get("type", "")).lower()
        url = str(finding.get("url", "")).lower()
        is_lfi = "local file inclusion" in finding_type or "lfi" in finding_type
        is_scanner_finding = finding_type.startswith("nuclei:") or finding.get("source") == "nuclei"
        has_traversal_path = "../" in url or "%2e%2e" in url
        parameter = str(finding.get("parameter", "")).lower()
        has_real_sink = bool(parameter) and parameter not in {
            "local file inclusion",
            "nginx server - local file inclusion",
            "unknown",
        }
        # A missing application-level parameter doesn't mean the probe is unresolved
        # if the captured response contains actual file content (e.g. /etc/passwd,
        # win.ini) — that's proof on its own, with or without an identified sink.
        response = " ".join(str(finding.get(key, "")) for key in ("nuclei_response", "http_response"))
        has_file_content_proof = any(signature in response for signature in LFI_SIGNATURES)
        return is_lfi and is_scanner_finding and has_traversal_path and not has_real_sink and not has_file_content_proof

    def _apply_deterministic_validation_rules(self, findings: List[Dict]) -> None:
        """Downgrade sink-only deserialization evidence before bucket selection."""
        for finding in findings:
            finding_type = str(finding.get("type", "")).lower()
            parameter = str(finding.get("parameter", ""))
            evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
            url_path = str(finding.get("url", "")).lower().split("?", 1)[0]

            if "deserial" in finding_type and not self._has_deserialization_execution_proof(finding):
                finding.update({
                    "status": "MANUAL_REVIEW_RECOMMENDED",
                    "validated": False,
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cvss_rationale": (
                        "The response proves a reachable unsafe deserialization sink, but no "
                        "gadget chain or code execution was demonstrated."
                    ),
                    "manual_review_reason": (
                        "Confirm accepted serialized types and gadget availability with a safe, authorized proof."
                    ),
                })
            elif "sqli" in finding_type and parameter.lower().startswith("header:"):
                if "baseline_db_type" not in evidence:
                    finding.update({
                        "status": "MANUAL_REVIEW_RECOMMENDED",
                        "validated": False,
                        "severity": "MEDIUM",
                        "manual_review_reason": (
                            "Legacy header SQLi evidence lacks a baseline comparison proving the DB signal was introduced."
                        ),
                    })
            elif "broken access control" in finding_type:
                if finding.get("validation_method") == "unauthenticated_admin_access" and not any(
                    marker in url_path for marker in ("/admin", "/internal", "/management")
                ):
                    finding.update({
                        "status": "MANUAL_REVIEW_RECOMMENDED",
                        "validated": False,
                        "severity": "MEDIUM",
                        "manual_review_reason": (
                            "The endpoint is not an administrative or restricted route; HTTP 200 alone does not prove BAC."
                        ),
                    })

    def _apply_deterministic_content_rules(self, findings: List[Dict]) -> None:
        """Keep high-risk report narratives aligned with the captured evidence."""
        for finding in findings:
            finding_type = str(finding.get("type", "")).lower()
            engine_type = str(
                finding.get("engine_type")
                or (finding.get("csti_metadata") or {}).get("type", "")
            ).lower()
            component_policy = self._get_js_component_policy(finding)

            if "deserial" in finding_type and not self._has_deserialization_execution_proof(finding):
                finding.update({
                    "description": (
                        "Malformed data in the user-controlled serialized value reached the server-side "
                        "deserializer and produced a deserialization error. This confirms an unsafe sink, "
                        "but does not demonstrate a usable gadget chain or remote code execution."
                    ),
                    "impact": (
                        "Impact depends on the accepted object types and available gadget chains. Manual "
                        "verification is required before claiming code execution."
                    ),
                    "exploitation_details": (
                        "The supplied marker triggered a deserialization error. This is evidence of a "
                        "reachable unsafe deserialization sink only; no command execution, callback, or "
                        "gadget-chain execution was observed."
                    ),
                    "remediation": (
                        "Do not deserialize untrusted client data. Use a non-executable format such as JSON "
                        "with strict schema validation, and protect client-stored state with integrity checks."
                    ),
                })
            elif "sqli" in finding_type and str(finding.get("parameter", "")).lower().startswith("header:"):
                evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
                if "baseline_db_type" not in evidence:
                    finding.update({
                        "description": (
                            "The response contained database-related text, but the legacy probe did not record "
                            "whether that text was already present before the header mutation."
                        ),
                        "impact": "SQL injection is not confirmed without a new response differential.",
                        "exploitation_details": (
                            "No baseline DB fingerprint was captured, so the header cannot be identified as the cause."
                        ),
                    })
            elif "broken access control" in finding_type and finding.get("status") == "MANUAL_REVIEW_RECOMMENDED":
                if finding.get("validation_method") == "unauthenticated_admin_access":
                    finding.update({
                        "description": (
                            "The endpoint returned HTTP 200 without authentication, but it was not identified as an "
                            "administrative or restricted route. Access-control impact remains unproven."
                        ),
                        "impact": "Manual classification of the exposed data is required.",
                        "exploitation_details": "HTTP accessibility alone does not establish broken access control.",
                    })
            elif self._is_unresolved_lfi_probe(finding):
                from urllib.parse import urlsplit, urlunsplit

                probe_url = str(finding.get("url", ""))
                target = urlsplit(self.target_url)
                finding.update({
                    "url": urlunsplit((target.scheme, target.netloc, "", "", "")),
                    "parameter": "Endpoint not determined",
                    "probe_url": probe_url,
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "cvss_vector": None,
                    "cvss_rationale": (
                        "A generic traversal probe was observed, but no injectable endpoint, "
                        "parameter, or file-read response was confirmed."
                    ),
                    "description": (
                        "Nuclei issued a generic path-traversal probe against the origin. The probe URL "
                        "is not evidence of the application's vulnerable endpoint; the sink remains unresolved."
                    ),
                    "impact": (
                        "No file disclosure is confirmed. Manual review should correlate this signal with "
                        "an observed file/path parameter before assigning impact."
                    ),
                    "exploitation_details": (
                        "Probe only. The scan did not demonstrate that the traversal response contained "
                        "the requested local file."
                    ),
                    "remediation": (
                        "Identify the actual file-handling endpoint first. If one exists, constrain paths to "
                        "an allowlisted directory and reject traversal after canonicalization."
                    ),
                    "reproduction": None,
                    "llm_reproduction_steps": [],
                })
            elif component_policy:
                component_name = str(component_policy.get("name", "JavaScript component"))
                version = finding.get("detected_version") or finding.get("version")
                if not version:
                    version_match = re.search(
                        rf"{re.escape(component_name)}\s+v?([0-9]+(?:\.[0-9]+)+)",
                        str(finding.get("description", "")),
                        re.IGNORECASE,
                    )
                    version = version_match.group(1) if version_match else "an affected version"
                cves = component_policy.get("cves", [])
                advisory = ", ".join(cves) if cves else "the configured advisory"
                finding.update({
                    "description": (
                        f"{component_name} {version} was detected and matches {advisory}. "
                        "Version detection alone does not prove an exploitable application path."
                    ),
                    "impact": (
                        "A vulnerable client-side dependency can increase browser-side risk when untrusted "
                        "input reaches affected library functionality."
                    ),
                    "exploitation_details": (
                        f"The scan identified {component_name} {version}. No exploit of {advisory} was demonstrated."
                    ),
                    "remediation": (
                        f"Upgrade {component_name} to a non-affected supported version and test the migration. "
                        "Do not expose untrusted input to affected library functionality."
                    ),
                    "cve": cves[0] if cves else None,
                    "cve_id": cves[0] if cves else "N/A",
                })
            elif ("csti" in finding_type or "template injection" in finding_type) and engine_type == "server-side":
                if not self._has_template_code_execution_proof(finding):
                    finding.update({
                        "impact": (
                            "Server-side template expression evaluation can expose application data or "
                            "enable stronger attacks depending on the template sandbox. Code execution "
                            "was not demonstrated by this scan."
                        ),
                        "exploitation_details": (
                            "A benign arithmetic expression was evaluated by the server-side template "
                            "engine. This confirms template injection, but not file access or remote code execution."
                        ),
                        "remediation": (
                            "Do not render untrusted input as a template. Pass user-controlled values as data, "
                            "use strict allowlists, and keep the template engine sandbox enabled."
                        ),
                    })
            elif ("csti" in finding_type or "template injection" in finding_type) and engine_type == "client-side":
                finding.update({
                    "impact": (
                        "An attacker can cause AngularJS expressions to execute in a victim's browser when "
                        "the victim opens a crafted URL. This is client-side execution, not server-side RCE."
                    ),
                    "exploitation_details": (
                        "The arithmetic expression was evaluated by AngularJS in the browser, confirming "
                        "client-side template injection. No server-side code execution was observed."
                    ),
                    "remediation": (
                        "Do not interpolate untrusted input into AngularJS templates. Treat it as text, "
                        "apply contextual output encoding, and migrate away from unsupported AngularJS."
                    ),
                    "cve": None,
                    "cve_id": "N/A",
                })
    def _has_minimum_evidence(self, finding: Dict) -> bool:
        """
        Safety net: check if a finding has minimum evidence quality to be
        included in validated findings. Findings that claim VALIDATED_CONFIRMED
        but have zero evidence are re-routed to manual_review instead.
        """
        # Captured exchanges and scanner output are direct proof.
        if any(finding.get(field) for field in (
            "http_request", "http_response", "response_excerpt", "reproduction",
            "nuclei_request", "nuclei_response", "nuclei_extracted_results",
        )):
            return True
        # Non-trivial evidence dict = sufficient
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict) and evidence and any(v for v in evidence.values() if v):
            return True
        elif isinstance(evidence, str) and evidence.strip():
            return True
        # Screenshot = sufficient
        if finding.get("screenshot_path"):
            return True
        logger.warning(
            f"[{self.name}] Quality gate: {finding.get('type')}/{finding.get('parameter')} "
            f"lacks minimum evidence, routing to manual_review"
        )
        return False

    # -- Patterns that indicate static analysis, not real exploits --
    _STATIC_ANALYSIS_PATTERNS = (
        "source-to-sink pattern detected",
        "detected via code analysis",
        "pattern detected via",
    )

    # -- XSS validation levels that lack browser-confirmed execution --
    _XSS_UNCONFIRMED_LEVELS = {"L0.5", "L1"}

    # -- Injection/exploitation classes that REQUIRE a concrete location (url + parameter).
    # A confirmed finding of these types with NEITHER a url NOR a parameter is not
    # reproducible (the classic bogus SSRF reported with url:None, param:None) and is routed
    # to manual_review. Matched by whole token / phrase to avoid substring accidents
    # (e.g. "RCE" inside "foRCEful"). Site-wide/info classes (headers, cookies, rate-limit,
    # components, weak-JWT, GraphQL introspection, API-docs) are intentionally absent here —
    # they legitimately have no url/param and pass through untouched.
    _LOCATION_REQUIRED_TOKENS = {
        "SQLI", "XSS", "SSRF", "RCE", "CSTI", "SSTI", "LFI", "XXE", "IDOR", "OPENREDIRECT",
    }
    _LOCATION_REQUIRED_PHRASES = (
        "SQL INJECTION", "REMOTE CODE", "COMMAND INJECTION", "OS COMMAND",
        "TEMPLATE INJECTION", "PATH TRAVERSAL", "FILE INCLUSION", "OPEN REDIRECT",
        "HEADER INJECTION", "PROTOTYPE POLLUTION", "MASS ASSIGNMENT",
    )

    def _meets_report_quality(self, finding: Dict) -> bool:
        """
        Quality gate for the final report. Ensures findings meet pentest-grade
        standards. Weak findings are routed to manual_review instead.

        Filters:
        - XSS/DOM-XSS with static-analysis payloads (no real exploit)
        - XSS validated only via HTTP response analysis (no browser execution)
        """
        vuln_type = (finding.get("type") or "").upper()
        payload = (finding.get("payload") or "").lower()
        evidence = finding.get("evidence") or {}
        # evidence can be a string (e.g. SQLi DB-enrichment stores raw text) — normalize to a
        # dict so the evidence.get(...) checks below don't AttributeError and drop a confirmed
        # finding out of the report.
        if not isinstance(evidence, dict):
            evidence = {}
        level = evidence.get("level", "") or ""
        validation_method = (finding.get("validation_method") or "").lower()

        # --- Filter 0: injection/exploitation-class findings need a concrete, reproducible location.
        # A "confirmed" finding of these classes with NEITHER a url NOR a parameter is not
        # reproducible and was never really confirmed (the classic bogus SSRF reported url:"" param:""
        # — auto-dispatched from a URL-accepting param on the /api/debug/vulns cheat-sheet and never
        # OOB-confirmed). Route to manual_review. Target-agnostic; whole-token match.
        _LOCATION_REQUIRED = ("SSRF", "RCE", "XXE", "SSTI", "CSTI", "LFI", "IDOR", "SQLI", "XSS",
                              "OPEN_REDIRECT", "COMMAND INJ", "DESERIAL", "PROTOTYPE", "HEADER INJECT")
        if any(k in vuln_type for k in _LOCATION_REQUIRED):
            if not (finding.get("url") or "").strip() and not (finding.get("parameter") or "").strip():
                logger.info(
                    f"[{self.name}] Report quality gate: {vuln_type} confirmed with no url AND no "
                    f"parameter (not reproducible), routing to manual_review"
                )
                return False

        # --- Filter 1: Static analysis payloads are not real exploits ---
        for pattern in self._STATIC_ANALYSIS_PATTERNS:
            if pattern in payload:
                logger.info(
                    f"[{self.name}] Report quality gate: {vuln_type}/{finding.get('parameter')} "
                    f"has static-analysis payload, routing to manual_review"
                )
                return False

        # --- Filter 2: XSS without browser-confirmed execution ---
        if vuln_type == "XSS" and level in self._XSS_UNCONFIRMED_LEVELS:
            # v3.5 Hotfix: If the agent explicitly confirmed via HTTP smart probe (e.g., characters survived)
            # we allow it as a valid finding even without browser execution.
            if isinstance(evidence, dict) and evidence.get("http_confirmed") is True:
                logger.info(
                    f"[{self.name}] Report quality gate: XSS/{finding.get('parameter')} "
                    f"is {level} but has http_confirmed=True. Allowing in report."
                )
                return True
                
            logger.info(
                f"[{self.name}] Report quality gate: XSS/{finding.get('parameter')} "
                f"validated at {level} (HTTP-only), routing to manual_review"
            )
            return False
        
        # --- Filter 3: SQLi without solid exploitation evidence ---
        if vuln_type == "SQLI":
            # Strong evidence indicators
            has_sqlmap_confirmed = evidence.get("sqlmap_confirmed") is True
            has_data_extracted = bool(
                finding.get("extracted_databases") or 
                finding.get("extracted_tables") or 
                finding.get("sample_data")
            )
            has_oob_callback = evidence.get("oob_callback_received") is True
            
            # Error-based requires DB type identified + not just "unknown"
            has_solid_error = (
                finding.get("dbms_detected") not in (None, "", "unknown")
            )

            # Quote-parity: bidirectional status differential confirming SQL string
            # literal balance (' → 500, '' → 200). One of the strongest error-based proofs.
            has_quote_parity = bool(evidence.get("quote_parity_confirmed"))

            # Time-based requires triple verification (key: "triple_verified" in evidence)
            has_verified_time = (
                evidence.get("time_based_triple_verified") is True
                or evidence.get("triple_verified") is True
            )

            # Boolean requires high diff_ratio (>0.5) or explicit confidence tag
            has_confirmed_boolean = (
                evidence.get("boolean_confidence") in ("HIGH", "MAXIMUM")
                or (isinstance(evidence.get("diff_ratio"), (int, float))
                    and evidence["diff_ratio"] > 0.5)
            )

            # Union-based: proof is the canary the DATABASE had to ASSEMBLE via string
            # concatenation — the request only ever carries the halves, so a reflecting page
            # can never produce the contiguous value.
            #
            # This condition used to accept `data_extracted` / `columns_found` /
            # `canary_position`, which are NOT evidence: _create_union_finding writes all
            # three unconditionally on every union candidate it builds. The gate was
            # therefore asking the producer for permission, and a third-party page that
            # merely echoed the request URI was published as a CVSS 9.8 union injection.
            # Only the computed canary distinguishes execution from reflection.
            has_union_confirmed = bool(evidence.get("computed_canary_confirmed"))

            has_solid_evidence = (
                has_sqlmap_confirmed or
                has_data_extracted or
                has_oob_callback or
                has_solid_error or
                has_quote_parity or
                has_verified_time or
                has_confirmed_boolean or
                has_union_confirmed
            )
            # NOTE: `http_confirmed` is deliberately NOT sufficient here. It is a flag the
            # L5 ManipulatorOrchestrator path sets when its own mutation loop reports
            # success; the finding it builds records nothing the server said (it even reads
            # the DB type out of our own payload). A heuristic's self-report cannot be the
            # thing that promotes a finding to CONFIRMED. Such findings go to manual_review
            # until that path records the response that convinced it.
            
            if not has_solid_evidence:
                logger.info(
                    f"[{self.name}] Report quality gate: SQLI/{finding.get('parameter')} "
                    f"lacks solid exploitation evidence (status_differential/weak boolean), "
                    f"routing to manual_review"
                )
                return False

        # --- Filter 4: injection-class finding confirmed WITHOUT a location ---
        # An exploitation-class finding (SSRF/SQLi/XSS/RCE/...) confirmed with NEITHER a url
        # NOR a parameter is not reproducible — route to manual_review. This catches false
        # positives like a bogus SSRF emitted as VALIDATED_CONFIRMED with url:None, param:None.
        # Site-wide/info classes (cookies, headers, rate-limit, components, weak-JWT, GraphQL
        # introspection) are not location-required and are unaffected.
        vt_norm = re.sub(r"[^A-Z0-9]+", " ", vuln_type)  # "OPEN_REDIRECT" -> "OPEN REDIRECT"
        tokens = set(vt_norm.split())
        is_location_required = bool(tokens & self._LOCATION_REQUIRED_TOKENS) or \
            any(p in vt_norm for p in self._LOCATION_REQUIRED_PHRASES)
        if is_location_required:
            url_val = str(finding.get("url") or finding.get("attack_url") or "").strip()
            param_val = str(finding.get("parameter") or finding.get("vuln_parameter") or "").strip()
            if not url_val and not param_val:
                logger.info(
                    f"[{self.name}] Report quality gate: {vuln_type} confirmed without "
                    f"url+parameter (not reproducible), routing to manual_review"
                )
                return False

        return True

    def _calculate_scan_stats(self, all_findings: List[Dict]) -> Dict:
        """Calculate scan statistics (duration, URLs scanned, token usage)."""
        stats = {"urls_scanned": 0, "duration": "Unknown"}
        try:
            # Calculate duration
            stats.update(self._calculate_scan_duration())
            # Count URLs scanned
            stats["urls_scanned"] = self._count_urls_scanned(all_findings)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to calc stats: {e}")

        # Token usage & cost from LLM client
        try:
            from bugtrace.core.llm_client import llm_client
            token_summary = llm_client.token_tracker.get_summary()
            stats["total_tokens"] = token_summary.get("total", 0)
            stats["input_tokens"] = token_summary.get("total_input", 0)
            stats["output_tokens"] = token_summary.get("total_output", 0)
            stats["estimated_cost"] = token_summary.get("estimated_cost", 0.0)
            stats["tokens_by_model"] = token_summary.get("by_model", {})
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to get token stats: {e}")

        return stats

    def _calculate_scan_duration(self) -> Dict:
        """Calculate scan duration from directory name timestamp (DB = write-only)."""
        try:
            if self.output_dir:
                import re as _re
                # Extract timestamp from dir name: target_YYYYMMDD_HHMMSS
                ts_match = _re.search(r"(\d{8})_(\d{6})$", self.output_dir.name)
                if ts_match:
                    ts_str = f"{ts_match.group(1)}_{ts_match.group(2)}"
                    start_time = datetime.strptime(ts_str, "%Y%m%d_%H%M%S")
                else:
                    # Fallback: earliest file in the scan directory
                    import os
                    earliest = None
                    for root, _, files in os.walk(self.output_dir):
                        for f in files:
                            ft = os.path.getmtime(os.path.join(root, f))
                            if earliest is None or ft < earliest:
                                earliest = ft
                    if earliest:
                        start_time = datetime.fromtimestamp(earliest)
                    else:
                        return {}

                duration = datetime.now() - start_time
                hours, remainder = divmod(int(duration.total_seconds()), 3600)
                minutes, seconds = divmod(remainder, 60)
                return {
                    "duration": f"{hours}h {minutes}m {seconds}s",
                    "duration_seconds": int(duration.total_seconds())
                }
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to calculate duration: {e}")
        return {}

    def _count_urls_scanned(self, all_findings: List[Dict]) -> int:
        """Count URLs scanned from file, memory, or findings."""
        # Priority: File on disk (persistent) > Shared Context (memory) > Findings
        urls_file = self.output_dir / "recon" / "urls.txt"

        if urls_file.exists():
            with open(urls_file, "r") as f:
                return len([line.strip() for line in f if line.strip()])

        from bugtrace.core.conductor import conductor
        urls = conductor.get_shared_context("discovered_urls") or []
        if urls:
            return len(urls)

        # Fallback to counting unique finding URLs
        unique_urls = set(f.get("url") for f in all_findings if f.get("url"))
        return len(unique_urls)

    def _parse_nuclei_tech_for_report(self) -> Dict[str, Any]:
        """Parse raw Nuclei findings into a structured tech summary for the report.

        Extracts actual version numbers, EOL status, and product names from
        raw_tech_findings and raw_vuln_findings instead of showing template names.

        Returns:
            Dict with keys: technologies (list of dicts), waf_details (list), summary (str)
        """
        if not self.tech_profile:
            return {"technologies": [], "waf_details": [], "summary": ""}

        raw_findings = (
            self.tech_profile.get("raw_tech_findings", [])
            + self.tech_profile.get("raw_vuln_findings", [])
        )

        # Known product display names (avoid "Php", show "PHP" etc.)
        _DISPLAY_NAMES = {
            "php": "PHP", "asp": "ASP.NET", "iis": "IIS", "aws": "AWS",
            "gcp": "GCP", "cdn": "CDN", "jquery": "jQuery", "angularjs": "AngularJS",
            "vuejs": "Vue.js", "nodejs": "Node.js", "reactjs": "React",
        }

        def _display_name(raw: str) -> str:
            if not raw:
                return "Unknown"
            return _DISPLAY_NAMES.get(raw.lower(), raw.capitalize())

        # Merge findings by product/technology, keeping best version info
        tech_map: Dict[str, Dict] = {}  # key = normalized product name (lowercase)
        waf_details_set: set = set()
        waf_details = []

        for finding in raw_findings:
            template_id = finding.get("template-id", "")
            info = finding.get("info", {})
            name = info.get("name", "")
            metadata = info.get("metadata", {})
            extracted = finding.get("extracted-results", [])
            matcher_name = finding.get("matcher-name", "")

            # WAF detection → only include if verified by NucleiAgent FP filter
            if template_id == "waf-detect":
                if not self.tech_profile.get("waf"):
                    continue  # All WAF detections were filtered as FP
                waf_type = matcher_name.replace("generic", "").strip() if matcher_name else "Unknown"
                if waf_type and waf_type.lower() not in waf_details_set:
                    waf_details_set.add(waf_type.lower())
                    waf_details.append(_display_name(waf_type))
                continue

            # Wappalyzer tech-detect → use matcher-name as product
            if template_id == "tech-detect":
                product = _display_name(matcher_name) if matcher_name else ""
                if not product:
                    continue
                key = matcher_name.lower() if matcher_name else ""
                if key not in tech_map:
                    tech_map[key] = {
                        "name": product,
                        "version": None,
                        "eol": False,
                        "category": "Technology",
                    }
                continue

            # Skip security misconfig findings — these are NOT technologies
            _MISCONFIG_PREFIXES = (
                "http-missing-", "missing-", "cookies-without-",
                "cookies-", "security-headers-", "cors-", "cluster-",
            )
            if any(template_id.startswith(p) for p in _MISCONFIG_PREFIXES):
                continue

            # Version/EOL detections → extract product + version
            raw_product = metadata.get("product", "")
            product = _display_name(raw_product) if raw_product else ""
            if not product:
                # Infer from template-id: e.g. "nginx-version" → "Nginx"
                raw_product = template_id.split("-")[0] if template_id else ""
                product = _display_name(raw_product) if raw_product else ""
            if not product:
                continue

            key = product.lower()
            is_eol = "eol" in template_id

            # Extract version from results
            version = None
            if extracted:
                raw_ver = extracted[0]
                # Clean: "nginx/1.19.0" → "1.19.0"
                if "/" in raw_ver:
                    version = raw_ver.split("/", 1)[1]
                else:
                    version = raw_ver

            # Determine category
            category = "Technology"
            if any(x in key for x in ["nginx", "apache", "iis", "tomcat", "lighttpd"]):
                category = "Web Server"
            elif any(x in key for x in ["php", "python", "node", "ruby", "java", "asp", "perl"]):
                category = "Language / Runtime"
            elif any(x in key for x in ["angular", "react", "vue", "jquery", "bootstrap"]):
                category = "Framework"
            elif any(x in key for x in ["wordpress", "drupal", "joomla", "magento"]):
                category = "CMS"
            elif any(x in key for x in ["aws", "azure", "gcp", "cloudfront"]):
                category = "Infrastructure"
            elif any(x in key for x in ["cloudflare", "akamai", "fastly"]):
                category = "CDN"

            if key in tech_map:
                # Merge: prefer version, accumulate EOL
                if version and not tech_map[key]["version"]:
                    tech_map[key]["version"] = version
                if is_eol:
                    tech_map[key]["eol"] = True
                if category != "Technology":
                    tech_map[key]["category"] = category
            else:
                tech_map[key] = {
                    "name": product,
                    "version": version,
                    "eol": is_eol,
                    "category": category,
                }

        technologies = sorted(tech_map.values(), key=lambda t: t["name"])
        return {
            "technologies": technologies,
            "waf_details": waf_details,
            "summary": ", ".join(
                f"{t['name']} {t['version'] or ''}" .strip()
                for t in technologies if t["version"]
            ),
        }

    def _generate_json_reports(self, all_findings: List[Dict], categorized: Dict) -> Dict[str, Path]:
        """Generate JSON report files.

        v3.2: validated_findings.json now applies deduplication
        v3.3: validated_findings.json includes manual_review array
        """
        # Deduplicate validated findings for JSON output
        validated_deduped = self._deduplicate_findings(categorized["validated"])
        manual_review_deduped = self._deduplicate_findings(categorized["manual_review"])
        # Pending (POTENTIAL) findings already reach the Markdown + engagement deliverables;
        # include them here too so validated_findings.json stays in parity and the rich-report
        # path (report_service) can surface them (PENDING* is a REPORTABLE_STATUS).
        pending_deduped = self._deduplicate_findings(categorized.get("pending", []))

        return {
            "raw_findings": self._write_json(
                categorized["raw"],
                "raw_findings.json",
                "All findings before/after AgenticValidator"
            ),
            "validated_findings": self._write_validated_json(
                validated_deduped,
                manual_review_deduped,
                pending_deduped,
            )
        }

    def _write_validated_json(
        self,
        validated: List[Dict],
        manual_review: List[Dict],
        pending: Optional[List[Dict]] = None,
    ) -> Path:
        """Write validated_findings.json with confirmed, manual_review and pending findings."""
        path = self.output_dir / "validated_findings.json"
        pending = pending or []

        output = {
            "meta": {
                "scan_id": self.scan_id,
                "target": self.target_url,
                "generated_at": datetime.now().isoformat(),
                "description": "VALIDATED_CONFIRMED + manual_review + pending findings (deduplicated)",
                "count": len(validated),
                "manual_review_count": len(manual_review),
                "pending_count": len(pending),
                "reporting_failover_count": self._reporting_failover_count,
            },
            "findings": validated,
            "manual_review": manual_review,
            "pending": pending,
        }

        self._write_json_document_atomic(path, output)

        logger.info(
            f"[{self.name}] Wrote validated_findings.json "
            f"({len(validated)} validated, {len(manual_review)} manual_review, {len(pending)} pending)"
        )
        return path

    def _generate_markdown_reports(self, categorized: Dict) -> Dict[str, Path]:
        """Generate Markdown report files.

        v3.2: Removed redundant raw_findings.md and validated_findings.md
        (JSON versions are sufficient, MD was duplicating information)
        """
        return {
            "final_report": self._write_markdown_report(
                validated=categorized["validated"],
                manual_review=categorized["manual_review"],
                pending=categorized["pending"],
                false_positives=categorized.get("false_positives", [])
            )
        }

    def _generate_data_files(
        self,
        all_findings: List[Dict],
        categorized: Dict,
        stats: Dict,
        tech_stack: Dict
    ) -> Dict[str, Path]:
        """Generate engagement data files (JS and JSON)."""
        # Generate both JS and JSON engagement data files
        self._write_engagement_json(
            all_findings=all_findings,
            validated=categorized["validated"],
            false_positives=categorized["false_positives"],
            manual_review=categorized["manual_review"],
            pending=categorized["pending"],
            stats=stats,
            tech_stack=tech_stack
        )

        return {
            "engagement_data": self._write_engagement_js(
                all_findings=all_findings,
                validated=categorized["validated"],
                false_positives=categorized["false_positives"],
                manual_review=categorized["manual_review"],
                pending=categorized["pending"],
                stats=stats,
                tech_stack=tech_stack
            )
        }

    def _generate_html_report(self, paths: Dict[str, Path]) -> Dict[str, Path]:
        """Generate HTML report using HTMLGenerator."""
        from bugtrace.reporting.generator import HTMLGenerator

        generator = HTMLGenerator()
        return {
            "report_html": Path(generator.generate(
                paths.get("engagement_data"),
                self.output_dir / "report.html"
            ))
        }

    def _get_findings_from_db(self) -> List[Dict]:
        """DEPRECATED: DB is write-only from CLI. Returns empty list.
        Primary source is _load_specialist_results() which reads from files."""
        logger.warning(f"[{self.name}] _get_findings_from_db() called but DB is write-only. Returning empty.")
        return []

    def _db_build_finding_dict(self, f) -> Dict:
        """Build finding dictionary from database record."""
        return {
            "id": f.id,
            "type": str(f.type.value if hasattr(f.type, 'value') else f.type),
            "severity": f.severity,
            "url": f.attack_url,
            "parameter": f.vuln_parameter,
            "payload": f.payload_used,
            "description": f.details,
            "status": f.status,
            "validator_notes": f.validator_notes,
            "screenshot_path": f.proof_screenshot_path,
            "reproduction": getattr(f, 'reproduction_command', None),
            "created_at": None
        }

    def _db_enrich_sqli_metadata(self, finding: Dict, f) -> None:
        """Parse and enrich SQLMap metadata from details JSON."""
        import json

        # Only process SQLi findings with details
        if finding["type"] not in ["SQLI", "SQLi"]:
            return
        if not f.details:
            return

        try:
            details_json = json.loads(f.details)
            # Extract SQLMap-specific fields
            finding["db_type"] = details_json.get("db_type")
            finding["tamper_used"] = details_json.get("tamper_used")
            finding["confidence"] = details_json.get("confidence")
            finding["evidence"] = details_json.get("evidence")
            finding["description"] = details_json.get("description", f.details)
            # Extract reproduction command if present in details
            if details_json.get("reproduction_command"):
                finding["reproduction"] = details_json.get("reproduction_command")
        except (json.JSONDecodeError, TypeError):
            # Not JSON, use as-is
            pass

    def _load_nuclei_findings(self) -> tuple[List[Dict], Dict]:
        """
        Load Nuclei findings from tech_profile.json.
        Returns tuple: (list of findings, tech_stack dict)
        """
        # Try multiple possible locations (NucleiAgent saves to recon/ subdir)
        possible_paths = [
            self.output_dir / "recon" / "tech_profile.json",
            self.output_dir / "tech_profile.json",
        ]
        tech_profile_path = None
        for path in possible_paths:
            if path.exists():
                tech_profile_path = path
                break

        if not tech_profile_path:
            logger.debug(f"[{self.name}] No tech_profile.json found")
            return [], {}

        tech_profile = self._nuclei_load_file(tech_profile_path)
        if not tech_profile:
            return [], {}

        nuclei_findings = self._nuclei_parse_findings(tech_profile)
        tech_stack = self._nuclei_extract_tech_stack(tech_profile)

        logger.info(f"[{self.name}] Loaded {len(nuclei_findings)} Nuclei findings, tech stack: {tech_stack}")
        return nuclei_findings, tech_stack

    def _nuclei_load_file(self, path: Path) -> Optional[Dict]:
        """Load and parse tech_profile.json file."""
        try:
            with open(path, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load tech_profile.json: {e}")
            return None

    def _nuclei_parse_findings(self, tech_profile: Dict) -> List[Dict]:
        """Parse Nuclei findings from tech profile."""
        nuclei_findings = []
        for finding in (tech_profile.get("raw_tech_findings") or []) + (tech_profile.get("raw_vuln_findings") or []):
            info = finding.get("info", {})
            template = self._nuclei_stable_template_value(
                finding, "template", "template_path", "template-path",
                "template_id", "template-id",
            )
            template_id = self._nuclei_stable_template_value(
                finding, "template_id", "template-id", "template",
                "template_path", "template-path",
            )
            matcher = self._nuclei_source_value(finding, "matcher_name", "matcher-name")
            matched_at = self._nuclei_source_value(finding, "matched_at", "matched-at")
            severity = self._nuclei_map_severity(info.get("severity"))
            status = "VALIDATED_CONFIRMED" if severity in ["CRITICAL", "HIGH"] else "PENDING_VALIDATION"

            nuclei_findings.append({
                "id": None,
                "type": f"NUCLEI:{info.get('name', 'Unknown')}",
                "severity": severity,
                "url": matched_at,
                "parameter": info.get("name", ""),  # Template name as "parameter"
                "payload": template_id,  # Template ID
                "description": info.get("description", f"Detected by Nuclei template: {template_id or 'unknown'}"),
                "status": status,
                "validator_notes": f"Nuclei detection (template: {template_id or 'unknown'})",
                "screenshot_path": None,
                "reproduction": None,
                "source": "nuclei",
                "nuclei_template": template,
                "nuclei_template_id": template_id,
                "nuclei_matcher": matcher,
                "nuclei_tags": info.get("tags", []),
                "nuclei_extracted_results": self._nuclei_source_value(
                    finding, "extracted_results", "extracted-results",
                ),
                "nuclei_request": self._nuclei_source_value(finding, "request"),
                "nuclei_response": self._nuclei_source_value(finding, "response"),
                "nuclei_source_fingerprint": "ns1:" + hashlib.sha256(
                    json.dumps(
                        finding, sort_keys=True, separators=(",", ":"), default=str,
                    ).encode("utf-8")
                ).hexdigest(),
            })
        return nuclei_findings

    @staticmethod
    def _nuclei_source_value(finding: Dict, *keys: str) -> Any:
        """Read standard Nuclei JSON aliases without losing template identity."""
        for key in keys:
            value = finding.get(key)
            if value not in (None, "", [], {}):
                return value
        return ""

    def _nuclei_stable_template_value(self, finding: Dict, *keys: str) -> Any:
        """Return the first non-cluster template alias from Nuclei output."""
        for key in keys:
            value = finding.get(key)
            normalized = self._nuclei_normalize_identity_value(value)
            if value not in (None, "", [], {}) and not normalized.startswith("cluster-"):
                return value
        return ""

    def _nuclei_map_severity(self, nuclei_sev: Optional[str]) -> str:
        """Map Nuclei severity to our severity scale."""
        nuclei_sev = (nuclei_sev or "info").upper()
        severity_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFO"
        }
        return severity_map.get(nuclei_sev, "INFO")

    def _nuclei_extract_tech_stack(self, tech_profile: Dict) -> Dict:
        """Extract full tech stack info from tech profile."""
        return {
            "frameworks": tech_profile.get("frameworks", []),
            "languages": tech_profile.get("languages", []),
            "servers": tech_profile.get("servers", []),
            "waf": tech_profile.get("waf", []),
            "infrastructure": tech_profile.get("infrastructure", []),
            "cdn": tech_profile.get("cdn", []),
            "cms": tech_profile.get("cms", []),
            "tech_tags": tech_profile.get("tech_tags", []),
        }

    def _write_json(self, findings: List[Dict], filename: str, description: str) -> Path:
        """Write findings to a JSON file."""
        path = self.output_dir / filename

        output = {
            "meta": {
                "scan_id": self.scan_id,
                "target": self.target_url,
                "generated_at": datetime.now().isoformat(),
                "description": description,
                "count": len(findings)
            },
            "findings": findings
        }

        self._write_json_document_atomic(path, output)

        logger.info(f"[{self.name}] Wrote {filename} ({len(findings)} findings)")
        return path

    @staticmethod
    def _write_json_document_atomic(path: Path, document: Dict) -> None:
        """Replace a JSON artifact only after complete durable serialization."""
        import tempfile

        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            json.dump(document, handle, indent=2, default=str, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
            temporary = Path(handle.name)
        try:
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def _normalize_type_for_dedup(self, vuln_type: str) -> str:
        """
        Normalize vulnerability type for deduplication grouping.

        Strips technique suffixes so variants group together:
        - "SQL Injection (Error-Based)" → "SQL INJECTION"
        - "SQL Injection (Boolean-Based Blind)" → "SQL INJECTION"
        - "XSS" → "XSS"
        - "CSTI (AngularJS)" → "CSTI"
        """
        normalized = (vuln_type or "UNKNOWN").upper().strip()
        paren_idx = normalized.find("(")
        if paren_idx > -1:
            normalized = normalized[:paren_idx].strip()
        # Canonicalize the RCE / command-injection family so the SAME vuln under different
        # labels merges (e.g. "Authenticated RCE" + "RCE" on the same cmd param/endpoint were
        # counted as two CRITICAL findings). The dedup key still includes param + path, so
        # genuinely distinct endpoints stay separate. Matched precisely to avoid substring
        # collisions (e.g. "SOURCE CODE DISCLOSURE" contains "RCE").
        if (normalized == "RCE" or normalized.endswith(" RCE")
                or "REMOTE CODE EXECUTION" in normalized
                or "COMMAND INJECTION" in normalized):
            normalized = "RCE"
        return normalized

    @staticmethod
    def _nuclei_normalize_identity_value(value: Any) -> str:
        return re.sub(r"[^a-z0-9._/-]+", "-", str(value or "").lower()).strip("-")

    def _nuclei_group_material(self, finding: Dict) -> Dict:
        """Return a stable logical identity for a Nuclei report group."""
        template = ""
        for key in (
            "nuclei_template", "template", "template_path", "template-path",
            "nuclei_template_id", "template_id", "template-id", "payload",
        ):
            candidate = self._nuclei_normalize_identity_value(finding.get(key))
            if candidate and not candidate.startswith("cluster-"):
                template = candidate
                break
        matcher = self._nuclei_normalize_identity_value(self._nuclei_source_value(
            finding, "nuclei_matcher", "matcher_name", "matcher-name",
        ))
        fallback_name = self._nuclei_normalize_identity_value(
            finding.get("parameter") or str(finding.get("type", "")).replace("NUCLEI:", "")
        )
        return {
            "identity_version": 1,
            "kind": "template",
            "template": template or fallback_name or "unknown",
            "matcher": matcher,
        }

    def _nuclei_group_id(self, finding: Dict) -> str:
        material = self._nuclei_group_material(finding)
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":"))
        return "ng1:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def _normalize_parameter_for_dedup(self, param: str) -> str:
        """
        Normalize parameter for deduplication grouping.

        Handles variations like:
        - "Cookie: TrackingId" / "cookie: trackingid" / "TrackingId (cookie)"
        - "Header: X-Forwarded-For" / "x-forwarded-for header"

        Returns lowercase normalized key for grouping.
        """
        param_lower = (param or "").lower().strip()

        # Cookie normalization: extract just the cookie name
        if "cookie" in param_lower:
            # Remove "cookie:" prefix and extract name
            clean = param_lower.replace("cookie:", "").replace("cookie", "").strip()
            clean = clean.split()[0] if clean else "unknown"  # First word
            clean = clean.strip(":").strip()
            return f"cookie:{clean}" if clean else "cookie:unknown"

        # Header normalization
        if "header" in param_lower:
            clean = param_lower.replace("header:", "").replace("header", "").strip()
            clean = clean.split()[0] if clean else "unknown"
            clean = clean.strip(":").strip()
            return f"header:{clean}" if clean else "header:unknown"

        return param_lower

    def _deduplicate_findings(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings by (type, normalized_parameter).

        For example, if we have 4 SQLi findings on Cookie: TrackingId across
        different URLs, we'll return 1 representative finding.

        v3.2: Improved parameter normalization for cookies/headers.

        Returns: List of deduplicated findings with 'affected_urls' metadata.
        """
        from collections import defaultdict
        from urllib.parse import urlparse

        # Group by (normalized_type, normalized_parameter, path).
        # Cookie/header params are request-wide (the same cookie is sent to every
        # endpoint) → path is blanked so findings merge across URLs (the documented
        # "4 SQLi on Cookie: TrackingId across URLs → 1" intent is preserved).
        # Query/body params are endpoint-specific → the path stays in the key so two
        # genuinely distinct vulns that share a common param name (e.g. `url` on
        # /api/fetch vs /admin/proxy, or `id` on /orders vs /users) are NOT collapsed
        # into one — that silently dropped a real finding.
        groups = defaultdict(list)
        for f in findings:
            if str(f.get("type", "")).upper().startswith("NUCLEI:") and f.get("nuclei_group_id"):
                groups[("NUCLEI_GROUP", f["nuclei_group_id"])].append(f)
                continue
            param_raw = f.get("parameter", "")
            param_normalized = self._normalize_parameter_for_dedup(param_raw)
            vuln_type = self._normalize_type_for_dedup(f.get("type", "Unknown"))
            parsed_url = urlparse(f.get("url") or "")
            # Older IDOR artifacts represented one numeric path mutation twice:
            # once as "URL Path" and once as a synthetic `<resource>_id` alias.
            # Canonicalize those aliases to the concrete route template while
            # retaining endpoint identity, so /orders/{id} never merges with
            # /blog/{id}.
            if vuln_type == "IDOR" and re.search(r"/\d+(?:/|$)", parsed_url.path):
                if "path" in param_normalized or param_normalized.endswith("_id"):
                    param_normalized = "path:id"
                    path_key = re.sub(r"/\d+(?=/|$)", "/{id}", parsed_url.path).rstrip("/")
                else:
                    path_key = parsed_url.path.rstrip("/")
            elif param_normalized.startswith(("cookie:", "header:")):
                path_key = ""
            else:
                path_key = parsed_url.path.rstrip("/")
            key = (vuln_type, param_normalized, path_key)
            groups[key].append(f)

        deduplicated = []
        for key, group in groups.items():
            if key[0] == "NUCLEI_GROUP":
                deduplicated.append(group[0])
                continue
            vuln_type, param_key, _path_key = key
            if len(group) == 1:
                # No duplicates - keep as-is
                deduplicated.append(group[0])
            else:
                # Multiple findings - pick the best one as representative
                # Prefer VALIDATED_CONFIRMED > others, then highest severity
                sorted_group = sorted(
                    group,
                    key=lambda x: (
                        # CDP-validated findings carry status "VALIDATED" (not
                        # "VALIDATED_CONFIRMED"); treat both as confirmed so the
                        # severity tiebreaker keeps the stronger finding (a CDP
                        # CRITICAL was previously dropped for a specialist MEDIUM).
                        x.get("status") in ("VALIDATED_CONFIRMED", "VALIDATED"),
                        x.get("source") == "ai_repeater",
                        {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(
                            (x.get("severity") or "medium").lower(), 2
                        )
                    ),
                    reverse=True
                )
                representative = sorted_group[0].copy()
                for duplicate in sorted_group[1:]:
                    representative = self._merge_duplicate_finding_records(
                        representative, duplicate,
                    )

                # Collect all affected URLs (deduplicated)
                affected_urls = list(set(f.get("url", "") for f in group if f.get("url")))
                representative["affected_urls"] = affected_urls
                representative["affected_count"] = len(affected_urls)

                # Original parameter for display
                original_param = representative.get("parameter", param_key)

                # Update description to mention multiple URLs
                original_desc = representative.get("description", "")
                if len(affected_urls) > 1:
                    dedup_note = f"\n\n**Note:** This vulnerability affects {len(affected_urls)} endpoints with parameter `{original_param}`."
                    representative["description"] = original_desc + dedup_note

                deduplicated.append(representative)

                logger.info(f"[{self.name}] Deduplicated {len(group)} {vuln_type} findings on '{param_key}' → 1 finding")

        return deduplicated

    def _enrichment_key(self, finding: Dict) -> Tuple[str, str, str, str]:
        """Stable report-level identity used to preserve prior enrichment."""
        from urllib.parse import urlparse

        vuln_type = self._normalize_type_for_dedup(finding.get("type", "Unknown"))
        parameter = self._normalize_parameter_for_dedup(finding.get("parameter", ""))
        path = "" if parameter.startswith(("cookie:", "header:")) else urlparse(
            finding.get("url") or ""
        ).path.rstrip("/")
        evidence_fingerprint = finding.get("evidence_fingerprint", "")
        if finding.get("source") == "ai_repeater":
            if not evidence_fingerprint:
                import hashlib
                proof = "\0".join(str(finding.get(field, "")) for field in (
                    "url", "http_request", "response_status", "http_response", "response_excerpt",
                ))
                evidence_fingerprint = hashlib.sha256(proof.encode("utf-8")).hexdigest()
        elif not evidence_fingerprint:
            import hashlib

            proof = {
                field: finding.get(field)
                for field in (
                    "url", "parameter", "payload", "http_request", "http_response",
                    "response_status", "response_excerpt", "reproduction", "evidence",
                    "validator_notes", "screenshot_path",
                )
            }
            evidence_fingerprint = hashlib.sha256(
                json.dumps(proof, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
            ).hexdigest()
        return vuln_type, parameter, path, evidence_fingerprint

    def _restore_existing_enrichment(self, findings: List[Dict]) -> None:
        """Merge successful fields from an existing report without overwriting fresh evidence."""
        path = self.output_dir / "validated_findings.json"
        if not path.is_file():
            return

        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return

        old_findings = []
        if isinstance(previous, dict):
            old_findings.extend(previous.get("findings", []))
        old_by_key = {
            self._enrichment_key(finding): finding
            for finding in old_findings
            if isinstance(finding, dict)
        }
        enrichment_fields = (
            "cvss_score", "cvss_vector", "cvss_rationale", "cwe", "cve",
            "exploitation_details", "llm_reproduction_steps",
            "description", "impact", "remediation",
        )
        for finding in findings:
            # Nuclei narratives are restored only from the fingerprinted sidecar.
            # Generic report reuse cannot prove that prior prose still describes
            # the current template evidence and affected endpoints.
            if str(finding.get("type", "")).upper().startswith("NUCLEI:"):
                continue
            old = old_by_key.get(self._enrichment_key(finding))
            if not old:
                continue
            for field in enrichment_fields:
                if finding.get(field) in (None, "", []):
                    value = old.get(field)
                    if value not in (None, "", []):
                        finding[field] = value
            finding["enriched"] = bool(
                finding.get("cvss_score") is not None
                and finding.get("exploitation_details")
            )


    def _build_triager_findings(
        self,
        validated: List[Dict],
        manual_review: List[Dict],
        i_param: int = 1
    ) -> Tuple[List[Dict], List[Dict]]:
        """Build triager-ready findings from validated and manual review lists."""
        triager_findings = []

        # Process validated findings
        for i, f in enumerate(validated, i_param):
            finding_entry = self._build_finding_entry(f, f"F-{i:03d}", "VALIDATED_CONFIRMED", "CERTAIN")
            triager_findings.append(finding_entry)

        # Process manual review findings
        for i, f in enumerate(manual_review, len(validated) + i_param):
            finding_entry = self._build_finding_entry(f, f"M-{i:03d}", "MANUAL_REVIEW_RECOMMENDED", "POTENTIAL")
            triager_findings.append(finding_entry)

        # Separate Nuclei findings
        nuclei_infra = [f for f in triager_findings if f.get("type", "").startswith("NUCLEI:")]
        vuln_findings = [f for f in triager_findings if not f.get("type", "").startswith("NUCLEI:")]

        return vuln_findings, nuclei_infra

    def _build_pending_infra_findings(self, pending: List[Dict]) -> List[Dict]:
        """Build engagement entries for the PENDING bucket's informational Nuclei detections.

        The pending bucket holds informational NUCLEI:* detections (tech fingerprints, GraphQL
        probes, CORS, cookies, missing headers) — already grouped + enriched upstream. They
        render in the markdown pending section but were absent from engagement_data.json/.js,
        so the HTML viewer showed none. Route the NUCLEI:* ones into infrastructure.nuclei_findings
        for Markdown/HTML/JSON parity. Non-Nuclei pending items (unconfirmed specialist findings,
        rare) stay in the markdown pending section only — never promoted into a confirmed list.
        """
        if not pending:
            return []
        entries = []
        for i, f in enumerate(pending, 1):
            if not str(f.get("type", "")).startswith("NUCLEI:"):
                continue
            entries.append(
                self._build_finding_entry(f, f"P-{i:03d}", "PENDING_VALIDATION", "INFORMATIONAL")
            )
        return entries

    def _build_pending_vuln_findings(self, pending: List[Dict]) -> List[Dict]:
        """Build viewer entries for non-Nuclei PENDING vulns (SQLi/XSS/…) so they appear in the
        HTML/JSON viewer with a POTENTIAL badge (isValidated=false), same as the markdown Pending
        section. Without this a real unconfirmed vuln (e.g. a cookie SQLi) showed in the markdown
        but was silently absent from the HTML report. The viewer already renders a ⚠️ POTENTIAL
        badge for non-VALIDATED_CONFIRMED findings and counts validated separately, so surfacing
        these is safe and does not inflate the confirmed count."""
        if not pending:
            return []
        vulns = [f for f in pending if not str(f.get("type", "")).startswith("NUCLEI:")]
        vulns = self._deduplicate_findings(vulns)
        return [
            self._build_finding_entry(f, f"PV-{i:03d}", "PENDING_VALIDATION", "POTENTIAL")
            for i, f in enumerate(vulns, 1)
        ]

    def _render_evidence_dict(self, f: Dict, markdown: bool = True) -> str:
        """Render a specialist's structured ``evidence`` into readable lines.

        Many detectors (OpenRedirect, CSTI, CORS, IDOR, Broken Access…) put their proof in
        ``evidence`` as a dict rather than in raw http_request/response, and it was never
        surfaced anywhere in the deliverable → those findings rendered with an empty panel.

        ``markdown`` picks the renderer for the CONSUMER, because the two deliverables
        parse this text differently and the same bytes cannot serve both:

        * ``True`` — ``final_report.md`` and everything the WEB pushes through
          marked+DOMPurify. Evidence routinely carries the proof payload, and a payload
          written bare into prose is markup: ``<svg onload=…>`` is parsed as a tag and then
          DELETED by the viewer's allowlist, so the panel proved the finding on disk and
          proved nothing on screen. Values that the grammar can transform get a fenced
          block; inert ones stay inline so the panel stays compact.
        * ``False`` — the static HTML viewer (which HTML-escapes this into a ``<code>``
          block itself) and the LLM prompts. Both read it as plain text, so fences would
          be rendered/read literally.
        """
        ev = f.get("evidence")
        if isinstance(ev, str):
            return ev.strip()
        pairs, dropped_keys = evidence_pairs(
            ev,
            limit=settings.REPORT_EVIDENCE_MAX_FIELDS,
            value_budget=settings.REPORT_EVIDENCE_VALUE_CHARS,
        )
        if not pairs:
            return ""
        if dropped_keys or any(d for _, _, d in pairs):
            logger.debug(
                f"[ReportingAgent] Evidence panel bounded for {f.get('type', '?')} on "
                f"{f.get('url', '?')}: {dropped_keys} field(s) and "
                f"{sum(d for _, _, d in pairs)} character(s) not printed "
                f"(full value in raw_findings.json)"
            )
        render = md_evidence_block if markdown else plain_evidence_block
        return render(pairs, dropped_keys)

    def _md_injection_point(self, f: Dict) -> str:
        """URL / Parameter / Payload for `f`, rendered byte-exact (fenced blocks).

        Single source of truth for the trio across every markdown deliverable, so a
        payload cannot round-trip losslessly in one file and be mangled in the next.
        The detection probe is surfaced whenever the report ships a different (visual)
        payload than the one the evidence was captured with.
        """
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        return md_injection_point(
            f.get("url", ""), f.get("parameter", ""), f.get("payload", ""),
            ev.get("original_payload"),
        )

    def _synthesize_description(self, f: Dict) -> str:
        """A meaningful description when a specialist left ``description`` empty — built from
        type + parameter, so no finding renders with a blank body.

        The payload is deliberately NOT inlined here: a description is markdown-active
        prose, where a code span deletes the payload's backticks and a bare payload loses
        its backslashes (and, if it looks like a tag, is dropped by the viewer's sanitizer
        allowlist). Every deliverable prints the payload in its own fenced block instead,
        in full — the old inline copy was also silently cut at 100 characters.
        """
        vuln_type = f.get("type", "Unknown")
        url = f.get("url", "")
        param = f.get("parameter", "")
        desc = f"{vuln_type} detected on {url}"
        if param:
            desc += f" via parameter '{param}'"
        return desc + ". See the Payload section for the exact input."

    def _build_finding_entry(self, f: Dict, finding_id: str, status: str, confidence: str) -> Dict:
        """Build a single finding entry with all required fields."""
        # Determine source (event_bus or database)
        source = f.get("source", "database")
        validation_source = "event_bus" if source == "event_bus" else "database"

        # The finding URL is the URL that was actually exercised, and the report's only
        # job is to let a human reproduce it. This used to strip gospider's FUZZ
        # placeholder for cosmetics, which was measurably harmful:
        # `?search=FUZZ&back=<payload>` was rewritten to `?search&back=<payload>` — a
        # dangling key, i.e. a URL that was never sent — while the SAME finding's
        # visual_exploit_url still carried the tested value, so one entry contradicted
        # itself. It also mutated f["url"] in place, propagating the corruption to every
        # later reader. And the second, unbounded replace corrupted any legitimate value
        # merely CONTAINING the token ("FUZZY logic" -> "Y logic"). A placeholder that
        # reaches a confirmed finding is what we actually probed: show it verbatim.
        url = f.get("url", "")

        # Fallback description when specialists don't provide one (synthesized from
        # type + parameter + payload so no finding renders with a blank body).
        description = f.get("description") or self._synthesize_description(f)

        entry = {
            "id": finding_id,
            # Human-readable title (consolidated findings set a richer one, e.g.
            # "Missing Security Headers (3 headers)"); the viewer prefers f.title.
            "title": f.get("title") or f.get("type", "Unknown"),
            "type": f.get("type", "Unknown"),
            "severity": f.get("severity", "MEDIUM" if status == "VALIDATED_CONFIRMED" else "HIGH"),
            "confidence": confidence,
            "status": status,
            "url": url,
            "parameter": f.get("parameter", ""),
            "payload": f.get("payload", ""),
            "validation": self._build_validation_section(f, status),
            "reproduction": self._build_reproduction_section(f),
            "description": description,
            "impact": f.get("impact") or self._get_impact_for_type(f.get("type", "")),
            "remediation": f.get("remediation") or self._get_remediation_for_type(f.get("type", "")),
            "cvss_score": f.get("cvss_score"),
            "cvss_vector": f.get("cvss_vector"),
            "cvss_rationale": f.get("cvss_rationale"),
            "cve": f.get("cve"),
            "markdown_block": self._generate_finding_markdown(f, int(finding_id.split("-")[1])),
            # Source tracking for report viewers
            "source": source,
            "validation_source": validation_source,
        }

        # Add SQLi-specific fields
        if f.get("db_type"):
            entry["db_type"] = f.get("db_type")
        if f.get("tamper_used"):
            entry["tamper_used"] = f.get("tamper_used")
        # Forward the SQLi agent's rich metadata (technique, DB, one-click exploit URL,
        # exfiltrated tables/DBs, raw evidence). The HTML viewer's "SQL Injection Analysis"
        # panel renders ENTIRELY from f.sqli_metadata, so without this the flagship SQLi
        # proof-of-impact UI was permanently empty even though the data was on the finding.
        if f.get("sqli_metadata"):
            entry["sqli_metadata"] = f.get("sqli_metadata")

        # Add exploitation details if present
        if f.get("exploitation_details"):
            entry["exploitation_details"] = f.get("exploitation_details")

        # Add screenshot path if available
        if f.get("screenshot_path"):
            entry["screenshot_path"] = f"captures/{Path(f.get('screenshot_path', '')).name}"

        # Add CDP validation metadata if present (from event_bus findings)
        if f.get("cdp_validated"):
            entry["cdp_validated"] = f.get("cdp_validated")
        if f.get("cdp_confidence"):
            entry["cdp_confidence"] = f.get("cdp_confidence")
        if f.get("specialist"):
            entry["specialist"] = f.get("specialist")

        # Add validation method label for report display
        entry["validation_method_label"] = self._extract_validation_method(f)

        # Enrichment status per finding (backwards compat: default True for old scans)
        entry["enriched"] = f.get("enriched", True)

        # Add alternative payloads if available
        if f.get("successful_payloads") and len(f["successful_payloads"]) > 1:
            entry["successful_payloads"] = f["successful_payloads"]

        # Technical Proof evidence array — the HTML viewer renders its evidence panel
        # from f.evidence, which was NEVER emitted here, so the panel was always empty
        # (or "No additional evidence provided") for every finding without a screenshot.
        # Surface the agent's REAL captured request/response (same fields the markdown
        # Evidence section uses).
        _evidence = []
        _req = (f.get("http_request") or "").strip()
        _resp = (f.get("http_response") or "").strip()
        if _req:
            _evidence.append({"description": "HTTP Request", "content": _req})
        if _resp:
            _evidence.append({"description": "HTTP Response (excerpt)", "content": _resp[:1500]})
        # Also surface the specialist's structured evidence dict (OpenRedirect/CSTI/CORS/
        # Broken Access… keep their proof here, not in raw request/response) — else the
        # evidence panel is empty for those types.
        # markdown=False: the static viewer HTML-escapes this into a <code> block and the
        # WEB shows it verbatim, so fenced blocks would be rendered literally there.
        _ev_block = self._render_evidence_dict(f, markdown=False)
        if _ev_block:
            _evidence.append({"description": "Detection Evidence", "content": _ev_block})
        if _evidence:
            entry["evidence"] = _evidence

        return entry

    def _build_validation_section(self, f: Dict, status: str) -> Dict:
        """Build validation section for a finding."""
        if status == "MANUAL_REVIEW_RECOMMENDED":
            return {
                "method": "Manual Review Required",
                "screenshot": f"captures/{Path(f.get('screenshot_path', '')).name}" if f.get("screenshot_path") else None,
                "notes": f.get("validator_notes", "") or "Automated validation inconclusive. Manual verification required."
            }
        return {
            "method": self._get_validation_method(f),
            "screenshot": f"captures/{Path(f.get('screenshot_path', '')).name}" if f.get("screenshot_path") else None,
            "notes": self._get_validation_notes(f)
        }

    def _build_reproduction_section(self, f: Dict) -> Dict:
        """Build reproduction section for a finding."""
        # Prefer the LLM-written steps (richer, triager-ready) when enrichment produced
        # them — the markdown deliverable already does this; HTML/JSON were silently
        # falling back to the poorer type-builder steps for the same finding.
        _llm = f.get("llm_reproduction_steps")
        steps = _llm if isinstance(_llm, list) and _llm else self._generate_reproduction_steps(f)
        cmd = self._generate_curl(f)
        return {
            "steps": steps,
            # Emit the command under BOTH keys: the shipped static viewer (report_viewer.html)
            # reads reproduction.curl, while the minimal fallback template reads reproduction.poc.
            # Keying only `poc` meant the viewer fell through to a GENERIC reconstructed command
            # (e.g. "sqlmap -u ... --batch --dbs") instead of the real captured/type-specific one.
            "poc": cmd,
            "curl": cmd,
        }

    def _sort_findings_by_cvss(self, findings: List[Dict]) -> List[Dict]:
        """Sort findings by CVSS score descending."""
        severity_weights = {"CRITICAL": 10.0, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}

        def get_score(x):
            s = x.get("cvss_score")
            if s is not None and isinstance(s, (int, float)):
                return float(s)
            sev = (x.get("severity") or "MEDIUM").upper()
            return severity_weights.get(sev, 5.0)

        return sorted(findings, key=get_score, reverse=True)

    def _write_engagement_json(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        pending: List[Dict] = None,
        stats: Dict = None,
        tech_stack: Dict = None
    ) -> Path:
        """Write the structured engagement_data.json for HTML viewer."""
        path = self.output_dir / "engagement_data.json"
        output = self._build_engagement_data(
            all_findings, validated, false_positives, manual_review, stats, tech_stack, pending
        )

        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

        logger.info(f"[{self.name}] Wrote engagement_data.json ({len(output['findings'])} vuln findings, {len(output['infrastructure']['nuclei_findings'])} nuclei findings)")
        return path

    def _write_engagement_js(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        pending: List[Dict] = None,
        stats: Dict = None,
        tech_stack: Dict = None
    ) -> Path:
        """Write the structured engagement_data.js for HTML viewer (JSONP style).

        Raises:
            RuntimeError: If JSON serialization fails or file cannot be written.
            This ensures the pipeline fails explicitly instead of producing broken HTML.
        """
        path = self.output_dir / "engagement_data.js"
        output = self._build_engagement_data(
            all_findings, validated, false_positives, manual_review, stats, tech_stack, pending
        )

        # Validate JSON serialization BEFORE writing
        try:
            json_str = json.dumps(output, indent=2, default=str)
        except (TypeError, ValueError) as e:
            logger.error(f"[{self.name}] CRITICAL: Failed to serialize engagement data to JSON: {e}")
            raise RuntimeError(f"engagement_data.js generation failed: JSON serialization error: {e}")

        # Validate minimum required fields
        if "report_signature" not in output.get("meta", {}):
            logger.error(f"[{self.name}] CRITICAL: engagement_data missing report_signature")
            raise RuntimeError("engagement_data.js generation failed: missing report_signature")

        # Write as JS assignment
        js_content = f"window.BUGTRACE_REPORT_DATA = {json_str};"

        with open(path, "w", encoding="utf-8") as f:
            f.write(js_content)

        # Validate file was written correctly
        if not path.exists() or path.stat().st_size < 100:
            logger.error(f"[{self.name}] CRITICAL: engagement_data.js was not written correctly (size={path.stat().st_size if path.exists() else 0})")
            raise RuntimeError("engagement_data.js generation failed: file not written correctly")

        logger.info(f"[{self.name}] Wrote engagement_data.js ({len(output['findings'])} vuln findings, {len(output['infrastructure']['nuclei_findings'])} nuclei findings)")
        return path

    def _build_engagement_data(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        stats: Dict = None,
        tech_stack: Dict = None,
        pending: List[Dict] = None
    ) -> Dict:
        """Build engagement data structure (shared between JSON and JS outputs)."""
        stats = stats or {"urls_scanned": 0, "duration": "0s"}
        tech_stack = tech_stack or {}
        pending = pending or []

        # Deduplicate and process findings
        validated = self._deduplicate_findings(validated)
        manual_review = self._deduplicate_findings(manual_review)
        pending = self._deduplicate_findings(pending)
        # Count EVERY finding the report renders with a severity badge (validated +
        # manual_review + pending) so engagement_data's summary matches the Markdown
        # histogram (_md_build_header). Previously counted only `validated`, so the
        # engagement "Findings by Severity" total was lower than the Markdown total.
        by_severity = self._count_by_severity(validated + manual_review + pending)

        # Build and sort findings
        vuln_findings, nuclei_infra = self._build_triager_findings(validated, manual_review)
        # The PENDING bucket renders in the markdown but was absent from engagement_data → the
        # HTML/JSON viewer. Surface it so all three deliverables agree: informational NUCLEI:*
        # detections (grouped + enriched in Phase 2.5/2.5b) go to infrastructure.nuclei_findings,
        # and real unconfirmed vulns (SQLi/XSS/…) go into findings with a ⚠️ POTENTIAL badge.
        nuclei_infra = nuclei_infra + self._build_pending_infra_findings(pending)
        vuln_findings = vuln_findings + self._build_pending_vuln_findings(pending)
        vuln_findings = self._sort_findings_by_cvss(vuln_findings)
        nuclei_infra = self._sort_findings_by_cvss(nuclei_infra)

        return {
            "meta": self._engagement_build_meta(),
            "stats": self._engagement_build_stats(stats),
            "summary": self._engagement_build_summary(all_findings, validated, false_positives, manual_review, by_severity),
            "findings": vuln_findings,
            "infrastructure": {
                "tech_stack": tech_stack,
                "nuclei_findings": nuclei_infra
            }
        }

    def _engagement_build_meta(self) -> Dict:
        """Build engagement metadata section."""
        meta = {
            "scan_id": self.scan_id,
            "target": self.target_url,
            "scan_date": datetime.now().isoformat(),
            "tool_version": settings.VERSION,
            "validation_engine": "AgenticValidator + CDP + Vision AI",
            "report_signature": "BUGTRACE_AI_REPORT_V5",
            "enrichment_status": getattr(
                self, "_audited_enrichment_status", self._compute_enrichment_status(),
            ),
            "enrichment_stats": {
                "total": self._enrichment_total,
                "enriched": self._enrichment_total - self._enrichment_failures,
                "failed": self._enrichment_failures,
            },
        }
        return meta

    def _engagement_build_stats(self, stats: Dict) -> Dict:
        """Build engagement statistics section."""
        result = {
            "urls_scanned": stats.get("urls_scanned", 0),
            "duration": stats.get("duration", "N/A"),
            "duration_seconds": stats.get("duration_seconds", 0),
            "validation_coverage": "100%",
            "total_tokens": stats.get("total_tokens", 0),
            "estimated_cost": stats.get("estimated_cost", 0.0),
        }
        # Add parsed technology stack
        tech_data = self._parse_nuclei_tech_for_report()
        technologies = list(tech_data["technologies"])

        # Merge frameworks/servers/cms/cdn from tech_profile (HTML parsing fallback)
        if self.tech_profile:
            existing = {t["name"].lower() for t in technologies}
            _CATEGORY_MAP = {
                "frameworks": "Framework",
                "servers": "Web Server",
                "cms": "CMS",
                "cdn": "CDN",
                "languages": "Language / Runtime",
            }
            for field, category in _CATEGORY_MAP.items():
                for name in self.tech_profile.get(field, []):
                    if name.lower() not in existing:
                        existing.add(name.lower())
                        technologies.append({
                            "name": name,
                            "version": None,
                            "eol": False,
                            "category": category,
                        })

        if technologies or tech_data["waf_details"]:
            result["tech_stack"] = {
                "technologies": technologies,
                "waf": tech_data["waf_details"],
            }
        return result

    def _engagement_build_summary(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        by_severity: Dict
    ) -> Dict:
        """Build engagement summary section with source tracking."""
        # Count findings by source
        event_sourced = sum(1 for f in all_findings if f.get("source") == "event_bus")
        db_sourced = sum(1 for f in all_findings if f.get("source") in ("database", None))
        nuclei_sourced = sum(1 for f in all_findings if f.get("source") == "nuclei")

        return {
            "total_findings": len(all_findings),
            "validated": len(validated),
            "false_positives": len(false_positives),
            "manual_review": len(manual_review),
            "by_severity": by_severity,
            # Source breakdown for report insights
            "event_sourced": event_sourced,
            "db_sourced": db_sourced,
            "nuclei_sourced": nuclei_sourced,
        }

    def _count_by_severity(self, validated: List[Dict]) -> Dict[str, int]:
        """Count findings by severity level."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in validated:
            sev = (f.get("severity") or "medium").lower()
            if sev in by_severity:
                by_severity[sev] += 1
        return by_severity

    def _write_markdown_report(
        self,
        validated: List[Dict],
        manual_review: List[Dict],
        pending: List[Dict],
        false_positives: List[Dict] = None
    ) -> Path:
        """Write the triager-ready markdown report.

        v3.2: Added deduplication to prevent duplicate findings
        (e.g., 4 SQLi on same parameter → 1 finding with affected URLs)
        """
        path = self.output_dir / "final_report.md"

        # v3.2: Deduplicate findings to prevent repetition
        validated = self._deduplicate_findings(validated)
        manual_review = self._deduplicate_findings(manual_review)
        pending = self._deduplicate_findings(pending)

        lines = []
        self._md_build_header(lines, validated, manual_review, pending, false_positives)
        self._md_build_validated_findings(lines, validated)
        self._md_build_manual_review(lines, manual_review)
        self._md_build_pending_findings(lines, pending)

        # Write file
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"[{self.name}] Wrote final_report.md ({len(validated)} validated, deduplicated)")
        return path

    def _md_build_header(self, lines: List[str], validated: List[Dict], manual_review: List[Dict], pending: List[Dict], false_positives: List[Dict] = None):
        """Build markdown report header and summary with standardized structure."""
        # Calculate stats for header
        stats = self._calculate_scan_stats(validated + manual_review + pending)
        # Count EVERYTHING the report actually renders with a severity badge:
        # validated (Confirmed) + manual_review (Needs Manual Review) + pending. The
        # histogram previously omitted manual_review, so its Total was lower than the
        # number of findings a reader counts in the body.
        by_severity = self._count_by_severity(validated + manual_review + pending)

        # Header: Security Assessment Report
        lines.append("# Security Assessment Report\n")

        # Scan Metadata table
        lines.append("## Scan Metadata\n")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Target** | {self.target_url} |")
        lines.append(f"| **Scan ID** | {self.scan_id} |")
        lines.append(f"| **Date** | {datetime.now().strftime('%d %b %Y %H:%M')} |")
        lines.append(f"| **Tool Version** | BugTraceAI v{settings.VERSION} |")
        lines.append(f"| **Duration** | {stats.get('duration', 'N/A')} |")
        lines.append(f"| **URLs Scanned** | {stats.get('urls_scanned', 0)} |")
        if stats.get('total_tokens', 0) > 0:
            lines.append(f"| **LLM Tokens Used** | {stats.get('total_tokens', 0):,} ({stats.get('input_tokens', 0):,} in / {stats.get('output_tokens', 0):,} out) |")
            lines.append(f"| **Estimated API Cost** | ${stats.get('estimated_cost', 0.0):.4f} |")
        lines.append("")

        # Technology Stack Section — parsed from raw Nuclei findings
        if self.tech_profile:
            tech_data = self._parse_nuclei_tech_for_report()
            techs = tech_data["technologies"]
            waf_details = tech_data["waf_details"]

            if techs or waf_details:
                lines.append("## Technology Stack\n")
                lines.append("| Component | Version | Category | Notes |")
                lines.append("|-----------|---------|----------|-------|")
                for t in techs:
                    version = t["version"] or "-"
                    notes = "End-of-Life" if t["eol"] else ""
                    lines.append(f"| **{t['name']}** | {version} | {t['category']} | {notes} |")
                lines.append("")

                if waf_details:
                    lines.append(f"**Security Controls:** WAF detected ({', '.join(waf_details)})\n")

            lines.append("---\n")

        # Executive Summary
        lines.append("## Executive Summary\n")

        # Findings by Severity table
        lines.append("### Findings by Severity\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {by_severity.get('critical', 0)} |")
        lines.append(f"| High | {by_severity.get('high', 0)} |")
        lines.append(f"| Medium | {by_severity.get('medium', 0)} |")
        lines.append(f"| Low | {by_severity.get('low', 0)} |")
        lines.append(f"| Info | {by_severity.get('info', 0)} |")
        total_count = sum(by_severity.values())
        lines.append(f"| **Total** | **{total_count}** |")
        lines.append("")

        # Validation Summary table
        lines.append("### Validation Summary\n")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Confirmed | {len(validated)} |")
        lines.append(f"| Manual Review | {len(manual_review)} |")

        # False positives threaded through from categorized["false_positives"] so the markdown
        # Validation Summary agrees with the HTML/JSON deliverable (was hardcoded 0).
        false_positive_count = len(false_positives or [])
        lines.append(f"| False Positives | {false_positive_count} |")
        lines.append(f"| Pending | {len(pending)} |")
        lines.append("")

    def _md_build_validated_findings(self, lines: List[str], validated: List[Dict]):
        """Build validated findings section of markdown report."""
        lines.append("---\n")
        lines.append("## Confirmed Vulnerabilities (Triager Ready)\n")

        if not validated:
            lines.append("*No confirmed vulnerabilities found.*\n")
            return

        # Sort by CVSS (desc) with the shared helper — the HTML/JSON deliverable already
        # sorts this way, but the markdown used a severity-name-only order, so the same
        # scan presented findings in a different priority order per deliverable.
        validated_sorted = self._sort_findings_by_cvss(validated)

        for i, f in enumerate(validated_sorted, 1):
            self._md_build_finding_entry(lines, f, i)

    def _generate_standardized_finding(self, finding: Dict, index: int) -> str:
        """
        Generate a standardized finding entry using the finding template.

        Args:
            finding: Finding dictionary with all data
            index: Finding number (1-based)

        Returns:
            Formatted markdown string for the finding
        """
        # Load template
        template_path = Path(__file__).parent.parent / "reporting" / "templates" / "finding_template.md"
        try:
            with open(template_path, "r") as f:
                template = f.read()
        except FileNotFoundError:
            logger.warning(f"[{self.name}] Template not found, falling back to inline format")
            return self._md_build_finding_entry_inline(finding, index)

        # Extract finding data
        vuln_type = finding.get("type", "Unknown")
        severity = finding.get("severity", "MEDIUM")
        description = finding.get("description") or self._synthesize_description(finding)
        # Surface the specialist's structured evidence (OpenRedirect/CSTI/CORS/Broken Access…
        # keep their proof in `evidence`, not raw request/response) into the markdown body —
        # else these findings render with an empty Evidence section.
        _ev_block = self._render_evidence_dict(finding)
        if _ev_block and _ev_block not in description:
            description = f"{description}\n\n**Detection Evidence:**\n\n{_ev_block}"

        # Get CWE reference: LLM-assigned first, then framework mapping fallback.
        # Render a bare "N/A" (not a link) when there's no CWE — the old code set
        # cwe_num="0", so the template emitted a live link to .../definitions/0.html (404).
        cwe_id = finding.get("cwe") or get_cwe_for_vuln(vuln_type) or "N/A"
        if cwe_id and cwe_id != "N/A":
            cwe_num = cwe_id.replace("CWE-", "")
            cwe_cell = f"[{cwe_id}](https://cwe.mitre.org/data/definitions/{cwe_num}.html)"
        else:
            cwe_cell = "N/A"

        # Format CVE reference: finding first, then framework reference lookup
        cve_raw = finding.get("cve")
        if not cve_raw:
            cve_raw = get_reference_cve(vuln_type, finding)
        if cve_raw:
            try:
                cve_reference = f"[{format_cve(cve_raw)}](https://nvd.nist.gov/vuln/detail/{format_cve(cve_raw)})"
            except ValueError:
                cve_reference = "N/A"
        else:
            cve_reference = "N/A"

        # Get remediation (prefer from finding, fallback to standards)
        remediation = finding.get("remediation") or get_remediation_for_vuln(vuln_type)

        # Get impact (prefer finding-level, e.g. LLM-enriched Nuclei) with type-map fallback
        impact = finding.get("impact") or self._get_impact_for_type(vuln_type)

        # Format CVSS score
        cvss_score = finding.get("cvss_score")
        cvss_score_str = f"{cvss_score:.1f}" if cvss_score else "N/A"

        # Severity badge (emoji-based)
        severity_badges = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🔵 LOW",
            "INFO": "⚪ INFO"
        }
        severity_badge = severity_badges.get(severity, severity)

        # Status badge
        status_badge = "✅ CONFIRMED"

        # Evidence request/response — prefer the agent's REAL captured request and response
        # over a synthesized curl (only fall back for the request, which we can always
        # reconstruct). The response has no synthetic equivalent: falling back to
        # validator_notes or description put the CVSS-analysis prose (or the finding's own
        # description) inside a block labeled "Response (excerpt)" and fenced as ```http```
        # — text that was never an HTTP response. That prose is already rendered in its own
        # Description / Exploitation Analysis sections below; an empty fence here (same
        # empty-block convention already used for Payload on config/observation findings)
        # is honest about not having captured a real response.
        http_request = (finding.get("http_request") or "").strip() or self._generate_curl(finding)
        validator_notes = finding.get("validator_notes", "")
        http_response_excerpt = (finding.get("http_response") or "").strip()[:1500]
        # Fenced in Python, not in the template: a captured request or an LLM-written
        # reproduction can itself contain a ``` run, which closes a fixed 3-backtick fence
        # early and spills the rest of the request into the page as prose.
        http_request_block = md_labeled_block("Request", http_request, "http")
        http_response_block = md_labeled_block("Response (excerpt)", http_response_excerpt, "http")

        # Screenshot section
        screenshot_section = ""
        if finding.get("screenshot_path"):
            img_name = Path(finding.get("screenshot_path")).name
            screenshot_section = f"**Screenshot:**\n\n![Evidence](captures/{img_name})"

        # Reproduction steps — prefer the LLM-written steps (richer, triager-ready) when the
        # enrichment produced them; otherwise the type-specific builder.
        _llm_steps = finding.get("llm_reproduction_steps")
        reproduction_steps_list = _llm_steps if isinstance(_llm_steps, list) and _llm_steps else self._generate_reproduction_steps(finding)
        reproduction_steps = "\n".join(str(s) for s in reproduction_steps_list)

        # Fold the LLM exploitation narrative (Summary / Attack Scenario / Max Impact / Proof)
        # into the markdown description too — previously only the HTML/JSON deliverables showed it.
        _exploit = (finding.get("exploitation_details") or "").strip()
        if _exploit and _exploit not in description:
            description = f"{description}\n\n**Exploitation Analysis:**\n\n{_exploit}"

        # Validation method label
        validation_method = self._extract_validation_method(finding)

        # Alternative payloads section — one fenced block per payload. A numbered list of
        # inline code spans looked tidier but deleted every backtick in the payload.
        alt_payloads = finding.get("successful_payloads") or []
        if len(alt_payloads) > 1:
            lines = ["\n**Alternative Payloads:**\n"]
            for i, p in enumerate(alt_payloads, 1):
                lines.append(f"Payload {i}:\n\n{md_code_block(p)}\n")
            alternative_payloads_section = "\n".join(lines) + "\n"
        else:
            alternative_payloads_section = ""

        # URL / Parameter / Payload — byte-exact fenced blocks, plus the detection probe
        # whenever the report ships a different (visual) payload than the evidence used.
        injection_point = self._md_injection_point(finding)

        # Fill template
        filled = template.format(
            index=index,
            title=finding.get("title") or vuln_type,
            severity_badge=severity_badge,
            cwe_cell=cwe_cell,
            cve_reference=cve_reference,
            status_badge=status_badge,
            cvss_score=cvss_score_str,
            validation_method=validation_method,
            injection_point=injection_point,
            description=description,
            impact=impact,
            remediation=remediation,
            http_request_block=http_request_block,
            http_response_block=http_response_block,
            screenshot_section=screenshot_section,
            reproduction_steps=reproduction_steps,
            alternative_payloads_section=alternative_payloads_section
        )

        return filled

    def _md_build_finding_entry_inline(self, finding: Dict, index: int) -> str:
        """
        Fallback method to build finding entry inline (used when template not found).
        Returns markdown string instead of appending to lines list.
        """
        lines = []
        lines.append(f"### {index}. {finding.get('type', 'Unknown Vulnerability')}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Severity** | {finding.get('severity', 'MEDIUM')} |")
        cvss_score = finding.get("cvss_score")
        cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
        lines.append(f"| **CVSS Score** | {cvss_str} |")
        lines.append(f"| **Status** | ✅ CONFIRMED |")
        lines.append(f"| **Validation Method** | {self._extract_validation_method(finding)} |")
        if finding.get("db_type"):
            lines.append(f"| **DB Type** | {finding.get('db_type')} |")
        if finding.get("tamper_used"):
            lines.append(f"| **Tamper Script** | {finding.get('tamper_used')} |")
        lines.append("")

        # URL / Parameter / Payload as fenced blocks — a markdown table cell cannot carry
        # them byte-exact (no newlines, pipes break the row, runs of spaces collapse).
        lines.append(self._md_injection_point(finding))
        lines.append("")

        # Steps to Reproduce (type-specific)
        lines.append("#### Steps to Reproduce\n")
        for step in self._generate_reproduction_steps(finding):
            lines.append(step)
        lines.append("")

        # PoC (Only for SQLi where we have SQLMap command)
        if "SQL" in finding.get("type", "").upper() and not self._generate_curl(finding).startswith("#"):
            lines.append("#### Proof of Concept\n")
            lines.append(md_code_block(self._generate_curl(finding), "bash"))
            lines.append("")

        # Validator Notes
        if finding.get("validator_notes"):
            lines.append("#### Validation Notes\n")
            lines.append(f"> {finding.get('validator_notes')}\n")

        # Screenshot
        if finding.get("screenshot_path"):
            img_name = Path(finding.get("screenshot_path")).name
            lines.append(f"#### Screenshot\n")
            lines.append(f"![Evidence](captures/{img_name})\n")

        lines.append("---\n")
        return "\n".join(lines)

    def _md_build_finding_entry(self, lines: List[str], f: Dict, index: int):
        """Build a single finding entry in markdown report using standardized template."""
        # Use new standardized generation
        finding_md = self._generate_standardized_finding(f, index)
        lines.append(finding_md)

    def _md_build_manual_review(self, lines: List[str], manual_review: List[Dict]):
        """Build manual review section of markdown report.

        Manual-review findings carry the SAME rich data as confirmed ones (description,
        impact, remediation, reproduction, evidence) — they just weren't browser-confirmed.
        The HTML/JSON deliverable renders all of it via _build_finding_entry, so the markdown
        must too; otherwise the same finding is a full write-up in HTML and a skeleton in .md.
        """
        if not manual_review:
            return

        lines.append("## Needs Manual Review\n")
        lines.append("> These findings have high AI confidence but could not be confirmed via browser automation.\n")

        # Sort by CVSS so MR-1..MR-n appear in the SAME priority order as the HTML/JSON
        # deliverable (which folds manual_review into vuln_findings + _sort_findings_by_cvss).
        # The validated and pending sections already share this sort; manual_review was missed.
        manual_review = self._sort_findings_by_cvss(manual_review)

        severity_badges = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🔵 LOW",
            "INFO": "⚪ INFO"
        }
        for i, f in enumerate(manual_review, 1):
            severity = f.get('severity', 'HIGH').upper()
            severity_badge = severity_badges.get(severity, severity)
            cvss_score = f.get("cvss_score")
            cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
            lines.append(f"### MR-{i}. {f.get('type', 'Unknown')}\n")
            lines.append(f"- **Severity:** {severity_badge}")
            lines.append(f"- **CVSS Score:** {cvss_str}")
            lines.append(self._md_injection_point(f))
            lines.append("")

            # Full-fidelity body (parity with the HTML/JSON deliverable): description, evidence,
            # impact, remediation and reproduction — synthesized when a field is blank.
            desc = f.get("description") or self._synthesize_description(f)
            lines.append("#### Description\n")
            lines.append(f"{desc}")
            lines.append("")

            _ev = self._render_evidence_dict(f)
            if _ev:
                lines.append("#### Detection Evidence\n")
                lines.append(_ev)
                lines.append("")

            impact = f.get("impact") or self._get_impact_for_type(f.get("type", ""))
            if impact:
                lines.append("#### Impact\n")
                lines.append(f"{impact}")
                lines.append("")

            remediation = f.get("remediation") or self._get_remediation_for_type(f.get("type", ""))
            if remediation:
                lines.append("#### Remediation\n")
                lines.append(f"{remediation}")
                lines.append("")

            # Reproduction only for genuine injection findings (has a payload); observation/
            # config findings rely on Description + Detection Evidence — no forced curl.
            if f.get("payload"):
                _repro = self._generate_curl(f)
                if _repro:
                    lines.append("#### Reproduction\n")
                    lines.append(md_code_block(_repro, "bash"))
                    lines.append("")

            if f.get("validator_notes"):
                lines.append(f"- **AI Notes:** {f.get('validator_notes')}")
                lines.append("")

    def _md_build_pending_findings(self, lines: List[str], pending: List[Dict]):
        """Build pending findings section of markdown report.

        These are findings detected by specialists but not yet confirmed via CDP.
        They often represent valid vulnerabilities that require manual verification.
        """
        if not pending:
            return

        lines.append("---\n")
        lines.append("## Pending Validation (High Confidence)\n")
        lines.append("> ⚠️ These findings were detected by specialist agents but could not be confirmed via browser automation.")
        lines.append("> They likely represent valid vulnerabilities. Manual verification recommended.\n")

        # Sort by CVSS (desc) — the HTML/JSON viewer sorts pending by CVSS via
        # _sort_findings_by_cvss, so the markdown must match or the same set is ordered
        # differently per deliverable.
        pending_sorted = self._sort_findings_by_cvss(pending)

        for i, f in enumerate(pending_sorted, 1):
            vuln_type = f.get('type', 'Unknown')
            severity = f.get('severity', 'HIGH').upper()
            severity_badges = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🔵 LOW",
                "INFO": "⚪ INFO"
            }
            severity_badge = severity_badges.get(severity, severity)

            lines.append(f"### P-{i}. {vuln_type}\n")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {severity_badge} |")
            cvss_score = f.get("cvss_score")
            cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
            lines.append(f"| **CVSS Score** | {cvss_str} |")
            lines.append(f"| **Status** | ⏳ PENDING |")
            lines.append("")
            lines.append(self._md_injection_point(f))
            lines.append("")

            # Description — synthesized from type/param/payload when the specialist (or a raw
            # Nuclei stub) left it blank, so pending entries never render an empty body.
            desc = f.get("description") or self._synthesize_description(f)
            lines.append("#### Description\n")
            lines.append(f"{desc}")
            lines.append("")

            # Detection Evidence — surface the structured evidence dict (same as confirmed
            # findings); pending Nuclei/informational detections keep their proof here.
            _ev = self._render_evidence_dict(f)
            if _ev:
                lines.append("#### Detection Evidence\n")
                lines.append(_ev)
                lines.append("")

            if f.get("impact"):
                lines.append("#### Impact\n")
                lines.append(f"{f.get('impact')}")
                lines.append("")

            if f.get("validator_notes"):
                lines.append("#### Validator Notes\n")
                lines.append(f"{f.get('validator_notes')}")
                lines.append("")

            lines.append("---\n")

    def _copy_html_template(self) -> Path:
        """Copy the static HTML template that loads engagement_data.json.

        DEAD (verified 2026-07-28 by import graph): nothing calls this, nor the
        ``_create_minimal_html`` / ``_build_html_template`` pair below it. The report.html
        that ships is written by ``reporting/generator.py``, which copies
        ``templates/report_viewer.html`` — the viewer that HTML-ESCAPES every payload it
        prints. The two templates this method would use do NOT escape: they concatenate
        ``reproduction.poc`` / ``exploitation_details`` / ``validation.notes`` straight into
        ``innerHTML``, so any payload containing a tag would be swallowed by the parser and
        never shown. Revive either of them and that has to be fixed first.
        """
        # The HTML template location
        template_src = Path(__file__).parent.parent / "reporting" / "templates" / "report_dynamic.html"
        dest = self.output_dir / "report.html"

        if template_src.exists():
            shutil.copy(template_src, dest)
        else:
            # Create a minimal HTML if template doesn't exist
            self._create_minimal_html(dest)

        logger.info(f"[{self.name}] Copied report.html")
        return dest

    def _create_minimal_html(self, path: Path):
        """Create minimal HTML that loads JSON dynamically."""
        html = self._build_html_template()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_html_template(self) -> str:
        """
        Build HTML template string for dynamic report viewer.
        Note: HTML template strings >50 lines are acceptable per 08-03 decision.
        """
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugTraceAI Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { font-family: system-ui, sans-serif; background: #f8fafc; }
        .severity-critical { background: #991b1b; color: white; }
        .severity-high { background: #dc2626; color: white; }
        .severity-medium { background: #d97706; color: white; }
        .severity-low { background: #2563eb; color: white; }
        .severity-info { background: #059669; color: white; }
        pre { background: #1e293b; color: #e2e8f0; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
    </style>
</head>
<body class="p-8">
    <div id="app" class="max-w-6xl mx-auto">
        <div class="text-center py-8">
            <p class="text-gray-500">Loading report...</p>
        </div>
    </div>

    <script>
        async function loadReport() {
            try {
                const response = await fetch('./engagement_data.json');
                const data = await response.json();
                renderReport(data);
            } catch (e) {
                document.getElementById('app').innerHTML =
                    '<p class="text-red-500">Error loading report: ' + e.message + '</p>';
            }
        }

        function renderReport(data) {
            const app = document.getElementById('app');

            let html = `
                <header class="mb-8">
                    <h1 class="text-3xl font-bold text-gray-900">Security Assessment Report</h1>
                    <p class="text-gray-600 mt-2">Target: ${data.meta.target}</p>
                    <p class="text-gray-500 text-sm">Scan ID: ${data.meta.scan_id} | Date: ${data.meta.scan_date}</p>
                </header>

                <section class="grid grid-cols-4 gap-4 mb-8">
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-green-600">${data.summary.validated}</p>
                        <p class="text-gray-600">Confirmed</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-yellow-600">${data.summary.manual_review}</p>
                        <p class="text-gray-600">Manual Review</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-red-600">${data.summary.false_positives}</p>
                        <p class="text-gray-600">False Positives</p>
                    </div>
                    <div class="bg-white p-4 rounded-lg shadow">
                        <p class="text-3xl font-bold text-gray-600">${data.summary.total_findings}</p>
                        <p class="text-gray-600">Total</p>
                    </div>
                </section>

                <section>
                    <h2 class="text-2xl font-bold mb-4">Confirmed Vulnerabilities</h2>
            `;

            if (data.findings.length === 0) {
                html += '<p class="text-gray-500">No confirmed vulnerabilities found.</p>';
            } else {
                data.findings.forEach((f, i) => {
                    const sevClass = 'severity-' + f.severity.toLowerCase();
                    html += `
                        <div class="bg-white rounded-lg shadow mb-4 overflow-hidden">
                            <div class="flex items-center justify-between p-4 border-b">
                                <h3 class="text-xl font-bold">${f.id}. ${f.type}</h3>
                                <span class="px-3 py-1 rounded text-sm font-bold ${sevClass}">${f.severity}</span>
                            </div>
                            <div class="p-4">
                                <p class="mb-2"><strong>URL:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.url}</code></p>
                                <p class="mb-2"><strong>Parameter:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.parameter}</code></p>
                                <p class="mb-4"><strong>Payload:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.payload}</code></p>
                                ${f.db_type ? `<p class="mb-2"><strong>DB Type:</strong> <span class="bg-blue-100 text-blue-800 px-2 py-1 rounded">${f.db_type}</span></p>` : ''}
                                ${f.tamper_used ? `<p class="mb-2"><strong>Tamper Script:</strong> <code class="bg-gray-100 px-2 py-1 rounded">${f.tamper_used}</code></p>` : ''}

                                <h4 class="font-bold mt-4 mb-2">Steps to Reproduce</h4>
                                <ol class="list-decimal list-inside mb-4">
                                    ${(f.reproduction && f.reproduction.steps) ? f.reproduction.steps.map(s => '<li>' + s + '</li>').join('') : '<li>No specific reproduction steps provided.</li>'}
                                </ol>

                                ${(f.reproduction && f.reproduction.poc && !f.reproduction.poc.trim().startsWith('#')) ?
                                `<h4 class="font-bold mt-4 mb-2">Proof of Concept</h4>
                                <pre class="whitespace-pre-wrap">${f.reproduction.poc}</pre>` : ''}

                                ${f.exploitation_details ? '<div class="mt-4 p-4 bg-red-50 border-l-4 border-red-500 rounded"><h4 class="font-bold text-red-700 mb-2">🎯 Exploitation Details</h4><pre class="whitespace-pre-wrap text-sm text-gray-800">' + f.exploitation_details + '</pre></div>' : ''}

                                ${f.validation.notes ? '<p class="mt-4 text-gray-600"><strong>Validator Notes:</strong> ' + f.validation.notes + '</p>' : ''}
                                ${f.validation.screenshot ? '<img src="' + f.validation.screenshot + '" class="mt-4 rounded border" />' : ''}
                            </div>
                        </div>
                    `;
                });
            }

            html += '</section>';
            app.innerHTML = html;
        }

        loadReport();
    </script>
</body>
</html>'''

    def _copy_screenshots(self, findings: List[Dict], captures_dir: Path):
        """Copy all screenshots to the captures folder."""
        for f in findings:
            self._copy_single_screenshot(f, captures_dir)

    def _copy_single_screenshot(self, finding: Dict, captures_dir: Path):
        """Copy a single screenshot to captures directory."""
        src = finding.get("screenshot_path")
        if not src:
            return
        # screenshot_path is stored RELATIVE to the report dir (so the WEB can fetch
        # it via the API file route). Resolve it against the report dir before the
        # existence check — otherwise a relative path is tested against the process
        # CWD, silently no-ops the copy, and leaves a broken captures/<name> link.
        src_path = Path(src)
        if not src_path.is_absolute():
            src_path = captures_dir.parent / src
        if not src_path.exists():
            return

        try:
            shutil.copy(src_path, captures_dir / src_path.name)
        except Exception as e:
            logger.debug(f"Could not copy screenshot {src}: {e}")

    def _generate_curl(self, finding: Dict) -> str:
        """
        Generate reproduction command for the finding.
        2026-01-24 FIX: Generate useful curl commands for ALL vuln types.
        """
        # Priority 1: Use specialist-provided reproduction command
        if finding.get("reproduction"):
            return finding.get("reproduction")

        # Priority 2: Generate command based on vuln type
        vuln_type = (finding.get("type") or "").upper()
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")

        if vuln_type in ["SQLI", "SQL"]:
            return self._curl_build_sqli(url, param)

        if vuln_type in ["CSTI", "SSTI"]:
            return self._curl_build_csti(url, param, payload)

        if vuln_type == "XSS":
            return self._curl_build_xss(url, param, payload, finding.get("http_method") or finding.get("method"))

        if vuln_type == "SSRF":
            return (
                "# SSRF: Use Burp Collaborator or webhook.site to test OOB callbacks\n"
                + curl_get(url)
            )

        if vuln_type == "LFI":
            return self._curl_build_lfi(url, param, payload)

        if vuln_type == "IDOR":
            return "# IDOR: Test with different user IDs/values\n" + curl_get(url)

        return self._curl_build_fallback(url, param, payload)

    def _curl_build_sqli(self, url: str, param: str) -> str:
        """Build SQLi reproduction command."""
        if param:
            return f"sqlmap -u {shell_word(url)} -p {param} --batch --dbs"
        return f"sqlmap -u {shell_word(url)} --batch --dbs"

    def _curl_build_csti(self, url: str, param: str, payload: str) -> str:
        """Build CSTI/SSTI reproduction command.

        Every payload travels through a byte-safe channel — a quoted shell word for the
        header/body shapes, percent-encoding for the URL shape. The project's own visual
        CSTI banner contains a single quote, which used to break the command outright.

        The success indicator is DERIVED from the probe that was actually sent
        (``{{7*7}}`` → 49) instead of being hardcoded: an upgraded, non-arithmetic payload
        gets no `grep` that could never match.
        """
        default_payload = "{{7*7}}"
        test_payload = payload if payload else default_payload
        expected = template_expression_result(test_payload)
        check = f" | grep {shell_word(expected)}" if expected else ""

        # Check if it's a header injection
        if param and param.startswith("HEADER:"):
            header_name = param.replace("HEADER:", "")
            cmd = curl_header(url, header_name, test_payload, extra=check.lstrip())
            if cmd:
                return cmd
            # The payload cannot legally be a header field value (CR/LF); a curl would
            # silently deliver a truncated header, so point at the injection instead.
            return (f"# CSTI via header {header_name} on {url}\n"
                    f"# The payload below spans multiple lines and cannot ride an HTTP\n"
                    f"# header — replay the captured request in an intercepting proxy.\n"
                    f"{test_payload}")
        elif param and param.startswith("POST:"):
            param_name = param.replace("POST:", "")
            return curl_form_field(url, param_name, test_payload) + check
        elif param and payload:
            # URL param injection — percent-encoded, so the command has no shell metacharacters
            test_url = build_query_url(url, param, payload)
            if test_url:
                return curl_get(test_url) + check
        return f"# CSTI on {url} - inject {{{{7*7}}}} in parameter {param}"

    def _curl_build_xss(self, url: str, param: str, payload: str, method: str = "") -> str:
        """Build XSS reproduction command (a browser URL, not a curl — an XSS PoC has to
        run in a DOM, and the percent-encoded URL carries the payload byte-exact).

        Exception: a POST-only endpoint. Emitting a GET URL for it sends the triager to a
        page that shows nothing, and the honest conclusion they reach is "false positive".
        The sibling builders (_build_xxe_steps / _build_ssrf_steps / _build_generic_steps)
        already branch on http_method; XSS was the only one that never received it.
        """
        if param and payload and (method or "").upper() == "POST":
            return (
                "# Stored/reflected XSS on a POST endpoint — submit the field, then load the\n"
                "# page that renders it to observe execution:\n"
                + curl_form_field(url, param, payload)
            )
        if param and payload:
            test_url = build_query_url(url, param, payload)
            if test_url:
                return f"# Open in browser to trigger XSS:\n{test_url}"
        if payload:
            # No URL to build. The reproduction is always RENDERED inside a code block
            # (md_code_block picks a fence long enough for it), so the payload can sit on
            # its own plain line here and still reach the clipboard byte-exact.
            return (
                f"# XSS: inject the payload below into parameter: {param or 'unknown'}\n"
                f"{payload}"
            )
        return f"# XSS on {url} - test the input fields for {param or 'reflected input'}"

    def _curl_build_lfi(self, url: str, param: str, payload: str = "") -> str:
        """Build LFI reproduction command from the finding's OWN traversal payload."""
        if param and payload:
            return curl_get(build_query_url(url, param, payload) or url)
        if param:
            return f"# LFI on {url} - inject a traversal path into parameter {param}"
        return f"# LFI on {url} - test with a directory-traversal path"

    def _curl_build_fallback(self, url: str, param: str, payload: str) -> str:
        """Build fallback reproduction command.

        The payload sits on its own line rather than inside a `# Payload: ...` comment:
        the whole command is rendered inside a code block, so a plain line reaches the
        clipboard byte-exact while a comment line invites callers to lift it into prose.
        """
        if url and param:
            head = f"# Vulnerable endpoint: {url}\n# Parameter: {param}"
            return f"{head}\n# Payload:\n{payload}" if payload else head
        elif url:
            return f"# Vulnerable endpoint: {url}"
        else:
            return "# No reproduction command available"

    def _extract_validation_method(self, finding: Dict) -> str:
        """
        Extract and normalize validation method from findings.

        Maps various validation method indicators to standardized labels:
        - OOB (Interactsh): Out-of-band validation via Interactsh callbacks
        - HTTP Response Analysis: Server response analysis without browser
        - Playwright Browser: Full browser automation validation
        - CDP + Vision AI: Chrome DevTools Protocol with visual AI
        - SQLMap Automated: SQLMap tool validation
        - Template Engine: CSTI/SSTI template injection validation
        - Fuzzer Validation: Go fuzzer or similar tool validation

        Args:
            finding: Finding dictionary with validation data

        Returns:
            Standardized validation method label
        """
        # Extract raw method from multiple possible locations
        raw_method = finding.get("validation_method")
        if not raw_method:
            evidence = finding.get("evidence")
            if isinstance(evidence, dict):
                raw_method = evidence.get("validation_method")
        if not raw_method:
            raw_method = ""
        raw_method = str(raw_method).lower()

        # OOB-based validation (Interactsh callbacks)
        if "interactsh" in raw_method or "oob" in raw_method:
            return "OOB (Interactsh)"

        # HTTP response analysis (no browser needed)
        if "http" in raw_method or raw_method == "http_response_analysis":
            return "HTTP Response Analysis"

        # Playwright browser validation
        if "playwright" in raw_method or "browser" in raw_method:
            return "Playwright Browser"

        # CDP validation (Chrome DevTools Protocol)
        if finding.get("cdp_validated") or "cdp" in raw_method or "vision" in raw_method:
            return "CDP + Vision AI"

        # SQLMap validation
        if "sqlmap" in raw_method:
            return "SQLMap Automated"

        # Template-specific (CSTI)
        template_engines = ["jinja", "twig", "freemarker", "velocity", "mako", "smarty"]
        if raw_method and any(engine in raw_method for engine in template_engines):
            return f"Template Engine ({raw_method.title()})"

        # Fuzzer-based
        if "fuzzer" in raw_method:
            return "Fuzzer Validation"

        # Fallback based on vuln type
        vuln_type = (finding.get("type") or "").upper()
        if vuln_type in ["SQLI", "SQL"]:
            return "SQLMap/Error Detection"
        if vuln_type == "XSS":
            return "HTTP/Playwright"

        return raw_method.title() if raw_method else "Automated Check"

    def _get_validation_method(self, finding: Dict) -> str:
        """
        Get validation method based on finding.
        Delegates to _extract_validation_method for consistent extraction.
        """
        return self._extract_validation_method(finding)
    
    def _get_validation_notes(self, finding: Dict) -> str:
        """Generate detailed validation notes based on finding type.

        PLAIN TEXT, deliberately. The one consumer of this string is the finding entry's
        ``validation.notes``, and every viewer that reads it HTML-escapes the value into a
        pre-formatted block — so the markdown this used to emit (``**bold**`` labels and a
        fenced evidence block) reached the reader as literal asterisks and backticks, and
        the SQLi payload inside the fence was shown with the fence around it. Escaping also
        means the payload needs no encoding here: it arrives byte-exact as-is.
        """
        vuln_type = finding.get("type", "").upper()

        if vuln_type != "SQLI":
            return finding.get("validator_notes", "Confirmed by specialist agent (CDP not required)")

        notes = ["SQLMap Validation Results:"]
        if finding.get("db_type"):
            notes.append(f"- Database Type: {finding.get('db_type')}")
        if finding.get("payload"):
            notes.append(f"- Injection Technique: {finding.get('payload')}")
        if finding.get("tamper_used"):
            notes.append(f"- WAF Bypass: {finding.get('tamper_used')}")
        if finding.get("confidence"):
            notes.append(f"- Confidence: {finding.get('confidence')*100:.0f}%")

        evidence = finding.get("evidence")
        if isinstance(evidence, dict) and evidence:
            pairs, dropped_keys = evidence_pairs(
                evidence,
                limit=settings.REPORT_EVIDENCE_MAX_FIELDS,
                value_budget=settings.REPORT_EVIDENCE_VALUE_CHARS,
            )
            rendered = plain_evidence_block(pairs, dropped_keys)
        elif evidence:
            text, dropped = truncate_marked(str(evidence), settings.REPORT_EVIDENCE_VALUE_CHARS)
            rendered = text + (f"\n  (truncated: {len(text)} of {len(text) + dropped} "
                               f"characters shown)" if dropped else "")
        else:
            rendered = ""
        if rendered:
            notes.append("\nEvidence:\n" + rendered)
        return "\n".join(notes)

    def _generate_reproduction_steps(self, finding: Dict) -> List[str]:
        """
        Generate detailed, triager-ready reproduction steps based on vulnerability type.
        These steps tell the triager EXACTLY what to do and what to observe.
        """
        vuln_type = (finding.get("type") or "").upper()

        if vuln_type == "XXE":
            return self._build_xxe_steps(finding)

        if vuln_type in ["SQLI", "SQL_INJECTION"]:
            return self._build_sqli_steps(finding)

        if vuln_type in ["XSS", "STORED_XSS", "REFLECTED_XSS"]:
            return self._build_xss_steps(finding)

        if vuln_type == "SSRF":
            return self._build_ssrf_steps(finding)

        if vuln_type == "CSRF":
            return self._build_csrf_steps(finding)

        if vuln_type == "OPEN_REDIRECT":
            return self._build_open_redirect_steps(finding)

        return self._build_generic_steps(finding)

    def _build_xxe_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for XXE vulnerabilities."""
        # Derive the injection point from the finding itself — the XXE endpoint is the
        # finding's own URL, never a hardcoded path (was pinned to ginandjuice's
        # /catalog/product/stock, which 404s on any other target).
        url = finding.get("url", "")
        method = (finding.get("http_method") or finding.get("method") or "POST").upper()

        return [
            md_step_with_value("1. Identify the endpoint that accepts an XML request body:", url),
            "2. Open an intercepting proxy (e.g. Burp) or browser DevTools (F12) → Network tab",
            "3. Trigger the feature that submits XML and capture the normal request",
            f"4. Intercept the {method} request to that endpoint",
            "5. Replace the XML body with the malicious payload containing the XXE entity",
            "6. Forward the request and observe the out-of-band callback on your server",
            "7. **Expected Result:** Your OOB server receives a DNS/HTTP callback from the target server"
        ]

    def _build_sqli_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for SQLi vulnerabilities."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")

        is_time_based = any(kw in payload.lower() for kw in ["sleep", "benchmark", "pg_sleep", "waitfor", "delay"])
        is_error_based = any(kw in payload.lower() for kw in ["cast", "convert", "extractvalue", "updatexml"])

        if is_time_based:
            return [
                md_step_with_value("1. Navigate to:", url),
                md_step_with_value("2. Locate this parameter in the URL/form:", param),
                md_step_with_block("3. Inject the time-based payload:", payload),
                "4. Submit the request and start a timer",
                "5. **Expected Result:** Response takes 5+ seconds (indicating SQL SLEEP executed)",
                "6. Compare with normal request time (should be <1 second)",
                "7. Difference in response time confirms blind SQL injection"
            ]
        elif is_error_based:
            return [
                md_step_with_value("1. Navigate to:", url),
                md_step_with_value("2. Locate this parameter:", param),
                md_step_with_block("3. Inject the error-based payload:", payload),
                "4. Submit the request",
                "5. **Expected Result:** Response contains database data in error message",
                "6. Look for extracted values (usernames, passwords, etc.) in the error output"
            ]
        else:
            return [
                md_step_with_value("1. Navigate to:", url),
                md_step_with_value("2. Locate this parameter:", param),
                md_step_with_block("3. Inject the payload:", payload),
                "4. Submit the request",
                "5. **Expected Result:** SQL error message or altered response indicating injection",
                # `-p` only when there IS a parameter: with an empty one the option
                # swallowed the next flag (`-p  --batch`) and sqlmap tested "--batch".
                md_step_with_block(
                    "6. For further exploitation, use SQLMap:",
                    f"sqlmap -u {shell_word(url)}"
                    + (f" -p {shell_word(param)}" if param else "")
                    + " --batch", "bash")
            ]

    def _build_xss_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for XSS vulnerabilities — from the finding's own data
        (was static filler that told the triager to 'copy the exploit URL' while emitting none)."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        method = (finding.get("http_method") or finding.get("method") or "").upper()
        loc = "the parameter above" if param else "the injection point"
        # Step 1 used to tell the triager to load the URL in a browser regardless of method.
        # On a POST-only endpoint that renders a blank page, and the report reads as a false
        # positive for a finding that is real.
        if method == "POST":
            head = [
                (md_step_with_value("1. Submit the payload with a POST request to this endpoint (see the reproduction command):", url)
                 if url else "1. Submit the payload with a POST request to the affected endpoint"),
            ]
        else:
            head = [
                (md_step_with_value("1. Load this URL in a fresh incognito browser window:", url)
                 if url else "1. Open the affected page in a fresh incognito browser window"),
            ]
        if param:
            head.append(md_step_with_value("2. Injection parameter:", param))
        n = len(head) + 1
        head.append(md_step_with_block(f"{n}. Payload injected into {loc}:", payload) if payload
                    else f"{n}. Inject the XSS payload into {loc}")
        tail = [
            "**Expected Result:** a JavaScript alert box appears, or the payload executes in the DOM",
            "Open DevTools Console (F12) to confirm execution",
            "For stored XSS: navigate to where the payload is rendered and confirm it fires",
            "Screenshot the alert/execution as proof",
        ]
        return head + [f"{n + 1 + i}. {t}" for i, t in enumerate(tail)]

    def _build_ssrf_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for SSRF vulnerabilities."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")

        return [
            "1. Set up an out-of-band callback server (Burp Collaborator, interactsh, or webhook.site)",
            md_step_with_value("2. Navigate to:", url),
            (md_step_with_value("3. Locate this parameter:", param) if param
             else "3. Locate the request parameter that accepts a URL/host value"),
            "4. Inject your callback URL as the payload",
            "5. Submit the request",
            "6. **Expected Result:** Your callback server receives a request from the target server",
            "7. For internal network access, try: http://169.254.169.254/latest/meta-data/ (AWS metadata)"
        ]

    def _build_csrf_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for CSRF from the finding's own endpoint/method
        (was static filler that promised a non-existent auto-submit 'csrf_poc.html'
        and an 'item added to cart' outcome unrelated to the actual target)."""
        url = finding.get("url", "")
        method = (finding.get("http_method") or finding.get("method") or "POST").upper()
        return [
            (md_step_with_value(
                "1. Log into the target, then confirm this state-changing request carries "
                "no anti-CSRF token:", f"{method} {url}") if url else
             "1. Log into the target, then confirm the state-changing request carries no anti-CSRF token"),
            "2. Build an HTML page on an external origin that auto-submits that same request (a cross-site `<form>` or fetch)",
            "3. While still authenticated to the target, open that attacker page in the same browser",
            "4. **Expected Result:** the action at that endpoint executes using the victim's session — no token/Origin check blocks it",
            "5. Verify in the application that the unauthorized action took effect",
        ]

    def _build_open_redirect_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for Open Redirect — from the finding's own data (was static
        filler that said 'copy the exploit URL' while emitting no URL and no redirect param)."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        steps = [
            (md_step_with_value("1. Load this URL in a new browser tab:", url) if url
             else "1. Load the affected URL in a new browser tab"),
        ]
        if param:
            steps.append(md_step_with_value(
                f"{len(steps) + 1}. The redirect is driven by this parameter:", param))
        if payload:
            steps.append(md_step_with_block(
                f"{len(steps) + 1}. Redirect payload:", payload))
        if not param and not payload:
            steps.append("2. Set the redirect parameter to an external attacker domain")
        tail = [
            "**Expected Result:** the browser redirects to the external attacker domain",
            "Confirm the destination in the address bar",
            "Impact: usable for phishing — redirect users from the trusted domain to a fake login page",
        ]
        return steps + [f"{len(steps) + 1 + i}. {t}" for i, t in enumerate(tail)]

    def _build_generic_steps(self, finding: Dict) -> List[str]:
        """Reproduction steps for types without a dedicated builder.

        A curl is synthesized ONLY when it genuinely reproduces the finding — i.e. there is
        a captured request, or an injection payload that goes into a request. For
        observation / configuration findings (missing headers, CORS, rate-limiting,
        vulnerable components, access-control without a captured request…) a bare curl
        proves nothing, so we point to the Evidence instead of fabricating one. (The old
        "always emit a curl" default slapped meaningless `curl -i url` onto everything.)
        """
        url = (finding.get("url") or "").strip()
        param = (finding.get("parameter") or "").strip()
        payload = (finding.get("payload") or "").strip()
        method = (finding.get("http_method") or finding.get("method") or "").upper()
        raw_req = (finding.get("http_request") or "").strip()

        # A real captured request reproduces it exactly.
        if raw_req and len(raw_req) > 12:
            return [
                md_step_with_value("1. Target endpoint:", url),
                md_step_with_block(
                    "2. Replay the exact request below (curl, or an intercepting proxy like Burp):",
                    raw_req, "http",
                ),
                "3. Observe the response for the indicator described in the Evidence section.",
            ]

        # A genuine injection (a payload goes into the request) — here a curl IS a real PoC.
        # The payload rides in a percent-encoded URL (GET) or a quoted --data-urlencode
        # word (POST); interpolated raw it broke the command, or silently sent nothing.
        if url and payload:
            if param:
                curl = curl_get(build_query_url(url, param, payload) or url)
                detail = md_step_with_value(
                    "2. This injects the payload into this parameter:", param)
            else:
                curl = curl_raw_body(url, payload, method=method or "POST")
                detail = "2. This sends the payload to the endpoint as the request body."
            return [
                md_step_with_block("1. Reproduce with:", curl, "bash"),
                detail,
                "3. Compare the response against the Evidence to confirm the indicator.",
            ]

        # No injection input → an observation / configuration finding. Do NOT fabricate a
        # curl (a bare `curl -i url` proves nothing for CORS / missing headers / rate-limiting
        # / vulnerable components). Point to the Evidence instead.
        return [
            "1. This is an observation / configuration finding, confirmed from the scanner's Evidence below.",
            (md_step_with_value("2. Affected:", url) if url
             else "2. See the Evidence section for the affected component."),
            "3. Validate by reviewing the response / configuration in the Evidence — no injection request applies.",
        ]

    def _get_impact_for_type(self, vuln_type: str) -> str:
        """Get standard impact description for vulnerability type."""
        impacts = {
            "XSS": "Cross-Site Scripting can lead to session hijacking, credential theft, defacement, and malware distribution.",
            "SQLI": "SQL Injection can lead to unauthorized data access, data manipulation, and complete database compromise.",
            "LFI": "Local File Inclusion can expose sensitive files and potentially lead to remote code execution.",
            "RCE": "Remote Code Execution allows attackers to run arbitrary commands on the server.",
            "SSRF": "Server-Side Request Forgery can expose internal services and sensitive data.",
            "IDOR": "Insecure Direct Object Reference can lead to unauthorized access to other users' data.",
            "CSTI": "Client-Side Template Injection can lead to XSS, data theft, and in some cases remote code execution.",
            "SSTI": "Server-Side Template Injection can lead to remote code execution and full server compromise.",
            "JWT": "JWT vulnerabilities can lead to authentication bypass and unauthorized access to protected resources.",
            "XXE": "XML External Entity injection can expose sensitive files, perform SSRF, and cause denial of service.",
            "OPEN_REDIRECT": "Open Redirect can be used for phishing attacks and credential theft via trusted domain abuse.",
            "PROTOTYPE_POLLUTION": "Prototype Pollution can lead to XSS, denial of service, and privilege escalation in JavaScript applications.",
            "HEADER_INJECTION": "HTTP Header Injection can lead to cache poisoning, session fixation, and XSS via response splitting.",
            "FILE_UPLOAD": "Unrestricted file upload can lead to remote code execution and server compromise.",
            "MASS_ASSIGNMENT": "Mass Assignment can allow privilege escalation by modifying restricted fields like roles or permissions.",
            "API_SECURITY": "API security issues can expose sensitive data, enable unauthorized operations, and lead to data breaches.",
            "BROKEN_ACCESS_CONTROL": "Broken Access Control allows unauthorized users to access administrative or restricted functionality.",
            "INSECURE_COOKIE_CONFIGURATION": "Insecure cookie configuration can expose session tokens to theft via network sniffing or XSS attacks.",
            "GRAPHQL_INTROSPECTION": "GraphQL introspection exposure allows attackers to map the entire API schema and discover hidden queries and mutations.",
            "API_DOCUMENTATION_EXPOSURE": "Exposed API documentation reveals endpoint structure, parameters, and data models to potential attackers.",
            "MISSING_SECURITY_HEADER": "Missing security headers reduce defense-in-depth, making other vulnerabilities easier to exploit.",
            "INSECURE_DESERIALIZATION": "Insecure deserialization can lead to remote code execution, authentication bypass, and data tampering.",
            # Previously fell through to the generic placeholder impact:
            "CSRF": "Cross-Site Request Forgery lets an attacker force an authenticated victim's browser into performing state-changing actions without their consent.",
            "CORS_MISCONFIGURATION": "A permissive CORS policy lets malicious origins read authenticated responses, exposing user data across sites.",
            "WEAK_CRYPTOGRAPHY": "Weak or outdated cryptography can expose sensitive data through decryption, forgery, or downgrade attacks.",
            "INFORMATION_DISCLOSURE": "Information disclosure leaks internal details (paths, versions, stack traces) that help an attacker mount further attacks.",
            "MISSING_RATE_LIMITING": "Absent rate limiting enables brute-force, credential stuffing, and resource-exhaustion abuse of the endpoint.",
            "VULNERABLE_DEPENDENCY": "Using components with known vulnerabilities exposes the application to publicly documented exploits for that library version.",
        }
        # Normalize any casing/spacing/hyphen variant to one canonical key
        # ("CORS Misconfiguration" / "cors-misconfiguration" → "CORS_MISCONFIGURATION"),
        # so we don't carry duplicate space+underscore keys (DRY).
        key = re.sub(r"[^A-Z0-9]+", "_", (vuln_type or "").upper()).strip("_")
        return impacts.get(key, "This vulnerability may compromise the security of the application.")


    async def _enrich_findings_batch(self, findings: List[Dict]):
        """
        Enrich a batch of findings with CVSS scores and professional PoC using LLM.

        v3.5: CVSS uses batch mode (1 LLM call per chunk of 10 findings).
        PoC still uses individual calls (needs detailed per-finding output).
        """
        # Manual-review findings are intentionally unconfirmed. Generating an
        # exploitation narrative for them can turn weak evidence into confident,
        # client-facing claims, so only confirmed findings enter this LLM stage.
        findings = [finding for finding in findings if self._is_confirmed_status(finding)]
        if not findings:
            return

        self._enrichment_total = len(findings)
        self._enrichment_failures = 0

        self._normalize_cvss_severities(findings)

        cvss_findings = [f for f in findings if f.get("cvss_score") is None]
        poc_findings = [f for f in findings if not f.get("exploitation_details")]
        for finding in findings:
            finding["enriched"] = bool(
                finding.get("cvss_score") is not None
                and finding.get("exploitation_details")
            )

        if not cvss_findings and not poc_findings:
            logger.info(f"[{self.name}] All {len(findings)} final findings already enriched")
            return

        # Pre-check: Is LLM available?
        health = llm_client.get_health_status() or {}
        if health.get("state") == "CRITICAL":
            logger.warning(f"[{self.name}] LLM circuit breaker OPEN. Skipping enrichment for {len(findings)} findings.")
            dashboard.log(
                f"[Reporting] LLM unavailable (circuit breaker OPEN). "
                f"{len(findings)} findings will not be enriched with CVSS/PoC details. "
                f"Use re-enrich to retry when LLM recovers.",
                "WARN"
            )
            for finding in poc_findings:
                self._apply_deterministic_poc_fallback(finding)
            for finding in findings:
                finding["enriched"] = bool(
                    finding.get("cvss_score") is not None
                    and finding.get("exploitation_details")
                )
            self._enrichment_failures = sum(1 for f in findings if not f.get("enriched"))
            enriched_count = len(findings) - self._enrichment_failures
            if self._enrichment_failures:
                await self._event_bus.emit(EventType.ENRICHMENT_DEGRADED, {
                    "scan_id": self.scan_id,
                    "total": len(findings),
                    "enriched": enriched_count,
                    "failed": self._enrichment_failures,
                    "enrichment_status": self._compute_enrichment_status(),
                    "message": (
                        f"LLM unavailable — {self._enrichment_failures}/{len(findings)} "
                        "confirmed findings remain incomplete after evidence fallback."
                    ),
                })
            return

        # CVSS and PoC enrichment run IN PARALLEL (they write to different fields)
        # CVSS writes: cvss_score, cvss_vector, severity, cvss_rationale, cwe, cve
        # PoC writes: exploitation_details, llm_reproduction_steps, enriched
        groups = self._poc_group_findings_by_type(poc_findings)
        logger.info(
            f"[{self.name}] Starting parallel enrichment: CVSS + PoC for {len(findings)} findings "
            f"in {len(groups)} type groups: {list(groups.keys())}"
        )

        enrichment_tasks = []
        if cvss_findings:
            enrichment_tasks.append(self._calculate_cvss_batch(cvss_findings))
        enrichment_tasks.extend(
            self._poc_enrich_group_with_fallback(vtype, group)
            for vtype, group in groups.items()
        )
        await asyncio.gather(*enrichment_tasks)

        # Final completeness is field-based, not call-attempt based. This keeps
        # recovered batch failures and preserved re-enrichment fields accurate.
        for f in findings:
            f["enriched"] = bool(
                f.get("cvss_score") is not None
                and f.get("exploitation_details")
            )
        self._enrichment_failures = sum(1 for f in findings if not f.get("enriched"))

        # Emit degraded event if any failures
        if self._enrichment_failures > 0:
            enrichment_status = self._compute_enrichment_status()
            enriched_count = self._enrichment_total - self._enrichment_failures
            logger.warning(
                f"[{self.name}] Enrichment degraded: {enriched_count}/{self._enrichment_total} findings enriched"
            )
            dashboard.log(
                f"[Reporting] {self._enrichment_failures}/{self._enrichment_total} findings could not be enriched. "
                f"Use re-enrich to retry when LLM recovers.",
                "WARN"
            )
            await self._event_bus.emit(EventType.ENRICHMENT_DEGRADED, {
                "scan_id": self.scan_id,
                "total": self._enrichment_total,
                "enriched": enriched_count,
                "failed": self._enrichment_failures,
                "enrichment_status": enrichment_status,
                "message": f"{self._enrichment_failures}/{self._enrichment_total} findings lack enrichment.",
            })

    async def _enrich_poc_with_llm(self, finding: Dict):
        """
        Use LLM to generate professional, triager-ready exploitation explanation AND detailed reproduction steps.
        This adds detailed context that makes reports stand out on bug bounty platforms.
        """
        try:
            context = self._poc_prepare_context(finding)
            prompt = self._poc_build_prompt(context)
            response, provenance = await self._poc_execute_llm(prompt)

            if response and ("LLM unavailable" in response or "fail open" in response or '"payloads"' in response):
                # Circuit breaker returned fallback — not real enrichment
                finding["enriched"] = self._apply_deterministic_poc_fallback(finding)
                if not finding["enriched"]:
                    self._enrichment_failures += 1
                return

            if response:
                self._poc_parse_response(finding, response)
                finding["poc_enrichment_provenance"] = provenance
                finding["enriched"] = True
            else:
                finding["enriched"] = self._apply_deterministic_poc_fallback(finding)
                if not finding["enriched"]:
                    self._enrichment_failures += 1

        except Exception as e:
            logger.debug(f"[{self.name}] Exploitation enrichment skipped for {finding.get('id')}: {e}")
            finding["enriched"] = self._apply_deterministic_poc_fallback(finding)
            if not finding["enriched"]:
                self._enrichment_failures += 1

    def _apply_deterministic_poc_fallback(self, finding: Dict) -> bool:
        """Build a bounded PoC narrative strictly from already-recorded proof."""
        request = finding.get("http_request") or finding.get("reproduction") or finding.get("nuclei_request") or ""
        response = finding.get("http_response") or finding.get("response_excerpt") or finding.get("nuclei_response") or ""
        # Rendered PLAIN and then wrapped in one fenced block below: `exploitation_details`
        # is markdown, and slicing a markdown-rendered evidence panel could cut a fence in
        # half — an unclosed fence swallows the rest of the write-up.
        evidence = self._render_evidence_dict(finding, markdown=False)
        payload = finding.get("payload") or ""
        proof = request or response or evidence or payload
        if not proof:
            return False

        proof_parts = []
        if request:
            proof_parts.append("Captured request:\n\n" + md_code_block(str(request)[:2000], "http"))
        if response:
            proof_parts.append("Captured response:\n\n" + md_code_block(str(response)[:2000], "http"))
        if evidence:
            proof_parts.append("Recorded evidence:\n\n" + md_code_block(evidence))
        if payload and not request:
            # No length cap on the payload: it is the one field that has to be lossless
            # (the request/response above are explicitly labelled excerpts).
            proof_parts.append("Recorded payload:\n\n" + md_code_block(payload))

        finding["exploitation_details"] = (
            "## Reproduction Steps\n"
            "1. Reissue the recorded request or payload against the affected endpoint.\n"
            "2. Compare the result with the recorded evidence below.\n\n"
            "## Evidence\n" + "\n\n".join(proof_parts) + "\n\n"
            "## Validation Note\n"
            "This fallback contains only scan-recorded evidence; no additional exploitability claims were inferred."
        )
        finding["poc_enrichment_provenance"] = "deterministic_evidence"
        return True

    def _compute_enrichment_status(self) -> str:
        """Compute overall enrichment status for the scan."""
        if self._enrichment_total == 0:
            return "full"
        if self._enrichment_failures == 0:
            return "full"
        if self._enrichment_failures == self._enrichment_total:
            return "none"
        return "partial"

    def _audit_enrichment_completeness(self, confirmed: List[Dict]) -> Dict[str, Any]:
        """Ground-truth completeness of the written deliverable.

        Inspects the ACTUAL cvss_score / exploitation fields of CONFIRMED findings
        (informational/pending findings legitimately lack these, so they're excluded).
        Unlike _compute_enrichment_status — a counter a mid-enrichment cancellation can
        bypass, falsely reading "full" — this measures the report that was actually
        written, so "the report came out empty" is always detectable. Returns
        {status, degraded, confirmed, missing_cvss, missing_exploitation}.
        """
        # Informational findings (missing headers, etc.) legitimately carry an evidence
        # pointer instead of a full CVSS/PoC, so they must not drag a complete report to
        # 'partial'. (The docstring's stated intent, previously unimplemented.)
        confirmed = [
            f for f in confirmed
            if str(f.get("severity", "")).strip().lower() not in ("info", "informational")
        ]
        total = len(confirmed)
        if total == 0:
            return {"status": "full", "degraded": False, "confirmed": 0,
                    "missing_cvss": 0, "missing_exploitation": 0}
        # A cvss_score of 0.0 is a REAL score, not "missing" — test for None, not
        # truthiness (`not 0.0` is True and would false-flag the scan 'partial').
        missing_cvss = sum(1 for f in confirmed if f.get("cvss_score") is None)
        missing_expl = sum(
            1 for f in confirmed
            if not (f.get("exploitation_details") or f.get("llm_reproduction_steps"))
        )
        worst = max(missing_cvss, missing_expl)
        status = "full" if worst == 0 else ("none" if worst >= total else "partial")
        return {"status": status, "degraded": worst > 0, "confirmed": total,
                "missing_cvss": missing_cvss, "missing_exploitation": missing_expl}

    def _poc_prepare_context(self, finding: Dict) -> Dict:
        """Prepare context for PoC enrichment prompt."""
        vuln_type = finding.get("type", "Unknown")
        validator_notes = finding.get("validator_notes", "")
        extra_evidence = f"- Validation Evidence: {validator_notes}" if validator_notes else ""
        # nuclei_request/nuclei_response is where nuclei-sourced findings carry their
        # captured evidence (see _nuclei_parse_findings) — without this fallback the
        # LLM gets an empty "Captured HTTP Proof" block for a real, evidenced finding
        # and correctly-but-misleadingly reports the proof as unavailable.
        http_request = (finding.get("http_request") or finding.get("reproduction") or finding.get("nuclei_request") or "")[:4000]
        http_response = (finding.get("http_response") or finding.get("response_excerpt") or finding.get("nuclei_response") or "")[:4000]
        # Prompt context: the LLM reads plain text, so no markdown fences here.
        structured_evidence = self._render_evidence_dict(finding, markdown=False)[:3000]

        return {
            "vuln_type": vuln_type,
            "url": finding.get("url", ""),
            "param": finding.get("parameter", ""),
            "payload": finding.get("payload", ""),
            "description": finding.get("description", ""),
            "extra_evidence": extra_evidence,
            "http_request": http_request,
            "http_response": http_response,
            "structured_evidence": structured_evidence,
            "response_status": finding.get("response_status"),
        }

    def _poc_build_prompt(self, context: Dict) -> str:
        """Build PoC enrichment prompt."""
        return f"""You are writing an evidence-grounded security report.
Use ONLY the captured proof below. Do not invent infrastructure, cloud providers, credentials, internal services, data access, versions, or exploit results. If a consequence is not demonstrated, explicitly state that it was not demonstrated.

**Confirmed Vulnerability:**
- Type: {context['vuln_type']}
- URL: {context['url']}
- Vulnerable Parameter: {context['param']}
- Payload Used: {context['payload']}
- Detection Notes: {context['description']}
{context['extra_evidence']}

**Captured HTTP Proof:**
Request:
```http
{context['http_request']}
```
Response status: {context['response_status']}
Response excerpt:
```text
{context['http_response']}
```
Structured evidence:
{context['structured_evidence']}

**Your Task: Write a comprehensive exploitation report covering:**

1. **Summary** (1-2 sentences): Explain the vulnerability and its core impact in plain English.

2. **Attack Scenario**: Describe only the demonstrated behavior and the minimum steps needed to exercise it.

3. **Maximum Impact**: State only consequences directly supported by the proof. Label anything unverified as not demonstrated.

4. **Proof of Exploitation**: A specific one-liner or description of what the provided payload proves.

5. **Step-by-Step Reproduction (CRITICAL)**:
   - Must be extremely detailed and idiot-proof.
   - Do NOT just say "Scan with tool".
   - Use the captured request/payload; do not invent UI controls or commands.
   - Mention exactly what recorded evidence confirms success.
   - If it involves a complex HTTP request, describe how to construct it.

**Format your response as plain text with these exact headers:**
## Summary
[your summary]

## Attack Scenario
[your scenario]

## Maximum Impact
[your impact]

## Proof of Exploitation
[your proof]

## Reproduction Steps
[1. Step one...
2. Step two...
3. ...]

Every factual claim must be traceable to the supplied URL, request, response, payload, validation notes, or structured evidence."""

    async def _reporting_generate(
        self, prompt: str, module_name: str, temperature: float, max_tokens: int = 1500
    ) -> Tuple[Optional[str], str]:
        """Reporting/enrichment LLM call with a scoped provider failover.

        Returns (text, provenance):
          'llm'                     — active provider succeeded
          'llm_<provider>_failover' — active provider failed/degraded, secondary recovered it
          'none'                    — both failed (caller applies deterministic fallback)
        Failover is reporting-scoped only: it does NOT change the scan's active provider.
        """
        response = await llm_client.generate(
            prompt,
            module_name=module_name,
            model_override=settings.REPORTING_MODEL,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        degraded = (not response) or ("LLM unavailable" in response) or ("fail open" in response) or ('"payloads"' in response)
        if not degraded:
            return response, "llm"
        if not getattr(settings, "REPORTING_FAILOVER_ENABLED", True):
            return None, "none"
        fb_provider = (getattr(settings, "REPORTING_FAILOVER_PROVIDER", "anthropic") or "").strip().lower()
        if not fb_provider or fb_provider == getattr(llm_client, "provider_id", ""):
            return None, "none"
        fb = await llm_client.generate_reporting_fallback(
            prompt, module_name=module_name, temperature=temperature, max_tokens=max_tokens,
        )
        if fb and ("LLM unavailable" not in fb) and ("fail open" not in fb):
            self._reporting_failover_count += 1
            logger.warning(f"[{self.name}] {module_name}: primary degraded → recovered via '{fb_provider}' failover")
            return fb, f"llm_{fb_provider}_failover"
        return None, "none"

    async def _poc_execute_llm(self, prompt: str) -> Tuple[Optional[str], str]:
        """Execute LLM call for PoC enrichment (with scoped reporting failover)."""
        return await self._reporting_generate(prompt, module_name="Reporting-Exploitation", temperature=0.2)

    # PURE apart from the findings it mutates
    def _protect_narrative_values(self, findings: List[Dict]) -> None:
        """Fence the finding data that the enrichment narrative quotes inline.

        The model interpolates the payload straight into its sentence, where markdown
        reads the payload's OWN backticks as code-span delimiters and deletes them:
        ``d.setAttribute(`style`,…)`` reaches the reader as ``d.setAttribute( style ,…)``,
        a payload nobody can copy, while the identical bytes sit correct in
        raw_findings.json. The loss is purely at render time and it lands on the one
        field the report exists to deliver.

        Both the shipped payload and the probe it was upgraded from are protected: the
        narrative was written about the latter and may quote either.
        """
        for f in findings:
            details = f.get("exploitation_details")
            if not details:
                continue
            evidence = f.get("evidence")
            original = evidence.get("original_payload") if isinstance(evidence, dict) else None
            f["exploitation_details"] = md_document_with_values(
                details,
                f.get("payload"),
                original,
                f.get("surviving_chars"),
                f.get("url"),
            )

    def _poc_parse_response(self, finding: Dict, response: str):
        """Parse PoC enrichment response and update finding."""
        content = _normalize_markdown_document(response)
        finding["exploitation_details"] = content

        # Extract Reproduction Steps for structured usage
        steps_match = re.search(r"## Reproduction Steps\s*(.*?)(?:$|##)", content, re.DOTALL)
        if steps_match:
            raw_steps = steps_match.group(1).strip()
            # Split by lines starting with numbers or bullet points
            steps_list = [line.strip() for line in raw_steps.split('\n') if line.strip()]
            if steps_list:
                finding["llm_reproduction_steps"] = steps_list

    # ── Grounded LLM enrichment of GROUPED Nuclei findings ───────────────
    NUCLEI_NARRATIVE_SCHEMA = "bugtrace.nuclei-narrative/v1"
    NUCLEI_NARRATIVE_BATCH_SIZE = 3
    NUCLEI_NARRATIVE_WORKERS = 2
    NUCLEI_NARRATIVE_SOFT_SECONDS = 285
    NUCLEI_NARRATIVE_BATCH_SECONDS = 65
    NUCLEI_NARRATIVE_SINGLE_SECONDS = 45
    NUCLEI_NARRATIVE_MAX_SINGLE_RETRIES = 6
    NUCLEI_NARRATIVE_MAX_FIELD_CHARS = 6000

    def _nuclei_state_path(self, scan_id: Optional[int] = None) -> Path:
        state_scan_id = getattr(self, "scan_id", "unknown") if scan_id is None else scan_id
        return self.output_dir / f"reporting_enrichment_state.{state_scan_id}.json"

    def _nuclei_fingerprint(self, finding: Dict) -> str:
        """Fingerprint complete source evidence, excluding generated report text."""
        members = finding.get("nuclei_group_members") or [finding]
        records = []
        for member in members:
            records.append({
                "template": self._nuclei_group_material(member)["template"],
                "matcher": self._nuclei_source_value(member, "nuclei_matcher", "matcher_name", "matcher-name"),
                "name": member.get("parameter", ""),
                "severity": member.get("severity", ""),
                "description": member.get("description", ""),
                "url": member.get("url", ""),
                "extracted_results": member.get("nuclei_extracted_results", ""),
                "request": member.get("nuclei_request") or member.get("request") or "",
                "response": member.get("nuclei_response") or member.get("response") or "",
                "source_fingerprint": member.get("nuclei_source_fingerprint", ""),
            })
        urls = finding.get("affected_urls") or ([finding.get("url")] if finding.get("url") else [])
        material = {
            "version": 1,
            "group_id": finding["nuclei_group_id"],
            "members": sorted(records, key=lambda record: json.dumps(record, sort_keys=True, default=str)),
            "urls": sorted(set(urls)),
        }
        return "ef1:" + hashlib.sha256(
            json.dumps(material, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        ).hexdigest()

    def _load_nuclei_state(self, scan_id: Optional[int] = None) -> Dict:
        expected_scan_id = getattr(self, "scan_id", "unknown") if scan_id is None else scan_id
        path = self._nuclei_state_path(expected_scan_id)
        if not path.is_file():
            return {}
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning(f"[{self.name}] Ignoring corrupt Nuclei narrative state: {exc}")
            return {}
        if (
            not isinstance(state, dict)
            or state.get("schema") != "bugtrace.nuclei-narrative-state"
            or state.get("schema_version") != 1
            or str(state.get("scan_id")) != str(expected_scan_id)
            or not isinstance(state.get("groups"), dict)
        ):
            return {}
        return state

    def _write_nuclei_state(self, state: Dict) -> None:
        """Persist derived narrative state atomically beside scan artifacts."""
        path = self._nuclei_state_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(state, handle, sort_keys=True, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def _async_nuclei_state_file_lock(path: Path):
        """Serialize sidecar read-modify-write operations across API processes."""
        import fcntl
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def lock():
            lock_path = path.with_name(f".{path.name}.lock")
            handle = lock_path.open("a+b")
            await asyncio.to_thread(fcntl.flock, handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                await asyncio.to_thread(fcntl.flock, handle.fileno(), fcntl.LOCK_UN)
                handle.close()

        return lock()

    async def _persist_nuclei_narratives(self, findings: List[Dict]) -> None:
        """Persist one accepted response as a single sidecar transaction."""
        lock = getattr(self, "_nuclei_state_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self._nuclei_state_lock = lock
        async with lock:
            async with self._async_nuclei_state_file_lock(self._nuclei_state_path()):
                state = self._load_nuclei_state() or {
                    "schema": "bugtrace.nuclei-narrative-state",
                    "schema_version": 1,
                    "scan_id": getattr(self, "scan_id", "unknown"),
                    "contract_version": self.NUCLEI_NARRATIVE_SCHEMA,
                    "groups": {},
                }
                for finding in findings:
                    state["groups"][finding["nuclei_group_id"]] = {
                        "input_fingerprint": finding["nuclei_input_fingerprint"],
                        "contract_version": self.NUCLEI_NARRATIVE_SCHEMA,
                        "description": finding["description"],
                        "impact": finding["impact"],
                        "remediation": finding["remediation"],
                        "provenance": finding["nuclei_narrative_provenance"],
                        "updated_at": datetime.now().isoformat(),
                    }
                state["updated_at"] = datetime.now().isoformat()
                self._write_nuclei_state(state)

    async def _persist_nuclei_narrative(self, finding: Dict) -> None:
        await self._persist_nuclei_narratives([finding])

    def _prepare_nuclei_fallback(self, finding: Dict) -> None:
        finding.setdefault("description", "Nuclei detected this configuration or exposure from the recorded evidence.")
        finding.setdefault("impact", "The recorded detection should be reviewed in context; it does not alone prove broader compromise.")
        finding.setdefault("remediation", "Review the affected configuration or exposure, apply vendor hardening, and rerun the same Nuclei check.")
        finding.setdefault("nuclei_narrative_provenance", "deterministic")

    def _nuclei_restore_scan_ids(self) -> List[int]:
        """Return this scan plus its direct parent when a resume reuses artifacts."""
        scan_ids = [getattr(self, "scan_id", "unknown")]
        parent_scan_id = getattr(self, "nuclei_parent_scan_id", None)
        if parent_scan_id is None:
            try:
                from bugtrace.schemas.db_models import ScanTable

                with self.db.get_session() as session:
                    scan = session.get(ScanTable, self.scan_id)
                    parent_scan_id = getattr(scan, "resumed_from_id", None) if scan else None
            except Exception:
                parent_scan_id = None
        if parent_scan_id not in (None, "", scan_ids[0]):
            scan_ids.append(parent_scan_id)
        return scan_ids

    def _restore_nuclei_narratives(self, findings: List[Dict]) -> int:
        states = [self._load_nuclei_state(scan_id) for scan_id in self._nuclei_restore_scan_ids()]
        restored = 0
        for finding in findings:
            finding["nuclei_group_id"] = finding.get("nuclei_group_id") or self._nuclei_group_id(finding)
            finding["nuclei_input_fingerprint"] = self._nuclei_fingerprint(finding)
            self._prepare_nuclei_fallback(finding)
            for state in states:
                cached = state.get("groups", {}).get(finding["nuclei_group_id"])
                if not isinstance(cached, dict) or (
                    cached.get("input_fingerprint") != finding["nuclei_input_fingerprint"]
                    or cached.get("contract_version") != self.NUCLEI_NARRATIVE_SCHEMA
                ):
                    continue
                if all(isinstance(cached.get(field), str) and cached[field].strip() for field in ("description", "impact", "remediation")):
                    for field in ("description", "impact", "remediation"):
                        finding[field] = cached[field]
                    finding["nuclei_narrative_provenance"] = "restored"
                    restored += 1
                    break
        return restored

    def _nuclei_batch_prompt(self, findings: List[Dict]) -> str:
        entries = []
        for finding in findings:
            urls = sorted(set(finding.get("affected_urls") or ([finding.get("url")] if finding.get("url") else [])))
            entries.append({
                "id": finding["nuclei_group_id"],
                "type": str(finding.get("type", "")).replace("NUCLEI:", ""),
                "evidence": self._nuclei_prompt_evidence(finding) or "(evidence exceeds safe prompt bound)",
                "affected_urls": urls[:10],
            })
        return f"""You are a senior penetration tester writing grounded client-facing Nuclei report entries.
Analyze ONLY supplied evidence. Do not invent versions, CVEs, payloads, behavior, or exploitability.
Return ONLY this JSON object: {{"schema_version":"{self.NUCLEI_NARRATIVE_SCHEMA}","results":[{{"id":"exact supplied id","description":"...","impact":"...","remediation":"..."}}]}}.
Every requested id must appear exactly once and all three narrative fields must be non-empty.
Requested entries: {json.dumps(entries, ensure_ascii=False)}"""

    def _nuclei_prompt_evidence(self, finding: Dict) -> Optional[str]:
        """Render bounded scanner evidence for one grouped Nuclei narrative."""
        members = finding.get("nuclei_group_members") or [finding]
        max_chars = 12000

        def excerpt(value: Any, limit: int) -> str:
            if value in (None, "", [], {}):
                return ""
            rendered = json.dumps(value, ensure_ascii=False, default=str) if isinstance(value, (dict, list)) else str(value)
            if len(rendered) <= limit:
                return rendered
            half = max(16, (limit - 19) // 2)
            return f"{rendered[:half]}...[truncated]...{rendered[-half:]}"

        first = members[0]
        per_member = max(80, min(500, 4200 // len(members)))
        samples = []
        for member in members:
            sample = {
                "response": excerpt(
                    member.get("nuclei_response") or member.get("response"),
                    max(48, int(per_member * 0.55)),
                ),
                "request": excerpt(
                    member.get("nuclei_request") or member.get("request"),
                    max(24, int(per_member * 0.2)),
                ),
                "extracted_results": excerpt(
                    member.get("nuclei_extracted_results", ""),
                    max(24, int(per_member * 0.25)),
                ),
            }
            compact = {key: value for key, value in sample.items() if value}
            if compact:
                samples.append(compact)

        record = {
            "template": excerpt(self._nuclei_group_material(first)["template"], 180),
            "matcher": excerpt(first.get("nuclei_matcher", ""), 120),
            "description": excerpt(first.get("description", ""), 350),
            "group_instances": len(members),
            "samples": samples,
        }
        if not any(samples) and not record["template"] and not record["description"]:
            return "(no structured evidence captured)"

        rendered = json.dumps(record, ensure_ascii=False)
        while len(rendered) > max_chars:
            candidates = [
                (len(sample.get(field, "")), sample, field)
                for sample in samples
                for field in ("request", "extracted_results", "response")
                if len(sample.get(field, "")) > (32 if field == "response" else 16)
            ]
            if not candidates:
                break
            _, sample, field = max(candidates, key=lambda item: item[0])
            minimum = 32 if field == "response" else 16
            sample[field] = excerpt(sample[field], max(minimum, int(len(sample[field]) * 0.75)))
            rendered = json.dumps(record, ensure_ascii=False)
        return rendered if len(rendered) <= max_chars else None

    def _parse_nuclei_batch_response(self, response: str, expected_ids: set[str]) -> Dict[str, Dict]:
        payload = safe_json_loads(response, fallback=None)
        if not isinstance(payload, dict) or payload.get("schema_version") != self.NUCLEI_NARRATIVE_SCHEMA:
            return {}
        rows = extract_json_list(payload, "results", fallback=None)
        if not isinstance(rows, list):
            return {}
        accepted, duplicate_ids, seen_ids = {}, set(), set()
        for row in rows:
            if not isinstance(row, dict) or row.get("id") not in expected_ids:
                continue
            group_id = row["id"]
            if group_id in seen_ids:
                duplicate_ids.add(group_id)
                continue
            seen_ids.add(group_id)
            narrative = {field: row.get(field) for field in ("description", "impact", "remediation")}
            if all(isinstance(value, str) and value.strip() and len(value) <= self.NUCLEI_NARRATIVE_MAX_FIELD_CHARS for value in narrative.values()):
                accepted[group_id] = narrative
        for group_id in duplicate_ids:
            accepted.pop(group_id, None)
        return accepted

    async def _enrich_nuclei_findings_llm(self, findings: List[Dict]) -> None:
        """Enrich grouped Nuclei entries through bounded batches and durable state."""
        targets = [
            f for f in findings
            if str(f.get("type", "")).upper().startswith("NUCLEI:")
            and not self._is_manual_review_status(f)
        ]
        if not targets:
            return
        restored = self._restore_nuclei_narratives(targets)
        unresolved = [
            f for f in targets
            if f.get("nuclei_narrative_provenance") not in {"restored", "llm_batch", "llm_singleton"}
        ]
        if not unresolved:
            logger.info(f"[{self.name}] Restored {restored}/{len(targets)} grouped Nuclei narratives")
            return
        oversized = [finding for finding in unresolved if self._nuclei_prompt_evidence(finding) is None]
        if oversized:
            logger.warning(
                f"[{self.name}] {len(oversized)} Nuclei group(s) exceed the safe evidence prompt bound; "
                "keeping deterministic narratives."
            )
            unresolved = [finding for finding in unresolved if finding not in oversized]
        if not unresolved:
            return
        health = llm_client.get_health_status() or {}
        if health.get("state") == "CRITICAL":
            logger.info(f"[{self.name}] LLM unavailable — {len(unresolved)} Nuclei findings keep deterministic narratives.")
            return

        deadline = time.monotonic() + self.NUCLEI_NARRATIVE_SOFT_SECONDS
        retry_waves = math.ceil(
            self.NUCLEI_NARRATIVE_MAX_SINGLE_RETRIES / self.NUCLEI_NARRATIVE_WORKERS
        )
        primary_deadline = deadline - (retry_waves * self.NUCLEI_NARRATIVE_SINGLE_SECONDS)
        unresolved.sort(key=lambda finding: finding["nuclei_group_id"])
        accepted_ids = set()

        async def run_queue(items: List, handler) -> None:
            queue = asyncio.Queue()
            for item in items:
                queue.put_nowait(item)

            async def worker() -> None:
                while not queue.empty():
                    item = await queue.get()
                    try:
                        await handler(item)
                    finally:
                        queue.task_done()

            workers = [
                asyncio.create_task(worker())
                for _ in range(min(self.NUCLEI_NARRATIVE_WORKERS, len(items)))
            ]
            try:
                await asyncio.gather(*workers)
            except BaseException:
                for worker_task in workers:
                    worker_task.cancel()
                await asyncio.gather(*workers, return_exceptions=True)
                raise

        async def apply_batch(
            batch: List[Dict], provenance: str, timeout: int, phase_deadline: float,
        ) -> None:
            remaining = phase_deadline - time.monotonic()
            if remaining <= 0:
                return
            try:
                response = await asyncio.wait_for(
                    llm_client.generate(
                        self._nuclei_batch_prompt(batch),
                        module_name="Reporting-Nuclei-Batch" if len(batch) > 1 else "Reporting-Nuclei-Singleton",
                        model_override=settings.REPORTING_MODEL,
                        temperature=0.2,
                        max_tokens=1500,
                    ),
                    timeout=min(timeout, remaining),
                )
            except asyncio.TimeoutError:
                return
            except Exception as exc:
                logger.warning(f"[{self.name}] Nuclei narrative request failed: {exc}")
                return
            accepted = self._parse_nuclei_batch_response(
                response or "", {finding["nuclei_group_id"] for finding in batch},
            )
            accepted_findings = []
            for finding in batch:
                narrative = accepted.get(finding["nuclei_group_id"])
                if not narrative:
                    continue
                finding.update(narrative)
                finding["nuclei_narrative_provenance"] = provenance
                accepted_findings.append(finding)
            if not accepted_findings:
                return
            persist_task = asyncio.create_task(
                self._persist_nuclei_narratives(accepted_findings)
            )
            try:
                await asyncio.shield(persist_task)
            except asyncio.CancelledError:
                await asyncio.shield(persist_task)
                raise
            accepted_ids.update(
                finding["nuclei_group_id"] for finding in accepted_findings
            )

        batches = [
            unresolved[index:index + self.NUCLEI_NARRATIVE_BATCH_SIZE]
            for index in range(0, len(unresolved), self.NUCLEI_NARRATIVE_BATCH_SIZE)
        ]
        await run_queue(
            batches,
            lambda batch: apply_batch(
                batch, "llm_batch", self.NUCLEI_NARRATIVE_BATCH_SECONDS, primary_deadline,
            ),
        )
        retries = [
            [finding] for finding in unresolved
            if finding["nuclei_group_id"] not in accepted_ids
        ][:self.NUCLEI_NARRATIVE_MAX_SINGLE_RETRIES]
        await run_queue(
            retries,
            lambda batch: apply_batch(
                batch, "llm_singleton", self.NUCLEI_NARRATIVE_SINGLE_SECONDS, deadline,
            ),
        )
        logger.info(
            f"[{self.name}] Nuclei narratives: total={len(targets)} restored={restored} "
            f"accepted={len(accepted_ids)} fallback={len(unresolved) - len(accepted_ids)}"
        )

    def _nuclei_enrich_prompt(self, ntype: str, evidence: str, urls_txt: str, n: int) -> str:
        """Grounded prompt: analyze strictly from the template + evidence, no invention."""
        return f"""You are a senior penetration tester writing a client-facing report entry for a finding surfaced by the Nuclei scanner.

Nuclei check: "{ntype}"
Fired on {n} endpoint(s).

Evidence captured:
{evidence}

Affected endpoints:
{urls_txt}

Write the entry with EXACTLY these three markdown sections, grounded STRICTLY in the evidence above. Do NOT invent versions, CVEs, payloads, or behaviours not present in the evidence. Many Nuclei checks are informational (technology/version fingerprints, exposed dev endpoints, missing hardening) — if so, say that honestly and rate the impact modestly. Be concise and professional.

## Description
[2-3 sentences: what was detected and what it means, based only on the evidence]

## Impact
[1-2 sentences: the realistic security impact — honest, not inflated]

## Remediation
[1-2 concrete, actionable sentences]"""

    def _nuclei_parse_enrichment(self, f: Dict, response: str) -> None:
        """Parse the LLM's Description/Impact/Remediation; only overwrite when the model gave
        real content (else keep the deterministic fallback). Re-attaches the affected-endpoint
        list so the analysis doesn't drop it."""
        content = _normalize_markdown_document(response)

        def _section(name: str) -> str:
            m = re.search(rf"##\s*{name}\s*(.*?)(?:\n##|\Z)", content, re.DOTALL | re.IGNORECASE)
            return m.group(1).strip() if m else ""
        desc = _section("Description")
        impact = _section("Impact")
        remediation = _section("Remediation")
        if desc:
            urls = [u for u in (f.get("affected_urls") or []) if u]
            if urls:
                shown = urls[:25]
                block = f"\n\n**Affected endpoints ({len(urls)}):**\n" + "\n".join(f"- {u}" for u in shown)
                if len(urls) > len(shown):
                    block += f"\n- … and {len(urls) - len(shown)} more"
                desc += block
            f["description"] = desc
        if impact:
            f["impact"] = impact
        if remediation:
            f["remediation"] = remediation

    # ── Batch PoC Enrichment (grouped by vuln type) ──────────────────────

    def _poc_group_findings_by_type(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Group findings by normalized vulnerability type for batch PoC enrichment."""
        groups: Dict[str, List[Dict]] = {}
        for f in findings:
            vtype = self._normalize_type_for_dedup(f.get("type", "UNKNOWN"))
            groups.setdefault(vtype, []).append(f)
        return groups

    def _poc_batch_build_prompt(self, vuln_type: str, findings_in_group: List[Dict]) -> str:
        """Build a single prompt for batch PoC enrichment of a type group."""
        finding_blocks = []
        for i, f in enumerate(findings_in_group):
            payload_str = str(f.get("payload", ""))[:200]
            desc_str = str(f.get("description", ""))[:300]
            validator_notes = f.get("validator_notes", "")
            evidence = f"  Validation Evidence: {validator_notes}" if validator_notes else ""
            request = str(f.get("http_request") or f.get("reproduction") or "")[:1500]
            response = str(f.get("http_response") or f.get("response_excerpt") or "")[:1500]
            structured = self._render_evidence_dict(f, markdown=False)[:1200]
            finding_blocks.append(
                f"[Finding {i}]\n"
                f"  URL: {f.get('url', '')}\n"
                f"  Parameter: {f.get('parameter', '')}\n"
                f"  Payload: {payload_str}\n"
                f"  Description: {desc_str}\n"
                f"  Captured Request: {request}\n"
                f"  Captured Response: {response}\n"
                f"  Structured Evidence: {structured}\n"
                f"{evidence}"
            )

        findings_text = "\n\n".join(finding_blocks)

        return f"""You are writing evidence-grounded reports for {len(findings_in_group)} confirmed {vuln_type} findings.

Use ONLY each finding's captured request, response, payload, validation notes, and structured evidence. Never invent cloud providers, credentials, internal services, versions, data access, UI controls, or exploit outcomes.

**Confirmed Findings:**

{findings_text}

**Your Task:** For EACH finding above, write a complete exploitation report.

Return a JSON array where each element has:
- "finding_id": (integer, matching the [Finding N] number above)
- "summary": (1-2 sentences explaining the vulnerability)
- "attack_scenario": (only the demonstrated behavior and direct use of it)
- "maximum_impact": (only consequences supported by evidence; otherwise state not demonstrated)
- "proof_of_exploitation": (what the payload proves)
- "reproduction_steps": (array of strings, step-by-step, start from "Open the browser...")

**CRITICAL:** Return ONLY a valid JSON array. No markdown fences, no explanation outside the JSON.
Example format:
[
  {{"finding_id": 0, "summary": "...", "attack_scenario": "...", "maximum_impact": "...", "proof_of_exploitation": "...", "reproduction_steps": ["1. Open...", "2. Navigate..."]}},
  {{"finding_id": 1, "summary": "...", ...}}
]"""

    async def _poc_batch_execute_llm(self, prompt: str, n_findings: int) -> Optional[str]:
        """Execute LLM call for batch PoC enrichment with scaled token budget."""
        scaled_tokens = max(
            settings.REPORTING_POC_MIN_TOKENS,
            min(n_findings * settings.REPORTING_POC_TOKENS_PER_FINDING, settings.REPORTING_POC_MAX_TOKENS)
        )
        return await llm_client.generate(
            prompt,
            module_name="Reporting-Exploitation-Batch",
            model_override=settings.REPORTING_MODEL,
            temperature=0.2,
            max_tokens=scaled_tokens
        )

    def _poc_batch_parse_response(self, response: str, findings_in_group: List[Dict]) -> Tuple[int, List[int]]:
        """
        Parse batch JSON response and populate findings.

        Returns (enriched_count, list_of_failed_finding_ids).
        """
        enriched_count = 0
        failed_ids = []

        # Strip markdown code fences if present
        cleaned = response.strip()
        fence_match = re.search(r'```\w*\s*\n?(.*?)```', cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        elif cleaned.startswith("```"):
            cleaned = re.sub(r'^```\w*\s*\n?', '', cleaned).strip()

        # Extract JSON array from response
        parsed = None
        try:
            p = json.loads(cleaned)
            if isinstance(p, list):
                parsed = p
            elif isinstance(p, dict):
                for key in p:
                    if isinstance(p[key], list):
                        parsed = p[key]
                        break
        except (json.JSONDecodeError, ValueError):
            pass

        if not parsed:
            match = re.search(r'\[.*\]', cleaned, re.DOTALL)
            if match:
                try:
                    parsed = json.loads(match.group(0))
                except json.JSONDecodeError:
                    pass

        if not parsed:
            return 0, list(range(len(findings_in_group)))

        # Build lookup by finding_id
        parsed_map = {}
        for item in parsed:
            if isinstance(item, dict) and "finding_id" in item:
                parsed_map[item["finding_id"]] = item

        for i, f in enumerate(findings_in_group):
            item = parsed_map.get(i)
            if not item:
                failed_ids.append(i)
                continue

            # Reconstruct exploitation_details as markdown (compatible with current format)
            # The values this prose quotes are fenced later, by _protect_narrative_values,
            # because the payload is not final until the visual-PoC upgrade has run.
            sections = []
            summary = item.get("summary")
            if summary:
                sections.append(f"## Summary\n{summary}")
            attack_scenario = item.get("attack_scenario")
            if attack_scenario:
                sections.append(f"## Attack Scenario\n{attack_scenario}")
            max_impact = item.get("maximum_impact")
            if max_impact:
                sections.append(f"## Maximum Impact\n{max_impact}")
            proof = item.get("proof_of_exploitation")
            if proof:
                sections.append(f"## Proof of Exploitation\n{proof}")
            repro_steps = item.get("reproduction_steps", [])
            if repro_steps:
                steps_text = "\n".join(repro_steps) if isinstance(repro_steps, list) else str(repro_steps)
                sections.append(f"## Reproduction Steps\n{steps_text}")

            if sections:
                f["exploitation_details"] = "\n\n".join(sections)
                f["poc_enrichment_provenance"] = "llm"
                enriched_count += 1
            else:
                failed_ids.append(i)
                continue

            # Populate reproduction steps as structured list
            if item.get("reproduction_steps") and isinstance(item["reproduction_steps"], list):
                f["llm_reproduction_steps"] = item["reproduction_steps"]

        return enriched_count, failed_ids

    def _poc_write_wet_file(self, vuln_type: str, response: str, status: str,
                            n_findings: int, error_msg: Optional[str] = None) -> None:
        """Write raw LLM response to poc_enrichment/wet/ for traceability."""
        try:
            wet_dir = self.output_dir / "poc_enrichment" / "wet"
            wet_dir.mkdir(parents=True, exist_ok=True)

            safe_type = (vuln_type or "unknown").lower().replace(" ", "_")
            wet_path = wet_dir / f"{safe_type}_wet.json"

            wet_data = {
                "vuln_type": vuln_type,
                "timestamp": datetime.now().isoformat(),
                "model": settings.REPORTING_MODEL,
                "findings_count": n_findings,
                "max_tokens": max(
                    settings.REPORTING_POC_MIN_TOKENS,
                    min(n_findings * settings.REPORTING_POC_TOKENS_PER_FINDING, settings.REPORTING_POC_MAX_TOKENS)
                ),
                "status": status,
                "error_message": error_msg,
                "raw_response": response or ""
            }

            # Append mode: if file exists (sub-batches), load and extend
            if wet_path.exists():
                try:
                    existing = json.loads(wet_path.read_text(encoding="utf-8"))
                    if isinstance(existing, list):
                        existing.append(wet_data)
                        wet_data = existing
                    else:
                        wet_data = [existing, wet_data]
                except (json.JSONDecodeError, OSError):
                    wet_data = [wet_data]
            else:
                wet_data = [wet_data]

            wet_path.write_text(json.dumps(wet_data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to write WET file for {vuln_type}: {e}")

    def _poc_write_dry_file(self, vuln_type: str, findings_in_group: List[Dict],
                            enriched_ids: List[int], failed_ids: List[int],
                            parse_method: str = "batch_json") -> None:
        """Write parsed PoC summary to poc_enrichment/dry/ for traceability."""
        try:
            dry_dir = self.output_dir / "poc_enrichment" / "dry"
            dry_dir.mkdir(parents=True, exist_ok=True)

            safe_type = (vuln_type or "unknown").lower().replace(" ", "_")
            dry_path = dry_dir / f"{safe_type}_dry.json"

            findings_summary = []
            for i, f in enumerate(findings_in_group):
                status = "enriched" if i in enriched_ids else "failed"
                source = (
                    f.get("poc_enrichment_provenance")
                    or ("batch" if i in enriched_ids else "pending_fallback")
                )
                findings_summary.append({
                    "finding_id": i,
                    "url": f.get("url", ""),
                    "parameter": f.get("parameter", ""),
                    "status": status,
                    "enrichment_source": source,
                    "has_exploitation_details": bool(f.get("exploitation_details")),
                    "has_reproduction_steps": bool(f.get("llm_reproduction_steps")),
                    "reproduction_steps_count": len(f.get("llm_reproduction_steps", []))
                })

            failed_summary = []
            for fid in failed_ids:
                if fid < len(findings_in_group):
                    ff = findings_in_group[fid]
                    failed_summary.append({
                        "finding_id": fid,
                        "url": ff.get("url", ""),
                        "parameter": ff.get("parameter", ""),
                        "reason": "missing_from_response",
                        "fallback_action": "individual_enrichment"
                    })

            dry_data = {
                "vuln_type": vuln_type,
                "timestamp": datetime.now().isoformat(),
                "wet_count": len(findings_in_group),
                "dry_count": len(enriched_ids),
                "failed_count": len(failed_ids),
                "parse_method": parse_method,
                "findings": findings_summary,
                "failed_findings": failed_summary
            }

            # Append mode for sub-batches
            if dry_path.exists():
                try:
                    existing = json.loads(dry_path.read_text(encoding="utf-8"))
                    if isinstance(existing, list):
                        existing.append(dry_data)
                        dry_data = existing
                    else:
                        dry_data = [existing, dry_data]
                except (json.JSONDecodeError, OSError):
                    dry_data = [dry_data]
            else:
                dry_data = [dry_data]

            dry_path.write_text(json.dumps(dry_data, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to write DRY file for {vuln_type}: {e}")

    async def _poc_enrich_group_with_fallback(self, vuln_type: str, findings_in_group: List[Dict]) -> None:
        """
        Orchestrator: enrich a type group with batch LLM call + individual fallback.

        Flow:
        1. Single finding → direct individual enrichment (no JSON overhead)
        2. Multiple findings → batch call → parse → fallback for failures
        3. >BATCH_SIZE findings → chunk into sub-batches
        """
        # Ensure output directories exist
        (self.output_dir / "poc_enrichment" / "wet").mkdir(parents=True, exist_ok=True)
        (self.output_dir / "poc_enrichment" / "dry").mkdir(parents=True, exist_ok=True)

        n = len(findings_in_group)

        # Single finding: bypass batch overhead, use individual enrichment
        if n == 1:
            f = findings_in_group[0]
            await self._enrich_poc_with_llm(f)
            enriched = [0] if f.get("exploitation_details") else []
            failed = [] if f.get("exploitation_details") else [0]
            self._poc_write_wet_file(vuln_type, f.get("exploitation_details", ""), "success" if enriched else "fallback_individual", 1)
            self._poc_write_dry_file(vuln_type, findings_in_group, enriched, failed, parse_method="individual")
            logger.info(f"[{self.name}] Batch PoC: {vuln_type} group (1 finding) enriched individually")
            return

        # Chunk large groups into sub-batches
        batch_size = settings.REPORTING_POC_BATCH_SIZE
        chunks = [findings_in_group[i:i + batch_size] for i in range(0, n, batch_size)]

        all_enriched_ids = []
        all_failed_ids = []
        offset = 0

        for chunk in chunks:
            try:
                prompt = self._poc_batch_build_prompt(vuln_type, chunk)
                response = await self._poc_batch_execute_llm(prompt, len(chunk))

                if response and "LLM unavailable" not in response and '"payloads"' not in response:
                    self._poc_write_wet_file(vuln_type, response, "success", len(chunk))
                    enriched_count, failed_local = self._poc_batch_parse_response(response, chunk)
                    # Map local indices to global
                    enriched_local = [i for i in range(len(chunk)) if i not in failed_local]
                    all_enriched_ids.extend([i + offset for i in enriched_local])
                    all_failed_ids.extend([i + offset for i in failed_local])

                    logger.info(
                        f"[{self.name}] Batch PoC: {vuln_type} group ({len(chunk)} findings) "
                        f"enriched {enriched_count} in 1 call, {len(failed_local)} need fallback"
                    )

                    # Fallback for failed findings within this chunk
                    if failed_local:
                        health = llm_client.get_health_status() or {}
                        if health.get("state") != "CRITICAL":
                            for fid in failed_local:
                                await self._enrich_poc_with_llm(chunk[fid])
                                if chunk[fid].get("exploitation_details"):
                                    global_id = fid + offset
                                    try:
                                        all_failed_ids.remove(global_id)
                                    except ValueError:
                                        pass
                                    all_enriched_ids.append(global_id)
                else:
                    # Total failure: LLM unavailable or circuit breaker
                    self._poc_write_wet_file(vuln_type, response or "", "error", len(chunk),
                                            error_msg="LLM unavailable or circuit breaker open")
                    all_failed_ids.extend(range(offset, offset + len(chunk)))

                    health = llm_client.get_health_status() or {}
                    if health.get("state") != "CRITICAL":
                        logger.warning(f"[{self.name}] Batch PoC: {vuln_type} batch failed, falling back to individual")
                        for idx_in_chunk, f in enumerate(chunk):
                            await self._enrich_poc_with_llm(f)
                            idx = offset + idx_in_chunk
                            if f.get("exploitation_details"):
                                try:
                                    all_failed_ids.remove(idx)
                                except ValueError:
                                    pass
                                all_enriched_ids.append(idx)

            except Exception as e:
                logger.warning(f"[{self.name}] Batch PoC error for {vuln_type}: {e}")
                self._poc_write_wet_file(vuln_type, "", "error", len(chunk), error_msg=str(e))
                all_failed_ids.extend(range(offset, offset + len(chunk)))

                # Full fallback to individual
                health = llm_client.get_health_status() or {}
                if health.get("state") != "CRITICAL":
                    for idx_in_chunk, f in enumerate(chunk):
                        try:
                            await self._enrich_poc_with_llm(f)
                            idx = offset + idx_in_chunk
                            if f.get("exploitation_details"):
                                try:
                                    all_failed_ids.remove(idx)
                                except ValueError:
                                    pass
                                all_enriched_ids.append(idx)
                        except Exception:
                            pass

            offset += len(chunk)

        # A circuit breaker may prevent both batch and singleton LLM calls. Use
        # only captured proof in that case rather than leaving confirmed rows empty.
        for failed_id in list(dict.fromkeys(all_failed_ids)):
            if failed_id >= len(findings_in_group):
                continue
            finding = findings_in_group[failed_id]
            if self._apply_deterministic_poc_fallback(finding):
                all_failed_ids = [item for item in all_failed_ids if item != failed_id]
                if failed_id not in all_enriched_ids:
                    all_enriched_ids.append(failed_id)

        # Write final DRY summary
        self._poc_write_dry_file(vuln_type, findings_in_group, all_enriched_ids, all_failed_ids)
        logger.info(
            f"[{self.name}] Batch PoC: {vuln_type} complete — "
            f"{len(all_enriched_ids)}/{n} enriched, {len(all_failed_ids)}/{n} failed"
        )

    # ── End Batch PoC Enrichment ───────────────────────────────────────

    def _get_type_specific_context(self, vuln_type: str) -> str:
        """Get type-specific context for LLM prompt."""
        contexts = {
            "SQLI": """**SQLi-Specific Context:**
- This is a SQL Injection vulnerability
- Consider: Data exfiltration, authentication bypass, privilege escalation
- Think about what tables might exist (users, orders, payments, admin)
- Mention specific SQLMap flags or techniques if relevant""",

            "XSS": """**XSS-Specific Context:**
- This is a Cross-Site Scripting vulnerability
- Consider: Session hijacking, credential theft, keylogging, defacement
- Think about the impact if this executes in an admin's browser
- Mention if it's reflected, stored, or DOM-based""",

            "XXE": """**XXE-Specific Context:**
- This is an XML External Entity vulnerability
- Consider: File disclosure (/etc/passwd, application configs), SSRF, DoS
- Think about what sensitive files might be accessible
- Mention the ability to exfiltrate data via out-of-band channels""",

            "SSRF": """**SSRF-Specific Context:**
- This is a Server-Side Request Forgery vulnerability
- Consider: Internal network access, cloud metadata (169.254.169.254), port scanning
- Think about internal services (databases, admin panels, APIs)
- Mention AWS/GCP/Azure metadata endpoints if cloud-hosted""",

            "CSTI": """**CSTI-Specific Context:**
- This is a Client-Side Template Injection vulnerability
- Consider: XSS via template expressions, data exfiltration
- Think about the frontend framework (Angular, Vue, React)
- Mention the ability to execute arbitrary JavaScript""",

            "VULNERABLE AND OUTDATED COMPONENTS": """**Component-Specific Context:**
- Report only the affected version and mapped CVE from the supplied evidence
- Component detection does not by itself prove exploitation or server compromise
- Do not declare a severity different from the structured finding
- Keep impact bounded to the documented CVE prerequisites""",

            "IDOR": """**IDOR-Specific Context:**
- This is an Insecure Direct Object Reference vulnerability
- Consider: Access to other users' data, horizontal privilege escalation
- Think about what resources can be accessed (profiles, orders, files)
- Mention the predictability of object IDs"""
        }
        return contexts.get(vuln_type.upper(), "**Context:** This is a confirmed security vulnerability. Explain the real-world impact.")

    # Vuln types that are informational in bug bounty — skip LLM CVSS scoring
    INFORMATIONAL_TYPES = {"MISSING_SECURITY_HEADER", "API DOCUMENTATION EXPOSURE"}

    # Nuclei template patterns for grouping into consolidated findings
    _HEADER_TEMPLATES = {"security-headers-hsts", "security-headers-xcto", "security-headers-xfo",
                         "security-headers-csp", "security-headers-xxp", "security-headers-rp",
                         "security-headers-pp", "http-missing-security-headers", "missing-sri"}
    _API_DOCS_TEMPLATES = {"swagger-api", "redoc-api-docs", "openapi"}

    @staticmethod
    def _safe_evidence_get(finding: Dict, key: str, default: str = "") -> str:
        """Safely extract a key from finding['evidence'], handling string evidence."""
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict):
            return evidence.get(key, default)
        return default

    def _consolidate_informational(self, findings: List[Dict]) -> List[Dict]:
        """
        Consolidate informational findings into grouped entries.

        - All missing security header findings → 1 consolidated finding
        - All API documentation exposure findings → 1 consolidated finding
        - Other informational types pass through unchanged
        """
        header_findings = []
        api_docs_findings = []
        nuclei_groups: Dict[str, List[Dict]] = {}
        other_findings = []

        for f in findings:
            ftype = f.get("type", "").upper()
            ftype_norm = ftype.replace("_", " ")

            # Group ALL missing-header findings, regardless of which Nuclei template (or
            # source) produced them — covers both "MISSING_SECURITY_HEADER" and the
            # "NUCLEI:HTTP Missing Security Headers" variant.
            if "MISSING SECURITY HEADER" in ftype_norm:
                header_findings.append(f)
            elif "API DOCUMENTATION EXPOSURE" in ftype_norm:  # group ALL, regardless of template
                api_docs_findings.append(f)
            elif ftype.startswith("NUCLEI:"):
                # One Nuclei template fires once per URL (tech detection, GraphQL probes,
                # header checks, …) → dozens of near-identical rows. Group by type so each
                # template collapses to ONE entry with an affected-endpoint list.
                nuclei_groups.setdefault(self._nuclei_group_id(f), []).append(f)
            else:
                other_findings.append(f)

        result = list(other_findings)

        if header_findings:
            result.append(self._build_consolidated_header_finding(header_findings))

        if api_docs_findings:
            result.append(self._build_consolidated_api_docs_finding(api_docs_findings))

        grouped_nuclei_rows = 0
        grouped_nuclei_entries = 0
        for group_id, group in nuclei_groups.items():
            ntype = group[0].get("type", "NUCLEI:Unknown")
            if len(group) == 1:
                group[0]["nuclei_group_id"] = group_id
                clean = ntype.replace("NUCLEI:", "").strip()
                matcher = str(group[0].get("nuclei_matcher") or "").strip()
                if "wappalyzer technology detection" in clean.lower() and matcher:
                    group[0]["title"] = f"{clean}: {matcher.replace('-', ' ').title()}"
                result.append(group[0])  # single hit — nothing to consolidate
            else:
                result.append(self._build_consolidated_nuclei_finding(ntype, group, group_id))
                grouped_nuclei_rows += len(group)
                grouped_nuclei_entries += 1

        consolidated_count = len(header_findings) + len(api_docs_findings) + grouped_nuclei_rows
        if consolidated_count > 0:
            logger.info(
                f"[{self.name}] Consolidated {consolidated_count} informational/Nuclei findings → "
                f"{int(bool(header_findings)) + int(bool(api_docs_findings)) + grouped_nuclei_entries} grouped entries"
            )

        return result

    def _build_consolidated_nuclei_finding(
        self, ntype: str, findings: List[Dict], group_id: str,
    ) -> Dict:
        """Collapse repeated hits of one Nuclei template (same template, many URLs) into a
        single finding carrying an affected-endpoint list — so N near-identical rows become
        one report entry. Severity/type/description are inherited from the first hit."""
        base = dict(findings[0])
        urls = []
        seen = set()
        for f in findings:
            u = f.get("url", "")
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
        n = len(urls)
        clean = ntype.replace("NUCLEI:", "").strip() or "Nuclei finding"
        matcher = str(base.get("nuclei_matcher") or "").strip()
        if "wappalyzer technology detection" in clean.lower() and matcher:
            clean = f"{clean}: {matcher.replace('-', ' ').title()}"
        base["url"] = urls[0] if urls else base.get("url", "")
        base["affected_urls"] = urls
        base["instance_count"] = len(findings)
        base["nuclei_group_id"] = group_id
        base["nuclei_group_members"] = [dict(finding) for finding in findings]
        base["title"] = f"{clean} — {n} affected endpoint{'s' if n != 1 else ''}"
        desc = str(base.get("description", "")).strip()
        shown = urls[:25]
        url_block = f"\n\n**Affected endpoints ({n}):**\n" + "\n".join(f"- {u}" for u in shown)
        if n > len(shown):
            url_block += f"\n- … and {n - len(shown)} more"
        base["description"] = (desc + url_block).strip()
        return base

    def _build_consolidated_header_finding(self, findings: List[Dict]) -> Dict:
        """Build a single consolidated finding from multiple missing header findings."""
        # Collect unique header names from template IDs
        headers_detail = []
        urls_seen = set()
        for f in findings:
            tmpl = self._safe_evidence_get(f, "nuclei_template", f.get("parameter", ""))
            desc = f.get("description", "").strip()
            url = f.get("url", "")
            if url:
                urls_seen.add(url)
            # Build a readable name from template
            name = tmpl.replace("security-headers-", "").replace("http-missing-security-headers", "Multiple Headers").upper()
            header_map = {
                "HSTS": "Strict-Transport-Security (HSTS)",
                "XCTO": "X-Content-Type-Options",
                "XFO": "X-Frame-Options",
                "CSP": "Content-Security-Policy",
                "XXP": "X-XSS-Protection",
                "RP": "Referrer-Policy",
                "PP": "Permissions-Policy",
                "MISSING-SRI": "Subresource Integrity (SRI)",
                "MULTIPLE HEADERS": "HTTP Security Headers Bundle",
            }
            readable = header_map.get(name, name)
            one_liner = desc.split("\n")[0][:120] if desc else ""
            headers_detail.append({"header": readable, "template": tmpl, "description": one_liner})

        # Build consolidated description as markdown table
        header_lines = []
        for h in headers_detail:
            header_lines.append(f"| {h['header']} | {h['description']} |")

        description = (
            f"The target is missing {len(headers_detail)} recommended security headers. "
            "These are defense-in-depth measures and best practices — not directly exploitable vulnerabilities. "
            "In bug bounty programs, missing headers are typically classified as **Informational**.\n\n"
            "| Missing Header | Details |\n"
            "|---|---|\n"
            + "\n".join(header_lines) + "\n\n"
            "**Recommendation:** Configure the web server or application to include all standard "
            "security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)."
        )

        # Use first finding as base, override key fields
        base = dict(findings[0])
        base["type"] = "MISSING_SECURITY_HEADER"
        base["parameter"] = "security-headers-consolidated"
        base["title"] = f"Missing Security Headers ({len(headers_detail)} headers)"
        base["description"] = description
        base["severity"] = "INFO"
        base["cvss_score"] = 0.0
        base["cvss_vector"] = "N/A"
        base["cvss_rationale"] = "Informational — defense-in-depth headers, not directly exploitable."
        base["enriched"] = True
        base["evidence"] = {
            "nuclei_template": "security-headers-consolidated",
            "missing_headers": [h["header"] for h in headers_detail],
            "original_count": len(findings),
        }
        base["exploitation_details"] = description
        base["url"] = sorted(urls_seen)[0] if urls_seen else base.get("url", "")
        base.pop("cwe", None)
        base.pop("cve", None)
        return base

    def _build_consolidated_api_docs_finding(self, findings: List[Dict]) -> Dict:
        """Build a single consolidated finding from multiple API documentation exposure findings."""
        endpoints = []
        urls_seen = set()
        for f in findings:
            tmpl = self._safe_evidence_get(f, "nuclei_template", f.get("parameter", ""))
            url = f.get("url", "")
            desc = f.get("description", "").strip().split("\n")[0][:120]
            if url:
                urls_seen.add(url)
            endpoints.append({"template": tmpl, "url": url, "description": desc})

        endpoint_lines = []
        for ep in endpoints:
            endpoint_lines.append(f"| {ep['url']} | {ep['description']} |")

        description = (
            f"The application exposes {len(endpoints)} API documentation endpoint(s) without authentication. "
            "While this aids development, in production it reveals internal API structure to potential attackers. "
            "In bug bounty programs, API documentation exposure is typically classified as **Informational**.\n\n"
            "| Endpoint | Details |\n"
            "|---|---|\n"
            + "\n".join(endpoint_lines) + "\n\n"
            "**Recommendation:** Restrict API documentation endpoints to authenticated users or internal networks only."
        )

        base = dict(findings[0])
        base["type"] = "API DOCUMENTATION EXPOSURE"
        base["parameter"] = "api-docs-consolidated"
        base["title"] = f"API Documentation Exposure ({len(endpoints)} endpoints)"
        base["description"] = description
        base["severity"] = "INFO"
        base["cvss_score"] = 0.0
        base["cvss_vector"] = "N/A"
        base["cvss_rationale"] = "Informational — API documentation exposure aids reconnaissance but is not directly exploitable."
        base["enriched"] = True
        base["evidence"] = {
            "nuclei_template": "api-docs-consolidated",
            "exposed_endpoints": [ep["url"] for ep in endpoints],
            "original_count": len(findings),
        }
        base["exploitation_details"] = description
        base["url"] = sorted(urls_seen)[0] if urls_seen else base.get("url", "")
        base.pop("cwe", None)
        base.pop("cve", None)
        return base

    async def _calculate_cvss_batch(self, findings: List[Dict]):
        """
        Batch CVSS scoring with concurrent chunk processing.
        Uses semaphore to limit concurrent LLM calls.
        Falls back to individual calls on parse failure.
        """
        # Pre-assign informational findings — no LLM needed
        scorable = []
        for f in findings:
            if f.get("type", "").upper() in self.INFORMATIONAL_TYPES:
                f["severity"] = "INFO"
                f["cvss_score"] = 0.0
                f["cvss_vector"] = "N/A"
                f["cvss_rationale"] = "Informational finding — defense-in-depth measure or best practice, not a directly exploitable vulnerability."
                f["enriched"] = True
            else:
                scorable.append(f)

        if not scorable:
            logger.info(f"[{self.name}] Batch CVSS: all {len(findings)} findings are informational, no LLM scoring needed")
            return

        CHUNK_SIZE = 10
        MAX_CONCURRENT = 3
        semaphore = asyncio.Semaphore(MAX_CONCURRENT)

        chunks = []
        for chunk_start in range(0, len(scorable), CHUNK_SIZE):
            chunks.append(scorable[chunk_start:chunk_start + CHUNK_SIZE])

        info_count = len(findings) - len(scorable)
        logger.info(f"[{self.name}] Batch CVSS: {len(scorable)} scorable findings in {len(chunks)} chunks (max {MAX_CONCURRENT} concurrent), {info_count} informational skipped")

        async def _score_chunk(chunk: List[Dict], chunk_idx: int):
            async with semaphore:
                try:
                    await self._cvss_score_single_chunk(chunk, chunk_idx)
                except Exception as e:
                    logger.warning(f"[{self.name}] Batch CVSS chunk {chunk_idx} failed: {e}, falling back to individual")
                    for f in chunk:
                        await self._calculate_cvss(f)
                        await asyncio.sleep(0.5)

        await asyncio.gather(*[
            _score_chunk(chunk, i) for i, chunk in enumerate(chunks)
        ])

    async def _cvss_score_single_chunk(self, chunk: List[Dict], chunk_idx: int):
        """Score a single chunk of findings via batch LLM call."""
        findings_text = []
        for i, f in enumerate(chunk):
            # validator_notes carries WHAT the validator actually observed (e.g. an
            # error-based status differential vs a real UNION/data-dump) — without it
            # the scorer only sees the vuln TYPE label and defaults to that type's
            # worst-case example (an error-based SQLi read as "full DB access" CRITICAL).
            evidence = str(f.get("validator_notes") or "")[:200]
            evidence_line = f", Validation Evidence: {evidence}" if evidence else ""
            findings_text.append(
                f"[Finding {i}] Type: {f.get('type')}, URL: {f.get('url')}, "
                f"Parameter: {f.get('parameter')}, Payload: {str(f.get('payload', ''))[:100]}, "
                f"Description: {str(f.get('description', ''))[:150]}{evidence_line}"
            )
        findings_block = "\n".join(findings_text)

        prompt = f"""You are a Senior Bug Bounty Triager scoring vulnerabilities for a bug bounty program. Be CONSERVATIVE — overrating wastes program resources and damages credibility. Score ALL findings below in ONE response.

**Findings:**
{findings_block}

**Bug Bounty Severity Calibration (be strict, do NOT inflate):**
- CRITICAL (9.0-10.0): ONLY RCE with proven code execution, SQLi with full DB dump/write, Authentication Bypass to admin
- HIGH (7.0-8.9): Stored XSS with session hijack, SSRF to internal services, XXE with file read, IDOR accessing other users' sensitive data
- MEDIUM (4.0-6.9): Reflected XSS (requires user interaction), CSRF on sensitive actions, CSTI/SSTI without RCE escalation
- LOW (2.0-3.9): Open Redirect, CSRF on non-sensitive actions, verbose error messages, minor info disclosure
- INFO (0.1-1.9): Missing security headers, version disclosure, API documentation exposure, cookie flags

**Scoring rules:**
- Reflected XSS is MEDIUM at most (6.1), NEVER HIGH — it requires user interaction
- Open Redirect is LOW (3.1-4.0) unless chained with OAuth token theft
- Missing headers, API docs exposure = always INFO
- Missing rate limiting on authentication endpoints (login, register, password reset) = MEDIUM (5.3) — enables brute force and credential stuffing
- Missing rate limiting on non-auth endpoints = LOW (2.0-3.0)
- CSTI that only achieves client-side template evaluation = MEDIUM (5.4)
- Only score what the finding ACTUALLY demonstrates, not theoretical maximum impact

For EACH finding, provide: CVSS vector, score, severity, rationale (2-3 sentences), CWE, CVE (or null).

Output STRICT JSON array (no markdown):
[
  {{"finding_id": 0, "vector": "CVSS:3.1/...", "score": 9.8, "severity": "CRITICAL", "rationale": "...", "cwe": "CWE-89", "cve": null}},
  {{"finding_id": 1, "vector": "CVSS:3.1/...", "score": 6.1, "severity": "MEDIUM", "rationale": "...", "cwe": "CWE-79", "cve": null}}
]"""

        response = await self._cvss_execute_llm(prompt)
        if response:
            # Strip markdown code fences if present
            cleaned = response.strip()
            if cleaned.startswith("```"):
                cleaned = re.sub(r'^```\w*\s*\n?', '', cleaned)
                cleaned = re.sub(r'\n?```\s*$', '', cleaned)

            # Parse JSON array from response
            results = None
            try:
                parsed = json.loads(cleaned.strip())
                if isinstance(parsed, list):
                    results = parsed
                elif isinstance(parsed, dict):
                    for key in parsed:
                        if isinstance(parsed[key], list):
                            results = parsed[key]
                            break
            except (json.JSONDecodeError, ValueError):
                json_match = re.search(r'\[.*\]', cleaned, re.DOTALL)
                if json_match:
                    try:
                        results = json.loads(json_match.group(0))
                    except json.JSONDecodeError:
                        pass

            if results and isinstance(results, list):
                scored = 0
                for item in results:
                    if isinstance(item, dict):
                        idx = item.get("finding_id", -1)
                        if 0 <= idx < len(chunk):
                            self._cvss_update_finding(chunk[idx], item)
                            scored += 1
                logger.info(f"[{self.name}] Batch CVSS chunk {chunk_idx}: scored {scored}/{len(chunk)} findings")
                return

        # Fallback: individual calls for this chunk
        logger.warning(f"[{self.name}] Batch CVSS chunk {chunk_idx} parse failed, falling back to individual. Response: {str(response)[:300]}")
        for f in chunk:
            await self._calculate_cvss(f)
            await asyncio.sleep(0.5)

    async def _calculate_cvss(self, f: Dict):
        """
        Query LLM to calculate CVSS v3.1 score and severity.
        Updates the finding dictionary in-place.
        """
        try:
            prompt = self._cvss_build_prompt(f)
            response = await self._cvss_execute_llm(prompt)

            if response:
                data = self._cvss_parse_response(response)
                if data:
                    self._cvss_update_finding(f, data)
                else:
                    logger.debug(f"[{self.name}] CVSS parse returned None for {f.get('type')}. Raw: {response[:200]}")
            else:
                logger.debug(f"[{self.name}] CVSS LLM returned None for {f.get('type')}")

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to enrich finding {f.get('id')}: {e}")

    def _cvss_build_prompt(self, f: Dict) -> str:
        """Build CVSS calculation prompt for LLM."""
        validator_notes = str(f.get("validator_notes") or "")[:400]
        evidence_line = f"\n            - Validation Evidence: {validator_notes}" if validator_notes else ""
        return f"""
            You are a Senior Penetration Testing Expert analyzing a confirmed security vulnerability.

            **Vulnerability Details:**
            - Type: {f.get('type')}
            - Description: {f.get('description')}
            - URL: {f.get('url')}
            - Parameter: {f.get('parameter')}
            - Payload: {f.get('payload')}{evidence_line}

            **Your Task:**
            1. Calculate the CVSS v3.1 Vector String (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
            2. Calculate the Base Score (0.0-10.0) based on the vector
            3. Assign Severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)
            4. Write a DETAILED technical rationale explaining:
               - Why this vulnerability is exploitable
               - The complete exploitation path (step-by-step)
               - Real-world impact scenarios
               - Why each CVSS metric was chosen
            5. Assign the correct CWE ID for this vulnerability class (e.g., CWE-89 for SQL Injection, CWE-79 for XSS, CWE-1336 for Template Injection, CWE-918 for SSRF, CWE-22 for Path Traversal, CWE-611 for XXE, CWE-601 for Open Redirect, CWE-639 for IDOR, CWE-94 for Code Injection, CWE-113 for Header Injection, CWE-434 for File Upload, CWE-347 for JWT, CWE-1321 for Prototype Pollution)
            6. If this vulnerability relates to a known CVE (especially for specific technologies/libraries like Apache Velocity, Jinja2, AngularJS, Log4j, etc.), provide the most relevant CVE reference. For generic application-level vulnerabilities (like SQLi in a custom parameter), return null.

            **CRITICAL: SEVERITY CALIBRATION GUIDELINES**
            Be REALISTIC with scoring - not everything is CRITICAL. Score what the Validation Evidence
            above actually shows was demonstrated, NOT the theoretical worst case for this vuln type —
            e.g. an error-based status differential is not "full DB access" unless the evidence shows
            actual data was extracted. Use these guidelines:

            - **CRITICAL (9.0-10.0)**: Remote Code Execution, SQL Injection with full DB access, Authentication Bypass
            - **HIGH (7.0-8.9)**: Stored XSS, SSRF with internal network access, XXE with file read, CSTI/SSTI
            - **MEDIUM (4.0-6.9)**: Reflected XSS, CSRF, Information Disclosure, Open Redirect, XXE (DoS only)
            - **LOW (0.1-3.9)**: Security Misconfigurations, Minor info leaks

            **Scoring Examples:**
            - SQLi (UNION-based, data exfiltration): CRITICAL 9.8
            - Stored XSS (session hijacking): HIGH 8.0-8.5
            - Reflected XSS (requires user interaction): MEDIUM 6.0-7.0
            - XXE (file read): HIGH 7.5-8.0
            - SSRF (internal network): HIGH 7.0-8.0
            - Open Redirect: MEDIUM 4.0-6.0

            **Important:**
            - Be TECHNICAL and DETAILED - this is for professional pentesters
            - Explain the FULL exploitation chain, not just "attacker can execute code"
            - Include specific attack vectors and post-exploitation scenarios
            - Don't hold back on technical details - this is authorized security testing

            Output STRICT JSON ONLY (no markdown):
            {{
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
                "severity": "CRITICAL",
                "rationale": "Detailed 3-4 sentence technical explanation of exploitation path and impact...",
                "cwe": "CWE-89",
                "cve": "CVE-XXXX-XXXX" or null
            }}
            """

    async def _cvss_execute_llm(self, prompt: str) -> Optional[str]:
        """Execute LLM call for CVSS calculation.

        Note: actual HTTP timeout is 90s (LLM_TOTAL_TIMEOUT in llm_client.py).
        Large batches (10 findings/chunk) generate bigger prompts that may use
        most of this budget — the global 20-min enrichment timeout in
        generate_all_deliverables() protects against true hangs.
        """
        text, _ = await self._reporting_generate(prompt, module_name="Reporting-CVSS", temperature=0.3)
        return text

    def _cvss_parse_response(self, response: str) -> Optional[Dict]:
        """Parse LLM response and extract CVSS data."""
        # Extract content from markdown code fences (robust: handles trailing text)
        cleaned = response.strip()
        fence_match = re.search(r'```\w*\s*\n?(.*?)```', cleaned, re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1).strip()
        elif cleaned.startswith("```"):
            # Opening fence without closing — strip opening only
            cleaned = re.sub(r'^```\w*\s*\n?', '', cleaned).strip()

        # Try direct parse first (cleanest case)
        try:
            data = json.loads(cleaned.strip())
            if isinstance(data, dict):
                return data
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return data[0]
        except (json.JSONDecodeError, IndexError):
            pass

        # Extract JSON object from mixed text
        json_match = re.search(r'\{.*\}', cleaned, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(0))
            except json.JSONDecodeError:
                pass

        # Last resort: extract individual CVSS fields with regex (handles truncated JSON)
        extracted = {}
        vector_m = re.search(r'"vector(?:_string)?":\s*"(CVSS:3\.1/[^"]+)"', response)
        if vector_m:
            extracted['vector'] = vector_m.group(1)
        score_m = re.search(r'"(?:cvss_)?score":\s*([\d.]+)', response)
        if score_m:
            try:
                extracted['score'] = float(score_m.group(1))
            except ValueError:
                pass
        severity_m = re.search(r'"severity":\s*"(CRITICAL|HIGH|MEDIUM|LOW|INFO)"', response, re.IGNORECASE)
        if severity_m:
            extracted['severity'] = severity_m.group(1).upper()
        rationale_m = re.search(r'"rationale":\s*"([^"]{10,})', response)
        if rationale_m:
            extracted['rationale'] = rationale_m.group(1)
        cwe_m = re.search(r'"cwe":\s*"(CWE-\d+)"', response)
        if cwe_m:
            extracted['cwe'] = cwe_m.group(1)

        if extracted.get('score') is not None or extracted.get('vector'):
            logger.info(f"[{self.name}] CVSS extracted from truncated response: score={extracted.get('score')}, severity={extracted.get('severity')}")
            return extracted

        logger.warning(f"[{self.name}] CVSS no JSON found. Raw response: {response[:300]}")
        return None

    @staticmethod
    def _severity_from_cvss_score(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"

    def _normalize_cvss_severities(self, findings: List[Dict]) -> None:
        for finding in findings:
            try:
                score = float(finding.get("cvss_score"))
                if 0.0 <= score <= 10.0:
                    finding["severity"] = self._severity_from_cvss_score(score)
            except (TypeError, ValueError):
                pass

    def _cvss_update_finding(self, f: Dict, data: Dict):
        """Update finding with CVSS data."""
        # Accept score from multiple possible field names (provider compatibility)
        new_score = data.get('score')
        if new_score is None:
            new_score = data.get('cvss_score')
        if new_score is None:
            new_score = data.get('base_score')

        score_updated = False
        if new_score is not None:
            try:
                numeric_score = float(new_score)
                if not 0.0 <= numeric_score <= 10.0:
                    raise ValueError("CVSS score outside 0.0-10.0")
                f['cvss_score'] = numeric_score
                score_updated = True
                f['severity'] = self._severity_from_cvss_score(numeric_score)
            except (ValueError, TypeError):
                pass
        if not score_updated and data.get('severity'):
            f['severity'] = str(data['severity']).upper()
        new_vector = data.get('vector') or data.get('cvss_vector') or data.get('vector_string')
        f['cvss_vector'] = new_vector or f.get('cvss_vector')
        f['cvss_rationale'] = data.get('rationale') or data.get('analysis') or f.get('cvss_rationale')

        vuln_type = f.get('type', '')

        # CWE: LLM response first, then framework mapping as fallback
        cwe = data.get('cwe')
        if cwe:
            f['cwe'] = cwe
        # (fallback to get_cwe_for_vuln happens in markdown generation)

        # CVE: LLM response first, then framework reference lookup as fallback
        cve = data.get('cve')
        if not cve:
            cve = get_reference_cve(vuln_type, f)
        f['cve'] = cve

        # Append rationale to description or notes
        rationale = data.get('rationale', '')

        # Severity and cvss_score are deliberately NOT restated here. This prose is frozen into
        # validator_notes at enrichment time, but both fields are mutated several more times
        # afterwards (_apply_deterministic_severity_rules / _apply_severity_floor /
        # _normalize_cvss_severities, applied both pre- and post-PoC-enrichment) and nothing
        # rewrites this string. Restating them shipped findings whose header severity
        # contradicted their own CVSS block — re-injecting exactly the LLM overclaim the
        # deterministic rules exist to suppress. The finding header is the single source of
        # truth for severity; this block carries only what enrichment itself owns.
        enrichment_text = f"\n\n**CVSS Analysis**:\n- **Vector**: `{f.get('cvss_vector', 'N/A')}`\n- **Rationale**: {rationale}"
        if cve:
            # `cve` is free text from the LLM's enrichment JSON — it has been observed as a
            # single id ("CVE-2020-11022") AND as a comma-joined list ("CVE-2020-11022,
            # CVE-2020-11023"). The sibling builder at `_generate_standardized_finding` (~2993)
            # already guards this with `format_cve()` inside try/except; this site built the
            # link straight from the raw string, so a multi-CVE value produced one NVD URL with
            # a literal comma and space in the path — a link that never resolves. Build one
            # validated link per id instead of one broken link for the whole string.
            cve_links = []
            for candidate in cve.split(","):
                candidate = candidate.strip()
                if not candidate:
                    continue
                try:
                    formatted = format_cve(candidate)
                    cve_links.append(f"[{formatted}](https://nvd.nist.gov/vuln/detail/{formatted})")
                except ValueError:
                    continue
            if cve_links:
                enrichment_text += f"\n- **Reference CVE**: {', '.join(cve_links)}"

        # Append to validator_notes instead of overwriting description to keep original clean
        if f.get('validator_notes'):
            f['validator_notes'] += enrichment_text
        else:
            f['validator_notes'] = enrichment_text.strip()

    def _get_remediation_for_type(self, vuln_type: str) -> str:
        """
        Get standard remediation for vulnerability type.
        Delegates to centralized standards module for consistency.
        """
        return get_remediation_for_vuln(vuln_type)

    def _get_cwe_for_type(self, vuln_type: str) -> str:
        """
        Get CWE reference for vulnerability type.
        Delegates to centralized standards module.
        """
        return get_cwe_for_vuln(vuln_type) or "N/A"

    def _write_raw_markdown(self, findings: List[Dict]) -> Path:
        """Write raw findings to a markdown file (Pre-Audit)."""
        path = self.output_dir / "raw_findings.md"
        
        lines = []
        lines.append(f"# Raw Findings (Pre-Audit): {self.target_url}\n")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
        lines.append(f"**Total Findings:** {len(findings)}\n")
        lines.append("---\n")

        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f.get('type')} on {f.get('parameter', 'unknown')}\n")
            lines.append(self._md_injection_point(f))
            lines.append(f"\n**Description:** {f.get('description')}\n")
            lines.append("---\n")

        with open(path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        
        logger.info(f"[{self.name}] Wrote raw_findings.md")
        return path

    def _write_validated_markdown(self, validated: List[Dict], manual_review: List[Dict]) -> Path:
        """Write validated findings to a markdown file (Post-Audit)."""
        path = self.output_dir / "validated_findings.md"
        
        lines = []
        lines.append(f"# Validated Findings (Post-Audit): {self.target_url}\n")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
        lines.append(f"**Confirmed:** {len(validated)} | **Manual Review:** {len(manual_review)}\n")
        lines.append("---\n")

        # Confirmed Section
        if validated:
            lines.append("## ✅ Confirmed Vulnerabilities\n")
            for i, f in enumerate(validated, 1):
                lines.append(f"### C-{i}. {f.get('type')}\n")
                lines.append(f"**Severity:** {f.get('severity')}\n")
                lines.append(self._md_injection_point(f) + "\n")
                lines.append("**PoC:**\n\n" + md_code_block(self._generate_curl(f), "bash") + "\n")
                if f.get("validator_notes"):
                    lines.append(f"**Validation Notes:**\n> {f.get('validator_notes')}\n")
                lines.append("---\n")
        
        # Manual Review Section
        if manual_review:
            lines.append("## ⚠️ Needs Manual Review\n")
            for i, f in enumerate(manual_review, 1):
                lines.append(f"### M-{i}. {f.get('type')}\n")
                lines.append(self._md_injection_point(f) + "\n")
                lines.append(f"**Why Review:** {f.get('validator_notes')}\n")
                lines.append("---\n")

        with open(path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        
        logger.info(f"[{self.name}] Wrote validated_findings.md")
        return path

    def _generate_finding_markdown(self, f: Dict, index: int) -> str:
        """Generate the markdown block for a single finding (for copy-paste)."""
        md = []
        md.append(f"### {index}. {f.get('type')}")
        md.append(f"**Severity:** {f.get('severity')}")
        md.append(self._md_injection_point(f))
        if f.get("db_type"):
            md.append(f"**DB Type:** {f.get('db_type')}")
        if f.get("tamper_used"):
            md.append(f"**Tamper Script:** {f.get('tamper_used')}")
        md.append("")
        md.append("#### Steps to Reproduce")
        for step in self._generate_reproduction_steps(f):
            md.append(step)
        md.append("")
        if "SQL" in f.get("type", "").upper() and not self._generate_curl(f).startswith("#"):
            md.append("#### Proof of Concept")
            md.append(md_code_block(self._generate_curl(f), "bash"))
        # Real newlines, not the two-character sequence "\\n": this block is copied to the
        # clipboard verbatim by the viewer's COPY MD button, and escaped newlines turned the
        # whole write-up into one unusable line (and would break every fenced block in it).
        return "\n".join(md)
