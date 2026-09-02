"""Markdown/HTML/engagement render shell.

Shell mixin; hard max 2000 LOC.
"""

from __future__ import annotations

import asyncio
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from datetime import datetime
from loguru import logger

from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.llm_client import llm_client

from bugtrace.agents.base import BaseAgent
from bugtrace.core.database import get_db_manager
from bugtrace.core.event_bus import EventType, event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.json_parser import safe_json_loads, extract_json_list
from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln, get_remediation_for_vuln, get_reference_cve,
    normalize_severity, format_cve,
)
from bugtrace.reporting.poc_format import (
    build_query_url, curl_form_field, curl_get, curl_raw_body, curl_header,
    evidence_pairs, md_code_block, md_evidence_block, md_injection_point,
    md_labeled_block, md_document_with_values, md_step_with_block,
    md_step_with_value, plain_evidence_block, shell_word,
    template_expression_result, truncate_marked,
)
import hashlib
import math
import os
import shutil
import time


class ReportingRenderJsonMixin:
    """ReportingRenderJsonMixin."""

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

    def _nuclei_stable_template_value(self, finding: Dict, *keys: str) -> Any:
        """Return the first non-cluster template alias from Nuclei output."""
        for key in keys:
            value = finding.get(key)
            normalized = self._nuclei_normalize_identity_value(value)
            if value not in (None, "", [], {}) and not normalized.startswith("cluster-"):
                return value
        return ""

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

