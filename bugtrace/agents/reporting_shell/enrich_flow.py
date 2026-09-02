"""PoC/LLM enrichment shell for ReportingAgent.

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

from bugtrace.agents.reporting_shell.helpers import _normalize_markdown_document

from bugtrace.agents.reporting_shell.enrich_poc import ReportingPocEnrichMixin
from bugtrace.agents.reporting_shell.enrich_nuclei import ReportingNucleiEnrichMixin


class ReportingEnrichMixin(ReportingPocEnrichMixin, ReportingNucleiEnrichMixin):
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
        request = finding.get("http_request") or finding.get("reproduction") or ""
        response = finding.get("http_response") or finding.get("response_excerpt") or ""
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

