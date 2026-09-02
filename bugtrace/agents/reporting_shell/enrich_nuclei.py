"""Reporting enrichment mixin part."""

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


class ReportingNucleiEnrichMixin:
    """Nuclei-specific LLM enrichment helpers."""

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

