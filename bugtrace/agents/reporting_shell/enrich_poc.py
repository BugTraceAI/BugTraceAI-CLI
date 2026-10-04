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


class ReportingPocEnrichMixin:
    """PoC prompt build/parse and batch wet/dry file writers."""

    def _poc_prepare_context(self, finding: Dict) -> Dict:
        """Prepare context for PoC enrichment prompt."""
        vuln_type = finding.get("type", "Unknown")
        validator_notes = finding.get("validator_notes", "")
        extra_evidence = f"- Validation Evidence: {validator_notes}" if validator_notes else ""
        http_request = (finding.get("http_request") or finding.get("reproduction") or "")[:4000]
        http_response = (finding.get("http_response") or finding.get("response_excerpt") or "")[:4000]
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

    async def _poc_execute_llm(self, prompt: str) -> Tuple[Optional[str], str]:
        """Execute LLM call for PoC enrichment (with scoped reporting failover)."""
        return await self._reporting_generate(prompt, module_name="Reporting-Exploitation", temperature=0.2)

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

