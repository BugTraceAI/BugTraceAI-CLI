"""CVSS scoring shell.

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

class ReportingCvssMixin:
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
            findings_text.append(
                f"[Finding {i}] Type: {f.get('type')}, URL: {f.get('url')}, "
                f"Parameter: {f.get('parameter')}, Payload: {str(f.get('payload', ''))[:100]}, "
                f"Description: {str(f.get('description', ''))[:150]}"
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
        return f"""
            You are a Senior Penetration Testing Expert analyzing a confirmed security vulnerability.

            **Vulnerability Details:**
            - Type: {f.get('type')}
            - Description: {f.get('description')}
            - URL: {f.get('url')}
            - Parameter: {f.get('parameter')}
            - Payload: {f.get('payload')}

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
            Be REALISTIC with scoring - not everything is CRITICAL. Use these guidelines:

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

        enrichment_text = f"\n\n**CVSS Analysis**:\n- **Severity**: {f.get('severity', 'N/A')} ({f.get('cvss_score', 'N/A')})\n- **Vector**: `{f.get('cvss_vector', 'N/A')}`\n- **Rationale**: {rationale}"
        if cve:
            enrichment_text += f"\n- **Reference CVE**: [{cve}](https://nvd.nist.gov/vuln/detail/{cve})"

        # Append to validator_notes instead of overwriting description to keep original clean
        if f.get('validator_notes'):
            f['validator_notes'] += enrichment_text
        else:
            f['validator_notes'] = enrichment_text.strip()

