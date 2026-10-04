"""Finding build/dedup shell (part B).

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


class ReportingFindingsBExtraMixin:
    """Extra findings b helpers."""

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

    def _count_by_severity(self, validated: List[Dict]) -> Dict[str, int]:
        """Count findings by severity level."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in validated:
            sev = (f.get("severity") or "medium").lower()
            if sev in by_severity:
                by_severity[sev] += 1
        return by_severity

    def _generate_standardized_finding(self, finding: Dict, index: int) -> str:
        """
        Generate a standardized finding entry using the finding template.

        Args:
            finding: Finding dictionary with all data
            index: Finding number (1-based)

        Returns:
            Formatted markdown string for the finding
        """
        # Load template. NOTE: this module was peeled one level deeper (agents/reporting_shell/),
        # so it needs parent.parent.parent to reach bugtrace/ (stable resolved from agents/reporting.py
        # with parent.parent). Without the extra .parent this pointed at bugtrace/agents/reporting/
        # (nonexistent) → "Template not found" fallback on every finding.
        template_path = Path(__file__).parent.parent.parent / "reporting" / "templates" / "finding_template.md"
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
        # over a synthesized curl / validator notes (only fall back when they're absent).
        http_request = (finding.get("http_request") or "").strip() or self._generate_curl(finding)
        validator_notes = finding.get("validator_notes", "")
        http_response_excerpt = ((finding.get("http_response") or "").strip() or validator_notes or description or "")[:1500]
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

    def _generate_reproduction_steps(self, finding: Dict) -> List[str]:
        """
        Generate detailed, triager-ready reproduction steps based on vulnerability type.
        These steps tell the triager EXACTLY what to do and what to observe.
        """
        raw_type = str(finding.get("type") or "")
        try:
            from bugtrace.core.specialist_route_policy import specialist_queue_for_type
            vuln_type = (specialist_queue_for_type(raw_type.replace("_", " ")) or raw_type).upper()
        except Exception:
            vuln_type = raw_type.upper()

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

    def _build_xss_steps(self, finding: Dict) -> List[str]:
        """Build reproduction steps for XSS vulnerabilities — from the finding's own data
        (was static filler that told the triager to 'copy the exploit URL' while emitting none)."""
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        loc = "the parameter above" if param else "the injection point"
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
