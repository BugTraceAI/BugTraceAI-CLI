"""Finding quality/rules shell (part A).

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


class ReportingFindingsAExtraMixin:
    """Extra findings a helpers."""

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

