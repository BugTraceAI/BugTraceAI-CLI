"""Remaining reporting helpers.

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

class ReportingMiscMixin:
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

    def _setup_output_directories(self):
        """Create necessary output directories."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / "captures").mkdir(exist_ok=True)

    @classmethod
    def _is_manual_review_status(cls, finding: Dict) -> bool:
        return str(finding.get("status", "")).upper() in cls._MANUAL_REVIEW_STATUSES

    @classmethod
    def _is_confirmed_status(cls, finding: Dict) -> bool:
        return str(finding.get("status", "")).upper() in cls._CONFIRMED_STATUSES

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
    def _is_unresolved_lfi_probe(finding: Dict) -> bool:
        """Identify a scanner traversal probe that lacks an injectable sink.

        Does not treat findings with real file-disclosure content in the
        captured response as unresolved (stable 891f012).
        """
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
        # File content in response is proof even without a named sink.
        try:
            from bugtrace.agents.lfi.detection import LFI_SIGNATURES
        except Exception:
            LFI_SIGNATURES = ("root:x:0:0", "[extensions]", "127.0.0.1 localhost")
        response = " ".join(
            str(finding.get(key, ""))
            for key in ("nuclei_response", "http_response", "response_excerpt", "evidence")
        )
        response = response.lower()
        has_file_content_proof = any(
            str(signature).lower() in response for signature in LFI_SIGNATURES
        )
        return (
            is_lfi
            and is_scanner_finding
            and has_traversal_path
            and not has_real_sink
            and not has_file_content_proof
        )

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
        raw_type = str(finding.get("type") or "")
        try:
            from bugtrace.core.specialist_route_policy import specialist_queue_for_type
            vuln_type = (specialist_queue_for_type(raw_type.replace("_", " ")) or raw_type).upper()
        except Exception:
            vuln_type = raw_type.upper()
        url = finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")

        if vuln_type in ["SQLI", "SQL"]:
            return self._curl_build_sqli(url, param)

        if vuln_type in ["CSTI", "SSTI"]:
            return self._curl_build_csti(url, param, payload)

        if vuln_type == "XSS":
            return self._curl_build_xss(
                url,
                param,
                payload,
                finding.get("http_method") or finding.get("method") or "GET",
            )

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

    def _curl_build_xss(
        self, url: str, param: str, payload: str, http_method: str = "GET"
    ) -> str:
        """Build XSS reproduction command (a browser URL, not a curl — an XSS PoC has to
        run in a DOM, and the percent-encoded URL carries the payload byte-exact)."""
        if str(http_method or "GET").upper() == "POST" and param and payload:
            return curl_form_field(url, param.replace("POST:", "", 1), payload)
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

    @staticmethod
    def _safe_evidence_get(finding: Dict, key: str, default: str = "") -> str:
        """Safely extract a key from finding['evidence'], handling string evidence."""
        evidence = finding.get("evidence", {})
        if isinstance(evidence, dict):
            return evidence.get(key, default)
        return default

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
