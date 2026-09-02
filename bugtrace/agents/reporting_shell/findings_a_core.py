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
from bugtrace.tools.nuclei_results import is_reportable_nuclei_finding
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


def _redact_nuclei_request(text: Optional[str]) -> Optional[str]:
    """Redact Authorization / Cookie / Proxy-Authorization values from a raw
    Nuclei request blob before persisting the finding.

    Nuclei stores the FULL outgoing HTTP request — including whatever -H
    headers the scanner passed. Custom headers (Authorization, Cookie) must
    not appear in the persisted report. The redactor is name-aware so it
    preserves the header NAMES (a reader can still tell the request was
    authenticated) while replacing the VALUES with REDACTED.

    Defensive: never raises. Returns the input unchanged if it's empty.
    """
    if not text:
        return text
    try:
        from bugtrace.utils.headers import redact_text
        return redact_text(text)
    except Exception:
        # Never let a redaction failure break a report write.
        return text


class ReportingFindingsACoreMixin:
    """Core findings a helpers."""

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
                if component_name.lower() == "angularjs" and cves:
                    # CVE-2022-25869 is not applicable to the client-side
                    # AngularJS component signal; keep the canonical advisory.
                    cves = cves[:1]
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

    def _nuclei_parse_findings(self, tech_profile: Dict) -> List[Dict]:
        """Parse reportable Nuclei vulnerabilities from the tech profile."""
        nuclei_findings = []
        classified_template_ids = {
            str(misconfig.get("template_id") or "").lower()
            for misconfig in tech_profile.get("misconfigurations", [])
            if isinstance(misconfig, dict)
        }
        for finding in tech_profile.get("raw_vuln_findings") or []:
            if not is_reportable_nuclei_finding(
                finding,
                classified_template_ids=classified_template_ids,
            ):
                continue
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
                "nuclei_request": _redact_nuclei_request(
                    self._nuclei_source_value(finding, "request")
                ),
                # Redact secrets from the response too — a target server may
                # echo back Authorization or Set-Cookie in the HTTP response.
                "nuclei_response": _redact_nuclei_request(
                    self._nuclei_source_value(finding, "response")
                ),
                "nuclei_source_fingerprint": "ns1:" + hashlib.sha256(
                    json.dumps(
                        finding, sort_keys=True, separators=(",", ":"), default=str,
                    ).encode("utf-8")
                ).hexdigest(),
            })
        return nuclei_findings

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
