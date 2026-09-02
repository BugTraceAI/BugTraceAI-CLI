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


class ReportingFindingsBCoreMixin:
    """Core findings b helpers."""

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

    def _get_findings_from_db(self) -> List[Dict]:
        """DEPRECATED: DB is write-only from CLI. Returns empty list.
        Primary source is _load_specialist_results() which reads from files."""
        logger.warning(f"[{self.name}] _get_findings_from_db() called but DB is write-only. Returning empty.")
        return []

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

