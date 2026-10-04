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


class ReportingRenderMdMixin:
    """ReportingRenderMdMixin."""

    def _generate_markdown_reports(self, categorized: Dict) -> Dict[str, Path]:
        """Generate Markdown report files.

        v3.2: Removed redundant raw_findings.md and validated_findings.md
        (JSON versions are sufficient, MD was duplicating information)
        """
        return {
            "final_report": self._write_markdown_report(
                validated=categorized["validated"],
                manual_review=categorized["manual_review"],
                pending=categorized["pending"],
                false_positives=categorized.get("false_positives", [])
            )
        }

    def _md_injection_point(self, f: Dict) -> str:
        """URL / Parameter / Payload for `f`, rendered byte-exact (fenced blocks).

        Single source of truth for the trio across every markdown deliverable, so a
        payload cannot round-trip losslessly in one file and be mangled in the next.
        The detection probe is surfaced whenever the report ships a different (visual)
        payload than the one the evidence was captured with.
        """
        ev = f.get("evidence") if isinstance(f.get("evidence"), dict) else {}
        return md_injection_point(
            f.get("url", ""), f.get("parameter", ""), f.get("payload", ""),
            ev.get("original_payload"),
        )

    def _write_markdown_report(
        self,
        validated: List[Dict],
        manual_review: List[Dict],
        pending: List[Dict],
        false_positives: List[Dict] = None
    ) -> Path:
        """Write the triager-ready markdown report.

        v3.2: Added deduplication to prevent duplicate findings
        (e.g., 4 SQLi on same parameter → 1 finding with affected URLs)
        """
        path = self.output_dir / "final_report.md"

        # v3.2: Deduplicate findings to prevent repetition
        validated = self._deduplicate_findings(validated)
        manual_review = self._deduplicate_findings(manual_review)
        pending = self._deduplicate_findings(pending)

        lines = []
        self._md_build_header(lines, validated, manual_review, pending, false_positives)
        self._md_build_validated_findings(lines, validated)
        self._md_build_manual_review(lines, manual_review)
        self._md_build_pending_findings(lines, pending)

        # Write file
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        logger.info(f"[{self.name}] Wrote final_report.md ({len(validated)} validated, deduplicated)")
        return path

    def _md_build_header(self, lines: List[str], validated: List[Dict], manual_review: List[Dict], pending: List[Dict], false_positives: List[Dict] = None):
        """Build markdown report header and summary with standardized structure."""
        # Calculate stats for header
        stats = self._calculate_scan_stats(validated + manual_review + pending)
        # Count EVERYTHING the report actually renders with a severity badge:
        # validated (Confirmed) + manual_review (Needs Manual Review) + pending. The
        # histogram previously omitted manual_review, so its Total was lower than the
        # number of findings a reader counts in the body.
        by_severity = self._count_by_severity(validated + manual_review + pending)

        # Header: Security Assessment Report
        lines.append("# Security Assessment Report\n")

        # Scan Metadata table
        lines.append("## Scan Metadata\n")
        lines.append("| Field | Value |")
        lines.append("|-------|-------|")
        lines.append(f"| **Target** | {self.target_url} |")
        lines.append(f"| **Scan ID** | {self.scan_id} |")
        lines.append(f"| **Date** | {datetime.now().strftime('%d %b %Y %H:%M')} |")
        lines.append(f"| **Tool Version** | BugTraceAI v{settings.VERSION} |")
        lines.append(f"| **Duration** | {stats.get('duration', 'N/A')} |")
        lines.append(f"| **URLs Scanned** | {stats.get('urls_scanned', 0)} |")
        if stats.get('total_tokens', 0) > 0:
            lines.append(f"| **LLM Tokens Used** | {stats.get('total_tokens', 0):,} ({stats.get('input_tokens', 0):,} in / {stats.get('output_tokens', 0):,} out) |")
            lines.append(f"| **Estimated API Cost** | ${stats.get('estimated_cost', 0.0):.4f} |")
        lines.append("")

        # Technology Stack Section — parsed from raw Nuclei findings
        if self.tech_profile:
            tech_data = self._parse_nuclei_tech_for_report()
            techs = tech_data["technologies"]
            waf_details = tech_data["waf_details"]

            if techs or waf_details:
                lines.append("## Technology Stack\n")
                lines.append("| Component | Version | Category | Notes |")
                lines.append("|-----------|---------|----------|-------|")
                for t in techs:
                    version = t["version"] or "-"
                    notes = "End-of-Life" if t["eol"] else ""
                    lines.append(f"| **{t['name']}** | {version} | {t['category']} | {notes} |")
                lines.append("")

                if waf_details:
                    lines.append(f"**Security Controls:** WAF detected ({', '.join(waf_details)})\n")

            lines.append("---\n")

        # Executive Summary
        lines.append("## Executive Summary\n")

        # Findings by Severity table
        lines.append("### Findings by Severity\n")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Critical | {by_severity.get('critical', 0)} |")
        lines.append(f"| High | {by_severity.get('high', 0)} |")
        lines.append(f"| Medium | {by_severity.get('medium', 0)} |")
        lines.append(f"| Low | {by_severity.get('low', 0)} |")
        lines.append(f"| Info | {by_severity.get('info', 0)} |")
        total_count = sum(by_severity.values())
        lines.append(f"| **Total** | **{total_count}** |")
        lines.append("")

        # Validation Summary table
        lines.append("### Validation Summary\n")
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        lines.append(f"| Confirmed | {len(validated)} |")
        lines.append(f"| Manual Review | {len(manual_review)} |")

        # False positives threaded through from categorized["false_positives"] so the markdown
        # Validation Summary agrees with the HTML/JSON deliverable (was hardcoded 0).
        false_positive_count = len(false_positives or [])
        lines.append(f"| False Positives | {false_positive_count} |")
        lines.append(f"| Pending | {len(pending)} |")
        lines.append("")

    def _md_build_validated_findings(self, lines: List[str], validated: List[Dict]):
        """Build validated findings section of markdown report."""
        lines.append("---\n")
        lines.append("## Confirmed Vulnerabilities (Triager Ready)\n")

        if not validated:
            lines.append("*No confirmed vulnerabilities found.*\n")
            return

        # Sort by CVSS (desc) with the shared helper — the HTML/JSON deliverable already
        # sorts this way, but the markdown used a severity-name-only order, so the same
        # scan presented findings in a different priority order per deliverable.
        validated_sorted = self._sort_findings_by_cvss(validated)

        for i, f in enumerate(validated_sorted, 1):
            self._md_build_finding_entry(lines, f, i)

    def _md_build_finding_entry_inline(self, finding: Dict, index: int) -> str:
        """
        Fallback method to build finding entry inline (used when template not found).
        Returns markdown string instead of appending to lines list.
        """
        lines = []
        lines.append(f"### {index}. {finding.get('type', 'Unknown Vulnerability')}\n")
        lines.append(f"| Field | Value |")
        lines.append(f"|-------|-------|")
        lines.append(f"| **Severity** | {finding.get('severity', 'MEDIUM')} |")
        cvss_score = finding.get("cvss_score")
        cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
        lines.append(f"| **CVSS Score** | {cvss_str} |")
        lines.append(f"| **Status** | ✅ CONFIRMED |")
        lines.append(f"| **Validation Method** | {self._extract_validation_method(finding)} |")
        if finding.get("db_type"):
            lines.append(f"| **DB Type** | {finding.get('db_type')} |")
        if finding.get("tamper_used"):
            lines.append(f"| **Tamper Script** | {finding.get('tamper_used')} |")
        lines.append("")

        # URL / Parameter / Payload as fenced blocks — a markdown table cell cannot carry
        # them byte-exact (no newlines, pipes break the row, runs of spaces collapse).
        lines.append(self._md_injection_point(finding))
        lines.append("")

        # Steps to Reproduce (type-specific)
        lines.append("#### Steps to Reproduce\n")
        for step in self._generate_reproduction_steps(finding):
            lines.append(step)
        lines.append("")

        # PoC (Only for SQLi where we have SQLMap command)
        if "SQL" in finding.get("type", "").upper() and not self._generate_curl(finding).startswith("#"):
            lines.append("#### Proof of Concept\n")
            lines.append(md_code_block(self._generate_curl(finding), "bash"))
            lines.append("")

        # Validator Notes
        if finding.get("validator_notes"):
            lines.append("#### Validation Notes\n")
            lines.append(f"> {finding.get('validator_notes')}\n")

        # Screenshot
        if finding.get("screenshot_path"):
            img_name = Path(finding.get("screenshot_path")).name
            lines.append(f"#### Screenshot\n")
            lines.append(f"![Evidence](captures/{img_name})\n")

        lines.append("---\n")
        return "\n".join(lines)

    def _md_build_finding_entry(self, lines: List[str], f: Dict, index: int):
        """Build a single finding entry in markdown report using standardized template."""
        # Use new standardized generation
        finding_md = self._generate_standardized_finding(f, index)
        lines.append(finding_md)

    def _md_build_manual_review(self, lines: List[str], manual_review: List[Dict]):
        """Build manual review section of markdown report.

        Manual-review findings carry the SAME rich data as confirmed ones (description,
        impact, remediation, reproduction, evidence) — they just weren't browser-confirmed.
        The HTML/JSON deliverable renders all of it via _build_finding_entry, so the markdown
        must too; otherwise the same finding is a full write-up in HTML and a skeleton in .md.
        """
        if not manual_review:
            return

        lines.append("## Needs Manual Review\n")
        lines.append("> These findings have high AI confidence but could not be confirmed via browser automation.\n")

        # Sort by CVSS so MR-1..MR-n appear in the SAME priority order as the HTML/JSON
        # deliverable (which folds manual_review into vuln_findings + _sort_findings_by_cvss).
        # The validated and pending sections already share this sort; manual_review was missed.
        manual_review = self._sort_findings_by_cvss(manual_review)

        severity_badges = {
            "CRITICAL": "🔴 CRITICAL",
            "HIGH": "🟠 HIGH",
            "MEDIUM": "🟡 MEDIUM",
            "LOW": "🔵 LOW",
            "INFO": "⚪ INFO"
        }
        for i, f in enumerate(manual_review, 1):
            severity = f.get('severity', 'HIGH').upper()
            severity_badge = severity_badges.get(severity, severity)
            cvss_score = f.get("cvss_score")
            cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
            lines.append(f"### MR-{i}. {f.get('type', 'Unknown')}\n")
            lines.append(f"- **Severity:** {severity_badge}")
            lines.append(f"- **CVSS Score:** {cvss_str}")
            lines.append(self._md_injection_point(f))
            lines.append("")

            # Full-fidelity body (parity with the HTML/JSON deliverable): description, evidence,
            # impact, remediation and reproduction — synthesized when a field is blank.
            desc = f.get("description") or self._synthesize_description(f)
            lines.append("#### Description\n")
            lines.append(f"{desc}")
            lines.append("")

            _ev = self._render_evidence_dict(f)
            if _ev:
                lines.append("#### Detection Evidence\n")
                lines.append(_ev)
                lines.append("")

            impact = f.get("impact") or self._get_impact_for_type(f.get("type", ""))
            if impact:
                lines.append("#### Impact\n")
                lines.append(f"{impact}")
                lines.append("")

            remediation = f.get("remediation") or self._get_remediation_for_type(f.get("type", ""))
            if remediation:
                lines.append("#### Remediation\n")
                lines.append(f"{remediation}")
                lines.append("")

            # Reproduction only for genuine injection findings (has a payload); observation/
            # config findings rely on Description + Detection Evidence — no forced curl.
            if f.get("payload"):
                _repro = self._generate_curl(f)
                if _repro:
                    lines.append("#### Reproduction\n")
                    lines.append(md_code_block(_repro, "bash"))
                    lines.append("")

            if f.get("validator_notes"):
                lines.append(f"- **AI Notes:** {f.get('validator_notes')}")
                lines.append("")

    def _md_build_pending_findings(self, lines: List[str], pending: List[Dict]):
        """Build pending findings section of markdown report.

        These are findings detected by specialists but not yet confirmed via CDP.
        They often represent valid vulnerabilities that require manual verification.
        """
        if not pending:
            return

        lines.append("---\n")
        lines.append("## Pending Validation (High Confidence)\n")
        lines.append("> ⚠️ These findings were detected by specialist agents but could not be confirmed via browser automation.")
        lines.append("> They likely represent valid vulnerabilities. Manual verification recommended.\n")

        # Sort by CVSS (desc) — the HTML/JSON viewer sorts pending by CVSS via
        # _sort_findings_by_cvss, so the markdown must match or the same set is ordered
        # differently per deliverable.
        pending_sorted = self._sort_findings_by_cvss(pending)

        for i, f in enumerate(pending_sorted, 1):
            vuln_type = f.get('type', 'Unknown')
            severity = f.get('severity', 'HIGH').upper()
            severity_badges = {
                "CRITICAL": "🔴 CRITICAL",
                "HIGH": "🟠 HIGH",
                "MEDIUM": "🟡 MEDIUM",
                "LOW": "🔵 LOW",
                "INFO": "⚪ INFO"
            }
            severity_badge = severity_badges.get(severity, severity)

            lines.append(f"### P-{i}. {vuln_type}\n")
            lines.append(f"| Field | Value |")
            lines.append(f"|-------|-------|")
            lines.append(f"| **Severity** | {severity_badge} |")
            cvss_score = f.get("cvss_score")
            cvss_str = f"{cvss_score:.1f}" if cvss_score else "N/A"
            lines.append(f"| **CVSS Score** | {cvss_str} |")
            lines.append(f"| **Status** | ⏳ PENDING |")
            lines.append("")
            lines.append(self._md_injection_point(f))
            lines.append("")

            # Description — synthesized from type/param/payload when the specialist (or a raw
            # Nuclei stub) left it blank, so pending entries never render an empty body.
            desc = f.get("description") or self._synthesize_description(f)
            lines.append("#### Description\n")
            lines.append(f"{desc}")
            lines.append("")

            # Detection Evidence — surface the structured evidence dict (same as confirmed
            # findings); pending Nuclei/informational detections keep their proof here.
            _ev = self._render_evidence_dict(f)
            if _ev:
                lines.append("#### Detection Evidence\n")
                lines.append(_ev)
                lines.append("")

            if f.get("impact"):
                lines.append("#### Impact\n")
                lines.append(f"{f.get('impact')}")
                lines.append("")

            if f.get("validator_notes"):
                lines.append("#### Validator Notes\n")
                lines.append(f"{f.get('validator_notes')}")
                lines.append("")

            lines.append("---\n")

    def _write_raw_markdown(self, findings: List[Dict]) -> Path:
        """Write raw findings to a markdown file (Pre-Audit)."""
        path = self.output_dir / "raw_findings.md"
        
        lines = []
        lines.append(f"# Raw Findings (Pre-Audit): {self.target_url}\n")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
        lines.append(f"**Total Findings:** {len(findings)}\n")
        lines.append("---\n")

        for i, f in enumerate(findings, 1):
            lines.append(f"### {i}. {f.get('type')} on {f.get('parameter', 'unknown')}\n")
            lines.append(self._md_injection_point(f))
            lines.append(f"\n**Description:** {f.get('description')}\n")
            lines.append("---\n")

        with open(path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        
        logger.info(f"[{self.name}] Wrote raw_findings.md")
        return path

    def _write_validated_markdown(self, validated: List[Dict], manual_review: List[Dict]) -> Path:
        """Write validated findings to a markdown file (Post-Audit)."""
        path = self.output_dir / "validated_findings.md"
        
        lines = []
        lines.append(f"# Validated Findings (Post-Audit): {self.target_url}\n")
        lines.append(f"**Scan ID:** {self.scan_id}")
        lines.append(f"**Date:** {datetime.now().strftime('%d %b %Y %H:%M')}")
        lines.append(f"**Confirmed:** {len(validated)} | **Manual Review:** {len(manual_review)}\n")
        lines.append("---\n")

        # Confirmed Section
        if validated:
            lines.append("## ✅ Confirmed Vulnerabilities\n")
            for i, f in enumerate(validated, 1):
                lines.append(f"### C-{i}. {f.get('type')}\n")
                lines.append(f"**Severity:** {f.get('severity')}\n")
                lines.append(self._md_injection_point(f) + "\n")
                lines.append("**PoC:**\n\n" + md_code_block(self._generate_curl(f), "bash") + "\n")
                if f.get("validator_notes"):
                    lines.append(f"**Validation Notes:**\n> {f.get('validator_notes')}\n")
                lines.append("---\n")
        
        # Manual Review Section
        if manual_review:
            lines.append("## ⚠️ Needs Manual Review\n")
            for i, f in enumerate(manual_review, 1):
                lines.append(f"### M-{i}. {f.get('type')}\n")
                lines.append(self._md_injection_point(f) + "\n")
                lines.append(f"**Why Review:** {f.get('validator_notes')}\n")
                lines.append("---\n")

        with open(path, "w", encoding="utf-8") as file:
            file.write("\n".join(lines))
        
        logger.info(f"[{self.name}] Wrote validated_findings.md")
        return path

    def _generate_finding_markdown(self, f: Dict, index: int) -> str:
        """Generate the markdown block for a single finding (for copy-paste)."""
        md = []
        md.append(f"### {index}. {f.get('type')}")
        md.append(f"**Severity:** {f.get('severity')}")
        md.append(self._md_injection_point(f))
        if f.get("db_type"):
            md.append(f"**DB Type:** {f.get('db_type')}")
        if f.get("tamper_used"):
            md.append(f"**Tamper Script:** {f.get('tamper_used')}")
        md.append("")
        md.append("#### Steps to Reproduce")
        for step in self._generate_reproduction_steps(f):
            md.append(step)
        md.append("")
        if "SQL" in f.get("type", "").upper() and not self._generate_curl(f).startswith("#"):
            md.append("#### Proof of Concept")
            md.append(md_code_block(self._generate_curl(f), "bash"))
        # Real newlines, not the two-character sequence "\\n": this block is copied to the
        # clipboard verbatim by the viewer's COPY MD button, and escaped newlines turned the
        # whole write-up into one unusable line (and would break every fenced block in it).
        return "\n".join(md)

