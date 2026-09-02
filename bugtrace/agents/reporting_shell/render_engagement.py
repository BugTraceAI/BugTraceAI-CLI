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


class ReportingRenderEngagementMixin:
    """ReportingRenderEngagementMixin."""

    def _write_engagement_js(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        pending: List[Dict] = None,
        stats: Dict = None,
        tech_stack: Dict = None
    ) -> Path:
        """Write the structured engagement_data.js for HTML viewer (JSONP style).

        Raises:
            RuntimeError: If JSON serialization fails or file cannot be written.
            This ensures the pipeline fails explicitly instead of producing broken HTML.
        """
        path = self.output_dir / "engagement_data.js"
        output = self._build_engagement_data(
            all_findings, validated, false_positives, manual_review, stats, tech_stack, pending
        )

        # Validate JSON serialization BEFORE writing
        try:
            json_str = json.dumps(output, indent=2, default=str)
        except (TypeError, ValueError) as e:
            logger.error(f"[{self.name}] CRITICAL: Failed to serialize engagement data to JSON: {e}")
            raise RuntimeError(f"engagement_data.js generation failed: JSON serialization error: {e}")

        # Validate minimum required fields
        if "report_signature" not in output.get("meta", {}):
            logger.error(f"[{self.name}] CRITICAL: engagement_data missing report_signature")
            raise RuntimeError("engagement_data.js generation failed: missing report_signature")

        # Write as JS assignment
        js_content = f"window.BUGTRACE_REPORT_DATA = {json_str};"

        with open(path, "w", encoding="utf-8") as f:
            f.write(js_content)

        # Validate file was written correctly
        if not path.exists() or path.stat().st_size < 100:
            logger.error(f"[{self.name}] CRITICAL: engagement_data.js was not written correctly (size={path.stat().st_size if path.exists() else 0})")
            raise RuntimeError("engagement_data.js generation failed: file not written correctly")

        logger.info(f"[{self.name}] Wrote engagement_data.js ({len(output['findings'])} vuln findings, {len(output['infrastructure']['nuclei_findings'])} nuclei findings)")
        return path

    def _build_engagement_data(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        stats: Dict = None,
        tech_stack: Dict = None,
        pending: List[Dict] = None
    ) -> Dict:
        """Build engagement data structure (shared between JSON and JS outputs)."""
        stats = stats or {"urls_scanned": 0, "duration": "0s"}
        tech_stack = tech_stack or {}
        pending = pending or []

        # Deduplicate and process findings
        validated = self._deduplicate_findings(validated)
        manual_review = self._deduplicate_findings(manual_review)
        pending = self._deduplicate_findings(pending)
        # Count EVERY finding the report renders with a severity badge (validated +
        # manual_review + pending) so engagement_data's summary matches the Markdown
        # histogram (_md_build_header). Previously counted only `validated`, so the
        # engagement "Findings by Severity" total was lower than the Markdown total.
        by_severity = self._count_by_severity(validated + manual_review + pending)

        # Build and sort findings
        vuln_findings, nuclei_infra = self._build_triager_findings(validated, manual_review)
        # The PENDING bucket renders in the markdown but was absent from engagement_data → the
        # HTML/JSON viewer. Surface it so all three deliverables agree: informational NUCLEI:*
        # detections (grouped + enriched in Phase 2.5/2.5b) go to infrastructure.nuclei_findings,
        # and real unconfirmed vulns (SQLi/XSS/…) go into findings with a ⚠️ POTENTIAL badge.
        nuclei_infra = nuclei_infra + self._build_pending_infra_findings(pending)
        vuln_findings = vuln_findings + self._build_pending_vuln_findings(pending)
        vuln_findings = self._sort_findings_by_cvss(vuln_findings)
        nuclei_infra = self._sort_findings_by_cvss(nuclei_infra)

        return {
            "meta": self._engagement_build_meta(),
            "stats": self._engagement_build_stats(stats),
            "summary": self._engagement_build_summary(all_findings, validated, false_positives, manual_review, by_severity),
            "findings": vuln_findings,
            "infrastructure": {
                "tech_stack": tech_stack,
                "nuclei_findings": nuclei_infra
            }
        }

    def _engagement_build_meta(self) -> Dict:
        """Build engagement metadata section."""
        meta = {
            "scan_id": self.scan_id,
            "target": self.target_url,
            "scan_date": datetime.now().isoformat(),
            "tool_version": settings.VERSION,
            "validation_engine": "AgenticValidator + CDP + Vision AI",
            "report_signature": "BUGTRACE_AI_REPORT_V5",
            "enrichment_status": getattr(
                self, "_audited_enrichment_status", self._compute_enrichment_status(),
            ),
            "enrichment_stats": {
                "total": self._enrichment_total,
                "enriched": self._enrichment_total - self._enrichment_failures,
                "failed": self._enrichment_failures,
            },
        }
        return meta

    def _engagement_build_stats(self, stats: Dict) -> Dict:
        """Build engagement statistics section."""
        result = {
            "urls_scanned": stats.get("urls_scanned", 0),
            "duration": stats.get("duration", "N/A"),
            "duration_seconds": stats.get("duration_seconds", 0),
            "validation_coverage": "100%",
            "total_tokens": stats.get("total_tokens", 0),
            "estimated_cost": stats.get("estimated_cost", 0.0),
        }
        # Add parsed technology stack
        tech_data = self._parse_nuclei_tech_for_report()
        technologies = list(tech_data["technologies"])

        # Merge frameworks/servers/cms/cdn from tech_profile (HTML parsing fallback)
        if self.tech_profile:
            existing = {t["name"].lower() for t in technologies}
            _CATEGORY_MAP = {
                "frameworks": "Framework",
                "servers": "Web Server",
                "cms": "CMS",
                "cdn": "CDN",
                "languages": "Language / Runtime",
            }
            for field, category in _CATEGORY_MAP.items():
                for name in self.tech_profile.get(field, []):
                    if name.lower() not in existing:
                        existing.add(name.lower())
                        technologies.append({
                            "name": name,
                            "version": None,
                            "eol": False,
                            "category": category,
                        })

        if technologies or tech_data["waf_details"]:
            result["tech_stack"] = {
                "technologies": technologies,
                "waf": tech_data["waf_details"],
            }
        return result

    def _engagement_build_summary(
        self,
        all_findings: List[Dict],
        validated: List[Dict],
        false_positives: List[Dict],
        manual_review: List[Dict],
        by_severity: Dict
    ) -> Dict:
        """Build engagement summary section with source tracking."""
        # Count findings by source
        event_sourced = sum(1 for f in all_findings if f.get("source") == "event_bus")
        db_sourced = sum(1 for f in all_findings if f.get("source") in ("database", None))
        nuclei_sourced = sum(1 for f in all_findings if f.get("source") == "nuclei")

        return {
            "total_findings": len(all_findings),
            "validated": len(validated),
            "false_positives": len(false_positives),
            "manual_review": len(manual_review),
            "by_severity": by_severity,
            # Source breakdown for report insights
            "event_sourced": event_sourced,
            "db_sourced": db_sourced,
            "nuclei_sourced": nuclei_sourced,
        }

