"""
ReportingAgent: Generates all 4 deliverables for a scan.

Deliverables:
1. raw_findings.json - Pre-AgenticValidator findings (for manual review)
2. validated_findings.json - Only VALIDATED_CONFIRMED findings
3. final_report.md - Triager-ready markdown with all findings
4. engagement_data.json - Structured JSON for HTML viewer
5. report.html - Static HTML that loads engagement_data.json
"""

import json
import hashlib
import math
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from bugtrace.agents.base import BaseAgent
from bugtrace.core.config import settings
from bugtrace.core.database import get_db_manager
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.core.llm_client import llm_client
from bugtrace.core.event_bus import EventType, event_bus
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.json_parser import safe_json_loads, extract_json_list
# ScanTable import removed: DB is write-only from CLI
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    get_reference_cve,
    normalize_severity,
    format_cve,
)
from bugtrace.reporting.poc_format import (
    build_query_url,
    curl_form_field,
    curl_get,
    curl_raw_body,
    curl_header,
    evidence_pairs,
    md_code_block,
    md_evidence_block,
    md_injection_point,
    md_labeled_block,
    md_document_with_values,
    md_step_with_block,
    md_step_with_value,
    plain_evidence_block,
    shell_word,
    template_expression_result,
    truncate_marked,
)
import asyncio
import re

logger = get_logger("agents.reporting")


from bugtrace.agents.reporting_shell.helpers import _normalize_markdown_document


from bugtrace.agents.reporting_shell.enrich_flow import ReportingEnrichMixin
from bugtrace.agents.reporting_shell.cvss_flow import ReportingCvssMixin
from bugtrace.agents.reporting_shell.render_flow import ReportingRenderMixin
from bugtrace.agents.reporting_shell.load_flow import ReportingLoadMixin
from bugtrace.agents.reporting_shell.misc_flow import ReportingMiscMixin
from bugtrace.agents.reporting_shell.findings_a_flow import ReportingFindingsAMixin
from bugtrace.agents.reporting_shell.findings_b_flow import ReportingFindingsBMixin


class ReportingAgent(
    ReportingEnrichMixin,
    ReportingCvssMixin,
    ReportingRenderMixin,
    ReportingLoadMixin,
    ReportingMiscMixin,
    ReportingFindingsAMixin,
    ReportingFindingsBMixin,
    BaseAgent,
):
    """
    Final agent responsible for generating all report deliverables.

    Shell methods live in reporting_shell/* mixins (≤2000 LOC each).

    Class attrs restored after dual peel (were on monolith ReportingAgent).
    Missing attrs crash generate_report mid-scan → no validated_findings.json /
    final_report.md while pipeline still logs "Report generation complete".
    """

    _MANUAL_REVIEW_STATUSES = {
        "MANUAL_REVIEW_RECOMMENDED", "NEEDS_VALIDATION",
        "VALIDATION_ERROR", "NEEDS_CDP_VALIDATION",
    }
    _CONFIRMED_STATUSES = {
        "VALIDATED_CONFIRMED", "VALIDATED", "FINDING_VALIDATED",
    }
    _SEVERITY_FLOOR = {
        "rce": "Critical", "remote code": "Critical", "command inj": "Critical",
        "deserial": "Critical",
        "sqli": "High", "sql injection": "High",
        "ssti": "High", "template injection": "High", "csti": "High",
        "xxe": "High",
    }
    _SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    _SEVERITY_CVSS_FLOOR = {
        "critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "info": 0.0,
    }
    _DEFAULT_SEVERITY = {
        "xss": "Medium",
        "idor": "Medium",
        "ssrf": "Medium",
        "open redirect": "Low", "openredirect": "Low", "open_redirect": "Low",
        "prototype pollution": "Medium",
    }
    _STATIC_ANALYSIS_PATTERNS = (
        "source-to-sink pattern detected",
        "detected via code analysis",
        "pattern detected via",
    )
    _XSS_UNCONFIRMED_LEVELS = {"L0.5", "L1"}
    _LOCATION_REQUIRED_TOKENS = {
        "SQLI", "XSS", "SSRF", "RCE", "CSTI", "SSTI", "LFI", "XXE", "IDOR", "OPENREDIRECT",
    }
    _LOCATION_REQUIRED_PHRASES = (
        "SQL INJECTION", "REMOTE CODE", "COMMAND INJECTION", "OS COMMAND",
        "TEMPLATE INJECTION", "PATH TRAVERSAL", "FILE INCLUSION", "OPEN REDIRECT",
        "HEADER INJECTION", "PROTOTYPE POLLUTION", "MASS ASSIGNMENT",
    )
    NUCLEI_NARRATIVE_SCHEMA = "bugtrace.nuclei-narrative/v1"
    NUCLEI_NARRATIVE_BATCH_SIZE = 3
    NUCLEI_NARRATIVE_WORKERS = 2
    NUCLEI_NARRATIVE_SOFT_SECONDS = 285
    NUCLEI_NARRATIVE_BATCH_SECONDS = 65
    NUCLEI_NARRATIVE_SINGLE_SECONDS = 45
    NUCLEI_NARRATIVE_MAX_SINGLE_RETRIES = 6
    NUCLEI_NARRATIVE_MAX_FIELD_CHARS = 6000
    INFORMATIONAL_TYPES = {"MISSING_SECURITY_HEADER", "API DOCUMENTATION EXPOSURE"}
    _HEADER_TEMPLATES = {
        "security-headers-hsts", "security-headers-xcto", "security-headers-xfo",
        "security-headers-csp", "security-headers-xxp", "security-headers-rp",
        "security-headers-pp", "http-missing-security-headers", "missing-sri",
    }
    _API_DOCS_TEMPLATES = {"swagger-api", "redoc-api-docs", "openapi"}

    def __init__(self, scan_id: int, target_url: str, output_dir: Path, tech_profile: Dict = None):
        super().__init__("ReportingAgent", "Reporting Specialist", agent_id="reporting_agent")
        self.scan_id = scan_id
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.tech_profile = tech_profile or {}
        self.db = get_db_manager()

        # Event-driven finding accumulation
        self._validated_findings: List[Dict] = []
        self._event_bus = event_bus
        self._subscribed = False

        # Enrichment tracking
        self._enrichment_failures = 0
        self._enrichment_total = 0
        self._reporting_failover_count = 0  # recovered via scoped provider failover
        self._nuclei_state_lock = asyncio.Lock()
