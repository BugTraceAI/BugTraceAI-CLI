"""
IDOR Agent - Thin Orchestrator

Orchestrates IDOR (Insecure Direct Object Reference) detection and exploitation.
Delegates pure logic to idor.patterns/payloads/validation/dedup modules
and I/O operations to idor.discovery/exploitation modules.
"""

import asyncio
import json
import time
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.tools.external import external_tools
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# Extracted modules
from bugtrace.agents.idor.patterns import (
    detect_id_format,
    infer_app_context,
    generate_horizontal_test_ids,
    is_special_account,
    detect_privilege_indicators,
)
from bugtrace.agents.idor.payloads import inject_id, extract_path_id
from bugtrace.agents.idor.validation import (
    validate_idor_finding,
    determine_validation_status,
    analyze_differential,
    analyze_response_diff,
    phase3_impact_analysis,
)
from bugtrace.agents.idor.discovery import discover_idor_params
from bugtrace.agents.idor.exploitation import (
    test_custom_ids_python,
    phase1_retest,
    phase2_http_methods,
    phase4_horizontal_escalation,
    phase5_vertical_escalation,
    wait_for_auth_token,
    fetch_auth_headers,
)
from bugtrace.agents.idor.dedup import (
    generate_idor_fingerprint,
    fallback_fingerprint_dedup,
)

logger = get_logger("agents.idor")

from bugtrace.agents.idor.queue_flow import IDORQueueMixin
from bugtrace.agents.idor.exploit_flow import IDORExploitMixin

class IDORAgent(IDORExploitMixin, IDORQueueMixin, BaseAgent, TechContextMixin):
    """
    Specialist Agent for Insecure Direct Object Reference (IDOR).

    Thin orchestrator: delegates pure logic to idor.patterns/payloads/validation/dedup
    and I/O to idor.discovery/exploitation.
    """

    def __init__(self, url: str, params: List[Dict] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="IDORAgent",
            role="IDOR Specialist",
            event_bus=event_bus,
            agent_id="idor_agent",
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        self._tested_params = set()
        self._queue_mode = False
        self._emitted_findings: set = set()
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""
        self._dry_findings: List[Dict] = []

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}
        self._idor_prime_directive: str = ""

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """IDOR-specific validation before emitting finding."""
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error
        return validate_idor_finding(finding)

    def _emit_idor_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit IDOR finding using BaseAgent.emit_finding() with validation."""
        if "type" not in finding_dict:
            finding_dict["type"] = "IDOR"
        if scan_context:
            finding_dict["scan_context"] = scan_context
        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    def _determine_validation_status(self, evidence_type: str, confidence: str) -> str:
        """Determine IDOR validation status."""  # PURE
        return determine_validation_status(evidence_type, confidence)

    def _detect_id_format(self, original_value: str) -> tuple:
        """Detect ID format and generate test IDs."""  # PURE
        return detect_id_format(original_value)

    def _infer_app_context(self, domain: str, path: str) -> str:
        """Infer application type from domain/path."""  # PURE
        return infer_app_context(domain, path)

    def _generate_horizontal_test_ids(self, base_id, id_format, max_count):
        """Generate test IDs for enumeration."""  # PURE
        return generate_horizontal_test_ids(base_id, id_format, max_count)

    def _is_special_account(self, response_body: str) -> bool:
        """Check if response indicates special/privileged account."""  # PURE
        return is_special_account(response_body)

    def _detect_privilege_indicators(self, response_body: str) -> list:
        """Detect privilege indicators in response."""  # PURE
        return detect_privilege_indicators(response_body)

    def _inject(self, val, param_name, original_val):
        """Inject a test ID value into the URL."""  # PURE
        return inject_id(self.url, val, param_name, original_val)

    def _analyze_differential(self, baseline_status, baseline_body, baseline_length,
                              test_status, test_body, test_length, test_id):
        """Simplified semantic analysis."""  # PURE
        return analyze_differential(
            baseline_status, baseline_body, baseline_length,
            test_status, test_body, test_length, test_id,
        )

    def _analyze_response_diff(self, baseline, exploit):
        """Analyze response differences."""  # PURE
        return analyze_response_diff(baseline, exploit)

    def _generate_idor_fingerprint(
        self, url: str, resource_type: str, original_value: str = ""
    ) -> tuple:
        """Generate IDOR finding fingerprint."""  # PURE
        return generate_idor_fingerprint(url, resource_type, original_value)

    def _fallback_fingerprint_dedup(self, wet_findings):
        """Fallback fingerprint-based deduplication."""  # PURE
        return fallback_fingerprint_dedup(wet_findings)
