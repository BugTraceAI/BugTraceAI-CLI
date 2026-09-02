"""
OpenRedirectAgent — thin orchestrator.

Pure detection logic lives in ``detection.py``.
This module wires I/O (HTTP requests, Playwright, LLM) together.
"""
import asyncio
import re
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.utils.logger import get_logger
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.agents.openredirect_payloads import (
    REDIRECT_PARAMS, PATH_PATTERNS, JS_REDIRECT_PATTERNS,
    META_REFRESH_PATTERN, REDIRECT_STATUS_CODES,
    RANKED_PAYLOADS, get_payloads_for_tier, DEFAULT_ATTACKER_DOMAIN,
)
from bugtrace.agents.mixins.tech_context import TechContextMixin

from bugtrace.agents.openredirect.detection import (
    discover_param_vectors,
    discover_path_vectors,
    analyze_javascript_redirects,
    analyze_meta_refresh,
    is_external_redirect,
    get_technique_name,
    analyze_http_redirect,
    generate_openredirect_fingerprint,
    fallback_fingerprint_dedup,
    get_validation_status,
    validate_before_emit,
)

logger = get_logger("agents.openredirect")

from bugtrace.agents.openredirect.testing_flow import OpenRedirectTestingMixin
from bugtrace.agents.openredirect.queue_flow import OpenRedirectQueueMixin

class OpenRedirectAgent(OpenRedirectTestingMixin, OpenRedirectQueueMixin, BaseAgent, TechContextMixin):
    """
    Specialist Agent for Open Redirect vulnerabilities (CWE-601).

    Hunter/Auditor two-phase architecture plus WET->DRY queue consumer.
    """

    def __init__(
        self,
        url: str = "",
        params: List[str] = None,
        report_dir: Path = None,
        event_bus=None,
    ):
        super().__init__(
            name="OpenRedirectAgent",
            role="Open Redirect Specialist",
            event_bus=event_bus,
            agent_id="openredirect_specialist",
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_params: set = set()

        self._queue_mode = False
        self._emitted_findings: set = set()
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        self._dry_findings: List[Dict] = []

        self._tech_stack_context: Dict = {}
        self._openredirect_prime_directive: str = ""

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        return validate_before_emit(finding, super()._validate_before_emit)

    def _emit_openredirect_finding(
        self, finding_dict: Dict, scan_context: str = None,
    ) -> Optional[Dict]:
        if "type" not in finding_dict:
            finding_dict["type"] = "OPEN_REDIRECT"
        if scan_context:
            finding_dict["scan_context"] = scan_context
        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # ------------------------------------------------------------------
    # Compatibility wrappers (tests + hunter patches call these methods)
    # Pure logic lives in detection.py
    # ------------------------------------------------------------------

    def _discover_param_vectors(self) -> List[Dict]:
        return discover_param_vectors(self.url, self.params)

    def _discover_path_vectors(self) -> List[Dict]:
        return discover_path_vectors(self.url)

    def _analyze_javascript_redirects(self, html_content: str) -> List[Dict]:
        return analyze_javascript_redirects(html_content)

    def _analyze_meta_refresh(self, html_content: str) -> List[Dict]:
        return analyze_meta_refresh(html_content)

    def _is_external_redirect(self, location: str, payload: str) -> bool:
        return is_external_redirect(location, payload, self.url)

    def _get_technique_name(self, payload: str) -> str:
        return get_technique_name(payload)

    def _analyze_http_redirect(
        self, location: str, status_code: int, payload: str
    ) -> Tuple[bool, str]:
        return analyze_http_redirect(location, status_code, payload, self.url)

    def _generate_openredirect_fingerprint(self, finding: Dict) -> str:
        return generate_openredirect_fingerprint(finding)

    def _fallback_fingerprint_dedup(self, findings: List[Dict]) -> List[Dict]:
        return fallback_fingerprint_dedup(findings)

    def _get_validation_status(self, finding: Dict) -> str:
        return get_validation_status(finding)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run_loop(self) -> Dict:
        """Main execution loop for Open Redirect testing."""  # I/O
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting Open Redirect analysis on {self.url}", "INFO")

        vectors = await self._hunter_phase()
        if not vectors:
            dashboard.log(f"[{self.name}] No redirect vectors found", "INFO")
            return {
                "status": JobStatus.COMPLETED,
                "vulnerable": False,
                "findings": [],
                "findings_count": 0,
            }

        findings = await self._auditor_phase(vectors)

        for finding in findings:
            await self._create_finding(finding)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "findings_count": len(findings),
        }

    # ------------------------------------------------------------------
    # Hunter phase
    # ------------------------------------------------------------------

    async def _hunter_phase(self) -> List[Dict]:
        """Discover all potential redirect vectors."""  # I/O
        dashboard.log(f"[{self.name}] Hunter: Scanning for redirect vectors", "INFO")
        vectors: List[Dict] = []

        vectors.extend(self._discover_param_vectors())
        vectors.extend(self._discover_path_vectors())

        try:
            content_vectors = await self._discover_content_vectors()
            vectors.extend(content_vectors)
        except Exception as e:
            logger.warning(f"[{self.name}] Content analysis failed: {e}")

        dashboard.log(f"[{self.name}] Hunter found {len(vectors)} potential vectors", "INFO")
        return vectors

    async def _discover_content_vectors(self) -> List[Dict]:
        """Fetch page and analyse for JS/meta redirect vectors."""  # I/O
        vectors: List[Dict] = []
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(
                    self.url, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if response.status in REDIRECT_STATUS_CODES:
                        location = response.headers.get("Location", "")
                        if location:
                            vectors.append({
                                "type": "HTTP_REDIRECT",
                                "param": None,
                                "location": location,
                                "status_code": response.status,
                                "source": "HTTP_RESPONSE",
                                "confidence": "HIGH",
                            })

                    content = await response.text()
                    vectors.extend(analyze_javascript_redirects(content))
                    vectors.extend(analyze_meta_refresh(content))
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.warning(f"[{self.name}] HTTP request failed: {e}")

        return vectors

    # ------------------------------------------------------------------
    # Auditor phase
    # ------------------------------------------------------------------

    async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
        """Validate redirect vectors with exploitation payloads."""  # I/O
        dashboard.log(f"[{self.name}] Auditor: Validating {len(vectors)} vectors", "INFO")
        findings: List[Dict] = []

        for vector in vectors:
            key = f"{self.url}#{vector.get('param', vector.get('path', 'content'))}"
            if key in self._tested_params:
                continue
            self._tested_params.add(key)

            if vector["type"] == "QUERY_PARAM":
                result = await self._test_param_vector(vector)
            elif vector["type"] == "PATH":
                result = await self._test_path_vector(vector)
            elif vector["type"] in ("JAVASCRIPT", "META_REFRESH"):
                result = await self._test_content_vector(vector)
            elif vector["type"] == "HTTP_REDIRECT":
                result = analyze_http_redirect(vector, self.url)
            else:
                continue

            if result and result.get("exploitable"):
                findings.append(result)
                dashboard.log(
                    f"[{self.name}] CONFIRMED: {vector['type']} redirect via "
                    f"{result.get('technique', 'unknown')}",
                    "CRITICAL",
                )

        return findings

    async def _create_finding(self, result: Dict):
        """Report a confirmed finding."""  # I/O
        finding = {
            "type": "OPEN_REDIRECT",
            "severity": result.get("severity", "MEDIUM"),
            "url": self.url,
            "parameter": result.get("param"),
            "payload": result.get("payload"),
            "description": f"Open Redirect via {result.get('method', 'unknown')} in '{result.get('param')}'",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": f"curl -I '{result.get('test_url')}'",
            "cwe_id": get_cwe_for_vuln("OPEN_REDIRECT"),
            "remediation": get_remediation_for_vuln("OPEN_REDIRECT"),
            "cve_id": "N/A",
            "http_request": result.get("http_request", f"GET {result.get('test_url')}"),
            "http_response": result.get("http_response", f"Location: {result.get('location')}"),
        }
        logger.info(f"[{self.name}] OPEN REDIRECT CONFIRMED: {result.get('payload')} on {result.get('param')}")

    # ------------------------------------------------------------------
    # Queue lifecycle
    # ------------------------------------------------------------------
