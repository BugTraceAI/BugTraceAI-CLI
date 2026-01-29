import asyncio
import aiohttp
import re
import json
from typing import Dict, List, Optional
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.ui import dashboard
from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = get_logger("agents.prototype_pollution")


class PrototypePollutionAgent(BaseAgent):
    """
    Specialist Agent for Prototype Pollution vulnerabilities (CWE-1321).
    Target: Node.js APIs and frontend JavaScript with vulnerable merge/extend operations.

    Exploitation approach:
    - Hunter phase: Discover pollution vectors (query params, JSON body, frontend patterns)
    - Auditor phase: Validate pollution and escalate to RCE with tiered payloads
    """

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None):
        super().__init__(
            name="PrototypePollutionAgent",
            role="Prototype Pollution Specialist",
            agent_id="prototype_pollution_specialist"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_vectors = set()  # Deduplication

    async def run_loop(self) -> Dict:
        """Main execution loop for Prototype Pollution testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] Starting Prototype Pollution analysis on {self.url}", "INFO")

        # Phase 1: Hunter - Discover pollution vectors
        vectors = await self._hunter_phase()

        if not vectors:
            dashboard.log(f"[{self.name}] No pollution vectors found", "INFO")
            return {
                "status": JobStatus.COMPLETED,
                "vulnerable": False,
                "findings": [],
                "findings_count": 0
            }

        # Phase 2: Auditor - Validate pollution and escalate to RCE
        findings = await self._auditor_phase(vectors)

        # Report findings
        for finding in findings:
            await self._create_finding(finding)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "findings_count": len(findings)
        }

    async def _hunter_phase(self) -> List[Dict]:
        """
        Hunter Phase: Discover all potential prototype pollution vectors.

        Scans for:
        - Query parameters matching known config/object merge patterns
        - JSON body endpoints that accept POST/PUT requests
        - URL paths that suggest object/config modification
        - JavaScript merge/extend patterns in response

        Returns:
            List of vectors with type, parameter/method, and source
        """
        dashboard.log(f"[{self.name}] Hunter: Scanning for pollution vectors", "INFO")
        vectors = []

        # TODO (Plan 02): Implement parameter discovery
        # - Check existing query parameters for config-related names
        # - Test if endpoint accepts JSON body (POST/PUT)
        # - Analyze URL paths for object modification patterns

        dashboard.log(f"[{self.name}] Hunter found {len(vectors)} potential vectors", "INFO")
        return vectors

    async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
        """
        Auditor Phase: Validate pollution vectors and escalate to RCE.

        Tests each vector with tiered payloads (stop on first success):
        - Tier 1: Basic pollution detection (__proto__, constructor.prototype)
        - Tier 2: Encoding bypasses (obfuscation, URL encoding, Unicode)
        - Tier 3: Gadget chain discovery (Express, environment vars)
        - Tier 4: RCE exploitation (timing attacks, command execution)

        Returns:
            List of confirmed findings with exploitation details
        """
        dashboard.log(f"[{self.name}] Auditor: Validating {len(vectors)} vectors", "INFO")
        findings = []

        # TODO (Plan 03): Implement tiered payload testing
        # - Basic pollution confirmation
        # - Encoding bypass attempts
        # - Gadget chain discovery
        # - RCE escalation validation

        return findings

    async def _create_finding(self, result: Dict):
        """Reports a confirmed finding."""
        # Determine severity based on exploitation level
        severity = result.get("severity", "MEDIUM")
        if result.get("rce_confirmed"):
            severity = "CRITICAL"
        elif result.get("gadget_found"):
            severity = "HIGH"

        finding = {
            "type": "PROTOTYPE_POLLUTION",
            "severity": severity,
            "url": self.url,
            "parameter": result.get("param"),
            "payload": result.get("payload"),
            "description": f"Prototype Pollution via {result.get('method', 'unknown')} - {result.get('tier', 'basic')} exploitation",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": self._build_reproduction(result),
            "cwe_id": get_cwe_for_vuln("PROTOTYPE_POLLUTION"),
            "remediation": get_remediation_for_vuln("PROTOTYPE_POLLUTION"),
            "cve_id": "N/A",
            "http_request": result.get("http_request", ""),
            "http_response": result.get("http_response", ""),
            "exploitation_tier": result.get("tier", "pollution_detection"),
            "rce_evidence": result.get("rce_evidence"),
        }
        logger.info(f"[{self.name}] PROTOTYPE POLLUTION CONFIRMED: {result.get('tier')} on {self.url}")

    def _build_reproduction(self, result: Dict) -> str:
        """Build curl command for reproducing the vulnerability."""
        method = result.get("method", "GET")
        if method == "JSON_BODY":
            payload_json = json.dumps(result.get("payload_obj", {}))
            return f"curl -X POST -H 'Content-Type: application/json' -d '{payload_json}' '{self.url}'"
        elif method == "QUERY_PARAM":
            return f"curl '{result.get('test_url', self.url)}'"
        return f"curl '{self.url}'"
