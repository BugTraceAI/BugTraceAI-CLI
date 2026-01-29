import asyncio
import aiohttp
import re
import json
import time
from typing import Dict, List, Optional, Any
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
from bugtrace.agents.prototype_pollution_payloads import (
    POLLUTION_MARKER, VULNERABLE_PARAMS, get_query_param_payloads,
    BASIC_POLLUTION_PAYLOADS, ENCODING_BYPASSES, GADGET_CHAIN_PAYLOADS,
    RCE_GADGETS, PAYLOAD_TIERS, TIER_SEVERITY, get_payloads_for_tier
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

        Tests each vector with tiered payloads (stop on first success per tier):
        - Tier 1: Basic pollution detection (LOW severity)
        - Tier 2: Encoding bypasses (MEDIUM severity)
        - Tier 3: Gadget chain discovery (HIGH severity)
        - Tier 4: RCE exploitation (CRITICAL severity)

        Returns:
            List of confirmed findings with exploitation details
        """
        dashboard.log(f"[{self.name}] Auditor: Validating {len(vectors)} vectors", "INFO")
        findings = []

        for vector in vectors:
            # Skip already tested vectors (deduplication)
            key = f"{vector.get('type')}:{vector.get('param', '')}:{vector.get('method', '')}"
            if key in self._tested_vectors:
                continue
            self._tested_vectors.add(key)

            # Test based on vector type
            if vector["type"] == "JSON_BODY":
                result = await self._test_json_body_vector(vector)
            elif vector["type"] in ("QUERY_PARAM", "QUERY_PROTO"):
                result = await self._test_query_param_vector(vector)
            else:
                # JS_PATTERN and ERROR_PATTERN are informational
                continue

            if result and result.get("exploitable"):
                findings.append(result)
                severity = result.get("severity", "LOW")
                dashboard.log(
                    f"[{self.name}] CONFIRMED: {result.get('technique', 'unknown')} - {severity}",
                    "CRITICAL" if severity in ("CRITICAL", "HIGH") else "WARNING"
                )

                # Stop escalating this vector if RCE confirmed
                if result.get("rce_confirmed"):
                    dashboard.log(f"[{self.name}] RCE CONFIRMED - stopping escalation", "CRITICAL")

        return findings

    async def _test_json_body_vector(self, vector: Dict) -> Optional[Dict]:
        """
        Test JSON body vector with tiered payloads.

        Follows stop-on-first-success pattern within each tier,
        but continues to higher tiers for severity escalation.
        """
        best_result = None

        # Test each tier in order
        for tier in ["pollution_detection", "encoding_bypass", "gadget_chain", "rce_exploitation"]:
            payloads = get_payloads_for_tier(tier)

            for payload_info in payloads:
                if payload_info.get("method") not in ("JSON_BODY", None):
                    continue

                result = await self._test_json_payload(payload_info, tier)

                if result and result.get("exploitable"):
                    # Keep highest severity result
                    if not best_result or self._severity_rank(result.get("severity")) > self._severity_rank(best_result.get("severity")):
                        best_result = result

                    # Stop this tier on first success
                    dashboard.log(f"[{self.name}] Tier {tier}: Success with {result.get('technique')}", "INFO")
                    break

            # If we found RCE, no need to continue
            if best_result and best_result.get("rce_confirmed"):
                break

        return best_result

    def _severity_rank(self, severity: str) -> int:
        """Convert severity to numeric rank for comparison."""
        ranks = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return ranks.get(severity, 0)

    async def _test_json_payload(self, payload_info: Dict, tier: str) -> Optional[Dict]:
        """Test a single JSON payload and check for pollution confirmation."""
        payload_obj = payload_info.get("payload", {})
        technique = payload_info.get("technique", "unknown")

        try:
            # Measure response time for timing attack detection
            start_time = time.time()

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.url,
                    json=payload_obj,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=15)  # Longer for RCE timing
                ) as response:
                    elapsed = time.time() - start_time
                    resp_text = await response.text()

                    # Check for pollution confirmation
                    pollution_confirmed = await self._verify_pollution(resp_text, POLLUTION_MARKER)

                    # Check for RCE timing attack success (sleep 5)
                    rce_timing = elapsed >= 4.5 and "rce_timing" in technique

                    # Check for RCE command output
                    rce_output = self._check_rce_output(resp_text)

                    if pollution_confirmed or rce_timing or rce_output:
                        severity = TIER_SEVERITY.get(tier, "LOW")
                        if rce_timing or rce_output:
                            severity = "CRITICAL"

                        return {
                            "exploitable": True,
                            "type": "PROTOTYPE_POLLUTION",
                            "method": "JSON_BODY",
                            "payload": json.dumps(payload_obj),
                            "payload_obj": payload_obj,
                            "technique": technique,
                            "tier": tier,
                            "severity": severity,
                            "pollution_confirmed": pollution_confirmed,
                            "rce_confirmed": rce_timing or rce_output,
                            "rce_evidence": {
                                "timing_delay": elapsed if rce_timing else None,
                                "command_output": rce_output,
                            } if (rce_timing or rce_output) else None,
                            "test_url": self.url,
                            "status_code": response.status,
                            "http_request": f"POST {self.url}\nContent-Type: application/json\n\n{json.dumps(payload_obj, indent=2)}",
                            "http_response": f"HTTP/1.1 {response.status}\n\n{resp_text[:500]}...",
                        }

        except aiohttp.ClientError as e:
            logger.debug(f"[{self.name}] JSON payload test failed: {e}")
        except asyncio.TimeoutError:
            # Timeout could indicate successful timing attack
            logger.debug(f"[{self.name}] Request timeout (potential timing attack)")
        except json.JSONDecodeError as e:
            logger.debug(f"[{self.name}] JSON decode error: {e}")

        return None

    async def _verify_pollution(self, response_text: str, marker: str) -> bool:
        """
        Verify pollution by checking if marker appears in response.

        Pollution is confirmed when:
        1. Marker appears in JSON response (inherited property)
        2. Response structure changes indicating pollution
        """
        # Direct marker check
        if marker in response_text:
            return True

        # Check for JSON response with polluted property
        try:
            resp_json = json.loads(response_text)
            if self._search_json_for_marker(resp_json, marker):
                return True
        except json.JSONDecodeError:
            pass

        return False

    def _search_json_for_marker(self, obj: Any, marker: str) -> bool:
        """Recursively search JSON object for pollution marker."""
        if isinstance(obj, str) and marker in obj:
            return True
        if isinstance(obj, dict):
            for key, value in obj.items():
                if marker in str(key) or self._search_json_for_marker(value, marker):
                    return True
        if isinstance(obj, list):
            for item in obj:
                if self._search_json_for_marker(item, marker):
                    return True
        return False

    def _check_rce_output(self, response_text: str) -> Optional[str]:
        """
        Check response for RCE command output indicators.

        Looks for:
        - whoami output (username patterns)
        - id output (uid/gid patterns)
        - cat /etc/passwd output (root:x:0 pattern)
        - hostname output
        """
        resp_lower = response_text.lower()

        # Check for common command outputs
        rce_indicators = [
            # whoami patterns
            (r'\b(root|admin|www-data|node|ubuntu|ec2-user|nobody)\b', "whoami_output"),
            # id command patterns
            (r'uid=\d+.*gid=\d+', "id_output"),
            # /etc/passwd patterns
            (r'root:x:0:0', "passwd_read"),
            # hostname output
            (r'hostname\s*[:=]\s*\S+', "hostname_output"),
        ]

        for pattern, indicator_type in rce_indicators:
            if re.search(pattern, response_text, re.IGNORECASE):
                # Extract the matched evidence
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return f"{indicator_type}: {match.group(0)}"

        return None

    async def _test_query_param_vector(self, vector: Dict) -> Optional[Dict]:
        """Test query parameter vector with pollution payloads."""
        param = vector.get("param", "__proto__")
        query_payloads = get_query_param_payloads(POLLUTION_MARKER)

        for query in query_payloads:
            test_url = f"{self.url}{'&' if '?' in self.url else '?'}{query}"

            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as response:
                        resp_text = await response.text()

                        if await self._verify_pollution(resp_text, POLLUTION_MARKER):
                            return {
                                "exploitable": True,
                                "type": "PROTOTYPE_POLLUTION",
                                "method": "QUERY_PARAM",
                                "param": param,
                                "payload": query,
                                "technique": "query_pollution",
                                "tier": "pollution_detection",
                                "severity": "MEDIUM",  # Query param pollution is lower risk
                                "pollution_confirmed": True,
                                "rce_confirmed": False,
                                "test_url": test_url,
                                "status_code": response.status,
                                "http_request": f"GET {test_url}",
                                "http_response": f"HTTP/1.1 {response.status}\n\n{resp_text[:500]}...",
                            }

            except aiohttp.ClientError as e:
                logger.debug(f"[{self.name}] Query param test failed: {e}")
            except asyncio.TimeoutError:
                logger.debug(f"[{self.name}] Query param test timeout")

        return None

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
