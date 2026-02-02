import asyncio
import aiohttp
import re
import json
import time
from typing import Dict, List, Optional, Any
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

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # Agent-specific fingerprint
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

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
    # Queue Consumer Mode (Phase 20)
    # ========================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """Start PrototypePollutionAgent in queue consumer mode."""
        self._queue_mode = True
        self._scan_context = scan_context

        config = WorkerConfig(
            specialist="prototype_pollution",
            pool_size=settings.WORKER_POOL_DEFAULT_SIZE,
            process_func=self._process_queue_item,
            on_result=self._handle_queue_result,
            shutdown_timeout=settings.WORKER_POOL_SHUTDOWN_TIMEOUT
        )

        self._worker_pool = WorkerPool(config)

        if self.event_bus:
            self.event_bus.subscribe(
                EventType.WORK_QUEUED_PROTOTYPE_POLLUTION.value,
                self._on_work_queued
            )

        logger.info(f"[{self.name}] Starting queue consumer with {config.pool_size} workers")
        await self._worker_pool.start()

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

    async def _test_single_item_from_queue(self, url: str, param: str, finding: dict) -> Optional[Dict]:
        """Test a single item from queue for Prototype Pollution."""
        try:
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

        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "prototype_pollution",
                "finding": {
                    "type": "Prototype Pollution",
                    "url": result.get("url", result.get("test_url")),
                    "parameter": result.get("param") or result.get("parameter"),
                    "payload": result.get("payload"),
                    "rce_escalation": result.get("rce_confirmed", False),
                },
                "status": status,
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed Prototype Pollution: {result.get('url', result.get('test_url'))} (RCE: {result.get('rce_confirmed', False)}) [status={status}]")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_prototype_pollution notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

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
