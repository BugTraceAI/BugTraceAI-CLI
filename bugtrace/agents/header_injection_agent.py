"""
HeaderInjectionAgent - HTTP Response Header Injection / CRLF Specialist

CREATED: 2026-01-30
PURPOSE: Detect HTTP Response Header Injection (CRLF injection) vulnerabilities.

Burp Scanner finds these as "HTTP Response Header Injection" which allows:
- Response splitting attacks
- Cache poisoning
- XSS via injected headers
- Session fixation
"""

import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.agents.base import BaseAgent
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.event_bus import EventType

logger = get_logger("agents.header_injection")


class HeaderInjectionAgent(BaseAgent):
    """
    HTTP Response Header Injection (CRLF) Specialist Agent.

    Tests for:
    1. CRLF injection in URL parameters
    2. CRLF injection in cookies
    3. CRLF injection in custom headers
    4. Response splitting for cache poisoning
    """

    # CRLF payloads - various encodings to bypass filters
    CRLF_PAYLOADS = [
        # Standard CRLF
        "%0d%0aX-Injected: header",
        "%0d%0aSet-Cookie: injected=true",
        # Double encoding
        "%250d%250aX-Injected: header",
        # Unicode variants
        "%E5%98%8A%E5%98%8DX-Injected: header",
        # Mixed encoding
        "%0d%0a%0d%0a<html>injected</html>",
        # Null byte bypass
        "%00%0d%0aX-Injected: header",
        # Line feed only (some servers)
        "%0aX-Injected: header",
        # Carriage return only
        "%0dX-Injected: header",
        # URL encoded newline
        "\r\nX-Injected: header",
        # Tab + newline
        "%09%0d%0aX-Injected: header",
    ]

    # Headers to check for injection evidence
    INJECTION_MARKERS = [
        "X-Injected",
        "Set-Cookie: injected",
        "<html>injected",
    ]

    def __init__(
        self,
        url: str,
        params: List[str] = None,
        report_dir: Path = None,
        event_bus: Any = None,
        cookies: List[Dict] = None,
        headers: Dict[str, str] = None,
    ):
        super().__init__("HeaderInjectionAgent", "CRLF Injection Specialist", event_bus=event_bus, agent_id="header_injection_agent")
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("reports")
        self.cookies = cookies or []
        self.headers = headers or {}
        self.findings: List[Dict] = []

        # Statistics
        self._stats = {
            "params_tested": 0,
            "vulns_found": 0,
            "payloads_tested": 0,
        }

        # Queue consumption mode
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

    async def run_loop(self):
        """Standard run loop."""
        return await self.run()

    async def run(self) -> Dict:
        """
        Test for Header Injection vulnerabilities.

        Flow:
        1. Discover parameters from URL
        2. Test each parameter with CRLF payloads
        3. Check response headers for injection evidence
        4. Report confirmed findings
        """
        dashboard.current_agent = self.name
        logger.info(f"[{self.name}] 🔍 Starting Header Injection scan on {self.url}")
        dashboard.log(f"[{self.name}] 🔍 Starting Header Injection scan on {self.url}", "INFO")

        try:
            # Get parameters to test
            params_to_test = self._get_parameters_to_test()

            if not params_to_test:
                dashboard.log(f"[{self.name}] No parameters found to test", "WARN")
                return {"findings": [], "status": JobStatus.COMPLETED, "stats": self._stats}

            # Test each parameter
            async with aiohttp.ClientSession() as session:
                for param in params_to_test:
                    await self._test_parameter(session, param)

            self._log_completion_stats()

            return {"findings": self.findings, "status": JobStatus.COMPLETED, "stats": self._stats}

        except Exception as e:
            logger.error(f"HeaderInjectionAgent failed: {e}", exc_info=True)
            return {"error": str(e), "findings": [], "status": JobStatus.FAILED}

    def _get_parameters_to_test(self) -> List[str]:
        """Get list of parameters to test."""
        params_to_test = list(self.params) if self.params else []

        # Extract from URL query string
        if not params_to_test:
            parsed = urlparse(self.url)
            query_params = parse_qs(parsed.query)
            params_to_test = list(query_params.keys())

        # Also test cookie names
        if self.cookies:
            for cookie in self.cookies:
                cookie_name = cookie.get('name', '')
                if cookie_name and cookie_name not in params_to_test:
                    params_to_test.append(cookie_name)

        params_to_test = list(set(params_to_test))

        if not params_to_test:
            # Add common parameters that might be vulnerable
            params_to_test = ["url", "redirect", "next", "return", "callback", "ref", "page"]

        logger.info(f"[{self.name}] Parameters to test: {params_to_test}")
        return params_to_test

    async def _test_parameter(self, session: aiohttp.ClientSession, param: str):
        """Test a single parameter for CRLF injection."""
        self._stats["params_tested"] += 1
        dashboard.log(f"[{self.name}] Testing parameter: {param}", "INFO")

        for payload in self.CRLF_PAYLOADS:
            self._stats["payloads_tested"] += 1

            test_url = self._build_test_url(param, payload)
            finding = await self._check_injection(session, test_url, param, payload)

            if finding:
                self.findings.append(finding)
                self._stats["vulns_found"] += 1
                dashboard.add_finding("Header Injection", f"{self.url} [{param}]", "HIGH")

                # Found vulnerability, no need to test more payloads for this param
                break

    def _build_test_url(self, param: str, payload: str) -> str:
        """Build URL with CRLF payload in specified parameter."""
        parsed = urlparse(self.url)
        query_params = parse_qs(parsed.query)

        # Set or replace parameter with payload
        query_params[param] = [payload]

        new_query = urlencode(query_params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

    async def _check_injection(
        self,
        session: aiohttp.ClientSession,
        test_url: str,
        param: str,
        payload: str
    ) -> Optional[Dict]:
        """Check if CRLF injection was successful by examining response."""
        try:
            req_headers = {"User-Agent": getattr(settings, 'USER_AGENT', 'BugTraceAI/2.4')}
            req_headers.update(self.headers)

            if self.cookies:
                cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in self.cookies])
                req_headers["Cookie"] = cookie_str

            async with session.get(
                test_url,
                headers=req_headers,
                allow_redirects=False,  # Important: Don't follow redirects
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                # Check response headers for injection evidence
                resp_headers = dict(response.headers)
                body = await response.text()

                for marker in self.INJECTION_MARKERS:
                    # Check in response headers
                    for header_name, header_value in resp_headers.items():
                        if marker.lower() in header_name.lower() or marker.lower() in header_value.lower():
                            return self._create_finding(param, payload, marker, "header", header_name, header_value)

                    # Check in body (response splitting)
                    if marker.lower() in body.lower():
                        # Could be response splitting - check if HTML was injected
                        if "<html>injected" in body.lower():
                            return self._create_finding(param, payload, marker, "body", None, body[:500])

        except asyncio.TimeoutError:
            logger.debug(f"Timeout testing {param} with payload")
        except Exception as e:
            logger.debug(f"Error testing {param}: {e}")

        return None

    def _create_finding(
        self,
        param: str,
        payload: str,
        marker: str,
        location: str,
        header_name: Optional[str],
        evidence: str
    ) -> Dict:
        """Create a finding dictionary."""
        logger.info(f"[{self.name}] ✅ Header Injection confirmed in {param}!")
        dashboard.log(f"[{self.name}] ✅ Header Injection CONFIRMED in {param}!", "SUCCESS")

        return {
            "type": "Header Injection",
            "vulnerability_type": "HTTP_RESPONSE_HEADER_INJECTION",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "evidence": f"Injection marker '{marker}' found in {location}: {evidence[:200]}",
            "validated": True,
            "validation_method": "Response Header Analysis",
            "severity": "HIGH",
            "status": ValidationStatus.VALIDATED_CONFIRMED.value,
            "cwe": "CWE-113",
            "remediation": "Sanitize user input before including in HTTP headers. Remove or encode CR (\\r) and LF (\\n) characters.",
            "reproduction": f"curl -v '{self._build_test_url(param, payload)}'",
            "impact": "Response splitting, cache poisoning, XSS via headers, session fixation",
            "header_name": header_name,
        }

    def _log_completion_stats(self):
        """Log completion statistics."""
        stats_msg = (
            f"[{self.name}] Complete: {self._stats['params_tested']} params, "
            f"{self._stats['payloads_tested']} payloads, "
            f"{self._stats['vulns_found']} vulns found"
        )
        logger.info(stats_msg)
        dashboard.log(stats_msg, "SUCCESS" if self.findings else "INFO")

    def get_stats(self) -> Dict:
        """Get agent statistics."""
        return self._stats

    # =========================================================================
    # QUEUE CONSUMPTION MODE (Phase 29)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        Start HeaderInjectionAgent in queue consumer mode.

        Spawns a worker pool that consumes from the header_injection queue.
        """
        self._queue_mode = True
        self._scan_context = scan_context

        config = WorkerConfig(
            specialist="header_injection",
            pool_size=getattr(settings, 'WORKER_POOL_DEFAULT_SIZE', 5),
            process_func=self._process_queue_item,
            on_result=self._handle_queue_result,
            shutdown_timeout=getattr(settings, 'WORKER_POOL_SHUTDOWN_TIMEOUT', 30)
        )

        self._worker_pool = WorkerPool(config)

        if self.event_bus:
            self.event_bus.subscribe(
                EventType.WORK_QUEUED_HEADER_INJECTION.value,
                self._on_work_queued
            )

        logger.info(f"[{self.name}] Starting queue consumer with {config.pool_size} workers")
        await self._worker_pool.start()

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_HEADER_INJECTION.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_header_injection notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """
        Process a single item from the header_injection queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "Header Injection",
                "url": "...",
                "parameter": "...",
            },
            "priority": 85.5,
            "scan_context": "scan_123",
        }
        """
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        # Configure self for this specific test
        self.url = url

        # Test parameter for CRLF injection
        return await self._test_parameter_from_queue(param)

    async def _test_parameter_from_queue(self, param: str) -> Optional[Dict]:
        """Test a single parameter from queue for CRLF injection."""
        try:
            async with aiohttp.ClientSession() as session:
                for payload in self.CRLF_PAYLOADS:
                    test_url = self._build_test_url(param, payload)
                    finding = await self._check_injection(session, test_url, param, payload)

                    if finding:
                        return finding

                return None

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        """
        if result is None:
            return

        # Emit vulnerability_detected event
        if self.event_bus and getattr(settings, 'WORKER_POOL_EMIT_EVENTS', True):
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "header_injection",
                "finding": {
                    "type": "Header Injection",
                    "url": result["url"],
                    "parameter": result["parameter"],
                    "payload": result["payload"],
                    "severity": result["severity"],
                },
                "status": result["status"],
                "validation_requires_cdp": False,  # CRLF doesn't need CDP
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed Header Injection: {result['url']}?{result['parameter']}")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }
