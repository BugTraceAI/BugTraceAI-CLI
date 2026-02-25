"""
API Security Agent — Thin Orchestrator.

Inherits from BaseAgent and delegates all logic to pure (core.py) and
I/O (testing.py) modules. This class owns only:
- Agent lifecycle (init, run_loop, event subscriptions, queue consumer)
- State wiring (scan_context, endpoints, findings)
- Report generation and vulnerability correlation
"""

import asyncio
import json
import time
from typing import List, Dict, Set, Optional, Any
from pathlib import Path
from urllib.parse import urlparse
from loguru import logger
from datetime import datetime

import aiofiles

from bugtrace.agents.base import BaseAgent
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.event_bus import EventType
from bugtrace.core.queue import queue_manager
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.validation_status import ValidationStatus

from bugtrace.agents.api_security.core import is_api_url
from bugtrace.agents.api_security.testing import (
    test_graphql_endpoint,
    test_rest_endpoint,
    test_websocket,
    discover_graphql_endpoint,
)


class APISecurityAgent(BaseAgent):
    """
    Specialized agent for modern API security testing.

    Attack Surface:
    1. GraphQL (introspection, injection, DoS)
    2. REST APIs (parameter fuzzing, IDOR, auth bypass)
    3. WebSocket (injection, auth bypass)
    4. API Documentation (Swagger/OpenAPI exposure)
    """

    def __init__(self, url: str = "", event_bus=None):
        super().__init__(
            "APISecurityAgent",
            "API & GraphQL Specialist",
            event_bus,
            agent_id="api_security",
        )
        self.url = url
        self.graphql_endpoints: Set[str] = set()
        self.rest_endpoints: Set[str] = set()
        self.websocket_endpoints: Set[str] = set()
        self.findings: List[Dict] = []

        # Queue consumption mode
        self._queue_mode = False
        self._scan_context: str = ""
        self._emitted_findings: set = set()
        self._dry_findings: List[Dict] = []
        self.report_dir = None

    def _setup_event_subscriptions(self):
        """Subscribe to endpoint discovery and vulnerability events."""
        if self.event_bus:
            self.event_bus.subscribe("api_endpoint_found", self.handle_api_endpoint)
            self.event_bus.subscribe("graphql_endpoint_found", self.handle_graphql_endpoint)
            self.event_bus.subscribe(
                EventType.VULNERABILITY_DETECTED.value,
                self.handle_vulnerability_detected,
            )
            logger.info(f"[{self.name}] Subscribed to API and vulnerability events")

    async def handle_api_endpoint(self, data: Dict[str, Any]):
        """Triggered when REST API endpoint is discovered."""
        endpoint = data.get("url")
        self.think(f"New REST API endpoint: {endpoint}")
        await self._run_rest_test(endpoint)

    async def handle_graphql_endpoint(self, data: Dict[str, Any]):
        """Triggered when GraphQL endpoint is discovered."""
        endpoint = data.get("url")
        self.think(f"New GraphQL endpoint: {endpoint}")
        result = await test_graphql_endpoint(
            endpoint, log_fn=lambda msg, lvl: dashboard.log(msg, lvl)
        )
        for vuln in result.get("vulnerabilities", []):
            await self._report_finding(vuln)

    async def run_loop(self):
        """Main agent loop."""
        dashboard.current_agent = self.name
        self.think("API Security Agent initialized...")
        while self.running:
            await asyncio.sleep(1)

    # ==================== REST ENDPOINT WRAPPER ====================

    async def _run_rest_test(self, endpoint: str):
        """Run REST tests and report findings."""
        result = await test_rest_endpoint(
            endpoint, log_fn=lambda msg, lvl: dashboard.log(msg, lvl)
        )
        for vuln in result.get("vulnerabilities", []):
            await self._report_finding(vuln)

    # ==================== VULNERABILITY CORRELATION ====================

    async def handle_vulnerability_detected(self, data: Dict[str, Any]):
        """Handle vulnerability_detected events from specialist agents.

        Correlates specialist findings with API endpoints for deeper analysis.
        """
        specialist = data.get("specialist", "unknown")
        finding = data.get("finding", {})
        status = data.get("status", "")
        url = finding.get("url", "")

        if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
            return

        self.think(f"Received {specialist} finding for potential API correlation")
        await self._correlate_with_api_testing(specialist, finding, url)

    async def _correlate_with_api_testing(self, specialist: str, finding: Dict, url: str):
        """Correlate specialist findings with API security testing."""
        if not url:
            return

        is_rest = url in self.rest_endpoints
        is_graphql = url in self.graphql_endpoints

        if not is_rest and not is_graphql:
            if is_api_url(url):
                self.rest_endpoints.add(url)
                is_rest = True
                logger.info(f"[{self.name}] Added {url} to REST endpoints from {specialist} finding")

        if is_rest or is_graphql:
            await self._run_correlated_tests(specialist, finding, url, is_graphql)

    async def _run_correlated_tests(self, specialist: str, finding: Dict, url: str, is_graphql: bool):
        """Run additional tests based on correlated specialist findings."""
        correlation_tests = {
            "sqli": self._correlate_sqli_with_api,
            "idor": self._correlate_idor_with_api,
            "jwt": self._correlate_jwt_with_api,
            "ssrf": self._correlate_ssrf_with_api,
        }

        handler = correlation_tests.get(specialist.lower())
        if handler:
            await handler(finding, url, is_graphql)

    async def _correlate_sqli_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate SQLi finding with API -- check for GraphQL injection."""
        if is_graphql:
            self.think("SQLi on GraphQL endpoint - testing GraphQL injection")
            self.findings.append({
                "type": "API Correlation",
                "correlation": "SQLi -> GraphQL",
                "original_finding": finding,
                "recommendation": "Test GraphQL queries for similar injection patterns",
            })

    async def _correlate_idor_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate IDOR finding with API -- check for BOLA."""
        self.think("IDOR on API endpoint - testing for BOLA")
        self.findings.append({
            "type": "API Correlation",
            "correlation": "IDOR -> BOLA",
            "original_finding": finding,
            "recommendation": "Test all object-access endpoints for authorization bypass",
        })

    async def _correlate_jwt_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate JWT finding with API -- check auth bypass."""
        self.think("JWT vulnerability on API - testing for auth bypass across endpoints")
        self.findings.append({
            "type": "API Correlation",
            "correlation": "JWT -> API Auth Bypass",
            "original_finding": finding,
            "recommendation": "Test all authenticated API endpoints with forged tokens",
        })

    async def _correlate_ssrf_with_api(self, finding: Dict, url: str, is_graphql: bool):
        """Correlate SSRF finding with API -- check internal API access."""
        self.think("SSRF on API endpoint - testing for internal API access")
        self.findings.append({
            "type": "API Correlation",
            "correlation": "SSRF -> Internal API Access",
            "original_finding": finding,
            "recommendation": "Test SSRF payloads targeting internal API endpoints",
        })

    # ==================== FINDING REPORTING ====================

    async def _report_finding(self, vulnerability: Dict):
        """Report discovered vulnerability."""
        self.findings.append(vulnerability)

        # Store in knowledge graph
        try:
            from bugtrace.memory.manager import memory_manager
            vuln_url = vulnerability.get("url", "")
            vuln_type = vulnerability.get("type", "API_SECURITY")
            vuln_param = vulnerability.get("parameter", vulnerability.get("endpoint", ""))
            memory_manager.add_node(
                "Finding",
                f"API_SECURITY_{urlparse(vuln_url).path}_{vuln_param}",
                properties={
                    "type": vuln_type,
                    "url": vuln_url,
                    "parameter": vuln_param,
                    "details": str(vulnerability.get("description", ""))[:200],
                },
            )
        except Exception:
            pass

        # Emit finding event
        if self.event_bus:
            try:
                await self.event_bus.emit("vulnerability_detected", {
                    "agent": self.name,
                    "vulnerability": vulnerability,
                    "timestamp": datetime.now().isoformat(),
                })
            except Exception:
                pass

        # Dashboard notification
        severity = vulnerability.get("severity", "MEDIUM")
        vuln_type = vulnerability.get("type", "Unknown")
        dashboard.log(f"  {severity}: {vuln_type}", severity)

    # ==================== QUEUE CONSUMER (v3.2 Pipeline) ====================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET -> DRY). NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("APISecurityAgent", self._scan_context)

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")

        queue = queue_manager.get_queue("api_security")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {
            "agent": "APISecurity", "queue_depth": initial_depth,
        })

        # PHASE A: ANALYSIS & DEDUPLICATION
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "api_security")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {
                "agent": "APISecurity", "dry_count": 0, "vulns": 0,
            })
            return

        # PHASE B: EXPLOITATION
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0

        if results:
            await self._generate_specialist_report(results)

        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count,
        )

        self._v.emit("exploit.specialist.completed", {
            "agent": "APISecurity", "dry_count": len(dry_list), "vulns": vulns_count,
        })
        logger.info(f"[{self.name}] Queue consumer complete: {vulns_count} validated findings")

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Drain api_security queue and deduplicate by URL."""
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        queue = queue_manager.get_queue("api_security")
        wet_findings: List[Dict] = []

        # Wait up to 5 min for first item
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() > 0:
                break
            await asyncio.sleep(0.5)
        else:
            return []

        # Drain queue
        empty_count = 0
        while empty_count < 10:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)
                continue
            empty_count = 0
            finding = item.get("finding", {})
            url = finding.get("url", "")
            if url:
                wet_findings.append({
                    "url": url,
                    "parameter": finding.get("parameter", ""),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context),
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")

        if not wet_findings:
            return []

        # Deduplicate by URL
        seen_urls: set = set()
        for wf in wet_findings:
            parsed = urlparse(wf["url"])
            dedup_key = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            if dedup_key not in seen_urls:
                seen_urls.add(dedup_key)
                self._dry_findings.append(wf)

        logger.info(
            f"[{self.name}] Phase A: {len(wet_findings)} WET -> {len(self._dry_findings)} DRY"
        )
        return self._dry_findings

    async def exploit_dry_list(self) -> List[Dict]:
        """Test each DRY finding for API security vulnerabilities."""
        logger.info(
            f"[{self.name}] ===== PHASE B: Exploiting {len(self._dry_findings)} DRY findings ====="
        )
        validated: List[Dict] = []
        graphql_tested: set = set()

        for idx, f in enumerate(self._dry_findings, 1):
            url = f.get("url", "")
            finding = f.get("finding", {})
            finding_type = finding.get("type", "").lower()

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "APISecurity", "param": finding_type, "url": url,
                    "idx": idx, "total": len(self._dry_findings),
                })

            try:
                parsed = urlparse(url)
                base_key = f"{parsed.scheme}://{parsed.netloc}"

                # Always try GraphQL discovery (once per host)
                if base_key not in graphql_tested:
                    graphql_tested.add(base_key)
                    graphql_endpoint = await discover_graphql_endpoint(url)
                    if graphql_endpoint:
                        result = await test_graphql_endpoint(graphql_endpoint)
                        if result.get("vulnerabilities"):
                            for vuln in result["vulnerabilities"]:
                                vuln["status"] = ValidationStatus.VALIDATED_CONFIRMED.value
                                vuln["validated"] = True
                                await self._report_finding(vuln)
                            validated.extend(result["vulnerabilities"])

                # Also run REST API tests
                result = await test_rest_endpoint(url)
                if result.get("vulnerabilities"):
                    for vuln in result["vulnerabilities"]:
                        vuln["status"] = ValidationStatus.VALIDATED_CONFIRMED.value
                        vuln["validated"] = True
                        await self._report_finding(vuln)
                    validated.extend(result["vulnerabilities"])

            except Exception as e:
                logger.error(f"[{self.name}] Error testing {url}: {e}")

        logger.info(f"[{self.name}] Phase B: {len(validated)} vulnerabilities found")
        return validated

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Write specialist results to unified report directory."""
        scan_dir = getattr(self, 'report_dir', None) or (
            settings.BASE_DIR / "reports" / self._scan_context.split("/")[-1]
        )
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        report_path = results_dir / "api_security_results.json"

        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps({
                "agent": self.name,
                "timestamp": datetime.now().isoformat(),
                "scan_context": self._scan_context,
                "phase_a": {
                    "wet_count": len(self._dry_findings),
                    "dry_count": len(self._dry_findings),
                    "dedup_method": "url_normalization",
                },
                "phase_b": {
                    "validated_count": len([x for x in findings if x]),
                    "total_findings": len(findings),
                },
                "findings": findings,
            }, indent=2))

        logger.info(f"[{self.name}] Report saved: {report_path}")
        return str(report_path)


# Export
__all__ = ["APISecurityAgent"]
