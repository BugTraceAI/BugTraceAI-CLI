import logging
import aiohttp
from typing import Dict, List, Optional, Any
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.ui import dashboard
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.tools.external import external_tools
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation

logger = logging.getLogger(__name__)

class LFIAgent(BaseAgent):
    """
    Specialist Agent for Local File Inclusion (LFI) and Path Traversal.
    """

    def __init__(self, url: str, params: List[str] = None, report_dir: Path = None, event_bus=None):
        super().__init__(
            name="LFIAgent",
            role="LFI Specialist",
            event_bus=event_bus,
            agent_id="lfi_agent"
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")

        # Deduplication
        self._tested_params = set()

        # Queue consumption mode (Phase 20)
        self._queue_mode = False

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (url, param)
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""
        
    def _determine_validation_status(self, response_text: str, payload: str) -> str:
        """
        Determine validation status based on what we actually found.

        TIER 1 (VALIDATED_CONFIRMED):
            - /etc/passwd content visible (root:x:0:0)
            - win.ini content visible ([extensions])
            - PHP source code visible (<?php or base64 decoded PHP)

        TIER 2 (PENDING_VALIDATION):
            - Path traversal success but no sensitive file content
            - PHP wrapper returned something but unclear if source code
        """
        # TIER 1: Clear sensitive file signatures
        tier1_signatures = [
            "root:x:0:0",           # /etc/passwd Linux
            "root:*:0:0",           # /etc/passwd BSD
            "[extensions]",         # win.ini
            "[fonts]",              # win.ini
            "127.0.0.1 localhost",  # /etc/hosts
            "<?php",                # PHP source code (direct)
        ]

        for sig in tier1_signatures:
            if sig in response_text:
                logger.info(f"[{self.name}] Found '{sig}' in response. VALIDATED_CONFIRMED")
                return "VALIDATED_CONFIRMED"

        # TIER 1: Base64 decoded PHP (from php://filter)
        if "PD9waH" in response_text:  # Base64 for <?php
            logger.info(f"[{self.name}] Found base64 PHP source. VALIDATED_CONFIRMED")
            return "VALIDATED_CONFIRMED"

        # TIER 2: Path traversal worked but didn't get sensitive content
        # This could be a directory listing or error page
        logger.info(f"[{self.name}] LFI response unclear. PENDING_VALIDATION")
        return "PENDING_VALIDATION"

    async def _get_response_text(self, session, payload, param) -> str:
        """Get the response text for classification."""
        target_url = self._inject_payload(self.url, param, payload)
        try:
            async with session.get(target_url, timeout=5) as resp:
                return await resp.text()
        except Exception as e:
            logger.debug(f"_get_response_text failed: {e}")
            return ""
        
    def _create_lfi_finding_from_hit(self, hit: Dict, param: str) -> Dict:
        """Create LFI finding from fuzzer hit."""
        return {
            "type": "LFI / Path Traversal",
            "url": self.url,
            "parameter": param,
            "payload": hit["payload"],
            "description": f"Local File Inclusion success: Found {hit['file_found']}. File content leaked in response.",
            "severity": normalize_severity(hit["severity"]).value,  # Normalize to uppercase
            "cwe_id": get_cwe_for_vuln("LFI"),  # CWE-22
            "cve_id": "N/A",  # LFI vulnerabilities are class-based, not specific CVEs
            "remediation": get_remediation_for_vuln("LFI"),
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "evidence": hit["evidence"],
            "http_request": f"GET {self.url}?{param}={hit['payload']}",
            "http_response": hit["evidence"][:500] if isinstance(hit["evidence"], str) else str(hit["evidence"])[:500],
            "reproduction": f"curl '{self.url}?{param}={hit['payload']}'"
        }

    def _create_lfi_finding_from_wrapper(self, payload: str, param: str, response_text: str) -> Dict:
        """Create LFI finding from PHP wrapper test."""
        return {
            "type": "LFI / Path Traversal",
            "url": self.url,
            "parameter": param,
            "payload": payload,
            "description": f"LFI detected via PHP wrapper. Source code can be read using base64 encoding filter.",
            "severity": normalize_severity("CRITICAL").value,
            "cwe_id": get_cwe_for_vuln("LFI"),  # CWE-22
            "cve_id": "N/A",  # LFI vulnerabilities are class-based, not specific CVEs
            "remediation": get_remediation_for_vuln("LFI"),
            "validated": True,
            "evidence": f"PHP Wrapper matched signature after injecting {payload}",
            "status": self._determine_validation_status(response_text, payload),
            "http_request": f"GET {self.url}?{param}={payload}",
            "http_response": response_text[:500],
            "reproduction": f"curl '{self.url}?{param}={payload}' | base64 -d"
        }

    async def _test_php_wrappers(self, session, param: str) -> Optional[Dict]:
        """Test PHP wrapper payloads as fallback."""
        base_payloads = [
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/convert.base64-encode/resource=config.php"
        ]

        for p in base_payloads:
            dashboard.update_task(f"LFI:{param}", status=f"Testing Wrapper {p[:20]}...")
            if await self._test_payload(session, p, param):
                response_text = await self._get_response_text(session, p, param)
                return self._create_lfi_finding_from_wrapper(p, param, response_text)
        return None

    async def run_loop(self) -> Dict:
        """Main execution loop for LFI testing."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting LFI analysis on {self.url}", "INFO")

        all_findings = []
        async with orchestrator.session(DestinationType.TARGET) as session:
            for param in self.params:
                logger.info(f"[{self.name}] Testing LFI on {self.url} (param: {param})")

                key = f"{self.url}#{param}"
                if key in self._tested_params:
                    logger.info(f"[{self.name}] Skipping {param} - already tested")
                    continue

                await self._test_parameter_for_lfi(session, param, key, all_findings)

        return {"vulnerable": len(all_findings) > 0, "findings": all_findings}

    async def _test_parameter_for_lfi(self, session, param: str, key: str, all_findings: List):
        """Test a single parameter for LFI vulnerabilities."""
        # High-Performance Go Fuzzer
        dashboard.log(f"[{self.name}] 🚀 Launching Go LFI Fuzzer on '{param}'...", "INFO")
        go_result = await external_tools.run_go_lfi_fuzzer(self.url, param)

        if go_result and go_result.get("hits"):
            self._process_go_fuzzer_hits(go_result, param, key, all_findings)
            return

        # Base Payloads (Manual Fallback if Go fails or for PHP wrappers)
        if key not in self._tested_params:
            wrapper_finding = await self._test_php_wrappers(session, param)
            if wrapper_finding:
                all_findings.append(wrapper_finding)
                self._tested_params.add(key)

    def _process_go_fuzzer_hits(self, go_result: Dict, param: str, key: str, all_findings: List):
        """Process Go fuzzer hits and add to findings."""
        for hit in go_result["hits"]:
            dashboard.log(f"[{self.name}] 🚨 LFI HIT: {hit['payload']} ({hit['severity']})", "CRITICAL")
            all_findings.append(self._create_lfi_finding_from_hit(hit, param))
            self._tested_params.add(key)
            break

    async def _test_payload(self, session, payload, param) -> bool:
        """Injects payload and analyzes response."""
        target_url = self._inject_payload(self.url, param, payload)
        
        try:
            async with session.get(target_url, timeout=5) as resp:
                text = await resp.text()
                
                # Heuristics for detection
                signatures = [
                    "root:x:0:0",                  # /etc/passwd
                    "[extensions]",                # win.ini
                    "[fonts]",                     # win.ini
                    "PD9waH",                      # Base64 for <?php
                    "root:*:0:0",                  # /etc/passwd (other formats)
                    "127.0.0.1 localhost"         # /etc/hosts
                ]

                if any(sig in text for sig in signatures):
                    return True

        except Exception as e:
            logger.debug(f"Path traversal signature check failed: {e}")

        return False

    def _inject_payload(self, url, param, payload):
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        q[param] = [payload]
        new_query = urlencode(q, doseq=True)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

    # =========================================================================
    # Queue Consumption Mode (Phase 20)
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        Start LFIAgent in queue consumer mode.

        Spawns a worker pool that consumes from the lfi queue and
        processes findings in parallel.

        Args:
            scan_context: Scan identifier for event correlation
        """
        self._queue_mode = True
        self._scan_context = scan_context

        # Configure worker pool
        config = WorkerConfig(
            specialist="lfi",
            pool_size=settings.WORKER_POOL_DEFAULT_SIZE,
            process_func=self._process_queue_item,
            on_result=self._handle_queue_result,
            shutdown_timeout=settings.WORKER_POOL_SHUTDOWN_TIMEOUT
        )

        self._worker_pool = WorkerPool(config)

        # Subscribe to work_queued_lfi events (optional notification)
        if self.event_bus:
            self.event_bus.subscribe(
                EventType.WORK_QUEUED_LFI.value,
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
                EventType.WORK_QUEUED_LFI.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_lfi notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """
        Process a single item from the lfi queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "LFI",
                "url": "...",
                "parameter": "...",
            },
            "priority": 85.5,
            "scan_context": "scan_123",
            "classified_at": 1234567890.0
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

        # Run validation using existing LFI testing logic
        return await self._test_single_param_from_queue(url, param, finding)

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict
    ) -> Optional[Dict]:
        """
        Test a single parameter from queue for LFI.

        Uses existing validation pipeline optimized for queue processing.
        """
        try:
            # High-Performance Go Fuzzer first
            go_result = await external_tools.run_go_lfi_fuzzer(url, param)
            if go_result and go_result.get("hits"):
                hit = go_result["hits"][0]
                return self._create_lfi_finding_from_hit(hit, param)

            # Fallback to PHP wrappers
            async with orchestrator.session(DestinationType.TARGET) as session:
                wrapper_finding = await self._test_php_wrappers(session, param)
                if wrapper_finding:
                    return wrapper_finding

            return None

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    def _generate_lfi_fingerprint(self, url: str, parameter: str) -> tuple:
        """
        Generate LFI finding fingerprint for expert deduplication.

        LFI is URL-specific and parameter-specific.

        Args:
            url: Target URL
            parameter: Parameter name

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # LFI signature: (host, path, parameter)
        fingerprint = ("LFI", parsed.netloc, normalized_path, parameter.lower())

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        Uses centralized validation status to determine if CDP validation is needed.
        """
        if result is None:
            return

        # Use centralized validation status for proper tagging
        # PHP wrapper results may need additional verification if source code not confirmed
        finding_data = {
            "context": result.get("type", "LFI"),
            "payload": result.get("payload", ""),
            "validation_method": "lfi_fuzzer",
            "evidence": {"response": result.get("evidence", "")},
        }
        needs_cdp = requires_cdp_validation(finding_data)

        # LFI-specific edge case: PHP wrapper returned data but can't confirm source code
        payload = result.get("payload", "")
        status = result.get("status", "VALIDATED_CONFIRMED")
        if "php://filter" in payload and status == "PENDING_VALIDATION":
            needs_cdp = True

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_lfi_fingerprint(result.get("url", ""), result.get("parameter", ""))

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate LFI finding: {result.get('url')}?{result.get('parameter')} (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Emit vulnerability_detected event
        if self.event_bus and settings.WORKER_POOL_EMIT_EVENTS:
            await self.event_bus.emit(EventType.VULNERABILITY_DETECTED, {
                "specialist": "lfi",
                "finding": {
                    "type": "LFI",
                    "url": result.get("url"),
                    "parameter": result.get("parameter"),
                    "payload": result.get("payload"),
                },
                "status": status,
                "validation_requires_cdp": needs_cdp,
                "scan_context": self._scan_context,
            })

        logger.info(f"[{self.name}] Confirmed LFI: {result.get('url')}?{result.get('parameter')}")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }
