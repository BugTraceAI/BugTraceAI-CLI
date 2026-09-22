"""
XXE Agent - Thin Orchestrator

BaseAgent subclass that wires together pure functions from core.py
and I/O functions from testing.py.

This file contains only the class shell, __init__, and orchestration logic.
All business logic lives in core.py (pure) and testing.py (I/O).
"""

import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

import aiohttp

from bugtrace.agents.base import BaseAgent
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.utils.logger import get_logger
from bugtrace.agents.mixins.tech_context import TechContextMixin

from bugtrace.agents.xxe.core import (
    INITIAL_XXE_PAYLOADS,
    check_xxe_indicators,
    determine_validation_status,
    get_validation_status_from_evidence,
    validate_xxe_finding,
    create_finding,
    generate_xxe_fingerprint,
    fallback_fingerprint_dedup,
    build_specialist_report,
    build_evidence_from_result,
)
from bugtrace.agents.xxe.testing import (
    test_xml,
    test_heuristic_payloads,
    try_llm_bypass,
    discover_xxe_params,
    llm_analyze_and_dedup,
    drain_queue,
    write_specialist_report,
)

logger = get_logger("agents.xxe")


class XXEAgent(BaseAgent, TechContextMixin):
    """
    Specialist Agent for XML External Entity (XXE).
    Target: Endpoints consuming XML.
    """

    def __init__(self, url: str, event_bus: Any = None):
        super().__init__(
            name="XXEAgent",
            role="XXE Specialist",
            event_bus=event_bus,
            agent_id="xxe_agent",
        )
        self.url = url
        self.MAX_BYPASS_ATTEMPTS = 5

        # Queue consumption mode
        self._queue_mode = False
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # Expert deduplication
        self._emitted_findings: set = set()

        # WET -> DRY transformation
        self._dry_findings: List[Dict] = []

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}
        self._xxe_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION (delegates to core.py)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """XXE-specific validation before emitting finding."""
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        return validate_xxe_finding(finding)

    def _emit_xxe_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit XXE finding using BaseAgent.emit_finding()."""
        if "type" not in finding_dict:
            finding_dict["type"] = "XXE"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # =========================================================================
    # DIRECT MODE (run_loop)
    # =========================================================================

    async def run_loop(self) -> Dict:
        """Main execution loop for XXE testing."""
        logger.info(f"[{self.name}] Testing XML Injection on {self.url}")

        async with orchestrator.session(DestinationType.TARGET) as session:
            # Phase 1: Heuristic Checks
            successful_payloads, best_payload = await test_heuristic_payloads(
                session, self.url,
                verbose_emitter=getattr(self, '_v', None),
            )

            # Phase 2: LLM-Driven Bypass (if heuristics failed)
            if not successful_payloads:
                bypass_payloads, bypass_best = await try_llm_bypass(
                    session, self.url, self.system_prompt, "",
                    max_attempts=self.MAX_BYPASS_ATTEMPTS,
                )
                successful_payloads.extend(bypass_payloads)
                best_payload = bypass_best

        if successful_payloads:
            finding = create_finding(self.url, best_payload, successful_payloads)
            return {"vulnerable": True, "findings": [finding]}

        return {"vulnerable": False, "findings": []}

    # =========================================================================
    # WET -> DRY Two-Phase Processing
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        Phase A: Global analysis of WET list with LLM-powered deduplication.

        Process:
        1. Drain ALL items from queue
        2. AUTONOMOUS DISCOVERY: Expand each URL into multiple XXE endpoints
        3. LLM analysis with agent-specific dedup rules
        4. Return DRY list
        """
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("xxe")
        wet_findings = await drain_queue(queue, self._scan_context)

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to deduplicate")
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with XXE-focused discovery...")
        expanded_wet_findings: List[Dict] = []
        seen_urls: set = set()
        seen_endpoints: set = set()

        # 1. Always include ALL original WET findings first
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            endpoint_key = (url, wet_item.get("endpoint_type", ""), wet_item.get("method", ""))
            if endpoint_key not in seen_endpoints:
                seen_endpoints.add(endpoint_key)
                expanded_wet_findings.append(wet_item)

        # 2. Discover additional XXE endpoints per unique URL
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                xxe_endpoints = await discover_xxe_params(url)
                if not xxe_endpoints:
                    continue

                new_count = 0
                for endpoint_data in xxe_endpoints:
                    ep_url = endpoint_data.get("url", url)
                    endpoint_key = (ep_url, endpoint_data.get("type", "unknown"), endpoint_data.get("method", "POST"))
                    if endpoint_key not in seen_endpoints:
                        seen_endpoints.add(endpoint_key)
                        expanded_wet_findings.append({
                            "url": ep_url,
                            "endpoint_type": endpoint_data.get("type", "unknown"),
                            "accept_filter": endpoint_data.get("accept", ""),
                            "method": endpoint_data.get("method", "POST"),
                            "context": wet_item.get("context", "unknown"),
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True,
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] Discovered {new_count} additional XXE endpoints on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints -> {len(expanded_wet_findings)} testable XXE endpoints")

        # ========== DEDUPLICATION ==========
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        prime_directive = getattr(self, '_xxe_prime_directive', '')
        dedup_context = self.generate_xxe_dedup_context(tech_stack) if tech_stack else ''
        lang = tech_stack.get('lang', 'generic')
        xml_parser = self._infer_xml_parser(lang)

        try:
            dry_list = await llm_analyze_and_dedup(
                expanded_wet_findings, self._scan_context,
                tech_stack, prime_directive, dedup_context, xml_parser,
            )
        except Exception as e:
            logger.error(f"[{self.name}] LLM dedup failed: {e}. Falling back to fingerprint dedup")
            dry_list = fallback_fingerprint_dedup(expanded_wet_findings)

        self._dry_findings = dry_list

        dup_count = len(expanded_wet_findings) - len(dry_list)
        logger.info(
            f"[{self.name}] Phase A: Deduplication complete. "
            f"{len(expanded_wet_findings)} WET -> {len(dry_list)} DRY "
            f"({dup_count} duplicates removed)"
        )

        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Exploit DRY list (deduplicated findings only)."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding_data in enumerate(self._dry_findings, 1):
            url = finding_data.get("url", "")
            endpoint_type = finding_data.get("endpoint_type", "unknown")
            method = finding_data.get("method", "POST")
            finding = finding_data.get("finding", {})

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Testing {endpoint_type} on {url}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "XXE", "endpoint_type": endpoint_type,
                    "url": url, "idx": idx, "total": len(self._dry_findings),
                })
                self._v.reset("exploit.specialist.progress")

            try:
                self.url = url
                result = await self._test_single_url_from_queue(url, finding)

                if result and result.get("validated"):
                    result["endpoint_type"] = endpoint_type
                    result["http_method"] = method

                    validated_findings.append(result)

                    # FINGERPRINT CHECK
                    if finding_data.get("_discovered"):
                        from urllib.parse import urlparse
                        parsed = urlparse(url)
                        fingerprint = (parsed.scheme, parsed.netloc, parsed.path.rstrip('/'), endpoint_type)
                    else:
                        fingerprint = generate_xxe_fingerprint(url)

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)

                        if settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)
                            self._emit_xxe_finding({
                                "specialist": "xxe",
                                "type": "XXE",
                                "url": result.get("url"),
                                "payload": result.get("payload"),
                                "severity": result.get("severity"),
                                "description": result.get("description"),
                                "reproduction": result.get("reproduction"),
                                "endpoint_type": endpoint_type,
                                "status": status,
                                "evidence": result.get("evidence", {}),
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                            }, scan_context=self._scan_context)

                        logger.info(f"[{self.name}] Emitted unique XXE finding: {url} (type={endpoint_type})")

                        if hasattr(self, '_v'):
                            self._v.emit("exploit.specialist.confirmed", {
                                "agent": "XXE", "endpoint_type": endpoint_type,
                                "url": url, "severity": result.get("severity"),
                            })
                    else:
                        logger.debug(f"[{self.name}] Skipped duplicate: {fingerprint}")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Attack failed: {e}")
                continue
            finally:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {
                        "agent": "XXE", "endpoint_type": endpoint_type,
                        "url": url, "idx": idx,
                    })

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report_file(self, findings: List[Dict]) -> str:
        """Generate specialist report after exploitation."""
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1]
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        results_dir = scan_dir / "specialists" / "results"

        report = build_specialist_report(
            self.name, self._scan_context,
            self._dry_findings, findings,
        )

        report_path = results_dir / "xxe_results.json"
        await write_specialist_report(report, report_path)
        return str(report_path)

    # =========================================================================
    # QUEUE CONSUMER MODE
    # =========================================================================

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
        self._v = create_emitter("XXEAgent", self._scan_context)

        await self._load_xxe_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")

        queue = queue_manager.get_queue("xxe")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {"agent": "XXE", "queue_depth": initial_depth})

        # PHASE A
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "xxe")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "XXE", "dry_count": 0, "vulns": 0})
            return

        # PHASE B
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report_file(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)
        self._v.emit("exploit.specialist.completed", {
            "agent": "XXE", "dry_count": len(dry_list), "vulns": vulns_count,
        })

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

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
            async with orchestrator.session(DestinationType.TARGET) as session:
                successful_payloads, best_payload = await test_heuristic_payloads(
                    session, url,
                    verbose_emitter=getattr(self, '_v', None),
                )

                if successful_payloads:
                    return create_finding(url, best_payload, successful_payloads)

                bypass_payloads, bypass_best = await try_llm_bypass(
                    session, url, self.system_prompt, "",
                    max_attempts=self.MAX_BYPASS_ATTEMPTS,
                )
                if bypass_payloads:
                    return create_finding(url, bypass_best, bypass_payloads)

                return None
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        evidence = build_evidence_from_result(result)
        status = get_validation_status_from_evidence(evidence)

        url = result.get("url", "")
        fingerprint = generate_xxe_fingerprint(url)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate XXE finding: {url} (already reported)")
            return

        self._emitted_findings.add(fingerprint)

        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_xxe_finding({
                "specialist": "xxe",
                "type": "XXE",
                "url": result.get("url"),
                "payload": result.get("payload"),
                "status": status,
                "evidence": result.get("evidence", {}),
                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
            }, scan_context=self._scan_context)

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
                self._on_work_queued,
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

    # =========================================================================
    # TECH CONTEXT LOADING (v3.2)
    # =========================================================================

    async def _load_xxe_tech_context(self) -> None:
        """Load technology stack context from recon data (v3.2)."""
        scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
        scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._xxe_prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._xxe_prime_directive = self.generate_xxe_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        xml_parser = self._infer_xml_parser(lang)

        logger.info(f"[{self.name}] XXE tech context loaded: lang={lang}, parser={xml_parser}")
