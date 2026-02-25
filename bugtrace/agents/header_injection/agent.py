"""
Header Injection Agent - Thin Orchestrator

BaseAgent subclass that wires together pure functions from core.py
and I/O functions from testing.py.

This file contains only the class shell, __init__, and orchestration logic.
All business logic lives in core.py (pure) and testing.py (I/O).
"""

import asyncio
import json
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.agents.base import BaseAgent
from bugtrace.core.validation_status import ValidationStatus
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.agents.mixins.tech_context import TechContextMixin

from bugtrace.agents.header_injection.core import (
    CRLF_PAYLOADS,
    INJECTION_MARKERS,
    build_test_url,
    get_parameters_to_test,
    should_test_url,
    load_scope_config,
    create_finding,
    validate_header_injection_finding,
    generate_headerinjection_fingerprint,
    fallback_fingerprint_dedup,
    build_specialist_report,
)
from bugtrace.agents.header_injection.testing import (
    check_injection,
    smart_probe_crlf,
    test_parameter_from_queue,
    discover_header_params,
    llm_analyze_and_dedup,
    drain_queue,
    write_specialist_report,
)

logger = get_logger("agents.header_injection")


class HeaderInjectionAgent(BaseAgent, TechContextMixin):
    """
    HTTP Response Header Injection (CRLF) Specialist Agent.

    Tests for:
    1. CRLF injection in URL parameters
    2. CRLF injection in cookies
    3. CRLF injection in custom headers
    4. Response splitting for cache poisoning
    """

    # Config path for header injection scope filtering
    SCOPE_CONFIG_PATH = Path(__file__).parent.parent.parent / "data" / "header_injection_scope.json"

    def __init__(
        self,
        url: str,
        params: List[str] = None,
        report_dir: Path = None,
        event_bus: Any = None,
        cookies: List[Dict] = None,
        headers: Dict[str, str] = None,
    ):
        super().__init__(
            "HeaderInjectionAgent",
            "CRLF Injection Specialist",
            event_bus=event_bus,
            agent_id="header_injection_agent",
        )
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

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()

        # WET -> DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []

        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._header_injection_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION (delegates to core.py)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """Header Injection-specific validation before emitting finding."""
        # Call parent validation first
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        return validate_header_injection_finding(finding)

    def _emit_header_injection_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit Header Injection finding using BaseAgent.emit_finding() with validation."""
        if "type" not in finding_dict:
            finding_dict["type"] = "HEADER_INJECTION"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # =========================================================================
    # DIRECT MODE (run/run_loop)
    # =========================================================================

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
        logger.info(f"[{self.name}] Starting Header Injection scan on {self.url}")
        dashboard.log(f"[{self.name}] Starting Header Injection scan on {self.url}", "INFO")

        try:
            # Smart Scope Filter
            scope_config = load_scope_config(self.SCOPE_CONFIG_PATH)
            if scope_config:
                should_test, reason = should_test_url(self.url, scope_config)
                if not should_test:
                    dashboard.log(f"[{self.name}] Skipping - URL not in scope ({reason})", "INFO")
                    return {"findings": [], "status": JobStatus.COMPLETED, "stats": self._stats}
                logger.info(f"[{self.name}] URL in scope: {reason}")
            else:
                logger.warning(f"[{self.name}] Failed to load scope config, defaulting to test")

            # Get parameters to test
            params_to_test = get_parameters_to_test(self.url, self.params, self.cookies)

            if not params_to_test:
                dashboard.log(f"[{self.name}] No parameters found to test", "WARN")
                return {"findings": [], "status": JobStatus.COMPLETED, "stats": self._stats}

            logger.info(f"[{self.name}] Parameters to test: {params_to_test}")

            # Test each parameter
            user_agent = getattr(settings, 'USER_AGENT', 'BugTraceAI/2.4')
            validation_status = ValidationStatus.VALIDATED_CONFIRMED.value

            async with orchestrator.session(DestinationType.TARGET) as session:
                for param in params_to_test:
                    self._stats["params_tested"] += 1
                    dashboard.log(f"[{self.name}] Testing parameter: {param}", "INFO")

                    for payload in CRLF_PAYLOADS:
                        self._stats["payloads_tested"] += 1

                        test_url = build_test_url(self.url, param, payload)
                        finding = await check_injection(
                            session, test_url, param, payload, self.url,
                            self.headers, self.cookies, user_agent, validation_status,
                        )

                        if finding:
                            self.findings.append(finding)
                            self._stats["vulns_found"] += 1
                            dashboard.add_finding("Header Injection", f"{self.url} [{param}]", "HIGH")
                            logger.info(f"[{self.name}] Header Injection confirmed in {param}!")
                            dashboard.log(f"[{self.name}] Header Injection CONFIRMED in {param}!", "SUCCESS")
                            break  # Found vulnerability for this param

            self._log_completion_stats()

            return {"findings": self.findings, "status": JobStatus.COMPLETED, "stats": self._stats}

        except Exception as e:
            logger.error(f"HeaderInjectionAgent failed: {e}", exc_info=True)
            return {"error": str(e), "findings": [], "status": JobStatus.FAILED}

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
    # WET -> DRY Two-Phase Processing
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        PHASE A: Drain WET findings from queue, expand with autonomous discovery,
        and deduplicate.
        """
        from bugtrace.core.queue import queue_manager
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("header_injection")
        wet_findings = await drain_queue(queue)

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with autonomous discovery...")
        expanded_wet_findings = []
        seen_urls: set = set()
        seen_params: set = set()
        last_discovery_html = ""

        # 1. Always include ALL original WET params first (DASTySAST signals)
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            param = wet_item.get("parameter", "") or (wet_item.get("finding", {}) or {}).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                expanded_wet_findings.append(wet_item)

        # 2. Discover additional params per unique URL
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                all_params = await discover_header_params(url)
                if not all_params:
                    continue

                new_count = 0
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "context": wet_item.get("context", "unknown"),
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True,
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] Discovered {new_count} additional params on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # 2.5 Resolve endpoint URLs from HTML links/forms + reasoning fallback
        try:
            from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning
            # Use cached HTML from discovery (if available via browser_manager)
            # Note: discover_header_params caches HTML internally
            for base_url in seen_urls:
                # Try to get HTML from browser manager cache
                try:
                    from bugtrace.tools.visual.browser import browser_manager
                    state = await browser_manager.capture_state(base_url)
                    cached_html = state.get("html", "")
                except Exception:
                    cached_html = ""

                if cached_html:
                    endpoint_map = resolve_param_endpoints(cached_html, base_url)
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
                            logger.info(f"[{self.name}] Resolved {resolved_count} params to actual endpoint URLs")
        except Exception as e:
            logger.debug(f"[{self.name}] Endpoint resolution failed: {e}")

        logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints -> {len(expanded_wet_findings)} testable params")

        # ========== DEDUPLICATION ==========
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        prime_directive = getattr(self, '_header_injection_prime_directive', '')
        dedup_context = self.generate_header_injection_dedup_context(tech_stack) if tech_stack else ''

        try:
            dry_list = await llm_analyze_and_dedup(
                expanded_wet_findings, self._scan_context,
                tech_stack, prime_directive, dedup_context,
            )
        except Exception as e:
            logger.warning(f"[{self.name}] LLM dedup failed: {e}, using fallback")
            dry_list = fallback_fingerprint_dedup(expanded_wet_findings)

        # Store for later phases
        self._dry_findings = dry_list

        logger.info(
            f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET -> {len(dry_list)} DRY "
            f"({len(expanded_wet_findings) - len(dry_list)} duplicates removed)"
        )

        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """PHASE B: Exploit all DRY findings and emit validated vulnerabilities."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []
        user_agent = getattr(settings, 'USER_AGENT', 'BugTraceAI/2.4')

        for idx, finding in enumerate(self._dry_findings, 1):
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")
            header_name = finding.get("header_name", finding.get("injected_header", "X-Injected"))

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(self._dry_findings)}] Testing {url} header={header_name}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "HeaderInjection", "param": parameter,
                    "url": url, "idx": idx, "total": len(self._dry_findings),
                })
                self._v.reset("exploit.specialist.progress")

            # Check fingerprint to avoid re-emitting
            fingerprint = generate_headerinjection_fingerprint(header_name)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                continue

            # Execute Header Injection attack
            try:
                async with orchestrator.session(DestinationType.TARGET) as session:
                    result = await test_parameter_from_queue(
                        session, url, parameter, self.headers, self.cookies,
                        user_agent, ValidationStatus.VALIDATED_CONFIRMED.value,
                        verbose_emitter=getattr(self, '_v', None),
                    )

                if result:
                    # Mark as emitted
                    self._emitted_findings.add(fingerprint)

                    # Ensure dict format
                    if not isinstance(result, dict):
                        result = {
                            "url": url,
                            "parameter": parameter,
                            "type": "HEADER_INJECTION",
                            "header_name": header_name,
                            "severity": "MEDIUM",
                            "validated": True,
                        }

                    validated_findings.append(result)

                    if hasattr(self, '_v'):
                        self._v.emit("exploit.specialist.signature_match", {
                            "agent": "HeaderInjection", "param": parameter,
                            "url": url, "header_name": result.get("header_name", header_name),
                        })

                    # Emit event with validation
                    self._emit_header_injection_finding({
                        "type": "HEADER_INJECTION",
                        "url": result.get("url", url),
                        "parameter": result.get("parameter", parameter),
                        "header_name": result.get("header_name", header_name),
                        "payload": result.get("payload", ""),
                        "severity": result.get("severity", "MEDIUM"),
                        "evidence": {"header_reflected": True},
                    }, scan_context=self._scan_context)

                    if hasattr(self, '_v'):
                        self._v.emit("exploit.specialist.confirmed", {
                            "agent": "HeaderInjection", "param": parameter,
                            "url": url, "payload": result.get("payload", "")[:80],
                        })

                    logger.info(f"[{self.name}] Header Injection confirmed: header={header_name}")
                else:
                    logger.debug(f"[{self.name}] Header Injection not confirmed")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Exploitation failed: {e}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.completed", {
                    "agent": "HeaderInjection", "param": parameter, "url": url,
                })

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """Generate specialist report for Header Injection findings."""
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        results_dir = scan_dir / "specialists" / "results"

        report = build_specialist_report(
            self.name, self._scan_context,
            self._dry_findings, validated_findings,
        )

        await write_specialist_report(report, results_dir / "header_injection_results.json")

    # =========================================================================
    # QUEUE CONSUMPTION MODE
    # =========================================================================

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        TWO-PHASE queue consumer (WET -> DRY). NO infinite loop.

        Phase A: Drain ALL findings from queue and deduplicate
        Phase B: Exploit DRY list only
        """
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )
        from bugtrace.core.queue import queue_manager

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("HeaderInjection", self._scan_context)

        # v3.2: Load context-aware tech stack
        await self._load_header_injection_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")
        self._v.emit("exploit.specialist.started", {"agent": "HeaderInjection", "url": self.url})

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("header_injection")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A: Analyze and deduplicate
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "header_injection")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.completed", {"agent": "HeaderInjection", "dry_count": 0, "vulns": 0})
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        # PHASE B: Exploit DRY findings
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)

        if hasattr(self, '_v'):
            self._v.emit("exploit.specialist.completed", {
                "agent": "HeaderInjection",
                "dry_count": len(dry_list),
                "vulns": vulns_count,
            })

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_HEADER_INJECTION.value,
                self._on_work_queued,
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_header_injection notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[Dict]:
        """Process a single item from the header_injection queue."""
        finding = item.get("finding", {})
        url = finding.get("url")
        param = finding.get("parameter")

        if not url or not param:
            logger.warning(f"[{self.name}] Invalid queue item: missing url or parameter")
            return None

        self.url = url
        user_agent = getattr(settings, 'USER_AGENT', 'BugTraceAI/2.4')

        async with orchestrator.session(DestinationType.TARGET) as session:
            return await test_parameter_from_queue(
                session, url, param, self.headers, self.cookies,
                user_agent, ValidationStatus.VALIDATED_CONFIRMED.value,
            )

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing. Emits vulnerability_detected event."""
        if result is None:
            return

        header_name = result["parameter"]
        fingerprint = generate_headerinjection_fingerprint(header_name)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate HEADER_INJECTION finding (already reported)")
            return

        self._emitted_findings.add(fingerprint)

        if getattr(settings, 'WORKER_POOL_EMIT_EVENTS', True):
            self._emit_header_injection_finding({
                "specialist": "header_injection",
                "type": "HEADER_INJECTION",
                "url": result["url"],
                "parameter": result["parameter"],
                "header_name": result["parameter"],
                "payload": result["payload"],
                "severity": result["severity"],
                "status": result["status"],
                "evidence": {"header_reflected": True},
                "validation_requires_cdp": False,
            }, scan_context=self._scan_context)

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

    # =========================================================================
    # TECH CONTEXT LOADING (v3.2)
    # =========================================================================

    async def _load_header_injection_tech_context(self) -> None:
        """Load technology stack context from recon data (v3.2)."""
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._header_injection_prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._header_injection_prime_directive = self.generate_header_injection_context_prompt(self._tech_stack_context)

        server = self._tech_stack_context.get("server", "generic")
        cdn = self._tech_stack_context.get("cdn")
        waf = self._tech_stack_context.get("waf")

        logger.info(f"[{self.name}] Header Injection tech context loaded: server={server}, cdn={cdn or 'none'}, waf={waf or 'none'}")
