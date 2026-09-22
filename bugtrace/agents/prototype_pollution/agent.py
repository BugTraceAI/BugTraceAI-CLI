"""
Prototype Pollution Agent - Thin Orchestrator

BaseAgent subclass that wires together pure functions from core.py
and I/O functions from testing.py.

This file contains only the class shell, __init__, and orchestration logic.
All business logic lives in core.py (pure) and testing.py (I/O).
"""

import asyncio
import json
import time
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse

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
from bugtrace.agents.mixins.tech_context import TechContextMixin

from bugtrace.agents.prototype_pollution.core import (
    POLLUTION_MARKER,
    VULNERABLE_PARAMS,
    discover_param_vectors,
    analyze_response_for_vulnerable_patterns,
    deduplicate_vectors,
    severity_rank,
    get_validation_status,
    validate_prototype_pollution_finding,
    generate_protopollution_fingerprint,
    fallback_fingerprint_dedup,
    build_specialist_report,
    build_reproduction,
    verify_pollution_in_text,
    get_payloads_for_tier,
    get_query_param_payloads,
)
from bugtrace.agents.prototype_pollution.testing import (
    discover_json_body_vector,
    discover_query_pollution_vectors,
    fetch_response_content,
    test_json_body_vector,
    test_query_param_vector,
    test_json_payload,
    smart_probe_pollution,
    smart_probe_client_side,
    exploit_client_side_pp,
    discover_prototype_pollution_params,
    llm_analyze_and_dedup,
    drain_queue,
    write_specialist_report,
)

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
            agent_id="prototype_pollution_specialist",
        )
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self._tested_vectors: set = set()
        self._client_side_pp_confirmed = False
        self._client_side_pp_url = ""

        # Queue consumption mode
        self._queue_mode = False

        # Expert deduplication
        self._emitted_findings: set = set()

        # WET -> DRY transformation
        self._dry_findings: List[Dict] = []

        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # v3.2.0: Context-aware tech stack
        self._tech_stack_context: Dict = {}
        self._prototype_pollution_prime_directive: str = ""

    # =========================================================================
    # FINDING VALIDATION (delegates to core.py)
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> Tuple[bool, str]:
        """Prototype Pollution-specific validation before emitting finding."""
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        return validate_prototype_pollution_finding(finding)

    def _emit_prototype_pollution_finding(self, finding_dict: Dict, scan_context: str = None) -> Optional[Dict]:
        """Helper to emit Prototype Pollution finding using BaseAgent.emit_finding()."""
        if "type" not in finding_dict:
            finding_dict["type"] = "PROTOTYPE_POLLUTION"

        if scan_context:
            finding_dict["scan_context"] = scan_context

        finding_dict["agent"] = self.name
        return self.emit_finding(finding_dict)

    # =========================================================================
    # DIRECT MODE (run_loop)
    # =========================================================================

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
                "findings_count": 0,
            }

        # Phase 2: Auditor - Validate pollution and escalate to RCE
        findings = await self._auditor_phase(vectors)

        # Report findings
        for finding in findings:
            await self._create_finding_report(finding)

        return {
            "status": JobStatus.COMPLETED,
            "vulnerable": len(findings) > 0,
            "findings": findings,
            "findings_count": len(findings),
        }

    # =========================================================================
    # HUNTER PHASE (orchestration -- calls I/O + pure)
    # =========================================================================

    async def _hunter_phase(self) -> List[Dict]:
        """
        Hunter Phase: Discover all potential prototype pollution vectors.

        Scans for:
        - Query parameters that match vulnerable patterns
        - JSON body acceptance (POST/PUT endpoints)
        - Existing parameters that suggest object merging
        - Response content indicating merge operations
        """
        dashboard.log(f"[{self.name}] Hunter: Scanning for pollution vectors", "INFO")

        if not self.url:
            logger.warning(f"[{self.name}] No URL provided")
            return []

        vectors: List[Dict] = []

        # 1. Check if endpoint accepts JSON body
        json_vector = await discover_json_body_vector(self.url)
        if json_vector:
            vectors.append(json_vector)

        # 2. Check existing query parameters for vulnerable names (pure)
        param_vectors = discover_param_vectors(self.url, self.params)
        vectors.extend(param_vectors)

        # 3. Check for query parameter pollution acceptance (I/O)
        query_vectors = await discover_query_pollution_vectors(self.url)
        vectors.extend(query_vectors)

        # 4. Analyze response for vulnerable patterns (I/O + pure)
        content = await fetch_response_content(self.url)
        if content:
            content_vectors = analyze_response_for_vulnerable_patterns(content)
            vectors.extend(content_vectors)

        # Deduplicate and sort (pure)
        unique_vectors = deduplicate_vectors(vectors)

        dashboard.log(f"[{self.name}] Hunter found {len(unique_vectors)} unique vectors", "INFO")
        return unique_vectors

    # =========================================================================
    # AUDITOR PHASE (orchestration -- calls I/O)
    # =========================================================================

    async def _auditor_phase(self, vectors: List[Dict]) -> List[Dict]:
        """
        Auditor Phase: Validate pollution vectors and escalate to RCE.

        Tests each vector with tiered payloads.
        """
        dashboard.log(f"[{self.name}] Auditor: Validating {len(vectors)} vectors", "INFO")
        findings = []

        for vector in vectors:
            key = f"{vector.get('type')}:{vector.get('param', '')}:{vector.get('method', '')}"
            if key in self._tested_vectors:
                continue
            self._tested_vectors.add(key)

            if vector["type"] == "JSON_BODY":
                result = await test_json_body_vector(
                    self.url,
                    verbose_emitter=getattr(self, '_v', None),
                )
            elif vector["type"] in ("QUERY_PARAM", "QUERY_PROTO"):
                result = await test_query_param_vector(
                    self.url,
                    vector.get("param", "__proto__"),
                    verbose_emitter=getattr(self, '_v', None),
                )
            else:
                continue

            if result and result.get("exploitable"):
                findings.append(result)
                sev = result.get("severity", "LOW")
                dashboard.log(
                    f"[{self.name}] CONFIRMED: {result.get('technique', 'unknown')} - {sev}",
                    "CRITICAL" if sev in ("CRITICAL", "HIGH") else "WARNING",
                )

                if result.get("rce_confirmed"):
                    dashboard.log(f"[{self.name}] RCE CONFIRMED - stopping escalation", "CRITICAL")

        return findings

    async def _create_finding_report(self, result: Dict):
        """Reports a confirmed finding."""
        sev = result.get("severity", "MEDIUM")
        if result.get("rce_confirmed"):
            sev = "CRITICAL"
        elif result.get("gadget_found"):
            sev = "HIGH"

        finding = {
            "type": "PROTOTYPE_POLLUTION",
            "severity": sev,
            "url": self.url,
            "parameter": result.get("param"),
            "payload": result.get("payload"),
            "description": f"Prototype Pollution via {result.get('method', 'unknown')} - {result.get('tier', 'basic')} exploitation",
            "validated": True,
            "status": "VALIDATED_CONFIRMED",
            "reproduction": build_reproduction(self.url, result),
            "cwe_id": get_cwe_for_vuln("PROTOTYPE_POLLUTION"),
            "remediation": get_remediation_for_vuln("PROTOTYPE_POLLUTION"),
            "cve_id": "N/A",
            "http_request": result.get("http_request", ""),
            "http_response": result.get("http_response", ""),
            "exploitation_tier": result.get("tier", "pollution_detection"),
            "rce_evidence": result.get("rce_evidence"),
        }
        logger.info(f"[{self.name}] PROTOTYPE POLLUTION CONFIRMED: {result.get('tier')} on {self.url}")

    async def _test_hunter_phase(self) -> Dict:
        """Self-test method for Hunter phase verification."""
        test_results = {
            "json_body": False,
            "query_params": False,
            "response_analysis": False,
        }

        json_vector = await discover_json_body_vector(self.url)
        test_results["json_body"] = json_vector is not None

        param_vectors = discover_param_vectors(self.url, self.params)
        test_results["query_params"] = len(param_vectors) > 0

        all_vectors = await self._hunter_phase()
        test_results["total_vectors"] = len(all_vectors)

        return test_results

    # =========================================================================
    # WET -> DRY Two-Phase Processing
    # =========================================================================

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """PHASE A: Drain WET findings from queue and deduplicate."""
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("prototype_pollution")
        wet_findings = await drain_queue(queue)

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        # ========== AUTONOMOUS PARAMETER DISCOVERY ==========
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with PP-focused discovery...")
        expanded_wet_findings: List[Dict] = []
        seen_urls: set = set()
        seen_params: set = set()
        last_discovery_html = ""

        # 1. Always include ALL original WET params first
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
                all_params = await discover_prototype_pollution_params(url)
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
                            "_discovered": True,
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] Discovered {new_count} additional params on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # 2.5 Resolve endpoint URLs from HTML links/forms + reasoning fallback
        try:
            from bugtrace.tools.visual.browser import browser_manager
            for base_url in seen_urls:
                try:
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

        # LLM-powered deduplication on EXPANDED list
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        prime_directive = getattr(self, '_prototype_pollution_prime_directive', '')
        dedup_context = self.generate_prototype_pollution_dedup_context(tech_stack)

        try:
            dry_list = await llm_analyze_and_dedup(
                expanded_wet_findings, self._scan_context,
                tech_stack, prime_directive, dedup_context,
            )
        except Exception as e:
            logger.warning(f"[{self.name}] LLM dedup failed: {e}, using fallback")
            dry_list = fallback_fingerprint_dedup(expanded_wet_findings)

        self._dry_findings = dry_list

        logger.info(
            f"[{self.name}] Phase A: Deduplication complete. "
            f"{len(expanded_wet_findings)} WET -> {len(dry_list)} DRY "
            f"({len(expanded_wet_findings) - len(dry_list)} duplicates removed)"
        )

        return dry_list

    async def exploit_dry_list(self) -> List[Dict]:
        """PHASE B: Exploit all DRY findings and emit validated vulnerabilities."""
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        for idx, finding in enumerate(self._dry_findings, 1):
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(self._dry_findings)}] Testing {url} param={parameter}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "PrototypePollution", "param": parameter,
                    "url": url, "idx": idx, "total": len(self._dry_findings),
                })
                self._v.reset("exploit.specialist.progress")

            # Check fingerprint to avoid re-emitting
            fingerprint = generate_protopollution_fingerprint(url, parameter)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                continue

            try:
                self.url = url
                result = await self._test_single_item_from_queue(url, parameter, finding)

                if result:
                    self._emitted_findings.add(fingerprint)

                    if not isinstance(result, dict):
                        result = {
                            "url": url,
                            "parameter": parameter,
                            "type": "PROTOTYPE_POLLUTION",
                            "severity": "HIGH",
                            "validated": True,
                        }

                    validated_findings.append(result)

                    if hasattr(self, '_v'):
                        self._v.emit("exploit.specialist.signature_match", {
                            "agent": "PrototypePollution", "param": parameter,
                            "url": url, "tier": result.get("tier", ""),
                            "technique": result.get("technique", ""),
                        })

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
                        self._v.emit("exploit.specialist.confirmed", {
                            "agent": "PrototypePollution", "param": parameter,
                            "url": url, "payload": result.get("payload", "")[:80],
                        })

                    logger.info(f"[{self.name}] Prototype Pollution confirmed: {url} param={parameter}")
                else:
                    logger.debug(f"[{self.name}] Prototype Pollution not confirmed")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Exploitation failed: {e}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.completed", {
                    "agent": "PrototypePollution", "param": parameter, "url": url,
                })

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, validated_findings: List[Dict]) -> None:
        """Generate specialist report for Prototype Pollution findings."""
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if "/" in self._scan_context else self._scan_context
            scan_dir = settings.BASE_DIR / "reports" / scan_id
        results_dir = scan_dir / "specialists" / "results"

        report = build_specialist_report(
            self.name, self._scan_context,
            self._dry_findings, validated_findings,
        )

        await write_specialist_report(report, results_dir / "prototype_pollution_results.json")

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
        self._v = create_emitter("PrototypePollution", self._scan_context)

        await self._load_prototype_pollution_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")
        self._v.emit("exploit.specialist.started", {"agent": "PrototypePollution", "url": self.url})

        queue = queue_manager.get_queue("prototype_pollution")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "prototype_pollution")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.completed", {"agent": "PrototypePollution", "dry_count": 0, "vulns": 0})
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        # PHASE B
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        vulns_count = len([r for r in results if r]) if results else 0
        vulns_count += len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)

        if hasattr(self, '_v'):
            self._v.emit("exploit.specialist.completed", {
                "agent": "PrototypePollution",
                "dry_count": len(dry_list),
                "vulns": vulns_count,
            })

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

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
        # Reset client-side flags
        self._client_side_pp_confirmed = False
        self._client_side_pp_url = None

        try:
            probe_passed = await smart_probe_pollution(url)

            if not probe_passed:
                parsed = urlparse(url)
                origin_url = f"{parsed.scheme}://{parsed.netloc}/"
                if origin_url != url and origin_url.rstrip('/') != url.rstrip('/'):
                    logger.info(f"[{self.name}] Smart probe: trying origin URL {origin_url}")
                    self.url = origin_url
                    probe_passed = await smart_probe_pollution(origin_url)
                    if probe_passed:
                        url = origin_url

            if not probe_passed:
                return None

            # Client-side PP was confirmed by the browser probe
            if getattr(self, '_client_side_pp_confirmed', False):
                pp_url = getattr(self, '_client_side_pp_url', url)
                logger.info(f"[{self.name}] Client-side PP validated via Playwright on {pp_url}")
                return await exploit_client_side_pp(pp_url, param)

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

        evidence = {
            "pollution_verified": result.get("pollution_confirmed", False),
            "rce_confirmed": result.get("rce_confirmed", False),
            "gadget_chain_confirmed": result.get("gadget_found", False),
            "pollution_attempt": result.get("exploitable", False),
            "vulnerable_pattern": result.get("tier") in ("pollution_detection", "encoding_bypass"),
        }

        status = get_validation_status(evidence)

        url = result.get("url", result.get("test_url"))
        parameter = result.get("param") or result.get("parameter")
        fingerprint = generate_protopollution_fingerprint(url, parameter)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate PROTOTYPE_POLLUTION finding (already reported)")
            return

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

        logger.info(
            f"[{self.name}] Confirmed Prototype Pollution: "
            f"{result.get('url', result.get('test_url'))} "
            f"(RCE: {result.get('rce_confirmed', False)}) [status={status}]"
        )

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

    async def _load_prototype_pollution_tech_context(self) -> None:
        """v3.2.0: Load tech stack context for context-aware detection."""
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
