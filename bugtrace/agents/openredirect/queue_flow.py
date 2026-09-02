"""OpenRedirect agent mixin."""

from __future__ import annotations

import asyncio
import re
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import aiohttp
from bs4 import BeautifulSoup

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
from bugtrace.agents.openredirect_payloads import (
    REDIRECT_PARAMS, PATH_PATTERNS, JS_REDIRECT_PATTERNS,
    META_REFRESH_PATTERN, REDIRECT_STATUS_CODES,
    RANKED_PAYLOADS, get_payloads_for_tier, DEFAULT_ATTACKER_DOMAIN,
)
from bugtrace.agents.openredirect.detection import (
    discover_param_vectors,
    discover_path_vectors,
    analyze_javascript_redirects,
    analyze_meta_refresh,
    is_external_redirect,
    get_technique_name,
    analyze_http_redirect,
    generate_openredirect_fingerprint,
    fallback_fingerprint_dedup,
    get_validation_status,
    validate_before_emit,
)
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig

logger = get_logger("agents.openredirect")


class OpenRedirectQueueMixin:
    """WET→DRY queue consumer, LLM dedup, specialist report."""

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: Global analysis of WET list with LLM dedup + autonomous discovery."""  # I/O
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("openredirect")
        wet_findings: List[Dict] = []

        wait_start = time.monotonic()
        max_wait = 300.0

        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, "depth") else 0
            if depth > 0:
                logger.info(f"[{self.name}] Phase A: Queue has {depth} items, starting drain...")
                break
            await asyncio.sleep(0.5)
        else:
            return []

        empty_count = 0
        max_empty_checks = 10

        while empty_count < max_empty_checks:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)
                continue
            empty_count = 0
            finding = item.get("finding", {})
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")
            if url:
                wet_findings.append({
                    "url": url,
                    "parameter": parameter,
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context),
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")
        if not wet_findings:
            return []

        # Autonomous parameter discovery
        expanded_wet_findings: List[Dict] = []
        seen_urls: set = set()
        seen_params: set = set()

        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            param = wet_item.get("parameter", "") or (wet_item.get("finding", {}) or {}).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                expanded_wet_findings.append(wet_item)

        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                all_params = await self._discover_openredirect_params(url)
                if not all_params:
                    continue
                new_count = 0
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "context": wet_item.get("context", "discovered"),
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True,
                        })
                        new_count += 1
                if new_count:
                    logger.info(f"[{self.name}] Discovered {new_count} additional params on {url}")
            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # Resolve endpoint URLs
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning
        if hasattr(self, "_last_discovery_html") and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
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

        logger.info(
            f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints -> "
            f"{len(expanded_wet_findings)} testable params"
        )

        # Deduplication
        try:
            dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
        except Exception as e:
            logger.error(f"[{self.name}] LLM dedup failed: {e}. Falling back to fingerprint dedup")
            dry_list = fallback_fingerprint_dedup(expanded_wet_findings)

        self._dry_findings = dry_list
        dup_count = len(expanded_wet_findings) - len(dry_list)
        logger.info(
            f"[{self.name}] Phase A: Deduplication complete. "
            f"{len(expanded_wet_findings)} WET -> {len(dry_list)} DRY ({dup_count} duplicates removed)"
        )
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM-powered intelligent deduplication."""  # I/O
        from bugtrace.core.llm_client import llm_client
        import json

        tech_stack = getattr(self, "_tech_stack_context", {}) or {}
        openredirect_prime_directive = getattr(self, "_openredirect_prime_directive", "")
        openredirect_dedup_context = self.generate_openredirect_dedup_context(tech_stack)

        prompt = f"""You are analyzing {len(wet_findings)} potential Open Redirect findings.

{openredirect_prime_directive}

{openredirect_dedup_context}

## DEDUPLICATION RULES FOR OPEN REDIRECT

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Same URL + DIFFERENT param -> DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context -> DIFFERENT (keep both)

2. **Standard Deduplication:**
   - Same URL + Same parameter + Same context -> DUPLICATE (keep best)
   - Different endpoints -> DIFFERENT (keep both)

3. **Prioritization:**
   - Rank by exploitability given the tech stack
   - Remove findings unlikely to succeed

## WET LIST ({len(wet_findings)} findings):
{json.dumps(wet_findings, indent=2)}

## OUTPUT FORMAT (JSON only):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "context": "...",
      "rationale": "why this is unique and exploitable",
      "attack_priority": 1-5,
      "_discovered": true/false
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation"
}}
"""
        response = await llm_client.generate(
            prompt=prompt,
            system_prompt="You are an expert security analyst specializing in Open Redirect deduplication with autonomous parameter discovery.",
            module_name="OPENREDIRECT_DEDUP",
            temperature=0.2,
        )

        try:
            result = json.loads(response)
            findings = result.get("findings", wet_findings)
            logger.debug(
                f"[{self.name}] LLM dedup: {result.get('duplicates_removed', 'unknown')} duplicates removed. "
                f"Reason: {result.get('reasoning', 'N/A')}"
            )
            return findings
        except json.JSONDecodeError:
            logger.warning(f"[{self.name}] LLM returned invalid JSON, using fallback")
            return fallback_fingerprint_dedup(wet_findings)

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Exploit DRY list."""  # I/O
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings: List[Dict] = []

        for idx, finding_data in enumerate(self._dry_findings, 1):
            url = finding_data.get("url", "")
            parameter = finding_data.get("parameter", "")
            finding = finding_data.get("finding", {})

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Testing {url}?{parameter}")

            if hasattr(self, "_v"):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "OpenRedirect", "param": parameter, "url": url,
                    "idx": idx, "total": len(self._dry_findings),
                })
                self._v.reset("exploit.specialist.progress")

            try:
                self.url = url
                result = await self._test_single_param_from_queue(url, parameter, finding)

                if result and result.get("validated"):
                    validated_findings.append(result)
                    fingerprint = generate_openredirect_fingerprint(url, parameter)

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)
                        if settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)
                            self._emit_openredirect_finding({
                                "specialist": "openredirect",
                                "type": "OPEN_REDIRECT",
                                "url": result.get("url"),
                                "parameter": result.get("param"),
                                "payload": result.get("payload"),
                                "status": status,
                                "evidence": result.get("evidence", {"redirect_confirmed": True}),
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                            }, scan_context=self._scan_context)

                        if hasattr(self, "_v"):
                            self._v.emit("exploit.specialist.confirmed", {
                                "agent": "OpenRedirect", "param": parameter,
                                "url": url, "payload": result.get("payload", "")[:80],
                            })
                        logger.info(f"[{self.name}] Emitted unique finding: {url}?{parameter}")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Attack failed: {e}")
                continue

            if hasattr(self, "_v"):
                self._v.emit("exploit.specialist.param.completed", {
                    "agent": "OpenRedirect", "param": parameter, "url": url,
                    "found": result is not None and result.get("validated", False),
                })

        # Phase B.2: DOM-based redirect testing
        logger.info(f"[{self.name}] Phase B.2: Starting DOM redirect tests")
        try:
            dom_findings = await asyncio.wait_for(self._test_dom_redirects(), timeout=90.0)
            for dom_finding in dom_findings:
                fingerprint = generate_openredirect_fingerprint(
                    dom_finding["url"], dom_finding["param"],
                )
                if fingerprint not in self._emitted_findings:
                    self._emitted_findings.add(fingerprint)
                    validated_findings.append(dom_finding)
                    if settings.WORKER_POOL_EMIT_EVENTS:
                        self._emit_openredirect_finding({
                            "specialist": "openredirect",
                            "type": "OPEN_REDIRECT",
                            "url": dom_finding["url"],
                            "parameter": dom_finding["param"],
                            "payload": dom_finding["payload"],
                            "status": dom_finding["status"],
                            "evidence": dom_finding["evidence"],
                            "validation_requires_cdp": False,
                        }, scan_context=self._scan_context)
            logger.info(f"[{self.name}] Phase B.2: DOM redirect testing complete -- {len(dom_findings)} findings")
        except asyncio.TimeoutError:
            logger.warning(f"[{self.name}] Phase B.2: DOM redirect testing TIMEOUT (90s)")
        except Exception as e:
            logger.error(f"[{self.name}] DOM redirect testing failed: {e}", exc_info=True)

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict,
    ) -> Optional[Dict]:
        """Test a single parameter from DRY list (Phase B)."""  # I/O
        if not param:
            logger.warning(f"[{self.name}] Cannot test empty parameter on {url}")
            return None

        if not await self._smart_probe_redirect(url, param):
            return None

        parsed = urlparse(url)
        trusted_domain = parsed.netloc

        for tier in ["basic", "encoding", "whitelist", "advanced"]:
            payloads = get_payloads_for_tier(tier, DEFAULT_ATTACKER_DOMAIN, trusted_domain)
            for payload in payloads:
                if hasattr(self, "_v"):
                    self._v.progress("exploit.specialist.progress", {
                        "agent": "OpenRedirect", "param": param,
                        "tier": tier, "payload": payload[:60],
                    }, every=50)

                result = await self._test_single_payload(param, payload, tier)
                if result and result.get("exploitable"):
                    result["validated"] = True
                    result["param"] = param
                    result["url"] = url
                    evidence = {
                        "location_header_redirect": result.get("method") in ("HTTP_HEADER", "HTTP_HEADER_REFLECTED", "PATH_REDIRECT"),
                        "meta_refresh_redirect": result.get("method") == "META_REFRESH",
                        "js_redirect": result.get("method") in ("JAVASCRIPT", "JAVASCRIPT_DYNAMIC"),
                        "status_code": result.get("status_code"),
                        "external_redirect": True,
                    }
                    result["evidence"] = evidence
                    result["status"] = get_validation_status(evidence)

                    if hasattr(self, "_v"):
                        self._v.emit("exploit.specialist.signature_match", {
                            "agent": "OpenRedirect", "param": param,
                            "tier": tier, "method": result.get("method"),
                            "payload": payload[:80],
                        })

                    logger.info(
                        f"[{self.name}] OPEN REDIRECT confirmed: {param}={payload[:50]} "
                        f"(tier: {tier}, method: {result.get('method')})"
                    )
                    return result

        logger.debug(f"[{self.name}] No open redirect found in parameter '{param}' on {url}")
        return None

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET -> DRY)."""  # I/O
        from bugtrace.agents.specialist_utils import (
            report_specialist_start, report_specialist_done,
            report_specialist_wet_dry, write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("OpenRedirect", self._scan_context)

        await self._load_openredirect_tech_context()

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET -> DRY)")
        self._v.emit("exploit.specialist.started", {"agent": "OpenRedirect", "url": self.url})

        queue = queue_manager.get_queue("openredirect")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        # PHASE A
        dry_list = await self.analyze_and_dedup_queue()
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "openredirect")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            if hasattr(self, "_v"):
                self._v.emit("exploit.specialist.completed", {"agent": "OpenRedirect", "dry_count": 0, "vulns": 0})
            report_specialist_done(self.name, processed=0, vulns=0)
            return

        # PHASE B
        results = await self.exploit_dry_list()
        vulns_count = len([r for r in results if r]) if results else 0
        # dry_findings are CANDIDATES, not confirmations (stable 4074425)
        candidates_count = len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)

        if hasattr(self, "_v"):
            self._v.emit("exploit.specialist.completed", {
                "agent": "OpenRedirect", "dry_count": len(dry_list), "vulns": vulns_count,
            })

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Generate specialist report."""  # I/O
        import json
        import aiofiles
        from datetime import datetime

        scan_dir = getattr(self, "report_dir", None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1]
            scan_dir = settings.BASE_DIR / "reports" / scan_id

        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)

        report = {
            "agent": self.name,
            "timestamp": datetime.now().isoformat(),
            "scan_context": self._scan_context,
            "phase_a": {
                "wet_count": len(self._dry_findings) + (len(findings) if findings else 0),
                "dry_count": len(self._dry_findings),
                "dedup_method": "llm_with_fingerprint_fallback",
            },
            "phase_b": {
                "validated_count": len([f for f in findings if f.get("validated")]),
                "pending_count": len([f for f in findings if not f.get("validated")]),
                "total_findings": len(findings),
            },
            "findings": findings,
        }

        report_path = results_dir / "openredirect_results.json"
        async with aiofiles.open(report_path, "w") as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")
        return str(report_path)

    async def _load_openredirect_tech_context(self) -> None:
        """Load tech stack context for context-aware detection."""  # I/O
        scan_dir = getattr(self, "report_dir", None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if scan_dir:
            tech_stack = self.load_tech_stack(Path(scan_dir))
            self._tech_stack_context = tech_stack
            self._openredirect_prime_directive = self.generate_openredirect_context_prompt(tech_stack)
            if tech_stack:
                logger.info(f"[{self.name}] Tech context loaded: {list(tech_stack.keys())}")
        else:
            logger.debug(f"[{self.name}] No scan_dir available for tech context")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode."""  # I/O
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None
        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_OPENREDIRECT.value, self._on_work_queued,
            )
        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    def get_queue_stats(self) -> dict:
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}
        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }
