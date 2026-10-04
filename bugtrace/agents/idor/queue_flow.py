"""
IDOR Agent - Thin Orchestrator

Orchestrates IDOR (Insecure Direct Object Reference) detection and exploitation.
Delegates pure logic to idor.patterns/payloads/validation/dedup modules
and I/O operations to idor.discovery/exploitation modules.
"""

import asyncio
import json
import time
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.config import settings
from bugtrace.utils.logger import get_logger
from bugtrace.tools.external import external_tools
from bugtrace.core.http_orchestrator import orchestrator, DestinationType
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter

# v3.2.0: Import TechContextMixin for context-aware detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# Extracted modules
from bugtrace.agents.idor.patterns import (
    detect_id_format,
    infer_app_context,
    generate_horizontal_test_ids,
    is_special_account,
    detect_privilege_indicators,
)
from bugtrace.agents.idor.payloads import inject_id, extract_path_id
from bugtrace.agents.idor.validation import (
    validate_idor_finding,
    determine_validation_status,
    analyze_differential,
    analyze_response_diff,
    phase3_impact_analysis,
)
from bugtrace.agents.idor.discovery import discover_idor_params
from bugtrace.agents.idor.exploitation import (
    test_custom_ids_python,
    phase1_retest,
    phase2_http_methods,
    phase4_horizontal_escalation,
    phase5_vertical_escalation,
    wait_for_auth_token,
    fetch_auth_headers,
)
from bugtrace.agents.idor.dedup import (
    generate_idor_fingerprint,
    fallback_fingerprint_dedup,
)

logger = get_logger("agents.idor")



class IDORQueueMixin:
    """Queue consumer / dedup / report for IDORAgent."""

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """Phase A: WET -> DRY with autonomous parameter discovery."""  # I/O
        from bugtrace.core.queue import queue_manager
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list (autonomous discovery) =====")

        queue = queue_manager.get_queue("idor")
        wet_findings = []

        batch_size = settings.IDOR_QUEUE_BATCH_SIZE
        max_wait = settings.IDOR_QUEUE_MAX_WAIT

        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < max_wait:
            depth = queue.depth() if hasattr(queue, 'depth') else 0
            if depth > 0:
                break
            await asyncio.sleep(0.5)
        else:
            return []

        # Drain WET queue
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
                    "original_value": finding.get("original_value", ""),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context),
                })

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")
        if not wet_findings:
            return []

        # Autonomous parameter discovery
        expanded_wet_findings = []
        seen_urls = set()
        seen_params = set()
        seen_mutations = set()

        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            param = wet_item.get("parameter", "") or (wet_item.get("finding", {}) or {}).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                seen_mutations.add(generate_idor_fingerprint(
                    url, param, str(wet_item.get("original_value", ""))
                ))
                expanded_wet_findings.append(wet_item)

        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)
            try:
                all_params = await discover_idor_params(url)
                if not all_params:
                    continue
                for param_name, param_value in all_params.items():
                    mutation = generate_idor_fingerprint(url, param_name, str(param_value))
                    if (url, param_name) not in seen_params and mutation not in seen_mutations:
                        seen_params.add((url, param_name))
                        seen_mutations.add(mutation)
                        expanded_wet_findings.append({
                            "url": url, "parameter": param_name,
                            "original_value": param_value,
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True,
                        })
            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # Resolve endpoint URLs
        if hasattr(self, '_last_discovery_html') and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
                reasoning_map = resolve_param_from_reasoning(expanded_wet_findings, base_url)
                for k, v in reasoning_map.items():
                    if k not in endpoint_map:
                        endpoint_map[k] = v
                if endpoint_map:
                    for item in expanded_wet_findings:
                        if item.get("url") == base_url:
                            param = item.get("parameter", "")
                            if param in endpoint_map and endpoint_map[param] != base_url:
                                item["url"] = endpoint_map[param]

        # Deduplication
        try:
            dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
        except Exception:
            dry_list = fallback_fingerprint_dedup(expanded_wet_findings)

        self._dry_findings = dry_list
        logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET -> {len(dry_list)} DRY")
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """LLM-powered intelligent deduplication."""  # I/O
        from bugtrace.core.llm_client import llm_client

        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        frameworks = tech_stack.get('frameworks', [])

        idor_prime_directive = getattr(self, '_idor_prime_directive', '')
        idor_dedup_context = self.generate_idor_dedup_context(tech_stack) if tech_stack else ''

        system_prompt = f"""You are an expert security analyst specializing in IDOR deduplication.

## DEDUPLICATION RULES
1. Same URL + DIFFERENT param -> DIFFERENT (keep all)
2. Same URL + Same parameter + Same original_value -> DUPLICATE (keep best)
3. Different endpoints -> DIFFERENT (keep both)

{idor_prime_directive}"""

        prompt = f"""Analyzing {len(wet_findings)} potential IDOR findings.

{idor_dedup_context}

## TARGET CONTEXT
- Language: {lang}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'None detected'}

## WET LIST:
{json.dumps(wet_findings, indent=2)}

## OUTPUT FORMAT (JSON only):
{{
  "findings": [
    {{"url": "...", "parameter": "...", "original_value": "...", "rationale": "...", "attack_priority": 1-5}}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation"
}}"""

        response = await llm_client.generate(
            prompt=prompt, system_prompt=system_prompt,
            module_name="IDOR_DEDUP", temperature=0.2,
        )

        try:
            from bugtrace.utils.json_parser import extract_json_list, safe_json_loads
            result = safe_json_loads(response)
            findings = extract_json_list(result, "findings")
            if findings is None:
                return fallback_fingerprint_dedup(wet_findings)
            return fallback_fingerprint_dedup(findings)
        except Exception:
            return fallback_fingerprint_dedup(wet_findings)

    async def exploit_dry_list(self) -> List[Dict]:
        """Phase B: Exploit DRY list."""  # I/O
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")

        self._auth_headers = await fetch_auth_headers(self._scan_context)
        validated_findings = []

        for idx, finding_data in enumerate(self._dry_findings, 1):
            url = finding_data.get("url", "")
            parameter = finding_data.get("parameter", "")
            original_value = finding_data.get("original_value", "")

            logger.info(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: Testing {url}?{parameter}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {
                    "agent": "IDOR", "param": parameter, "url": url,
                    "idx": idx, "total": len(self._dry_findings),
                })
                self._v.reset("exploit.specialist.progress")

            try:
                self.url = url
                result = await self._test_single_param_from_queue(url, parameter, original_value, finding_data.get("finding", {}))

                if result and result.get("status") in [
                    ValidationStatus.VALIDATED_CONFIRMED.value,
                    ValidationStatus.PENDING_VALIDATION.value,
                ]:
                    if settings.IDOR_ENABLE_DEEP_EXPLOITATION:
                        severity = result.get("severity")
                        threshold = settings.IDOR_EXPLOITER_SEVERITY_THRESHOLD
                        severity_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
                        if severity_order.get(severity, 0) >= severity_order.get(threshold, 2):
                            result = await self._exploit_deep(result)

                    validated_findings.append(result)
                    fingerprint = generate_idor_fingerprint(url, parameter, str(original_value))

                    if fingerprint not in self._emitted_findings:
                        self._emitted_findings.add(fingerprint)
                        if settings.WORKER_POOL_EMIT_EVENTS:
                            status = result.get("status", ValidationStatus.VALIDATED_CONFIRMED.value)
                            self._emit_idor_finding({
                                "specialist": "idor", "type": "IDOR",
                                "url": result.get("url"), "parameter": result.get("parameter"),
                                "payload": result.get("payload"),
                                "original_value": result.get("original_value", original_value),
                                "baseline_url": result.get("baseline_url"),
                                "exploit_url": result.get("exploit_url"),
                                "tested_value": result.get("tested_value", result.get("payload")),
                                "severity": result.get("severity"), "status": status,
                                "evidence": result.get("evidence", {"differential_analysis": True}),
                                "validation_requires_cdp": status == ValidationStatus.PENDING_VALIDATION.value,
                            }, scan_context=self._scan_context)

                        if hasattr(self, '_v'):
                            self._v.emit("exploit.specialist.confirmed", {
                                "agent": "IDOR", "param": parameter, "url": url,
                                "severity": result.get("severity"),
                            })

            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}]: Attack failed: {e}")
            finally:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {
                        "agent": "IDOR", "param": parameter, "url": url, "idx": idx,
                    })

        logger.info(f"[{self.name}] Phase B: {len(validated_findings)} validated findings")
        return validated_findings

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        """Generate specialist report."""  # I/O
        import aiofiles
        from datetime import datetime

        scan_dir = getattr(self, 'report_dir', None)
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

        report_path = results_dir / "idor_results.json"
        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps(report, indent=2))

        logger.info(f"[{self.name}] Specialist report saved: {report_path}")
        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET -> DRY)."""  # I/O
        from bugtrace.agents.specialist_utils import (
            report_specialist_start, report_specialist_done,
            report_specialist_wet_dry, write_dry_file,
        )
        from bugtrace.core.queue import queue_manager

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("IDORAgent", self._scan_context)

        await self._load_idor_tech_context()

        queue = queue_manager.get_queue("idor")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)
        self._v.emit("exploit.specialist.started", {"agent": "IDOR", "queue_depth": initial_depth})

        # PHASE A
        dry_list = await self.analyze_and_dedup_queue()
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "idor")

        if not dry_list:
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "IDOR", "dry_count": 0, "vulns": 0})
            return

        # PHASE B
        results = await self.exploit_dry_list()
        vulns_count = len([r for r in results if r]) if results else 0
        # dry_findings are CANDIDATES, not confirmations (stable 4074425)
        candidates_count = len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        report_specialist_done(self.name, processed=len(dry_list), vulns=vulns_count)
        self._v.emit("exploit.specialist.completed", {"agent": "IDOR", "dry_count": len(dry_list), "vulns": vulns_count})

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None
        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _test_single_param_from_queue(self, url, param, original_value, finding) -> Optional[Dict]:
        """Test a single parameter from queue for IDOR."""  # I/O
        try:
            item = {"parameter": param, "original_value": original_value}
            return await self._test_idor_param(item)
        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _handle_queue_result(self, item: dict, result: Optional[Dict]) -> None:
        """Handle completed queue item processing."""
        if result is None:
            return

        finding_data = {
            "context": "idor_differential", "payload": result.get("payload", ""),
            "validation_method": "idor_fuzzer",
            "evidence": {"diff_type": result.get("evidence", "")},
        }
        needs_cdp = requires_cdp_validation(finding_data)

        status = result.get("status", "PENDING_VALIDATION")
        if status == "PENDING_VALIDATION":
            needs_cdp = True

        url = result.get("url")
        parameter = result.get("parameter")
        fingerprint = generate_idor_fingerprint(
            url, parameter, str(result.get("original_value", ""))
        )

        if fingerprint in self._emitted_findings:
            return

        self._emitted_findings.add(fingerprint)

        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_idor_finding({
                "specialist": "idor", "type": "IDOR",
                "url": result.get("url"), "parameter": result.get("parameter"),
                "payload": result.get("payload"),
                "original_value": result.get("original_value", ""),
                "baseline_url": result.get("baseline_url"),
                "exploit_url": result.get("exploit_url"),
                "tested_value": result.get("tested_value", result.get("payload")),
                "status": status,
                "evidence": result.get("evidence", {"differential_analysis": True}),
                "validation_requires_cdp": needs_cdp,
            }, scan_context=self._scan_context)

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}
        return {"mode": "queue", "queue_mode": True, "worker_stats": self._worker_pool.get_stats()}

    async def _load_idor_tech_context(self) -> None:
        """Load technology stack context from recon data (v3.2)."""  # I/O
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._idor_prime_directive = ""
            return

        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._idor_prime_directive = self.generate_idor_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        frameworks = self._tech_stack_context.get("frameworks", [])
        logger.info(f"[{self.name}] IDOR tech context loaded: lang={lang}, frameworks={frameworks[:3] if frameworks else 'none'}")

