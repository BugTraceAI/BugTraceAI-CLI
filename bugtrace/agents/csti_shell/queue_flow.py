"""CSTI queue/dedup/exploit shell.

Shell mixin; hard max 2000 LOC, prefer ~800-1500.
"""

from __future__ import annotations

import asyncio
import aiohttp
import re
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field, asdict

from bugtrace.agents.base import BaseAgent
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.mixins.tech_context import TechContextMixin
from bugtrace.core.ui import dashboard
from bugtrace.core.job_manager import JobStatus
from bugtrace.core.event_bus import EventType
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.llm_client import llm_client
from bugtrace.core.config import settings
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation
from bugtrace.core.verbose_events import create_emitter
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.utils.logger import get_logger
from bugtrace.utils.parsers import XmlParser
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy

logger = get_logger(__name__)

from bugtrace.agents.csti.types import CSTIFinding
from bugtrace.agents.csti.payloads import PAYLOAD_LIBRARY
from bugtrace.agents.csti.fingerprinter import TemplateEngineFingerprinter

class CSTIQueueMixin:
    async def run_loop(self) -> Dict:
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting Template Injection analysis", "INFO")

        all_findings = []

        try:
            await self._prepare_scan()
            all_findings = await self._scan_all_parameters()
            await self._cleanup_scan()
        except Exception as e:
            logger.error(f"CSTIAgent error: {e}", exc_info=True)

        dashboard.log(f"[{self.name}] ✅ Complete. Findings: {len(all_findings)}", "SUCCESS")
        return {"findings": all_findings, "status": JobStatus.COMPLETED}

    async def analyze_and_dedup_queue(self) -> List[Dict]:
        """
        PHASE A: Drain WET findings from queue and deduplicate using LLM + fingerprint fallback.

        Returns:
            List of DRY (deduplicated) findings
        """
        import asyncio
        import time
        from bugtrace.core.queue import queue_manager

        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")

        queue = queue_manager.get_queue("csti")
        wet_findings = []

        # Wait for queue to have items (timeout 300s)
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)

        # Drain all WET findings from queue
        logger.info(f"[{self.name}] Phase A: Queue has {queue.depth() if hasattr(queue, 'depth') else 0} items, starting drain...")

        stable_empty_count = 0
        drain_start = time.monotonic()

        while stable_empty_count < 10 and (time.monotonic() - drain_start) < 300.0:
            item = await queue.dequeue(timeout=0.5)  # Use dequeue(), not get_nowait()

            if item is None:
                stable_empty_count += 1
                continue

            stable_empty_count = 0

            finding = item.get("finding", {}) if isinstance(item, dict) else {}
            if finding:
                wet_findings.append(finding)

        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings from queue")

        if not wet_findings:
            logger.info(f"[{self.name}] Phase A: No findings to process")
            return []

        # Separate auto-dispatch items from real DASTySAST findings.
        # Auto-dispatch items have precise URL+param combos from the pipeline —
        # they should bypass LLM dedup which can mismatch URLs and params.
        auto_dispatch_items = [f for f in wet_findings if f.get("_auto_dispatched")]
        real_items = [f for f in wet_findings if not f.get("_auto_dispatched")]

        # LLM-powered deduplication (only for real DASTySAST findings)
        if real_items:
            dry_list = await self._llm_analyze_and_dedup(real_items, self._scan_context)
        else:
            dry_list = []

        # Fingerprint-dedup auto-dispatch items and add them
        if auto_dispatch_items:
            existing_fps = set()
            for f in dry_list:
                fp = self._generate_csti_fingerprint(
                    f.get("url", ""), f.get("parameter", ""), f.get("template_engine", "unknown")
                )
                existing_fps.add(fp)

            added = 0
            for f in auto_dispatch_items:
                fp = self._generate_csti_fingerprint(
                    f.get("url", ""), f.get("parameter", ""), f.get("template_engine", "unknown")
                )
                if fp not in existing_fps:
                    existing_fps.add(fp)
                    dry_list.append(f)
                    added += 1
            logger.info(f"[{self.name}] Auto-dispatch bypass: {len(auto_dispatch_items)} items, {added} added to DRY list")

        # Store for later phases
        self._dry_findings = dry_list

        logger.info(f"[{self.name}] Phase A: Deduplication complete. {len(wet_findings)} WET → {len(dry_list)} DRY ({len(wet_findings) - len(dry_list)} duplicates removed)")

        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """
        Use LLM to intelligently deduplicate CSTI findings (v3.2: Context-Aware).
        Falls back to fingerprint-based dedup if LLM fails.
        """
        from bugtrace.core.llm_client import llm_client
        import json

        # Extract tech stack info for prompt (v3.2)
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        frameworks = tech_stack.get('frameworks', [])
        waf = tech_stack.get('waf')

        # Get CSTI-specific context prompts
        csti_prime_directive = getattr(self, '_csti_prime_directive', '')
        csti_dedup_context = self.generate_csti_dedup_context(tech_stack) if tech_stack else ''

        # Detect engines for context
        raw_profile = tech_stack.get("raw_profile", {})
        tech_tags = [t.lower() for t in raw_profile.get("tech_tags", [])]
        detected_engines = self._detect_template_engines(frameworks, tech_tags, lang)

        # Build enhanced system prompt with tech context (v3.2)
        system_prompt = f"""You are an expert CSTI/SSTI deduplication analyst with deep knowledge of template engines.

{csti_prime_directive}

{csti_dedup_context}

## TARGET CONTEXT
- Backend Language: {lang}
- Detected Engines: {', '.join(detected_engines) if detected_engines else 'Unknown'}
- WAF: {waf or 'None detected'}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'Unknown'}

Your job is to identify and remove duplicate template injection findings while preserving unique vulnerabilities.
Different template engines represent different attack surfaces - NEVER merge findings with different engines."""

        prompt = f"""Analyze {len(wet_findings)} potential CSTI/SSTI findings.

## WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

## TASK
1. Apply engine-based deduplication rules
2. Distinguish CSTI (client-side: Angular, Vue) from SSTI (server-side: Jinja2, Twig)
3. Prioritize findings for detected engines: {detected_engines or ['generic']}
4. Remove true duplicates (same URL + param + engine)
5. IMPORTANT: For client-side engines (Angular, Vue), multiple params on the SAME PAGE share the same scope. Merge them into ONE finding per page per engine (keep the first param as representative)

## OUTPUT FORMAT (JSON only, no markdown):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "template_engine": "jinja2|twig|angular|vue|freemarker|erb|unknown",
      "injection_type": "SSTI|CSTI",
      "rationale": "why unique",
      "attack_priority": 1-5,
      "recommended_payload": "specific payload for this engine"
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief deduplication strategy"
}}"""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                module_name="CSTI_DEDUP",
                temperature=0.2
            )

            # Parse LLM response
            result = json.loads(response)
            dry_list = result.get("findings", [])

            if dry_list:
                logger.info(f"[{self.name}] LLM deduplication: {result.get('reasoning', 'No reasoning')}")
                logger.info(f"[{self.name}] LLM deduplication successful: {len(wet_findings)} → {len(dry_list)}")
                return dry_list
            else:
                logger.warning(f"[{self.name}] LLM returned empty list, using fallback")
                return self._fallback_fingerprint_dedup(wet_findings)

        except Exception as e:
            logger.warning(f"[{self.name}] LLM deduplication failed: {e}, using fallback")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _normalize_csti_finding_params(self, findings: List[Dict]) -> List[Dict]:
        """
        Normalize synthetic param names from ThinkingConsolidation.

        Some findings have synthetic params like 'URL Path/Fragment', 'None (POST Body)',
        '_auto_discover', 'username password' etc. These are labels, not real query params.
        When the URL already has query params, expand the finding into one per real param.
        This ensures _inject() creates valid URLs for testing.
        """
        normalized = []
        seen_url_param = set()  # Dedup: (url_path, param) pairs

        for finding in findings:
            param = finding.get("parameter", "")
            url = finding.get("url", "")

            is_synthetic = (
                " " in param
                or "/" in param
                or param.startswith("_auto")
                or param.startswith("None")
                or param.startswith("URL ")
                or param.startswith("POST ")
            )

            if is_synthetic:
                parsed = urlparse(url)
                url_params = parse_qs(parsed.query)

                if url_params:
                    for real_param in url_params:
                        key = (parsed.path, real_param)
                        if key not in seen_url_param:
                            seen_url_param.add(key)
                            new_finding = dict(finding)
                            new_finding["parameter"] = real_param
                            new_finding["_original_parameter"] = param
                            normalized.append(new_finding)
                    logger.info(
                        f"[{self.name}] Normalized synthetic param '{param}' on {parsed.path} → {list(url_params.keys())}"
                    )
                else:
                    # No URL params — keep original (auto-discover will handle)
                    key = (parsed.path, param)
                    if key not in seen_url_param:
                        seen_url_param.add(key)
                        normalized.append(finding)
            else:
                parsed = urlparse(url)
                key = (parsed.path, param)
                if key not in seen_url_param:
                    seen_url_param.add(key)
                    normalized.append(finding)
                else:
                    logger.debug(f"[{self.name}] Dedup: skipping duplicate ({parsed.path}, {param})")

        if len(normalized) != len(findings):
            logger.info(f"[{self.name}] Param normalization: {len(findings)} → {len(normalized)} findings")
        return normalized

    async def exploit_dry_list(self) -> List[Dict]:
        """
        PHASE B: 6-Level Escalation Pipeline for each DRY finding.

        v3.4: Each finding goes through L1→L6 escalation,
        each level more expensive but catches more edge cases.

        Returns:
            List of validated findings
        """
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list (6-Level Escalation) =====")
        logger.info(f"[{self.name}] Phase B: Exploiting {len(self._dry_findings)} DRY findings...")

        validated_findings = []

        # Load auth headers from scan_context (JWT tokens from JWTAgent)
        self._auth_headers = {}
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
            self._auth_headers = get_scan_auth_headers(self._scan_context, role="admin") or {}
            if self._auth_headers:
                logger.info(f"[{self.name}] Using admin auth token from JWTAgent")
        except Exception:
            pass

        # Setup Interactsh for OOB detection across all findings
        if not self.interactsh:
            await self._setup_interactsh()

        # Prioritize: 1) non-API real findings (client-side CSTI, fast),
        # 2) SSTI auto-dispatch, 3) client-side auto-dispatch,
        # 4) API endpoints LAST (need JWT from JWTAgent, which runs in parallel)
        real_findings = [f for f in self._dry_findings if not f.get("_auto_dispatched")]
        auto_findings = [f for f in self._dry_findings if f.get("_auto_dispatched")]
        ssti_auto = [f for f in auto_findings if f.get("template_engine") in ("jinja2", "mako", "freemarker", "twig", "erb")
                     or "ssti" in (f.get("reasoning") or "").lower()]
        csti_auto = [f for f in auto_findings if f not in ssti_auto]

        # Separate API endpoints (need auth) from non-API (test without auth)
        real_nonapi = [f for f in real_findings if "/api/" not in f.get("url", "")]
        real_api = [f for f in real_findings if "/api/" in f.get("url", "")]
        ordered_findings = real_nonapi + ssti_auto + csti_auto + real_api

        # Normalize synthetic param names (e.g. "URL Path/Fragment" → actual URL query params)
        ordered_findings = self._normalize_csti_finding_params(ordered_findings)
        api_count = len(real_api)
        logger.info(f"[{self.name}] Phase B: {len(real_findings)} real ({api_count} API→end) + {len(auto_findings)} auto-dispatch ({len(ordered_findings)} after normalization)")

        for idx, finding in enumerate(ordered_findings, 1):
            url = finding.get("url", "")
            parameter = finding.get("parameter", "")

            # API endpoints may have server-side template injection (SSTI)
            # e.g. POST /api/admin/email-preview with Jinja2 rendering
            is_api_endpoint = "/api/" in url
            template_engine = finding.get("template_engine", "unknown")

            logger.info(f"[{self.name}] Phase B: [{idx}/{len(ordered_findings)}] Testing {url} param={parameter} engine={template_engine}")

            if hasattr(self, '_v'):
                self._v.emit("exploit.specialist.param.started", {"agent": "CSTI", "param": parameter, "url": url, "engine": template_engine, "idx": idx, "total": len(self._dry_findings)})
                self._v.reset("exploit.specialist.progress")

            # Check fingerprint to avoid re-emitting
            fingerprint = self._generate_csti_fingerprint(url, parameter, template_engine)
            if fingerprint in self._emitted_findings:
                logger.debug(f"[{self.name}] Phase B: Skipping already emitted finding")
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx, "skipped": True})
                continue

            # For API endpoints: try POST with JSON body + auth (SSTI detection)
            # before falling through to the standard GET-based CSTI pipeline
            if is_api_endpoint:
                # Refresh auth before first API test (JWT may have appeared since Phase B start)
                if not self._auth_headers:
                    try:
                        from bugtrace.services.scan_context import get_scan_auth_headers
                        fresh = get_scan_auth_headers(self._scan_context, role="admin") or {}
                        if fresh:
                            self._auth_headers = fresh
                            logger.info(f"[{self.name}] Refreshed auth before API SSTI tests")
                    except Exception:
                        pass
                try:
                    api_result = await asyncio.wait_for(
                        self._test_api_ssti(url, parameter, finding),
                        timeout=210.0
                    )
                    if api_result and api_result.validated:
                        self._emitted_findings.add(fingerprint)
                        if hasattr(self, '_v'):
                            self._v.emit("exploit.specialist.confirmed", {"agent": "CSTI", "param": parameter, "url": url, "engine": api_result.template_engine, "payload": api_result.payload[:100], "status": "VALIDATED_CONFIRMED"})
                        finding_dict = {
                            "url": api_result.url,
                            "parameter": api_result.parameter,
                            "type": "CSTI",
                            "severity": "CRITICAL" if api_result.engine_type == "server-side" else "HIGH",
                            "template_engine": api_result.template_engine,
                            "engine_type": api_result.engine_type,
                            "payload": api_result.payload,
                            "validated": True,
                            "status": api_result.evidence.get("status", "VALIDATED_CONFIRMED"),
                            "description": f"Template Injection vulnerability detected. Expression '{api_result.payload}' was evaluated by the {api_result.engine_type} engine ({api_result.template_engine}). Method: API_POST_SSTI.",
                            "evidence": api_result.evidence,
                            "successful_payloads": api_result.successful_payloads,
                        }
                        validated_findings.append(finding_dict)
                        if settings.WORKER_POOL_EMIT_EVENTS:
                            self._emit_csti_finding(finding_dict, scan_context=self._scan_context)
                        logger.info(f"[{self.name}] ✅ SSTI confirmed on API endpoint {url} param={parameter}")
                        if hasattr(self, '_v'):
                            self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx})
                        continue
                except asyncio.TimeoutError:
                    logger.debug(f"[{self.name}] API SSTI test timeout for {url[:60]}")
                except Exception as e:
                    logger.debug(f"[{self.name}] API SSTI test failed: {e}")

            # Execute 6-Level CSTI Escalation Pipeline
            # Wrap in asyncio timeout to prevent Playwright deadlocks (max 180s per item)
            # 180s allows full L0→L1→L2→L3→L5 pipeline for client-side engines (Angular/Vue)
            try:
                self.url = url
                try:
                    result = await asyncio.wait_for(
                        self._csti_escalation_pipeline(url, parameter, finding),
                        timeout=180.0
                    )
                except asyncio.TimeoutError:
                    logger.warning(f"[{self.name}] Phase B: TIMEOUT (180s) for {parameter} on {url[:60]}, skipping")
                    result = None

                if result and result.validated:
                    self._emitted_findings.add(fingerprint)

                    if hasattr(self, '_v'):
                        self._v.emit("exploit.specialist.confirmed", {"agent": "CSTI", "param": parameter, "url": url, "engine": result.template_engine, "payload": result.payload[:100], "status": "VALIDATED_CONFIRMED"})

                    finding_dict = {
                        "url": result.url,
                        "parameter": result.parameter,
                        "type": "CSTI",
                        "severity": result.severity,
                        "template_engine": result.template_engine,
                        "engine_type": result.engine_type,
                        "payload": result.payload,
                        "validated": True,
                        "status": "VALIDATED_CONFIRMED",
                        "description": result.description,
                        "evidence": result.evidence if hasattr(result, 'evidence') else {}
                    }

                    # Add alternative payloads if available
                    if result.successful_payloads:
                        finding_dict["successful_payloads"] = result.successful_payloads

                    validated_findings.append(finding_dict)

                    self._emit_csti_finding({
                        "type": "CSTI",
                        "url": result.url,
                        "parameter": result.parameter,
                        "severity": result.severity,
                        "template_engine": result.template_engine,
                        "engine_type": result.engine_type,
                        "payload": result.payload,
                        "evidence": result.evidence if hasattr(result, 'evidence') else {},
                        "arithmetic_proof": result.arithmetic_proof if hasattr(result, 'arithmetic_proof') else False,
                    }, scan_context=self._scan_context)

                    logger.info(f"[{self.name}] ✓ CSTI confirmed: {url} param={parameter} engine={template_engine}")
                else:
                    logger.debug(f"[{self.name}] ✗ CSTI not confirmed after 6-level escalation")

            except Exception as e:
                logger.error(f"[{self.name}] Phase B: Escalation pipeline failed: {e}")
            finally:
                if hasattr(self, '_v'):
                    self._v.emit("exploit.specialist.param.completed", {"agent": "CSTI", "param": parameter, "url": url, "idx": idx})

        logger.info(f"[{self.name}] Phase B: Exploitation complete. {len(validated_findings)} validated findings")
        return validated_findings

    async def start_queue_consumer(self, scan_context: str) -> None:
        """
        TWO-PHASE queue consumer (WET → DRY). NO infinite loop.

        Phase A: Drain ALL findings from queue and deduplicate
        Phase B: Exploit DRY list only

        Args:
            scan_context: Scan identifier for event correlation
        """
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_progress,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )
        from bugtrace.core.queue import queue_manager

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("CSTI", self._scan_context)

        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_csti_tech_context()

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("csti")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)

        self._v.emit("exploit.specialist.started", {"agent": "CSTI", "queue_depth": initial_depth})

        # PHASE A: Analyze and deduplicate
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "csti")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.specialist.completed", {"agent": "CSTI", "processed": 0, "vulns": 0})
            return  # Terminate agent

        # PHASE B: Exploit DRY findings
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting DRY list =====")
        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities (only validated results, not all dry findings)
        vulns_count = len([r for r in results if r]) if results else 0

        # REPORTING: Generate specialist report
        if results or self._dry_findings:
            await self._generate_specialist_report(results)

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )

        self._v.emit("exploit.specialist.completed", {"agent": "CSTI", "processed": len(dry_list), "vulns": vulns_count})

        logger.info(f"[{self.name}] Queue consumer complete: {len(results)} validated findings")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        if self._worker_pool:
            await self._worker_pool.stop()
            self._worker_pool = None

        if self.event_bus:
            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_CSTI.value,
                self._on_work_queued
            )

        self._queue_mode = False
        logger.info(f"[{self.name}] Queue consumer stopped")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_csti notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[CSTIFinding]:
        """
        Process a single item from the csti queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "CSTI",
                "url": "...",
                "parameter": "...",
                "template_engine": "...",  # Optional: detected engine
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

        # Run validation using existing CSTI testing logic
        return await self._test_single_param_from_queue(url, param, finding)

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict
    ) -> Optional[CSTIFinding]:
        """
        Test a single parameter from queue for CSTI.
        """
        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.isolated_session(ConnectionProfile.EXTENDED) as session:
                self._configure_session(session)
                
                # Fetch page for template engine detection
                html = await self._fetch_page(session)

                # Detect template engine
                engines = TemplateEngineFingerprinter.fingerprint(html)

                # Use suggested engine from finding if available
                suggested_engine = finding.get("template_engine")
                if suggested_engine and suggested_engine != "unknown":
                    engines = [suggested_engine] + [e for e in engines if e != suggested_engine]

                # 1. Try the WET finding's payload FIRST
                wet_payload = finding.get("payload") or finding.get("exploitation_strategy") or finding.get("recommended_payload")
                if wet_payload:
                    logger.info(f"[{self.name}] Testing WET payload first: {wet_payload[:50]}...")
                    result = await self._test_wet_finding_payload(session, param, wet_payload, engines)
                    if result:
                        return self._dict_to_finding(result)

                # 2. Test with targeted payloads from library
                if engines and engines[0] != "unknown":
                    result = await self._targeted_probe(session, param, engines)
                    if result:
                        return self._dict_to_finding(result)

                # 3. Universal probe
                result = await self._universal_probe(session, param)
                if result:
                    return self._dict_to_finding(result)

                # 4. API SSTI (v3.5)
                if "/api/" in url or any(p in param.lower() for p in ["template", "body", "email", "preview"]):
                    logger.info(f"[{self.name}] Final attempt: API SSTI test for {url} ({param})")
                    api_result = await self._test_api_ssti(url, param, finding)
                    if api_result:
                        return api_result

                # 5. OOB probe if Interactsh available
                if not self.interactsh:
                    await self._setup_interactsh()
                if self.interactsh_url:
                    result = await self._oob_probe(session, param, engines)
                    if result:
                        return self._dict_to_finding(result)

            # 6. Admin Auth Retry (v3.5)
            # If no result, retry with admin credentials if available
            if hasattr(self, 'cookies') and self.cookies:
                 # Already using captured session, no need to retry with static admin token unless it failed
                 pass

            return None

        except Exception as e:
            logger.error(f"[{self.name}] CSTI test failed for {url}?{param}: {e}")
            return None

    async def _test_wet_finding_payload(
        self, session, param: str, payload: str, engines: List[str]
    ) -> Optional[Dict]:
        """
        Test the specific payload from WET finding.

        This prioritizes payloads that DASTySAST/Skeptic already identified
        as promising, rather than always starting from library payloads.

        v3.2.1 FIX: If payload has single quotes and fails (e.g., 500 error),
        try double-quote variants since some servers reject single quotes.
        """
        dashboard.set_current_payload(payload[:30] + "...", f"CSTI:{param}", "WET Payload")

        content, verified_url = await self._test_payload(session, param, payload)
        # v3.2.2 FIX: Use `is not None` instead of truthiness check
        # because JS-rendered sites return empty string "" which is falsy but valid
        if content is not None:
            # Determine engine from payload
            engine = self._detect_engine_from_payload(payload)
            if engine == "unknown" and engines:
                engine = engines[0]

            finding_obj = self._create_finding(param, payload, "wet_payload_validated", verified_url=verified_url)
            return self._finding_to_dict(finding_obj)

        # v3.2.1 FIX: Try double-quote variants if single-quote payload failed
        # Some servers (e.g., ginandjuice.shop) return 500 error for single quotes
        if "'" in payload:
            # Try replacing single quotes with double quotes
            dq_payload = payload.replace("'", '"')
            logger.info(f"[{self.name}] Single-quote payload failed, trying double-quote variant: {dq_payload[:50]}...")
            dashboard.set_current_payload(dq_payload[:30] + "...", f"CSTI:{param}", "WET DQ Variant")

            content, verified_url = await self._test_payload(session, param, dq_payload)
            if content is not None:
                engine = self._detect_engine_from_payload(dq_payload)
                if engine == "unknown" and engines:
                    engine = engines[0]
                finding_obj = self._create_finding(param, dq_payload, "wet_payload_validated_dq", verified_url=verified_url)
                return self._finding_to_dict(finding_obj)

            # Also try backtick variant for template literals
            bt_payload = payload.replace("'", '`')
            logger.info(f"[{self.name}] Double-quote also failed, trying backtick variant: {bt_payload[:50]}...")
            dashboard.set_current_payload(bt_payload[:30] + "...", f"CSTI:{param}", "WET BT Variant")

            content, verified_url = await self._test_payload(session, param, bt_payload)
            if content is not None:
                engine = self._detect_engine_from_payload(bt_payload)
                if engine == "unknown" and engines:
                    engine = engines[0]
                finding_obj = self._create_finding(param, bt_payload, "wet_payload_validated_bt", verified_url=verified_url)
                return self._finding_to_dict(finding_obj)

        return None

    async def _handle_queue_result(self, item: dict, result: Optional[CSTIFinding]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        Uses centralized validation status to determine if CDP validation is needed.
        """
        if result is None:
            return

        # Use centralized validation status for proper tagging
        # Client-side CSTI (Angular, Vue) may need browser validation
        finding_data = {
            "context": result.engine_type,
            "payload": result.payload,
            "validation_method": result.template_engine,
            "evidence": result.evidence,
        }
        # Use centralized validation status for proper tagging
        # Client-side CSTI (Angular, Vue) may need browser validation
        finding_data = {
            "context": result.engine_type,
            "payload": result.payload,
            "validation_method": result.template_engine,
            "evidence": result.evidence,
        }
        needs_cdp = requires_cdp_validation(finding_data)

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        fingerprint = self._generate_csti_fingerprint(result.url, result.parameter, result.template_engine)

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate CSTI finding (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Emit vulnerability_detected event with validation
        if settings.WORKER_POOL_EMIT_EVENTS:
            self._emit_csti_finding({
                "specialist": "csti",
                "type": "CSTI",
                "url": result.url,
                "parameter": result.parameter,
                "payload": result.payload,
                "template_engine": result.template_engine,
                "evidence": result.evidence if hasattr(result, 'evidence') else {},
                "status": result.status,
                "validation_requires_cdp": needs_cdp,
            }, scan_context=self._scan_context)

        logger.info(f"[{self.name}] Confirmed CSTI: {result.url}?{result.parameter} ({result.template_engine})")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
        }

