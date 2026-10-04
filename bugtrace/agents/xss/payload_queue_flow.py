"""
Payload/param queue testing and analyze-dedup shell.

Shell mixin extracted from xss_agent.py (hard max 1500 LOC per module for agent work).
"""
from __future__ import annotations

# --- shell runtime deps (mixin methods used these from xss_agent module scope) ---
import asyncio
import aiohttp
import json
import re
import urllib.parse
import html as html_module
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Iterable

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation, get_validation_status
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.tools.headless import detect_dom_xss, detect_dom_xss_batch
from bugtrace.tools.external import external_tools
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection
from bugtrace.utils.payload_amplifier import PayloadAmplifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    get_default_severity,
)
from bugtrace.agents.xss import coverage as xss_coverage
from bugtrace.agents.xss.types import XSSFinding, InjectionContext, ValidationMethod
from bugtrace.agents.xss.constants import (
    PROBE_STRING,
    PROBE_STRING_SAFE,
    OMNIPROBE_PAYLOAD,
    GOLDEN_PAYLOADS,
    FRAGMENT_PAYLOADS,
)
from bugtrace.agents.xss.finding_builder import (
    mask_auth_headers as _mask_auth_headers,
    auth_meta as _auth_meta,
    excerpt_around as _excerpt_around,
    build_raw_http as _build_raw_http,
    promote_repro as _promote_repro,
)
from bugtrace.agents.xss.waf import (
    detect_payload_encoding as _pure_detect_payload_encoding,
    record_bypass_result as _pure_record_bypass_result,
    get_waf_optimized_payloads as _pure_get_waf_optimized_payloads,
)
logger = get_logger(__name__)
from bugtrace.agents.xss.shell_constants import (
    _BROWSER_ONLY_CONTEXTS,
    _CDP_PROOF_LOCK,
    _L05_CHAR_PROBE,
    _LEGACY_PROBE_MARKER,
    _PROBE_NO_REFLECTION,
    _PROBE_NO_RESPONSE,
    _PROBE_REFLECTED,
    _REDIRECT_PARAM_SET,
    _REFLECTION_SNIPPET_RADIUS,
)
from bugtrace.agents.xss.context_reflection import (
    as_context_set as _as_context_set,
    canonical_probe_context as _canonical_probe_context,
)
# --- end shell runtime deps ---


def _queue_context(finding: Dict, default: str = "html") -> str:
    """Prefer measured probe context over placeholders or LLM prose."""
    for key in ("probe_context", "xss_context", "context"):
        raw = finding.get(key)
        canonical = _canonical_probe_context(raw)
        if canonical:
            return canonical
        if key == "context" and raw and str(raw).strip().lower() not in {
            "html", "unknown", "none", "no_reflection", "error", "wat",
        }:
            return str(raw).strip()
    return default


class XSSPayloadQueueMixin:
    async def analyze_and_dedup_queue(self) -> List[Dict]:
        import asyncio, time
        from bugtrace.core.queue import queue_manager
        logger.info(f"[{self.name}] ===== PHASE A: Analyzing WET list =====")
        queue = queue_manager.get_queue("xss")
        wet_findings = []
        wait_start = time.monotonic()
        while (time.monotonic() - wait_start) < 300.0:
            if queue.depth() if hasattr(queue, 'depth') else 0 > 0:
                break
            await asyncio.sleep(0.5)
        else:
            return []
        empty_count = 0
        while empty_count < 10:
            item = await queue.dequeue(timeout=0.5)
            if item is None:
                empty_count += 1
                await asyncio.sleep(0.5)
                continue
            empty_count = 0
            finding = item.get("finding", {})
            if finding.get("url") and finding.get("parameter"):
                wet_findings.append({
                    "url": finding["url"],
                    "parameter": finding["parameter"],
                    "context": _queue_context(finding),
                    "finding": finding,
                    "scan_context": item.get("scan_context", self._scan_context),
                })
        logger.info(f"[{self.name}] Phase A: Drained {len(wet_findings)} WET findings")
        if not wet_findings:
            return []

        # ARCHITECTURE: ALWAYS keep original WET params + ADD discovered params
        logger.info(f"[{self.name}] Phase A: Expanding WET findings with XSS-focused discovery...")
        expanded_wet_findings = []
        seen_urls = set()
        seen_params = set()

        # 1. Always include ALL original WET params first (DASTySAST signals)
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            param = wet_item.get("parameter", "") or (wet_item.get("finding", {}) or {}).get("parameter", "")
            if param and (url, param) not in seen_params:
                seen_params.add((url, param))
                # Propagate http_method from finding or default GET
                if "http_method" not in wet_item:
                    wet_item["http_method"] = (wet_item.get("finding", {}) or {}).get("http_method") or "GET"
                expanded_wet_findings.append(wet_item)

        # 2. Discover additional params per unique URL
        for wet_item in wet_findings:
            url = wet_item.get("url", "")
            if url in seen_urls:
                continue
            seen_urls.add(url)

            try:
                all_params = await self._discover_xss_params(url)
                # Gap 3 Fix: Store discovered params for DOM XSS parameter-aware testing
                self._last_all_params = all_params
                if not all_params:
                    continue

                new_count = 0
                param_meta = getattr(self, '_param_metadata', {})
                for param_name, param_value in all_params.items():
                    if (url, param_name) not in seen_params:
                        seen_params.add((url, param_name))
                        pm = param_meta.get(param_name, {})
                        expanded_wet_findings.append({
                            "url": url,
                            "parameter": param_name,
                            "context": wet_item.get("context", "html"),
                            "finding": wet_item.get("finding", {}),
                            "scan_context": wet_item.get("scan_context", self._scan_context),
                            "_discovered": True,
                            "http_method": getattr(self, '_param_methods', {}).get(param_name, "GET"),
                            "param_source": pm.get("source", "unknown"),
                            "form_enctype": pm.get("enctype", ""),
                            "form_action": pm.get("action_url", ""),
                        })
                        new_count += 1

                if new_count:
                    logger.info(f"[{self.name}] 🔍 Discovered {new_count} additional params on {url}")

            except Exception as e:
                logger.error(f"[{self.name}] Discovery failed for {url}: {e}")

        # 2.5 Resolve endpoint URLs from HTML links/forms + reasoning fallback
        from bugtrace.agents.specialist_utils import resolve_param_endpoints, resolve_param_from_reasoning
        if hasattr(self, '_last_discovery_html') and self._last_discovery_html:
            for base_url in seen_urls:
                endpoint_map = resolve_param_endpoints(self._last_discovery_html, base_url)
                # Fallback: extract endpoints from DASTySAST reasoning text
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
                        logger.info(f"[{self.name}] 🔗 Resolved {resolved_count} params to actual endpoint URLs")

        logger.info(f"[{self.name}] Phase A: Expanded {len(wet_findings)} hints → {len(expanded_wet_findings)} testable params")

        # Now deduplicate the expanded list
        try:
            dry_list = await self._llm_analyze_and_dedup(expanded_wet_findings, self._scan_context)
        except:
            dry_list = self._fallback_fingerprint_dedup(expanded_wet_findings)
        self._dry_findings = dry_list
        logger.info(f"[{self.name}] Phase A: {len(expanded_wet_findings)} WET → {len(dry_list)} DRY ({len(expanded_wet_findings)-len(dry_list)} duplicates removed)")
        return dry_list

    async def _llm_analyze_and_dedup(self, wet_findings: List[Dict], context: str) -> List[Dict]:
        """
        Call LLM to analyze WET list and generate DRY list (v3.2: Context-Aware).

        Uses tech stack context for intelligent XSS-specific filtering.
        """
        from bugtrace.core.llm_client import llm_client
        import json

        # Extract tech stack info for prompt
        tech_stack = getattr(self, '_tech_stack_context', {}) or {}
        lang = tech_stack.get('lang', 'generic')
        server = tech_stack.get('server', 'generic')
        waf = tech_stack.get('waf')
        frameworks = tech_stack.get('frameworks', [])

        # Get XSS-specific context prompts
        xss_prime_directive = getattr(self, '_xss_prime_directive', '')
        xss_dedup_context = self.generate_xss_dedup_context(tech_stack) if tech_stack else ''

        # Build enhanced system prompt with tech context (v3.2)
        system_prompt = f"""You are an expert XSS security analyst with deep knowledge of web frameworks.

{xss_prime_directive}

{xss_dedup_context}

## TARGET CONTEXT
- Backend Language: {lang}
- Web Server: {server}
- WAF: {waf or 'None detected'}
- Frameworks: {', '.join(frameworks[:3]) if frameworks else 'Unknown'}

## WET LIST ({len(wet_findings)} potential XSS findings):
{json.dumps(wet_findings, indent=2)}

## TASK
1. Analyze each finding considering the injection context (HTML body, attribute, JS, etc.)
2. **CRITICAL - Framework Detection from Findings:**
   - ALWAYS check each item's nested "finding.reasoning" field for framework mentions
   - Look for: AngularJS, Angular, Vue, React, Ember, Svelte in the reasoning text
   - If reasoning mentions "AngularJS" or "Angular 1.x" → recommended_payload_type: "template"
   - If reasoning mentions "Vue" → recommended_payload_type: "template"
   - If reasoning mentions "React" → recommended_payload_type: "template"
   - Template payloads like {{constructor.constructor('alert(1)')()}} bypass framework sandboxes
   - Event handlers (onclick, onerror, onfocus) are BLOCKED by Angular/Vue/React CSP
   - THIS IS CRITICAL: Event handler payloads WILL FAIL on these frameworks
3. Apply context-aware deduplication:
   - **CRITICAL:** If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param → DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context type → DIFFERENT (keep both)
   - Different endpoints → DIFFERENT (keep both)
   - ONLY mark as DUPLICATE if: Same URL + Same param + Same context
4. Prioritize findings based on framework exploitability
5. Filter findings unlikely to succeed given the tech stack
6. **ATTACK STRATEGY REASONING**: For each finding, reason about the BEST way to attack it:
   - Consider the http_method (GET vs POST — POST params must be sent in form body, not URL)
   - Consider the param_source (form_input, url_query, anchor_href)
   - Consider form_enctype if present (multipart vs url-encoded)
   - Consider the reflection context and server escaping behavior from the reasoning
   - Example: "POST form param reflecting unescaped in HTML text. Use visual DOM payload via POST body."
   - Example: "GET param in JS single-quoted string. Server escapes backslash to double-backslash but NOT quotes. Backslash-quote breakout: \\' followed by JS payload."

## OUTPUT FORMAT (JSON only, no markdown):
{{
  "findings": [
    {{
      "url": "...",
      "parameter": "...",
      "context": "html_body|attribute|javascript|url|css",
      "http_method": "GET or POST (preserve from input, default GET)",
      "attack_strategy": "Brief reasoning about HOW to exploit this param considering method, context, escaping",
      "rationale": "why this is unique and exploitable",
      "attack_priority": 1-5,
      "recommended_payload_type": "svg|img|script|event_handler|template"
    }}
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation of deduplication strategy"
}}"""

        try:
            response = await llm_client.generate(
                prompt="Analyze the WET list above and return deduplicated XSS findings in JSON format.",
                system_prompt=system_prompt,
                module_name="XSS_DEDUP",
                temperature=0.2
            )

            from bugtrace.utils.json_parser import extract_json_list, safe_json_loads

            dry_data = safe_json_loads(response)
            dry_list = extract_json_list(dry_data, "findings")
            if dry_list is None:
                logger.warning(f"[XSSAgent] LLM deduplication returned invalid JSON, using fingerprint fallback")
                dry_list = wet_findings

            # Post-LLM merge: ensure deterministic fields are preserved (LLM may drop them)
            wet_meta_map = {}
            for wf in wet_findings:
                key = (wf.get("url", ""), wf.get("parameter", ""))
                wet_meta_map[key] = {
                    "http_method": wf.get("http_method", "GET"),
                    "param_source": wf.get("param_source", ""),
                    "form_enctype": wf.get("form_enctype", ""),
                    "form_action": wf.get("form_action", ""),
                    "context": _queue_context(wf),
                }
            for df in dry_list:
                key = (df.get("url", ""), df.get("parameter", ""))
                wet_meta = wet_meta_map.get(key, {})
                llm_context = _canonical_probe_context(df.get("context"))
                if llm_context:
                    df["context"] = llm_context
                elif not df.get("context") or str(df.get("context")).lower() in {"html", "unknown"}:
                    df["context"] = wet_meta.get("context", "html")
                if not df.get("http_method"):
                    df["http_method"] = wet_meta.get("http_method", "GET")
                if not df.get("param_source"):
                    df["param_source"] = wet_meta.get("param_source", "")
                if not df.get("form_enctype"):
                    df["form_enctype"] = wet_meta.get("form_enctype", "")
                if not df.get("form_action"):
                    df["form_action"] = wet_meta.get("form_action", "")

            logger.info(f"[{self.name}] LLM deduplication: {dry_data.get('reasoning', 'No reasoning provided')}")
            return dry_list

        except Exception as e:
            logger.error(f"[{self.name}] LLM deduplication failed: {e}. Falling back to fingerprint dedup.")
            return self._fallback_fingerprint_dedup(wet_findings)

    async def _test_single_param_from_queue(
        self, url: str, param: str, finding: dict, payload_type: str = None
    ) -> Optional[XSSFinding]:
        """
        Test a single parameter from queue for XSS.

        Uses existing validation pipeline but optimized for queue processing:
        1. Check reflection context from finding
        2. Select appropriate payloads for context (or payload_type if provided)
        3. Test with HTTP-first validation (Phase 15)
        4. Fall back to Playwright/CDP only if needed

        Args:
            url: Target URL
            param: Parameter to test
            finding: Finding data from queue
            payload_type: Optional payload type from LLM dedup (template, event_handler, etc.)

        Returns:
            XSSFinding if confirmed, None otherwise
        """
        try:
            # Get context from finding if available
            context = finding.get("context", "unknown")

            # v3.2: If payload_type is 'template' (AngularJS/Vue), override context
            if payload_type == "template":
                context = "template"
                logger.info(f"[{self.name}] Using template payloads for framework injection (Angular/Vue)")

            # v2.1.0: Load full payload from JSON if truncated in event
            suggested_payload = load_full_payload_from_json(finding)

            # Initialize Interactsh if not already done
            if not self.interactsh:
                try:
                    self.interactsh = InteractshClient()
                    await self.interactsh.register()
                except Exception as e:
                    logger.warning(f"[{self.name}] Interactsh init failed: {e}")

            interactsh_url = self.interactsh.get_url() if self.interactsh else ""

            # Build payload list - CURATED FIRST (agnostic, fast)
            # v3.2: Curated payloads FIRST (833 proven payloads, technology-agnostic)
            # This is faster than LLM context manipulation and covers most cases
            curated = self.payload_learner.get_prioritized_payloads([])[:20]
            curated = [p.replace("{{interactsh_url}}", interactsh_url) for p in curated]

            payloads = list(curated)  # Start with curated

            # Then suggested payload from finding (if not already in curated)
            if suggested_payload and suggested_payload not in payloads:
                payloads.insert(0, suggested_payload)  # Prioritize suggested

            # Add context-specific payloads as fallback
            context_payloads = self.get_payloads_for_context(context, interactsh_url)
            for p in context_payloads[:5]:
                if p not in payloads:
                    payloads.append(p)

            # Dedupe payloads (already mostly deduped, but ensure)
            seen = set()
            unique_payloads = []
            for p in payloads:
                if p not in seen:
                    seen.add(p)
                    unique_payloads.append(p)

            # v3.3: BOMBARDMENT-FIRST - fire all payloads via HTTP, browser only as fallback
            # Phase 1: HTTP bombardment - fast, no browser
            http_confirmed = []
            reflecting_payloads = []  # Payloads that reflect but HTTP couldn't confirm

            for payload in unique_payloads[:25]:
                result = await self._test_payload_http_only(url, param, payload, context)
                if result:
                    if result.validated:
                        http_confirmed.append(result)
                    else:
                        reflecting_payloads.append(result)

            # If ANY HTTP-confirmed → return best one (no browser needed)
            if http_confirmed:
                logger.info(f"[{self.name}] HTTP confirmed {len(http_confirmed)} XSS for {param}, skipping browser")
                return http_confirmed[0]

            # Check Interactsh for OOB confirmations (batch poll)
            if self.interactsh:
                try:
                    interactions = await self.interactsh.poll()
                    if interactions:
                        # Find the interactsh payload that triggered
                        for rp in reflecting_payloads:
                            if self._payload_carries_oob(rp.payload):
                                return XSSFinding(
                                    url=url, parameter=param, payload=rp.payload,
                                    context=context, validation_method="interactsh",
                                    evidence={"oob_callback": True, "interactions": interactions},
                                    confidence=1.0, status="VALIDATED_CONFIRMED", validated=True
                                )
                except Exception as e:
                    logger.debug(f"[{self.name}] Interactsh poll failed: {e}")

            # Phase 2: Browser fallback - only for reflecting payloads, max 3
            if reflecting_payloads:
                logger.info(f"[{self.name}] {len(reflecting_payloads)} payloads reflect for {param}, trying browser on top 3")
                for rp in reflecting_payloads[:3]:
                    try:
                        browser_result = await self._validate_via_browser(url, param, rp.payload)
                        if browser_result:
                            return XSSFinding(
                                url=url, parameter=param, payload=rp.payload,
                                context=context, validation_method="browser",
                                evidence=browser_result, confidence=0.95,
                                status="VALIDATED_CONFIRMED", validated=True
                            )
                    except Exception as e:
                        logger.debug(f"[{self.name}] Browser validation failed: {e}")

                # Phase 3: Visual fallback - only if browser also failed
                best_reflection = reflecting_payloads[0]
                reflection_context = self._analyze_reflection_context(
                    best_reflection.evidence.get("response_html", ""), best_reflection.payload
                )
                contexts_found = [reflection_context.get("context", "unknown")]
                visual_payloads = await self._ask_deepseek_visual_payloads(
                    param=param, contexts=contexts_found,
                    sample_payloads={contexts_found[0]: best_reflection.payload}
                )
                if visual_payloads:
                    logger.info(f"[{self.name}] Testing {len(visual_payloads)} visual payloads...")
                    screenshots_dir = self.report_dir / "captures"
                    screenshots_dir.mkdir(parents=True, exist_ok=True)
                    for i, vp in enumerate(visual_payloads[:5]):
                        dashboard.set_current_payload(vp[:50], "XSS Visual", f"[{i+1}/5]", self.name)
                        ev = await self._validate_visual_payload(param=param, payload=vp, screenshots_dir=screenshots_dir)
                        if ev and ev.get("vision_confirmed"):
                            return XSSFinding(
                                url=url, parameter=param, payload=vp, context=context,
                                validation_method="visual_vision_ai", evidence=ev,
                                confidence=0.98, status="VALIDATED_CONFIRMED", validated=True
                            )

            return None

        except Exception as e:
            logger.error(f"[{self.name}] Queue item test failed: {e}")
            return None

    async def _test_with_manipulator(
        self, url: str, param: str, screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """
        v3.3: Use ManipulatorOrchestrator as the Python HTTP attack engine.

        This replaces the naive 25-payload loop with a full multi-phase campaign:
        - Phase 0: Context detection (where does probe reflect?)
        - Phase 1a: Static payload bombardment (PayloadAgent)
        - Phase 1b: LLM expansion × context-aware breakouts
        - Phase 2: WAF bypass encoding (Q-learning)
        - Phase 3: Blood smell analysis + agentic fallback

        If ManipulatorOrchestrator confirms via HTTP → return XSSFinding.
        If blood smell detected but not confirmed → browser validation fallback.
        """
        try:
            # Build MutableRequest from finding
            parsed = urllib.parse.urlparse(url)
            base_params = dict(urllib.parse.parse_qsl(parsed.query))
            # Ensure target param exists with a test value
            if param not in base_params:
                base_params[param] = "test"

            base_request = MutableRequest(
                method="GET",
                url=url.split("?")[0],  # Base URL without query string
                params=base_params
            )

            # Initialize ManipulatorOrchestrator with LLM and agentic fallback
            manipulator = ManipulatorOrchestrator(
                rate_limit=0.3,
                enable_agentic_fallback=True,
                enable_llm_expansion=True
            )

            dashboard.log(
                f"[{self.name}] ManipulatorOrchestrator: Starting HTTP campaign on '{param}'",
                "INFO"
            )

            # Run full campaign (Phases 0-3)
            success, mutation = await manipulator.process_finding(
                base_request,
                strategies=[MutationStrategy.PAYLOAD_INJECTION, MutationStrategy.BYPASS_WAF]
            )

            if success and mutation:
                # HTTP confirmed! Extract the working payload
                working_payload = mutation.params.get(param, str(mutation.params))
                logger.info(f"[{self.name}] ManipulatorOrchestrator CONFIRMED XSS: {param}={working_payload[:80]}")

                return XSSFinding(
                    url=url, parameter=param, payload=working_payload,
                    context="html", validation_method="manipulator_http",
                    evidence={"http_confirmed": True, "method": "ManipulatorOrchestrator"},
                    confidence=0.90, status="VALIDATED_CONFIRMED", validated=True
                )

            # ManipulatorOrchestrator failed - check blood smell for browser candidates
            if manipulator.blood_smell_history:
                blood_candidates = sorted(
                    manipulator.blood_smell_history,
                    key=lambda x: x["smell"]["severity"],
                    reverse=True
                )[:3]

                logger.info(
                    f"[{self.name}] ManipulatorOrchestrator: {len(blood_candidates)} blood smell "
                    f"candidates, trying browser validation"
                )

                for entry in blood_candidates:
                    blood_payload = entry["request"].params.get(param, "")
                    if not blood_payload:
                        continue
                    try:
                        browser_result = await self._validate_via_browser(url, param, blood_payload)
                        if browser_result:
                            return XSSFinding(
                                url=url, parameter=param, payload=blood_payload,
                                context="html", validation_method="manipulator_blood_browser",
                                evidence=browser_result, confidence=0.95,
                                status="VALIDATED_CONFIRMED", validated=True
                            )
                    except Exception as e:
                        logger.debug(f"[{self.name}] Blood browser validation failed: {e}")

            # Last resort: visual payloads (DeepSeek + Vision AI)
            logger.info(f"[{self.name}] ManipulatorOrchestrator exhausted, trying visual fallback")
            visual_payloads = await self._ask_deepseek_visual_payloads(
                param=param, contexts=["html"],
                sample_payloads={"html": f"<img src=x onerror=alert(1)>"}
            )
            if visual_payloads:
                for vp in visual_payloads[:5]:
                    dashboard.set_current_payload(vp[:50], "XSS Visual", "Testing", self.name)
                    ev = await self._validate_visual_payload(
                        param=param, payload=vp, screenshots_dir=screenshots_dir
                    )
                    if ev and ev.get("vision_confirmed"):
                        return XSSFinding(
                            url=url, parameter=param, payload=vp, context="html",
                            validation_method="visual_vision_ai", evidence=ev,
                            confidence=0.98, status="VALIDATED_CONFIRMED", validated=True
                        )

            await manipulator.shutdown()
            return None

        except Exception as e:
            logger.error(f"[{self.name}] ManipulatorOrchestrator campaign failed: {e}")
            # Fallback to simple queue test if manipulator crashes
            return await self._test_single_param_from_queue(url, param, {})

    async def _test_payload_from_queue(
        self, url: str, param: str, payload: str, context: str
    ) -> Optional[XSSFinding]:
        """
        Test a single payload against a parameter.

        Uses HTTP-first validation from Phase 15 for efficiency.

        Args:
            url: Target URL
            param: Parameter to test
            payload: XSS payload to test
            context: Reflection context

        Returns:
            XSSFinding if confirmed, None otherwise
        """
        try:
            # Update UI
            dashboard.set_current_payload(payload[:60], "XSS Queue", "Testing", self.name)

            # Send payload
            response_html = await self._send_payload(param, payload)

            if not response_html:
                return None

            # HTTP-first validation (Phase 15)
            evidence = {}
            if self._can_confirm_from_http_response(payload, response_html, evidence):
                return XSSFinding(
                    url=url,
                    parameter=param,
                    payload=payload,
                    context=context,
                    validation_method="http_analysis",
                    evidence={"http_confirmed": True, "reflection": self._payload_reflects(payload, response_html)},
                    confidence=0.85,
                    status="VALIDATED_CONFIRMED",
                    validated=True
                )

            # Check if browser validation needed - only if payload actually reflects
            if self._payload_reflects(payload, response_html) and self._requires_browser_validation(payload, response_html):
                # Attempt Playwright validation
                try:
                    browser_result = await self._validate_via_browser(url, param, payload)
                    if browser_result:
                        return XSSFinding(
                            url=url,
                            parameter=param,
                            payload=payload,
                            context=context,
                            validation_method="browser",
                            evidence=browser_result,
                            confidence=0.95,
                            status="VALIDATED_CONFIRMED",
                            validated=True
                        )
                except Exception as e:
                    logger.debug(f"[{self.name}] Browser validation failed: {e}")

            # Check Interactsh for OOB confirmation
            if self.interactsh and "interactsh" in payload.lower():
                await asyncio.sleep(2)  # Wait for callback
                try:
                    interactions = await self.interactsh.poll()
                    if interactions:
                        return XSSFinding(
                            url=url,
                            parameter=param,
                            payload=payload,
                            context=context,
                            validation_method="interactsh",
                            evidence={"oob_callback": True, "interactions": interactions},
                            confidence=1.0,
                            status="VALIDATED_CONFIRMED",
                            validated=True
                        )
                except Exception as e:
                    logger.debug(f"[{self.name}] Interactsh poll failed: {e}")

            # v3.2: Visual validation fallback - generate visual payloads and use Vision AI
            # This is the BULLETPROOF validation when HTTP/browser don't confirm
            if self._payload_reflects(payload, response_html):
                logger.info(f"[{self.name}] Payload reflects but not confirmed. Trying visual validation...")
                dashboard.log(f"[{self.name}] 🎨 Testing visual validation with Vision AI...", "INFO")

                # Get reflection context for visual payload generation
                reflection_context = self._analyze_reflection_context(response_html, payload)
                contexts_found = [reflection_context.get("context", "unknown")]

                # Generate visual payloads via DeepSeek
                visual_payloads = await self._ask_deepseek_visual_payloads(
                    param=param,
                    contexts=contexts_found,
                    sample_payloads={contexts_found[0]: payload}
                )

                if visual_payloads:
                    logger.info(f"[{self.name}] Testing {len(visual_payloads)} visual payloads...")
                    screenshots_dir = self.report_dir / "captures"
                    screenshots_dir.mkdir(parents=True, exist_ok=True)

                    for i, visual_payload in enumerate(visual_payloads[:5]):  # Max 5 visual payloads
                        dashboard.set_current_payload(
                            visual_payload[:50], "XSS Visual", f"Testing [{i+1}/5]", self.name
                        )

                        evidence = await self._validate_visual_payload(
                            param=param,
                            payload=visual_payload,
                            screenshots_dir=screenshots_dir
                        )

                        if evidence and evidence.get("vision_confirmed"):
                            logger.info(f"[{self.name}] ✅ Vision AI confirmed XSS!")
                            dashboard.log(f"[{self.name}] ✅ Vision AI CONFIRMED visual XSS!", "SUCCESS")
                            return XSSFinding(
                                url=url,
                                parameter=param,
                                payload=visual_payload,
                                context=context,
                                validation_method="visual_vision_ai",
                                evidence=evidence,
                                confidence=0.98,
                                status="VALIDATED_CONFIRMED",
                                validated=True
                            )

            # v3.2: CANDIDATE fallback - if payload reflects but couldn't be confirmed
            # This prevents losing findings that automated tools can't validate
            # but a human pentester should review
            if self._payload_reflects(payload, response_html):
                # Check if it's in a potentially dangerous context
                dangerous_contexts = [
                    '<script', 'javascript:', 'on', '{{', '${',
                    'href=', 'src=', 'action='
                ]
                in_dangerous_context = any(
                    ctx in response_html.lower() and payload.lower() in response_html.lower()
                    for ctx in dangerous_contexts
                )

                if in_dangerous_context:
                    logger.info(
                        f"[{self.name}] Payload reflects in potentially dangerous context "
                        f"but couldn't be auto-confirmed. Marking as CANDIDATE."
                    )
                    return XSSFinding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        context=context,
                        validation_method="reflection_analysis",
                        evidence={
                            "reflected": True,
                            "auto_confirmed": False,
                            "reason": "Payload reflects in dangerous context but execution not confirmed"
                        },
                        confidence=0.6,
                        status="CANDIDATE",
                        validated=False
                    )

            return None

        except Exception as e:
            logger.debug(f"[{self.name}] Payload test failed: {e}")
            return None

    async def exploit_dry_list(self) -> List[Dict]:
        logger.info(f"[{self.name}] ===== PHASE B: Exploiting {len(self._dry_findings)} DRY findings =====")

        # Setup Interactsh
        if not self.interactsh:
            try:
                self.interactsh = InteractshClient()
                await self.interactsh.register()
            except Exception as e:
                logger.warning(f"[{self.name}] Interactsh init failed: {e}")

        interactsh_url = ""
        if self.interactsh:
            try:
                interactsh_url = self.interactsh.get_url() if hasattr(self.interactsh, 'get_url') else ""
            except Exception:
                pass

        # Screenshots dir
        screenshots_dir = self.report_dir / "captures"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        _scan_root_url = self.url  # loop reassigns self.url per-finding; restore for Phase B.2/B.3
        # Worker/queue mode: this agent is created with url="" (team.py) and self.url is never
        # set to the target — so _scan_root_url would be "" and Phase B.2 DOM XSS would scan an
        # empty URL, never testing the real frontend (e.g. https://host/ where
        # ?search=<img onerror> -> dangerouslySetInnerHTML). Derive the scan-root origin from the
        # DRY candidates. (Fixes 3.6.1-beta regression: the restore-to-self.url assumed self.url
        # held the scan root, which is only true for the non-queue run_loop path.)
        if not _scan_root_url and self._dry_findings:
            _p = urllib.parse.urlparse(self._dry_findings[0].get("url", ""))
            if _p.scheme and _p.netloc:
                _scan_root_url = f"{_p.scheme}://{_p.netloc}/"
        validated = []
        for idx, f in enumerate(self._dry_findings, 1):
            try:
                self.url = f["url"]
                param_name = f["parameter"]

                # Read reflection context and HTTP method from DRY finding
                finding_context = _queue_context(f)
                probe_snippet = f.get("_probe_snippet", "")
                http_method = f.get("http_method", "GET")

                # Log LLM attack strategy if available
                attack_strategy = f.get("attack_strategy", "")
                if attack_strategy:
                    logger.info(f"[{self.name}] LLM strategy for '{param_name}': {attack_strategy}")

                logger.info(f"[{self.name}] [{idx}/{len(self._dry_findings)}] Testing '{param_name}' on {self.url} (method: {http_method}, context: {finding_context})")
                if hasattr(self, '_v'):
                    self._v.emit("exploit.xss.param.started", {"param": param_name, "url": self.url, "index": idx, "total": len(self._dry_findings), "context": finding_context, "method": http_method})
                    self._v.reset("exploit.xss.level.progress")

                # v3.4: 6-Level Escalation Pipeline
                result = await self._xss_escalation_pipeline(
                    self.url, param_name, interactsh_url, screenshots_dir,
                    context=finding_context, probe_snippet=probe_snippet,
                    http_method=http_method
                )

                if result and result.validated:
                    fp = self._generate_xss_fingerprint(self.url, param_name, result.context or "html")
                    if fp not in self._emitted_findings:
                        needs_cdp = (result.status == "NEEDS_CDP_VALIDATION")
                        result_evidence = dict(result.evidence) if isinstance(result.evidence, dict) else {}
                        result_evidence.setdefault("validated", True)
                        finding_dict = {
                            "type": "XSS",
                            "url": result.url,
                            "parameter": result.parameter,
                            "payload": result.payload,
                            "context": result.context,
                            "evidence": result_evidence,
                        }
                        emitted = self._emit_xss_finding(
                            finding_dict,
                            status=result.status or ValidationStatus.VALIDATED_CONFIRMED.value,
                            needs_cdp=needs_cdp
                        )
                        # Mirror stable — a validated reflected XSS survives an emit
                        # proof-gate rejection so it still reaches the specialist report,
                        # where _capture_proof_screenshot can attach the banner PoC.
                        self._emitted_findings.add(fp)
                        validated.append(result)
                        if emitted:
                            logger.info(f"[{self.name}] ✅ Emitted XSS: {self.url}?{param_name} (level: {result.evidence.get('level', '?')}, context: {result.context or 'html'})")
                            if hasattr(self, '_v'):
                                self._v.emit("exploit.xss.confirmed", {"param": param_name, "url": self.url, "level": result.evidence.get("level", "unknown"), "context": result.context or "html", "payload": result.payload[:80]})
                        else:
                            logger.warning(
                                f"[{self.name}] ⚠️  XSS NOT emitted (rejected by validate/emit): "
                                f"{self.url}?{param_name} (level: {result.evidence.get('level', '?')}) "
                                "— still reaches report via specialist results file"
                            )
                if hasattr(self, '_v'):
                    self._v.emit("exploit.xss.param.completed", {"param": param_name, "url": self.url, "confirmed": bool(result and result.validated)})
            except Exception as e:
                logger.error(f"[{self.name}] Phase B [{idx}/{len(self._dry_findings)}]: {e}")
        logger.info(f"[{self.name}] Phase B complete: {len(validated)} validated")
        self.url = _scan_root_url  # restore: loop above mutated self.url to the last DRY finding

        # NEGATIVE EVIDENCE: written here, before Phase B.2/B.3, so a later phase raising
        # cannot take the record of what Phase B actually did down with it.
        self._write_xss_coverage()

        # Phase B.2: DOM XSS testing (Playwright) - tests self.url + discovered internal URLs
        try:
            screenshots_dir = None
            if hasattr(self, 'report_dir') and self.report_dir:
                screenshots_dir = Path(self.report_dir) / "screenshots"
                screenshots_dir.mkdir(parents=True, exist_ok=True)
            await self._loop_test_dom_xss(screenshots_dir=screenshots_dir)
            # Collect DOM XSS findings and emit them
            for f in self.findings:
                if f.context == "dom_xss" and f.validated:
                    _ev = f.evidence or {}
                    fp = self._generate_xss_fingerprint(
                        f.url, f.parameter, "dom_xss",
                        sink=_ev.get("sink"), source=_ev.get("source")
                    )

                    # Global XSS root cause grouping (e.g., postMessage->eval on shared JS)
                    if fp[0] == "XSS_GLOBAL":
                        if fp in self._global_xss_findings:
                            if f.url not in self._global_xss_findings[fp]:
                                self._global_xss_findings[fp].append(f.url)
                            logger.info(f"[{self.name}] Global DOM XSS dedup: added {f.url} to root cause {fp[2]} "
                                       f"(now {len(self._global_xss_findings[fp])} affected URLs)")
                            continue  # Don't emit duplicate — already reported this root cause
                        else:
                            self._global_xss_findings[fp] = [f.url]
                            logger.info(f"[{self.name}] Global DOM XSS detected: root cause {fp[2]} on {f.url}")

                    if fp not in self._emitted_findings:
                        self._emitted_findings.add(fp)
                        evidence = f.evidence or {"validated": True, "level": "dom_xss"}
                        # For global XSS, include root cause and affected URLs in evidence
                        if fp[0] == "XSS_GLOBAL":
                            evidence = dict(evidence)  # Copy to avoid mutating original
                            evidence["root_cause"] = fp[2]
                            evidence["affected_urls"] = self._global_xss_findings[fp]
                        finding_dict = {
                            "type": "XSS",
                            "subtype": "DOM_XSS",
                            "url": f.url,
                            "parameter": f.parameter,
                            "payload": f.payload,
                            "context": "dom_xss",
                            "evidence": evidence
                        }
                        emitted = self._emit_xss_finding(
                            finding_dict,
                            status=f.status or ValidationStatus.VALIDATED_CONFIRMED.value,
                            needs_cdp=False
                        )
                        # Mirror stable xss_agent.py:6103 — append UNCONDITIONALLY. A
                        # hook-confirmed DOM XSS rejected by the emit proof-gate (only for
                        # lacking a screenshot) must still reach _generate_specialist_report,
                        # where _capture_proof_screenshot rescues it with the banner PoC.
                        validated.append(f)
                        if emitted:
                            logger.info(f"[{self.name}] Emitted DOM XSS: {f.url} (source: {f.parameter})")
                        else:
                            logger.warning(
                                f"[{self.name}] ⚠️  DOM XSS NOT emitted (rejected by validate/emit): "
                                f"{f.url} (source: {f.parameter}) — still reaches report via specialist results file"
                            )
        except Exception as e:
            logger.error(f"[{self.name}] Phase B.2 DOM XSS testing failed: {e}", exc_info=True)

        # Phase B.3: Stored XSS testing (POST → GET workflow)
        try:
            stored_results = await self._test_stored_xss(screenshots_dir)
            if stored_results:
                for f in stored_results:
                    fp = self._generate_xss_fingerprint(f["url"], f["parameter"], "stored_xss")
                    if fp not in self._emitted_findings:
                        emitted = self._emit_xss_finding(
                            f, status=ValidationStatus.VALIDATED_CONFIRMED.value
                        )
                        # Mirror stable — keep the validated stored-XSS even if the emit
                        # proof-gate rejects it, so it reaches the specialist report.
                        self._emitted_findings.add(fp)
                        validated.append(f)
                        if emitted:
                            logger.info(f"[{self.name}] Emitted Stored XSS: {f['url']} via {f['parameter']}")
                        else:
                            logger.warning(
                                f"[{self.name}] ⚠️  Stored XSS NOT emitted (rejected by validate/emit): "
                                f"{f['url']} via {f['parameter']} — still reaches report via specialist results file"
                            )
        except Exception as e:
            logger.error(f"[{self.name}] Phase B.3 Stored XSS testing failed: {e}", exc_info=True)

        return validated
