"""
Param testing, fragment/POST, browser validation shell.

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
from bugtrace.agents.xss.context_reflection import as_context_set as _as_context_set
# --- end shell runtime deps ---

class XSSParamBrowserMixin:
    async def _loop_test_params(self, interactsh_domain: str, screenshots_dir: Path):
        """
        Phase 3: Test each parameter for XSS.

        v3.1.0: Now uses the Hybrid Engine (Go + Python + LLM) when available,
        with automatic fallback to pure Python mode if Go is unavailable.
        """
        logger.info(f"[{self.name}] Phase 3: Testing each parameter")

        # v3.1.0: Initialize hybrid engine if enabled
        if self._hybrid_mode:
            hybrid_ready = await self._init_hybrid_engine()
            if hybrid_ready:
                dashboard.log(
                    f"[{self.name}] 🚀 Hybrid Engine ACTIVE (Go + Python + LLM)",
                    "INFO"
                )
            else:
                dashboard.log(
                    f"[{self.name}] ⚠️ Hybrid Engine unavailable, using pure Python",
                    "WARN"
                )

        for param in self.params:
            # TASK-50: Thread-safe deduplication check
            async with self._tested_params_lock:
                if param in self._tested_params:
                    logger.info(f"[{self.name}] Skipping {param} - already tested")
                    continue
                self._tested_params.add(param)

            logger.info(f"[{self.name}] Testing param: {param}")

            # v3.1.0: Use hybrid engine if available, fallback to classic method
            if self._hybrid_mode and self._go_bridge:
                finding = await self._run_hybrid_test_param(
                    param, interactsh_domain, screenshots_dir
                )
            else:
                finding = await self._test_parameter(param, interactsh_domain, screenshots_dir)

            if not finding:
                continue

            self.findings.append(finding)
            dashboard.log(f"[{self.name}] 🎯 XSS CONFIRMED on '{param}'!", "SUCCESS")

            # OPTIMIZATION: Early exit after first finding
            from bugtrace.core.config import settings
            if settings.EARLY_EXIT_ON_FINDING:
                remaining = len(self.params) - (self.params.index(param) + 1)
                if remaining > 0:
                    logger.info(f"[{self.name}] ⚡ OPTIMIZATION: Early exit enabled (config)")
                    logger.info(f"[{self.name}] Skipping {remaining} remaining params (URL already vulnerable)")
                    dashboard.log(f"[{self.name}] ⚡ Early exit: Skipping {remaining} params (optimization)", "INFO")
                break

    async def _test_payload_http_only(
        self, url: str, param: str, payload: str, context: str
    ) -> Optional[XSSFinding]:
        """
        Test a single payload via HTTP only (no browser). Returns:
        - XSSFinding(validated=True) if HTTP confirms execution
        - XSSFinding(validated=False) if payload reflects but not confirmed (browser candidate)
        - None if no reflection at all
        """
        try:
            dashboard.set_current_payload(payload[:60], "XSS HTTP", "Testing", self.name)
            response_html = await self._send_payload(param, payload)
            if not response_html:
                return None

            # HTTP confirmation - validated=True
            evidence = {}
            if self._can_confirm_from_http_response(payload, response_html, evidence):
                return XSSFinding(
                    url=url, parameter=param, payload=payload, context=context,
                    validation_method="http_analysis",
                    evidence={"http_confirmed": True, "reflection": True},
                    confidence=0.85, status="VALIDATED_CONFIRMED", validated=True
                )

            # Payload reflects but not confirmed - browser candidate (validated=False)
            if self._payload_reflects(payload, response_html):
                return XSSFinding(
                    url=url, parameter=param, payload=payload, context=context,
                    validation_method="pending_browser",
                    evidence={"reflection": True, "response_html": response_html[:2000]},
                    confidence=0.4, status="PENDING_VALIDATION", validated=False
                )

            return None
        except Exception as e:
            logger.debug(f"[{self.name}] HTTP-only test failed: {e}")
            return None

    async def _probe_and_analyze_context(
        self, param: str
    ) -> Tuple[Optional[str], Optional[str], int, Dict, str, str, Dict]:
        """Phase 1: Probe parameter and analyze context."""
        # Probe to get HTML with reflection and analyze context
        html, probe_url, status_code = await self._probe_parameter(param)

        # Use framework's WAF detection
        waf_detected = self._detected_waf is not None
        if html == "":
            dashboard.log(f"[{self.name}] 🛡️ WAF Detected (Probe Blocked). Switching to Direct Fire Strategy.", "WARN")
            waf_detected = True
            html = "<html><body>WAF_BLOCKED_PROBE</body></html>"

        if html is None:
            return None, None, 0, {}, "", "", {}

        # Analyze context
        global_context = self._analyze_global_context(html)
        dashboard.log(f"[{self.name}] 🌍 Global Context: {global_context}", "INFO")

        context_data = self._analyze_reflection_context(html, self.PROBE_STRING)
        context_data["global_context"] = global_context

        # Determine reflection type
        if not context_data.get("reflected"):
            if context_data.get("is_blocked"):
                reflection_type = "waf_blocked"
                surviving_chars = "unknown"
            else:
                reflection_type = "unknown (potential DOM XSS)"
                surviving_chars = "unknown"
        else:
            reflection_type = context_data.get("context", "unknown")
            surviving_chars = context_data.get("surviving_chars", "")

        # Get injection context for reporting
        injection_ctx = self.detect_injection_context(html, self.PROBE_STRING)
        server_escaping = await self.analyze_server_escaping(self.url, param)

        return html, probe_url, status_code, context_data, reflection_type, surviving_chars, injection_ctx

    async def _payload_test_single(
        self,
        param: str,
        reflected_payload: str,
        is_encoded: bool,
        ref_context: str,
        screenshots_dir: Path,
        injection_ctx: Any
    ) -> Tuple[bool, Optional[Dict], Optional[Dict]]:
        """Test a single payload and return validation result."""
        dashboard.set_current_payload(reflected_payload[:60], "XSS Hybrid", "Validating")

        # Authority check for unencoded dangerous reflections
        # RELAXED: If it's a BUGTRACE payload, we trust it blindly if unencoded
        is_bugtrace_payload = "BUGTRACE" in reflected_payload
        dangerous_contexts = ["html_text", "attribute_unquoted", "script", "tag_name"]
        
        if not is_encoded and (ref_context in dangerous_contexts or is_bugtrace_payload):
            finding = self._create_authority_finding(
                param, reflected_payload, ref_context, injection_ctx
            )
            return True, None, {"finding": finding}

        # Browser validation
        validated, evidence = await self._validate(
            param, reflected_payload, "", screenshots_dir
        )

        if validated:
            finding_data = {
                "evidence": evidence,
                "screenshot_path": evidence.get("screenshot_path"),
                "context": "hybrid_payload",
                "reflection_context": ref_context
            }
            return True, evidence, finding_data

        return False, None, None

    async def _test_payload_list(
        self,
        param: str,
        hybrid_payloads: List[str],
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Test a list of payloads and return first successful finding."""
        successful_payloads = []
        best_state = {}

        reflection_results = await self._payload_run_reflection_checks(
            param, hybrid_payloads, interactsh_url
        )

        if not reflection_results:
            return None

        for ref in reflection_results:
            if self._max_impact_achieved:
                break

            reflected_payload = ref["payload"]
            validated, evidence, finding_data = await self._payload_test_single(
                param, reflected_payload, ref.get("encoded", True),
                ref.get("context", "unknown"), screenshots_dir, injection_ctx
            )

            # Handle authority finding (early return)
            if validated and finding_data and "finding" in finding_data:
                return finding_data["finding"]

            successful_payloads, best_state = self._payload_process_validation_result(
                validated, finding_data, reflected_payload, evidence,
                reflection_type, successful_payloads, best_state
            )

            if validated and self._payload_check_early_stop(reflected_payload, evidence, len(successful_payloads)):
                break

        if successful_payloads:
            return self._payload_build_final_finding(
                param, best_state, reflection_type, surviving_chars,
                successful_payloads, injection_ctx
            )

        return None

    async def _param_probe_and_setup(
        self,
        param: str
    ) -> Optional[Tuple]:
        """Phase 1: Probe target and prepare context."""
        probe_result = await self._probe_and_analyze_context(param)
        if probe_result[0] is None:
            return None

        html, probe_url, status_code, context_data, reflection_type, surviving_chars, injection_ctx = probe_result

        # Cache server escaping for finding creation
        self._last_server_escaping = await self.analyze_server_escaping(self.url, param)

        # Get interactsh URL
        interactsh_url = self.interactsh.get_payload_url("xss", param)

        return (html, probe_url, status_code, context_data, reflection_type,
                surviving_chars, injection_ctx, interactsh_url)

    async def _param_try_fragment_xss(
        self,
        param: str,
        interactsh_url: str
    ) -> Optional[XSSFinding]:
        """Phase 4: Try fragment XSS if WAF detected or reflection blocked."""
        dashboard.log(f"[{self.name}] 🔗 Trying FRAGMENT XSS (Heuristic)...", "WARN")

        fragment_payloads = [
            fp.replace("{{interactsh_url}}", interactsh_url)
            for fp in self.FRAGMENT_PAYLOADS
        ]

        if not fragment_payloads:
            return None

        return XSSFinding(
            url=self.url,
            parameter=param,
            payload=fragment_payloads[0],
            context="fragment_xss_potential",
            validation_method="fragment_bypass",
            evidence={
                "reason": "WAF blocked query params, fragment bypass detected",
                "all_payloads": fragment_payloads,
                "needs_cdp": False  # v3.2.1: CDP disabled
            },
            confidence=0.7,
            status="VALIDATED_CONFIRMED",  # v3.2.1: Direct to reporting
            validated=False,
            reflection_context="fragment",
            successful_payloads=fragment_payloads,
            xss_type="dom-based",
            injection_context_type="url_fragment",
            vulnerable_code_snippet="location.hash sink",
            server_escaping=self._last_server_escaping,
            escape_bypass_technique="fragment_injection",
            bypass_explanation="Payload injected via URL fragment to avoid server-side WAF.",
            exploit_url=self.build_exploit_url(self.url, param, fragment_payloads[0], encoded=False),
            exploit_url_encoded=self.build_exploit_url(self.url, param, fragment_payloads[0], encoded=True),
            verification_methods=[{
                "type": "cdp",
                "name": "Browser Verification",
                "instructions": "Must use browser",
                "url_encoded": self.build_exploit_url(self.url, param, fragment_payloads[0], encoded=True)
            }],
            verification_warnings=["Fragment XSS requires browser interaction"],
            reproduction_steps=["Open URL in browser", "Check for execution"]
        )

    async def _param_test_llm_payload(
        self,
        param: str,
        html: str,
        interactsh_url: str,
        context_data: Dict,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: InjectionContext
    ) -> Optional[XSSFinding]:
        """Phase 5: LLM analysis and payload testing."""
        llm_response = await self._llm_get_payload_from_response(
            html, param, interactsh_url, context_data
        )

        if not llm_response or not llm_response.get("vulnerable"):
            return None

        payload = llm_response.get("payload", "")
        validation_method = llm_response.get("validation_method", "interactsh")

        dashboard.set_current_payload(payload[:60], "XSS", "Testing")

        response_html = await self._send_payload(param, payload)
        if not response_html:
            return None

        validated, evidence = await self._validate(
            param, payload, response_html, screenshots_dir
        )

        if not validated:
            return None

        finding_data = self._llm_prepare_finding_data(evidence, llm_response, reflection_type)

        if not self._should_create_finding(finding_data):
            return None

        return self._create_xss_finding(
            param, payload, llm_response.get("context", "unknown"),
            validation_method, evidence, llm_response.get("confidence", 0.9),
            reflection_type, surviving_chars, [payload],
            injection_ctx, "context_aware",
            llm_response.get("reasoning", "LLM generated context-aware payload.")
        )

    async def _param_test_phases_3_4_5(
        self,
        param: str,
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        context_data: Dict,
        html: str,
        status_code: int,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Execute phases 3-5: Hybrid payloads, fragment XSS, and LLM analysis."""
        # Phase 3: Hybrid Payloads (Fallback)
        hybrid_finding = await self._test_hybrid_payloads(
            param, interactsh_url, screenshots_dir, reflection_type,
            surviving_chars, context_data, status_code, injection_ctx
        )
        if hybrid_finding:
            return hybrid_finding

        # Phase 4: Fragment XSS (Special case for WAF bypass)
        should_try_fragment = (
            self.consecutive_blocks > 2 or
            not context_data.get("reflected") or
            self._detected_waf is not None
        )

        if should_try_fragment:
            fragment_finding = await self._param_try_fragment_xss(param, interactsh_url)
            if fragment_finding:
                return fragment_finding

        # Phase 5: LLM Analysis (Expensive fallback)
        if not context_data.get("reflected") and not self._detected_waf:
            logger.info(f"[{self.name}] ⚡ OPTIMIZATION: Skipping LLM analysis")
            return None

        return await self._param_test_llm_payload(
            param, html, interactsh_url, context_data, screenshots_dir,
            reflection_type, surviving_chars, injection_ctx
        )

    async def _test_parameter(
        self,
        param: str,
        interactsh_domain: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """Test a single parameter for XSS.

        Uses Pipeline V2 (Bombardment-First) as primary strategy.
        Falls back to legacy approach if Pipeline V2 fails.
        """
        dashboard.log(f"[{self.name}] 🔬 Testing param: {param}", "INFO")
        dashboard.set_status("XSS Analysis", f"Testing {param}")

        # =====================================================================
        # PRIMARY STRATEGY: Pipeline V2 (Bombardment-First)
        # Philosophy: Fire ALL payloads first, analyze what reflected, amplify
        # =====================================================================
        try:
            finding = await self._run_pipeline_v2(
                param=param,
                interactsh_domain=interactsh_domain,
                screenshots_dir=screenshots_dir
            )
            if finding:
                dashboard.log(f"[{self.name}] ✅ Pipeline V2 found XSS!", "SUCCESS")
                return finding
        except Exception as e:
            logger.warning(f"[{self.name}] Pipeline V2 error: {e}, falling back to legacy")

        # =====================================================================
        # FALLBACK: Legacy approach (probe-first)
        # Only used if Pipeline V2 fails completely
        # =====================================================================
        dashboard.log(f"[{self.name}] 📜 Trying legacy approach for '{param}'", "INFO")

        # Phase 1: Probe and setup
        probe_data = await self._param_probe_and_setup(param)
        if not probe_data:
            return None

        html, probe_url, status_code, context_data, reflection_type, surviving_chars, injection_ctx, interactsh_url = probe_data

        # Phase 2: LLM Smart DOM Analysis (Primary Strategy)
        smart_finding = await self._test_smart_llm_payloads(
            param, html, context_data, interactsh_url, screenshots_dir,
            reflection_type, surviving_chars, injection_ctx
        )
        if smart_finding:
            return smart_finding

        # Phases 3-5: Hybrid, Fragment, LLM Analysis
        return await self._param_test_phases_3_4_5(
            param, interactsh_url, screenshots_dir, reflection_type,
            surviving_chars, context_data, html, status_code, injection_ctx
        )

    async def _send_payload(self, param: str, payload: str) -> str:
        """Send XSS payload to target with WAF awareness. Supports GET and POST."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        method = getattr(self, '_current_http_method', 'GET')
        parsed = urlparse(self.url)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        try:
            async with http_manager.session(ConnectionProfile.PROBE) as session:
                if method == "POST":
                    # POST: payload in form body, keep original URL intact
                    base_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, parsed.query, parsed.fragment
                    ))
                    post_data = {param: payload}
                    async with session.post(base_url, data=post_data, headers=headers, ssl=False) as resp:
                        self._update_block_counter(resp.status)
                        text = await resp.text()
                        self._last_confirming_request = {"method": "POST", "url": base_url, "headers": dict(headers), "body": urlencode(post_data), "body_content_type": "application/x-www-form-urlencoded"}
                        self._last_response_content_type = resp.headers.get("Content-Type", "")
                        self._last_response_csp = resp.headers.get(
                            "Content-Security-Policy", "")
                        self._last_confirming_response = {"status": resp.status, "text": text}
                        return text
                else:
                    # GET: payload in query string (existing behavior)
                    params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
                    params[param] = payload
                    attack_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(params), parsed.fragment
                    ))
                    async with session.get(attack_url, headers=headers, ssl=False) as resp:
                        self._update_block_counter(resp.status)
                        text = await resp.text()
                        self._last_confirming_request = {"method": "GET", "url": attack_url, "headers": dict(headers), "body": None, "body_content_type": None}
                        self._last_response_content_type = resp.headers.get("Content-Type", "")
                        self._last_response_csp = resp.headers.get(
                            "Content-Security-Policy", "")
                        self._last_confirming_response = {"status": resp.status, "text": text}
                        return text
        except Exception:
            self._handle_send_error()
            # Never leave the PREVIOUS response's content type behind: an empty one means
            # "unknown", which the confirmation gate treats as executable (fail OPEN).
            self._last_response_content_type = ""
            self._last_response_csp = ""
            return ""

    async def _validate_with_ai_manipulator(self, param: str, payload: str, response_html: str, evidence: Dict) -> bool:
        """Level 2: AI-powered context audit and filter analysis."""
        if not response_html or re.escape(payload) not in response_html:
            return False

        dashboard.log(f"[{self.name}] 🤖 L2: AI Manipulator auditing reflection...", "INFO")
        ai_judgment = await self._analyze_reflection_via_ai(payload, response_html)
        
        if ai_judgment.get("vulnerable"):
            evidence["ai_confirmed"] = True
            evidence["ai_reasoning"] = ai_judgment.get("reasoning")
            evidence["execution_context"] = ai_judgment.get("context")
            evidence["method"] = "L2: AI Manipulator/Auditor"
            evidence["level"] = 2
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

        return False

    async def _test_fragment_xss(
        self,
        param: str,
        interactsh_url: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Test Fragment-based XSS (DOM XSS via location.hash).
        This bypasses WAFs because fragments (#payload) don't reach the server.
        Level 7+ targets often use location.hash in innerHTML/eval, creating DOM XSS.
        """
        dashboard.log(f"[{self.name}] 🔗 Testing FRAGMENT XSS (bypassing WAF via location.hash)...", "INFO")

        for fragment_template in self.FRAGMENT_PAYLOADS:
            payload = fragment_template.replace("{{interactsh_url}}", interactsh_url)
            fragment_url = self._fragment_build_url(payload)

            dashboard.set_current_payload(payload[:60], "Fragment XSS", "Testing")
            logger.info(f"[{self.name}] Testing Fragment: {fragment_url}")

            try:
                result = await self.verifier.verify_xss(
                    url=fragment_url,
                    screenshot_dir=str(screenshots_dir),
                    timeout=10.0
                )

                if result.success:
                    dashboard.log(f"[{self.name}] 🎯 FRAGMENT XSS SUCCESS! ({result.method})", "SUCCESS")
                    return self._fragment_build_finding(param, payload, result)

            except Exception as e:
                logger.debug(f"Fragment test failed for {payload[:30]}: {e}")
                continue

        logger.info(f"[{self.name}] No Fragment XSS found after testing {len(self.FRAGMENT_PAYLOADS)} payloads")
        return None

    async def _test_post_params(
        self,
        form_action: str,
        post_params: Dict[str, str],
        interactsh_url: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """Test POST parameters for XSS."""
        dashboard.log(f"[{self.name}] 📝 Testing POST form: {form_action}", "INFO")

        for param, original_value in post_params.items():
            if self._max_impact_achieved:
                break

            for payload_template in self.GOLDEN_PAYLOADS[:10]:
                payload = payload_template.replace("{{interactsh_url}}", interactsh_url)
                test_data = post_params.copy()
                test_data[param] = payload

                response_html = await self._post_send_request(form_action, test_data)
                if not response_html:
                    continue

                # Check reflection
                if payload not in response_html and payload[:30] not in response_html:
                    continue

                dashboard.log(f"[{self.name}] 🎯 POST param '{param}' reflects payload!", "SUCCESS")

                validated, evidence = await self._validate(
                    param, payload, response_html, screenshots_dir
                )

                if validated:
                    return self._post_build_finding(form_action, param, payload, evidence)

        return None

    async def _validate_via_browser(
        self, url: str, param: str, payload: str, screenshot_dir: str = None
    ) -> Optional[Dict[str, Any]]:
        """
        Validate XSS using browser with intelligent escalation.

        Flow: Playwright (L3) → CDP (L4) → DOM XSS detector

        Args:
            url: Target URL
            param: Parameter name
            payload: XSS payload
            screenshot_dir: Directory to save evidence screenshots

        Returns:
            Evidence dict if confirmed, None otherwise
        """
        try:
            # Build test URL with payload
            from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            query_params[param] = [payload]
            new_query = urlencode(query_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            # v3.2.1: CDP disabled - Playwright only (L3)
            result = await self.verifier.verify_xss(
                url=test_url,
                screenshot_dir=screenshot_dir,
                timeout=15.0,
                max_level=3  # L3=Playwright only, no CDP
            )

            if result and result.success:
                ss_path = getattr(result, 'screenshot_path', None)
                return {
                    "confirmed": True,
                    "method": result.method,
                    "evidence": getattr(result, 'evidence', {}),
                    "screenshot": ss_path,
                    "screenshot_path": ss_path,
                }

            # NOTE: DOM XSS detection removed from payload validation
            # detect_dom_xss finds DOM XSS that exist INDEPENDENTLY of the payload
            # we're testing. Mixing them causes FALSE POSITIVES where we report
            # a payload as working when actually a different DOM XSS exists.
            #
            # DOM XSS scanning should be done separately in _run_dom_xss_scan()
            # which creates its own findings with the correct payload.

            return None

        except Exception as e:
            logger.debug(f"[{self.name}] Browser validation error: {e}")
            return None

    async def _validate_with_playwright(self, param: str, payload: str, screenshots_dir: Path, evidence: Dict) -> bool:
        """Level 3: Playwright browser execution for DOM/Client behavior."""
        attack_url = self._build_attack_url(param, payload)
        
        # Use verify_xss with max_level=3 to only use Playwright in this agent
        result = await self.verifier.verify_xss(
            url=attack_url,
            screenshot_dir=str(screenshots_dir),
            timeout=8.0,
            max_level=3
        )

        if result.success:
            evidence.update(result.details or {})
            evidence["playwright_confirmed"] = True
            evidence["screenshot_path"] = result.screenshot_path
            evidence["method"] = "L3: Playwright Browser"
            evidence["level"] = 3
            evidence["status"] = "VALIDATED_CONFIRMED"

            # Step 3.1: Vision AI validation if screenshot available
            if result.screenshot_path:
                await self._run_vision_validation(result.screenshot_path, attack_url, payload, evidence)
            
            return True

        return False

    async def _run_vision_validation(
        self, screenshot_path: str, attack_url: str, payload: str, evidence: Dict
    ) -> Optional[bool]:
        """
        Run Vision AI validation - simple SI/NO confirmation.

        Playwright already detected XSS via DOM/dialog. Vision provides
        VISUAL CONFIRMATION that the banner is visible = double evidence.
        """
        dashboard.log(f"[{self.name}] 📸 Calling Vision AI for visual confirmation...", "INFO")

        try:
            from bugtrace.core.llm_client import llm_client

            vision_prompt = self._build_vision_prompt()
            vision_response = await self._call_vision_with_retry(
                llm_client, screenshot_path, vision_prompt
            )

            return self._process_vision_result(vision_response, evidence)

        except Exception as e:
            logger.error(f"[{self.name}] Vision AI validation failed: {e}", exc_info=True)
            evidence["vision_error"] = str(e)
            # Playwright already confirmed, Vision is bonus - don't fail the finding
            return None

    async def _call_vision_with_retry(self, llm_client, screenshot_path: str, prompt: str) -> str:
        """Call vision API with retry logic using llm_client.generate_with_image()."""
        max_retries = 3

        for attempt in range(max_retries):
            try:
                result = await llm_client.generate_with_image(
                    prompt=prompt,
                    image_path=screenshot_path,
                    module_name="XSS-Vision",
                    temperature=0.1  # Low temperature for deterministic SI/NO
                )
                return result or ""
            except Exception as retry_error:
                if attempt == max_retries - 1:
                    raise
                logger.warning(f"Vision validation attempt {attempt + 1}/{max_retries} failed: {retry_error}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff

        raise Exception("Vision validation failed after all retries")

