"""
Escalation ladder L0.5–L6 and related shell.

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


class XSSEscalationHighMixin:
    """L4-L6 escalation steps."""

    async def _escalation_l4_http_manipulator(
        self, url: str, param: str
    ) -> tuple:
        """L4: ManipulatorOrchestrator - context detection, WAF bypass, blood smell."""
        reflecting = []
        try:
            method = getattr(self, '_current_http_method', 'GET')
            parsed = urllib.parse.urlparse(url)
            base_params = dict(urllib.parse.parse_qsl(parsed.query))
            if param not in base_params:
                base_params[param] = "test"

            if method == "POST":
                base_request = MutableRequest(
                    method="POST",
                    url=url.split("?")[0],
                    params={},
                    data=base_params
                )
            else:
                base_request = MutableRequest(
                    method="GET",
                    url=url.split("?")[0],
                    params=base_params
                )

            manipulator = ManipulatorOrchestrator(
                rate_limit=0.3,
                enable_agentic_fallback=True,
                enable_llm_expansion=True
            )

            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.manipulator.phase", {"param": param, "phase": "process_finding", "strategies": ["PAYLOAD_INJECTION", "BYPASS_WAF"]})

            success, mutation = await manipulator.process_finding(
                base_request,
                strategies=[MutationStrategy.PAYLOAD_INJECTION, MutationStrategy.BYPASS_WAF]
            )

            if success and mutation:
                working_payload = mutation.params.get(param, str(mutation.params))
                original_value = base_params.get(param, "test")

                # Verify the TARGET param was actually mutated (not a different param)
                if working_payload == original_value:
                    logger.info(f"[{self.name}] L4: ManipulatorOrchestrator exploited different param, not '{param}'")
                    await manipulator.shutdown()
                    return None, reflecting

                # Verify payload contains XSS indicators
                xss_indicators = ["<script", "<img", "<svg", "<iframe", "onerror", "onload",
                                  "onclick", "onmouseover", "onfocus", "javascript:", "alert(",
                                  "confirm(", "prompt(", "document.", "eval(", "<div", "<body",
                                  "style=", "expression(", "\\x", "\\u00"]
                if not any(ind.lower() in working_payload.lower() for ind in xss_indicators):
                    logger.info(f"[{self.name}] L4: ManipulatorOrchestrator payload rejected (no XSS syntax): {working_payload[:80]}")
                    await manipulator.shutdown()
                    return None, reflecting

                # The manipulator's EncodingAgent may URL-encode the payload, which httpx then
                # re-encodes (params=) -> the request goes out DOUBLE-encoded. The server reflects
                # the inert percent-literal (e.g. "%3Cdiv"), and the manipulator's substring match
                # falsely "confirms" XSS. Re-verify the DECODED payload with the SAME strict
                # executable-context check used by L2/L3, sent RAW so httpx encodes exactly once.
                # No executable context => it was a false positive; defer to L5 browser (DOM) check.
                decoded_payload = urllib.parse.unquote(working_payload)
                verify_ev: dict = {}
                verify_resp = await self._send_payload(param, decoded_payload)
                if not self._can_confirm_from_http_response(decoded_payload, verify_resp or "", verify_ev):
                    logger.info(f"[{self.name}] L4: manipulator success but decoded payload not executable in response -> rejecting potential FP, deferring to L5: {decoded_payload[:80]}")
                    if verify_resp and self._payload_reflects(decoded_payload, verify_resp):
                        reflecting.append(decoded_payload)
                    await manipulator.shutdown()
                    return None, reflecting

                logger.info(f"[{self.name}] L4: ManipulatorOrchestrator CONFIRMED (strict re-verify): {param}={decoded_payload[:80]}")
                await manipulator.shutdown()
                # Store the RAW (decoded) payload + strict evidence; _can_confirm_from_http_response
                # already stamped a single-encoded confirming_request, so the repro is clean and the
                # base64 backup fires correctly (payload now carries literal <>/quotes again).
                return XSSFinding(
                    url=url, parameter=param, payload=decoded_payload,
                    context=verify_ev.get("execution_context", "html"),
                    validation_method="L4_manipulator_http",
                    evidence={**verify_ev, "level": "L4",
                              "manipulator_strategy": getattr(mutation, '_encoding_strategy', None)},
                    confidence=0.95, status="VALIDATED_CONFIRMED", validated=True
                ), reflecting

            # Collect blood smell candidates as reflecting payloads for L5
            if manipulator.blood_smell_history:
                for entry in sorted(manipulator.blood_smell_history, key=lambda x: x["smell"]["severity"], reverse=True)[:5]:
                    blood_payload = entry["request"].params.get(param, "")
                    if blood_payload:
                        reflecting.append(blood_payload)
                logger.info(f"[{self.name}] L4: {len(reflecting)} blood smell candidates for L5")

            await manipulator.shutdown()

        except Exception as e:
            logger.error(f"[{self.name}] L4: ManipulatorOrchestrator failed: {e}")

        return None, reflecting

    async def _escalation_l5_browser(
        self, url: str, param: str, reflecting_payloads: list, screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """L5: Browser validation (Playwright) on reflecting payloads."""
        # Dedupe and take top candidates
        seen = set()
        candidates = []
        for p in reflecting_payloads:
            if p not in seen:
                seen.add(p)
                candidates.append(p)

        # Limit to top 10 browser tests (expensive)
        candidates = candidates[:10]
        logger.info(f"[{self.name}] L5: Browser testing {len(candidates)} reflecting payloads on '{param}'")

        for i, payload in enumerate(candidates):
            dashboard.set_current_payload(payload[:60], "XSS L5 Browser", f"{i+1}/{len(candidates)}", self.name)
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.browser.testing", {"param": param, "index": i + 1, "total": len(candidates), "payload": payload[:80]})
            try:
                browser_result = await self._validate_via_browser(url, param, payload, screenshot_dir=str(screenshots_dir))
                if browser_result:
                    if hasattr(self, '_v'):
                        self._v.emit("exploit.xss.browser.result", {"param": param, "confirmed": True, "method": browser_result.get("method", "playwright")})
                    return XSSFinding(
                        url=url, parameter=param, payload=payload, context="dom",
                        validation_method="L5_browser", evidence={**browser_result, "level": "L5"},
                        confidence=0.95, status="VALIDATED_CONFIRMED", validated=True,
                        screenshot_path=browser_result.get("screenshot_path"),
                    )
            except Exception as e:
                logger.debug(f"[{self.name}] L5: Browser test {i+1} failed: {e}")

        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.browser.result", {"param": param, "confirmed": False, "tested": len(candidates)})
        logger.info(f"[{self.name}] L5: 0/{len(candidates)} confirmed in browser for '{param}'")
        return None

    async def _escalation_l6_cdp(
        self, url: str, param: str, reflecting_payloads: list
    ) -> Optional[XSSFinding]:
        """L6: Flag best reflecting payload for CDP AgenticValidator."""
        if not reflecting_payloads:
            return None

        # Pick best candidate (first one, which came from highest priority level)
        best_payload = reflecting_payloads[0]
        logger.info(f"[{self.name}] L6: Flagging '{param}' for CDP AgenticValidator (payload: {best_payload[:60]})")

        return XSSFinding(
            url=url, parameter=param, payload=best_payload, context="pending_cdp",
            validation_method="L6_cdp_flagged", evidence={"reflecting": True, "level": "L6", "needs_cdp": True},
            confidence=0.5, status="NEEDS_CDP_VALIDATION", validated=True
        )

