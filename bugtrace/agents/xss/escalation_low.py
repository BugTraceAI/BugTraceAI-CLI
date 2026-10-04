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
# Breakout helpers live in the xss.breakouts module post-peel; escalation_low calls
# them in L3 (see ~L793-800). Missing this import NameError'd Phase B → 0 validated
# → XSS never confirmed → no proof screenshot captured.
from bugtrace.agents.xss.breakouts import (
    merge_breakout_prefixes,
    context_breakout_prefixes,
    tag_closing_breakout_payloads,
)
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


class XSSEscalationLowMixin:
    """L0-L3 escalation steps."""

    async def _xss_escalation_pipeline(
        self, url: str, param: str, interactsh_url: str, screenshots_dir: Path,
        context: str = "html", probe_snippet: str = "",
        http_method: str = "GET"
    ) -> Optional[XSSFinding]:
        """Run the escalation ladder and record NEGATIVE EVIDENCE for this parameter.

        The ladder returns the same ``None`` for "tested hard, nothing executable" and for
        "never tested". This wrapper guarantees exactly ONE coverage record per call, on
        EVERY exit — including the exception path, which is an exit too: the record is closed
        before the exception is re-raised to the caller's ``except``.
        """
        # getattr, not attribute access: an XSSAgent built with __new__ (harnesses, some
        # reject-path shells) has no __init__ state, and an AttributeError raised in the
        # finally: below would MASK the ladder's real exception.
        if not isinstance(getattr(self, "_xss_coverage", None), list):
            self._xss_coverage = []
        self._xss_cov = xss_coverage.start_coverage(
            url, param, http_method=http_method, initial_context=context
        )
        try:
            return await self._xss_escalation_ladder(
                url, param, interactsh_url, screenshots_dir,
                context=context, probe_snippet=probe_snippet, http_method=http_method,
            )
        except Exception as e:
            self._xss_cov = xss_coverage.finish(
                self._xss_cov, xss_coverage.EXIT_EXCEPTION
            )
            logger.debug(f"[{self.name}] Coverage: '{param}' exited via exception: {e}")
            raise
        finally:
            self._xss_coverage.append(self._xss_cov)
            self._xss_cov = None

    async def _xss_escalation_ladder(
        self, url: str, param: str, interactsh_url: str, screenshots_dir: Path,
        context: str = "html", probe_snippet: str = "",
        http_method: str = "GET"
    ) -> Optional[XSSFinding]:
        """
        v3.5: Smart XSS Escalation Pipeline.

        L0.5: Smart probe      → reflection + context-specific payloads (1-6 reqs)
        L1: Polyglot probe     → HTTP reflection check (instant)
        L2: Bombing 1 (static) → Curated + GOLDEN payloads via HTTP
        L3: Bombing 2 (LLM)    → 100 LLM payloads × breakouts (SKIPPED if L2=0 reflections)
        L4: HTTP Manipulator   → ManipulatorOrchestrator (SKIPPED if L2=0 reflections)
        L5: Browser testing    → Playwright DOM execution
        L6: CDP Validation     → Flag for AgenticValidator
        """
        self._current_http_method = http_method  # Used by _send_payload()
        self._surviving_chars = ""  # Set by L0.5 char probe, read by L3 breakout selection
        reflecting_payloads = []  # Payloads that reflect but aren't confirmed - passed to L5/L6

        def _tag_method(finding):
            """Tag finding with HTTP method before returning."""
            if finding and hasattr(finding, 'http_method'):
                finding.http_method = http_method
            return finding

        # ===== L0.5: SMART PROBE =====
        dashboard.log(f"[{self.name}] L0.5: Smart probe on '{param}' (context: {context})", "INFO")
        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.level.started", {"level": "L0.5", "param": param, "context": context})
        smart_result, reflects, smart_ctx, smart_ctxs, probe_status = await self._escalation_l05_smart_probe(url, param, context)
        # Every context seen by ANY rung, kept unranked. The depth gate below asks this set
        # — not the single ranked label — whether the browser rungs must run anyway.
        observed_contexts = set(_as_context_set(smart_ctxs))
        # surviving_chars is only a MEASUREMENT when the marker came back; when it did not,
        # self._surviving_chars is still the "" this method initialised, and reporting that
        # as "no characters survived" would be a claim the probe never made.
        self._cov_probe(_L05_CHAR_PROBE, reflects,
                        self._surviving_chars if reflects else None)
        self._cov_level("L0.5", confirmed=bool(smart_result and smart_result.validated),
                        contexts=smart_ctxs, final_context=smart_ctx)
        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.probe.result", {"param": param, "reflects": reflects, "context": smart_ctx or context})
            self._v.emit("exploit.xss.level.completed", {"level": "L0.5", "param": param, "confirmed": bool(smart_result and smart_result.validated)})
        if smart_result and smart_result.validated:
            smart_result = await self._try_early_l5_validation(smart_result, url, param, [], screenshots_dir)
            self._cov_exit(xss_coverage.EXIT_CONFIRMED)
            return _tag_method(smart_result)
        if not reflects:
            # NOT "0 of N reflected": at this exit the reflecting list is empty BY
            # CONSTRUCTION — the bombing rungs never ran. The record says "not reached".
            reason = (
                xss_coverage.EXIT_NO_RESPONSE if probe_status == _PROBE_NO_RESPONSE
                else xss_coverage.EXIT_NO_REFLECTION
            )
            dashboard.log(f"[{self.name}] Smart probe: no reflection for '{param}', skipping all levels", "INFO")
            self._cov_exit(reason)
            return None
        if smart_ctx and smart_ctx not in ("unknown", "none", "blocked"):
            context = smart_ctx

        # ===== L1: POLYGLOT PROBE =====
        dashboard.log(f"[{self.name}] L1: Polyglot probe on '{param}' (context: {context})", "INFO")
        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.level.started", {"level": "L1", "param": param, "context": context})
        result, detected_context, l1_snippet, l1_ctxs = await self._escalation_l1_polyglot(url, param, interactsh_url, context)
        observed_contexts |= _as_context_set(l1_ctxs)
        self._cov_probe(settings.OMNI_PROBE_MARKER, None)
        self._cov_level("L1", confirmed=bool(result and result.validated),
                        contexts=l1_ctxs, final_context=detected_context)
        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.level.completed", {"level": "L1", "param": param, "confirmed": bool(result and result.validated)})
        if result and result.validated:
            result = await self._try_early_l5_validation(result, url, param, [], screenshots_dir)
            self._cov_exit(xss_coverage.EXIT_CONFIRMED)
            return _tag_method(result)
        # L1 may refine the context from live response analysis
        if detected_context and detected_context != "html":
            context = detected_context
        if l1_snippet:
            probe_snippet = l1_snippet

        # ===== L2: BOMBING 1 - STATIC PAYLOADS =====
        dashboard.log(f"[{self.name}] L2: Static bombardment on '{param}' (context: {context})", "INFO")
        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.level.started", {"level": "L2", "param": param, "context": context})
        result, l2_reflecting = await self._escalation_l2_static_bombing(url, param, interactsh_url, context)
        self._cov_level("L2", reflected=len(l2_reflecting),
                        confirmed=bool(result and result.validated), final_context=context)
        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.level.completed", {"level": "L2", "param": param, "confirmed": bool(result and result.validated), "reflecting": len(l2_reflecting)})
        if result and result.validated:
            result = await self._try_early_l5_validation(result, url, param, l2_reflecting, screenshots_dir)
            self._cov_exit(xss_coverage.EXIT_CONFIRMED)
            return _tag_method(result)
        reflecting_payloads.extend(l2_reflecting)

        # ── DEPTH GATE: quick stops after L2 ──
        _depth = getattr(self, '_scan_depth', '') or settings.SCAN_DEPTH
        if _depth == "quick":
            logger.info(f"[{self.name}] Quick depth: stopping at L2 for '{param}'")
            self._cov_exit(xss_coverage.EXIT_DEPTH_QUICK)
            return None

        # ===== SKIP L3+L4 if L2 found 0 reflecting payloads =====
        if not reflecting_payloads:
            dashboard.log(f"[{self.name}] L2: 0 reflections, skipping L3+L4 for '{param}'", "INFO")
            self._cov_note("L3+L4 skipped: 0 reflecting payloads after L2")
        else:
            # ===== L3: BOMBING 2 - LLM PAYLOADS × BREAKOUTS =====
            dashboard.log(f"[{self.name}] L3: LLM bombardment on '{param}' (context: {context})", "INFO")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.started", {"level": "L3", "param": param, "context": context})
            result, l3_reflecting = await self._escalation_l3_llm_bombing(
                url, param, interactsh_url, reflecting_payloads,
                context=context, probe_snippet=probe_snippet
            )
            self._cov_level("L3", reflected=len(l3_reflecting),
                            confirmed=bool(result and result.validated))
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.completed", {"level": "L3", "param": param, "confirmed": bool(result and result.validated), "reflecting": len(l3_reflecting)})
            if result and result.validated:
                self._cov_exit(xss_coverage.EXIT_CONFIRMED)
                return _tag_method(result)
            reflecting_payloads.extend(l3_reflecting)

            # ===== L4: HTTP MANIPULATOR =====
            dashboard.log(f"[{self.name}] L4: HTTP Manipulator on '{param}'", "INFO")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.started", {"level": "L4", "param": param})
            result, l4_reflecting = await self._escalation_l4_http_manipulator(url, param)
            self._cov_level("L4", reflected=len(l4_reflecting),
                            confirmed=bool(result and result.validated))
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.completed", {"level": "L4", "param": param, "confirmed": bool(result and result.validated), "reflecting": len(l4_reflecting)})
            if result and result.validated:
                self._cov_exit(xss_coverage.EXIT_CONFIRMED)
                return _tag_method(result)
            reflecting_payloads.extend(l4_reflecting)

        # ── DEPTH GATE: 'thorough' always browser-validates. 'standard' skips the browser
        #    for speed EXCEPT for browser-only candidates (a redirect/DOM-sink param whose
        #    value lands in an href/navigation — e.g. back=javascript:... fires only on a
        #    click — or a reflection in a browser-only context). Those auto-escalate so we
        #    don't silently lose DOM/interaction XSS at the default depth. ──
        _depth = getattr(self, '_scan_depth', '') or settings.SCAN_DEPTH
        if _depth != "thorough":
            if self._browser_only_candidate(param, observed_contexts | {context}, reflecting_payloads):
                logger.info(f"[{self.name}] {_depth.title()} depth: auto-escalating '{param}' to browser (browser-only XSS vector)")
            else:
                logger.info(f"[{self.name}] {_depth.title()} depth: skipping browser validation for '{param}'")
                self._cov_note("L5+L6 skipped: depth is not 'thorough' and no browser-only vector")
                self._cov_exit(xss_coverage.EXIT_DEPTH_NO_BROWSER)
                return None

        # ===== L5: BROWSER TESTING (Playwright) =====
        # Skip for POST params (Playwright form submission not supported yet)
        if reflecting_payloads and http_method == "GET":
            dashboard.log(f"[{self.name}] L5: Browser testing {len(reflecting_payloads)} candidates on '{param}'", "INFO")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.started", {"level": "L5", "param": param, "candidates": len(reflecting_payloads)})
            result = await self._escalation_l5_browser(url, param, reflecting_payloads, screenshots_dir)
            self._cov_level("L5", confirmed=bool(result and result.validated),
                            note=f"{len(reflecting_payloads)} candidates")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.completed", {"level": "L5", "param": param, "confirmed": bool(result and result.validated)})
            if result and result.validated:
                self._cov_exit(xss_coverage.EXIT_CONFIRMED)
                return _tag_method(result)
        elif reflecting_payloads and http_method == "POST":
            logger.info(f"[{self.name}] L5: Skipping browser test for POST param '{param}'")
            self._cov_note("L5 skipped: Playwright cannot submit POST params")
        else:
            self._cov_note("L5 skipped: no reflecting payloads to browser-test")

        # ===== L6: CDP VALIDATION (AgenticValidator) =====
        if reflecting_payloads:
            dashboard.log(f"[{self.name}] L6: Flagging for CDP AgenticValidator on '{param}'", "INFO")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.started", {"level": "L6", "param": param, "candidates": len(reflecting_payloads)})
            result = await self._escalation_l6_cdp(url, param, reflecting_payloads)
            self._cov_level("L6", note=f"{len(reflecting_payloads)} candidates flagged" if result else "")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.level.completed", {"level": "L6", "param": param, "flagged": bool(result)})
            if result:
                self._cov_exit(xss_coverage.EXIT_FLAGGED_CDP)
                return _tag_method(result)
        else:
            self._cov_note("L6 skipped: no reflecting payloads to flag for CDP")

        dashboard.log(f"[{self.name}] All 6 levels exhausted for '{param}', no XSS confirmed", "WARN")
        self._cov_exit(xss_coverage.EXIT_EXHAUSTED)
        return None

    async def _escalation_l05_smart_probe(
        self, url: str, param: str, initial_context: str = "html"
    ) -> tuple:
        """
        L0.5: Smart Probe — send char-test probe, detect reflection context,
        try 3-5 targeted payloads based on what survives.

        Returns:
            (XSSFinding or None, reflects: bool, detected_context: str or None,
             detected_contexts: list of EVERY context the probe reflected in,
             probe_status: one of _PROBE_NO_RESPONSE / _PROBE_NO_REFLECTION / _PROBE_REFLECTED)

        probe_status exists because "the target answered nothing" and "the target answered
        without the marker" are opposite facts about the SCAN, and the caller has to be able
        to say which one it observed. Collapsing both into reflects=False is what made the
        pipeline unable to distinguish a dead target from a non-injectable parameter.
        """
        # Send char-testing probe with interleaved sub-markers.
        # Each special char is bracketed by its own unique marker pair so its
        # survival is tested independently of the others.  This eliminates:
        #   - false positives: chars from surrounding HTML counted as surviving
        #   - false negatives: HTML-encoding of an earlier char (e.g. < → &lt;)
        #     shifting subsequent chars out of a fixed-size window
        # Format: BT7331A"BT7331B'BT7331C<BT7331D>BT7331E`BT7331F\BT7331G
        _CHAR_MARKERS = [
            ('"',  'A', 'B'),
            ("'",  'B', 'C'),
            ('<',  'C', 'D'),
            ('>',  'D', 'E'),
            ('`',  'E', 'F'),
            ('\\', 'F', 'G'),
        ]
        probe = _L05_CHAR_PROBE
        response = await self._send_payload(param, probe)
        if not response:
            # _send_payload returns "" on transport failure — no answer at all.
            return None, False, None, [], _PROBE_NO_RESPONSE
        if _LEGACY_PROBE_MARKER not in response:
            return None, False, None, [], _PROBE_NO_REFLECTION

        # Each char survives only if its exact bracketed substring is in the response.
        surviving = ""
        for char, before, after in _CHAR_MARKERS:
            if f"BT7331{before}{char}BT7331{after}" in response:
                surviving += char

        # Detect context via existing analysis
        reflection_info = self._analyze_reflection_context(response, "BT7331")
        detected_context = reflection_info.get("context", initial_context)
        detected_contexts = list(reflection_info.get("contexts") or [])

        # Share what the char probe proved with the later levels (same per-param,
        # sequential convention as _current_http_method): L3 uses it to pick
        # context-appropriate breakouts instead of the globally-ranked list alone.
        self._surviving_chars = surviving

        dashboard.log(
            f"[{self.name}] Smart probe: '{param}' reflects, "
            f"context={detected_context}, chars_survive={surviving}",
            "INFO",
        )

        # Select targeted payloads based on context + surviving chars
        smart = []
        if detected_context == "script":
            smart.append(self.SMART_PAYLOADS["js_sq_breakout"])
            smart.append(self.SMART_PAYLOADS["js_dq_breakout"])
        elif detected_context in ("attribute_value", "event_handler"):
            if '"' in surviving:
                smart.append(self.SMART_PAYLOADS["attr_dq_breakout"])
                smart.append(self.SMART_PAYLOADS["attr_dq_tag_breakout"])
            if "'" in surviving:
                smart.append(self.SMART_PAYLOADS["attr_sq_breakout"])
                smart.append(self.SMART_PAYLOADS["attr_sq_tag_breakout"])
            if '<' in surviving:
                smart.append(self.SMART_PAYLOADS["html_svg"])
        elif detected_context in ("html_text", "raw_text", "unknown"):
            if '<' in surviving:
                smart.append(self.SMART_PAYLOADS["html_svg"])
                smart.append(self.SMART_PAYLOADS["html_img"])
            if '"' in surviving:
                smart.append(self.SMART_PAYLOADS["attr_dq_breakout"])
                smart.append(self.SMART_PAYLOADS["attr_dq_tag_breakout"])
        elif detected_context == "comment":
            smart.append("--><svg onload=document.title=document.domain>")

        # Always try script breakout if < survives
        if '<' in surviving and self.SMART_PAYLOADS["script_breakout"] not in smart:
            smart.append(self.SMART_PAYLOADS["script_breakout"])

        # Dedupe and cap. Cap raised 5 → 7 so the tag-closing '">' candidates are ADDED,
        # never at the cost of dropping a payload that was already being tried.
        smart = list(dict.fromkeys(smart))[:7]

        if not smart:
            return None, True, detected_context, detected_contexts, _PROBE_REFLECTED

        # Test smart payloads
        dashboard.log(
            f"[{self.name}] Smart probe: testing {len(smart)} targeted payloads on '{param}'",
            "INFO",
        )
        for payload in smart:
            resp = await self._send_payload(param, payload)
            if resp:
                evidence = {}
                if self._can_confirm_from_http_response(payload, resp, evidence):
                    dashboard.log(
                        f"[{self.name}] Smart probe: CONFIRMED XSS on '{param}'",
                        "INFO",
                    )
                    finding = XSSFinding(
                        url=url,
                        parameter=param,
                        payload=payload,
                        context=detected_context,
                        validation_method="L0.5_smart_probe",
                        evidence={**evidence, "level": "L0.5", "surviving_chars": surviving},
                        confidence=0.9,
                        status="VALIDATED_CONFIRMED",
                        validated=True,
                    )
                    finding.successful_payloads = [payload]
                    return finding, True, detected_context, detected_contexts, _PROBE_REFLECTED

        return None, True, detected_context, detected_contexts, _PROBE_REFLECTED

    async def _escalation_l1_polyglot(
        self, url: str, param: str, interactsh_url: str, initial_context: str = "html"
    ) -> tuple:
        """
        L1: Send polyglot/omniprobe, check HTTP reflection.

        Returns:
            (XSSFinding or None, detected_context, html_snippet, detected_contexts)
            - detected_context: refined context from live response analysis
            - html_snippet: HTML around the reflection point for L3 LLM
            - detected_contexts: EVERY context the marker reflected in, unranked
        """
        probe = settings.OMNI_PROBE_MARKER
        response = await self._send_payload(param, probe)
        if not response:
            return None, initial_context, "", []

        # Check if probe reflects at all
        if probe not in response:
            logger.info(f"[{self.name}] L1: No reflection for '{param}'")
            return None, initial_context, "", []

        # Analyze reflection context from live response
        detected_context = initial_context
        html_snippet = ""
        detected_contexts = []
        try:
            # marker=probe: this call site holds a REAL marker (OMNI_PROBE_MARKER), unlike
            # the payload-passing call sites, so it must not fall back to the legacy
            # hardcoded one — that is what made every L1 context "none".
            reflection = self._analyze_reflection_context(response, probe, marker=probe)
            if reflection:
                detected_context = reflection.get("context", initial_context)
                detected_contexts = list(reflection.get("contexts") or [])
                html_snippet = (reflection.get("snippet") or "")[:500]
                if detected_context != initial_context:
                    logger.info(
                        f"[{self.name}] L1: Context refined: {initial_context} → {detected_context}"
                    )
        except Exception as e:
            logger.debug(f"[{self.name}] L1: Context analysis failed: {e}")

        # Probe reflects - check if any executable context
        evidence = {}
        if self._can_confirm_from_http_response(probe, response, evidence):
            return XSSFinding(
                url=url, parameter=param, payload=probe, context=evidence.get("execution_context", "html"),
                validation_method="L1_polyglot", evidence={**evidence, "level": "L1"},
                confidence=0.85, status="VALIDATED_CONFIRMED", validated=True
            ), detected_context, html_snippet, detected_contexts

        # Check Interactsh OOB
        if self.interactsh:
            try:
                interactions = await self.interactsh.poll()
                if interactions:
                    if hasattr(self, '_v'):
                        self._v.emit("exploit.xss.interactsh.callback", {"param": param, "level": "L1", "interactions": len(interactions)})
                    return XSSFinding(
                        url=url, parameter=param, payload=probe, context="oob",
                        validation_method="L1_interactsh", evidence={"oob": True, "level": "L1"},
                        confidence=1.0, status="VALIDATED_CONFIRMED", validated=True
                    ), detected_context, html_snippet, detected_contexts
            except Exception:
                pass

        logger.info(f"[{self.name}] L1: Probe reflects but not confirmed for '{param}' (context: {detected_context})")
        return None, detected_context, html_snippet, detected_contexts

    async def _escalation_l2_static_bombing(
        self, url: str, param: str, interactsh_url: str, context: str = "html"
    ) -> tuple:
        """L2: Fire all curated + GOLDEN payloads. Returns (result, reflecting_payloads).

        Uses Go fuzzer for mass reflection detection (50 concurrent goroutines, ~3s),
        then Python only for confirming the reflecting payloads (~5-10s).
        Falls back to pure Python if Go bridge unavailable.
        """
        # Build payload list: curated first, then GOLDEN
        curated = self.payload_learner.get_prioritized_payloads([])
        golden = [p.replace("{{interactsh_url}}", interactsh_url) for p in self.GOLDEN_PAYLOADS]
        curated = [p.replace("{{interactsh_url}}", interactsh_url) for p in curated]

        # Context-aware prioritization: context-specific payloads FIRST
        context_payloads = []
        if context and context != "html":
            try:
                context_payloads = self.get_payloads_for_context(context, interactsh_url)
                if context_payloads:
                    logger.info(
                        f"[{self.name}] L2: Prioritizing {len(context_payloads)} "
                        f"payloads for context '{context}'"
                    )
            except Exception as e:
                logger.debug(f"[{self.name}] L2: Context payload lookup failed: {e}")

        # Merge and dedupe: context-specific → golden (high quality) → curated
        seen = set()
        all_payloads = []
        for p in context_payloads + golden + curated:
            if p not in seen:
                seen.add(p)
                all_payloads.append(p)

        logger.info(f"[{self.name}] L2: Bombing {len(all_payloads)} static payloads on '{param}'")

        # ===== TRY GO BRIDGE (fast path: ~3s for 870 payloads) =====
        # Go bridge only supports GET — skip for POST params
        method = getattr(self, '_current_http_method', 'GET')
        go_available = await self._ensure_go_bridge() if method == "GET" else False
        if method == "POST":
            logger.info(f"[{self.name}] L2: Skipping Go bridge for POST param '{param}', using Python")
        if go_available:
            try:
                result, reflecting = await self._l2_go_fast_path(
                    url, param, all_payloads, interactsh_url, context
                )
                if result:
                    return result, reflecting

                # Go path completed - check Interactsh and return
                interactsh_result = await self._l2_check_interactsh(url, param, reflecting)
                if interactsh_result:
                    return interactsh_result, reflecting

                logger.info(f"[{self.name}] L2: {len(reflecting)} reflecting, 0 confirmed for '{param}'")
                return None, reflecting
            except Exception as e:
                logger.warning(f"[{self.name}] L2: Go bridge failed ({e}), falling back to Python")

        # ===== PYTHON FALLBACK (slow path: ~150s for 870 payloads) =====
        logger.info(f"[{self.name}] L2: Using Python fallback for {len(all_payloads)} payloads")
        result, reflecting = await self._l2_python_fallback(
            url, param, all_payloads, interactsh_url
        )
        if result:
            return result, reflecting

        interactsh_result = await self._l2_check_interactsh(url, param, reflecting)
        if interactsh_result:
            return interactsh_result, reflecting

        logger.info(f"[{self.name}] L2: {len(reflecting)} reflecting, 0 confirmed for '{param}'")
        return None, reflecting

    async def _l2_go_fast_path(
        self, url: str, param: str, payloads: list, interactsh_url: str, context: str
    ) -> tuple:
        """Go fast path: mass fuzz with Go, confirm reflecting with Python.

        Go fires all 870 payloads in ~3s with 50 goroutines, returns which ones
        reflected. Python then re-tests ONLY those (~5-30) with full HTTP analysis.
        """
        import time
        start = time.time()

        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.go_fuzzer.started", {"param": param, "payload_count": len(payloads)})

        # Step 1: Go mass fuzzing (all payloads in parallel)
        go_result = await self._go_bridge.run(
            url=url, param=param, payloads=payloads
        )

        go_duration = time.time() - start
        reflecting_payloads = [r.payload for r in (go_result.reflections or [])]

        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.go_fuzzer.completed", {"param": param, "total_requests": go_result.total_requests, "reflecting": len(reflecting_payloads), "duration_s": round(go_duration, 1), "rps": round(go_result.requests_per_second)})

        logger.info(
            f"[{self.name}] L2-Go: {go_result.total_requests} payloads tested in "
            f"{go_duration:.1f}s ({go_result.requests_per_second:.0f} req/s), "
            f"{len(reflecting_payloads)} reflecting"
        )

        if not reflecting_payloads:
            return None, []

        # Prioritize: payloads with document.domain/cookie first (higher impact proof)
        def _payload_quality_key(p):
            if "document.domain" in p or "document.cookie" in p:
                return 0
            if "BUGTRACEAI" in p or "BUGTRACE" in p:
                return 1
            return 2

        reflecting_payloads.sort(key=_payload_quality_key)

        # Step 2: Python confirms reflecting payloads (full HTTP analysis)
        logger.info(
            f"[{self.name}] L2-Py: Confirming {len(reflecting_payloads)} "
            f"reflecting payloads with full HTTP analysis"
        )

        confirmed_reflecting = []
        confirmed_payloads = []
        first_finding = None

        for i, payload in enumerate(reflecting_payloads):
            dashboard.set_current_payload(
                payload[:60], "XSS L2-Confirm",
                f"{i+1}/{len(reflecting_payloads)}", self.name
            )

            response = await self._send_payload(param, payload)
            if not response:
                continue

            # Full HTTP confirmation (5 checks including JS string breakout)
            evidence = {}
            if self._can_confirm_from_http_response(payload, response, evidence):
                confirmed_payloads.append(payload)
                if not first_finding:
                    first_finding = XSSFinding(
                        url=url, parameter=param, payload=payload,
                        context=evidence.get("execution_context", "html"),
                        validation_method="L2_go_static_http",
                        evidence={**evidence, "level": "L2", "engine": "go+python"},
                        confidence=0.90, status="VALIDATED_CONFIRMED", validated=True
                    )
                    logger.info(
                        f"[{self.name}] L2: CONFIRMED via Go+Python in "
                        f"{time.time() - start:.1f}s (context: {evidence.get('execution_context', 'unknown')})"
                    )
                if len(confirmed_payloads) >= 5:
                    break
                continue

            # Track as reflecting for L5 browser fallback
            if self._payload_reflects(payload, response):
                confirmed_reflecting.append(payload)

        if first_finding:
            first_finding.successful_payloads = confirmed_payloads
            logger.info(
                f"[{self.name}] L2: {len(confirmed_payloads)} alternative payloads confirmed "
                f"for '{param}'"
            )
            return first_finding, confirmed_reflecting

        return None, confirmed_reflecting

    async def _l2_python_fallback(
        self, url: str, param: str, payloads: list, interactsh_url: str
    ) -> tuple:
        """Pure Python fallback: sequential HTTP requests with analysis."""
        reflecting = []
        confirmed_payloads = []
        first_finding = None

        for i, payload in enumerate(payloads):
            if i % 50 == 0 and i > 0:
                dashboard.log(f"[{self.name}] L2: Progress {i}/{len(payloads)}", "DEBUG")
            if hasattr(self, '_v'):
                self._v.progress("exploit.xss.level.progress", {"level": "L2", "param": param, "total": len(payloads)}, every=50)
            dashboard.set_current_payload(payload[:60], "XSS L2", f"{i+1}/{len(payloads)}", self.name)

            response = await self._send_payload(param, payload)
            if not response:
                continue

            evidence = {}
            if self._can_confirm_from_http_response(payload, response, evidence):
                confirmed_payloads.append(payload)
                if not first_finding:
                    first_finding = XSSFinding(
                        url=url, parameter=param, payload=payload,
                        context=evidence.get("execution_context", "html"),
                        validation_method="L2_static_http",
                        evidence={**evidence, "level": "L2"},
                        confidence=0.90, status="VALIDATED_CONFIRMED", validated=True
                    )
                if len(confirmed_payloads) >= 5:
                    break
                continue

            if self._payload_reflects(payload, response):
                reflecting.append(payload)

        if first_finding:
            first_finding.successful_payloads = confirmed_payloads
            return first_finding, reflecting

        return None, reflecting

    async def _l2_check_interactsh(self, url: str, param: str, reflecting: list):
        """Check Interactsh for OOB callbacks after L2 bombing."""
        if self.interactsh:
            try:
                interactions = await self.interactsh.poll()
                if interactions:
                    if hasattr(self, '_v'):
                        self._v.emit("exploit.xss.interactsh.callback", {"param": param, "level": "L2", "interactions": len(interactions)})
                    for rp in reflecting:
                        if self._payload_carries_oob(rp):
                            return XSSFinding(
                                url=url, parameter=param, payload=rp, context="oob",
                                validation_method="L2_interactsh",
                                evidence={"oob": True, "level": "L2"},
                                confidence=1.0, status="VALIDATED_CONFIRMED", validated=True
                            )
            except Exception:
                pass
        return None

    async def _escalation_l3_llm_bombing(
        self, url: str, param: str, interactsh_url: str, existing_reflecting: list,
        context: str = "html", probe_snippet: str = ""
    ) -> tuple:
        """L3: Generate LLM payloads (max 10), multiply by breakouts, fire via HTTP."""
        # Use context from L1 analysis, or analyze from existing reflections
        sample_context = context if context != "html" else "html"
        html_snippet = probe_snippet

        if sample_context == "html" and existing_reflecting:
            sample_resp = await self._send_payload(param, existing_reflecting[0])
            if sample_resp:
                ctx = self._analyze_reflection_context(sample_resp, existing_reflecting[0])
                if ctx:
                    sample_context = ctx.get("context", "html")
                    html_snippet = ctx.get("snippet", "")[:500]

        # Ask DeepSeek for visual payloads tailored to context (with HTML snippet)
        visual_payloads = await self._ask_deepseek_visual_payloads(
            param=param, contexts=[sample_context],
            sample_payloads={sample_context: existing_reflecting[0] if existing_reflecting else "<img src=x onerror=alert(1)>"},
            html_snippet=html_snippet
        )

        if hasattr(self, '_v'):
            self._v.emit("exploit.xss.llm_payloads", {"param": param, "count": len(visual_payloads) if visual_payloads else 0, "context": sample_context})

        if not visual_payloads:
            logger.info(f"[{self.name}] L3: LLM generated 0 payloads, skipping")
            return None, []

        # Multiply by breakouts. get_top_breakouts() ranks by global success_count ALONE —
        # no context filter, no surviving-chars filter — so a breakout that actually fits
        # the detected context (e.g. '">' for a double-quoted attribute) can sit outside
        # the limit and never be tried. Union it with the prefixes the shared context
        # table prescribes for this context (single source of truth:
        # tools/manipulator/context_analyzer.CONTEXT_BREAKOUTS) and drop empty prefixes,
        # which only duplicate the base payload. The union is ADDITIVE in BOTH directions:
        # every globally ranked prefix survives it (see merge_breakout_prefixes) and
        # `sample_context` — which may be an LLM-invented label, not this agent's
        # reflection vocabulary — can only widen the set, never narrow it.
        from bugtrace.tools.manipulator.breakout_manager import breakout_manager
        surviving = getattr(self, "_surviving_chars", "")
        breakout_prefixes = merge_breakout_prefixes(
            context_breakout_prefixes(sample_context, surviving),
            [b.prefix for b in breakout_manager.get_top_breakouts(limit=10)],
        )

        # Deterministic tag-closing candidates first: L3 otherwise only ever fires what the
        # LLM invented, so the '"><svg onload=...>' family could stay unreachable.
        amplified = tag_closing_breakout_payloads(sample_context, surviving, self.SMART_PAYLOADS)
        for vp in visual_payloads:
            amplified.append(vp)  # Base payload
            for prefix in breakout_prefixes:
                amplified.append(prefix + vp)

        logger.info(f"[{self.name}] L3: Bombing {len(amplified)} LLM×breakout payloads on '{param}'")

        reflecting = []
        for i, payload in enumerate(amplified):
            if i % 100 == 0 and i > 0:
                dashboard.log(f"[{self.name}] L3: Progress {i}/{len(amplified)}", "DEBUG")
            if hasattr(self, '_v'):
                self._v.progress("exploit.xss.level.progress", {"level": "L3", "param": param, "total": len(amplified)}, every=50)
            dashboard.set_current_payload(payload[:60], "XSS L3", f"{i+1}/{len(amplified)}", self.name)

            response = await self._send_payload(param, payload)
            if not response:
                continue

            evidence = {}
            if self._can_confirm_from_http_response(payload, response, evidence):
                return XSSFinding(
                    url=url, parameter=param, payload=payload, context=evidence.get("execution_context", "html"),
                    validation_method="L3_llm_http", evidence={**evidence, "level": "L3"},
                    confidence=0.90, status="VALIDATED_CONFIRMED", validated=True
                ), reflecting

            if self._payload_reflects(payload, response):
                reflecting.append(payload)

        logger.info(f"[{self.name}] L3: {len(reflecting)} reflecting, 0 confirmed for '{param}'")
        return None, reflecting

    async def _param_try_bypass_attempts(
        self,
        param: str,
        payload: str,
        response_html: str,
        interactsh_url: str,
        validation_method: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: InjectionContext
    ) -> Optional[XSSFinding]:
        """Phase 6: Bypass attempts if initial payload failed."""
        max_attempts = self._bypass_determine_max_attempts()

        for attempt in range(max_attempts):
            bypass_response = await self._llm_generate_bypass(
                payload, response_html[:50000], interactsh_url
            )

            if not bypass_response or not bypass_response.get("bypass_payload"):
                break

            bypass_payload = bypass_response.get("bypass_payload")
            dashboard.set_current_payload(bypass_payload[:60], "XSS Bypass", "Testing")

            response_html = await self._send_payload(param, bypass_payload)
            validated, evidence = await self._validate(
                param, bypass_payload, response_html, screenshots_dir
            )

            if not validated:
                continue

            finding_data = self._bypass_prepare_finding_data(evidence, bypass_response, reflection_type)

            if not self._should_create_finding(finding_data):
                continue

            return self._create_xss_finding(
                param, bypass_payload, bypass_response.get("strategy", "bypass"),
                validation_method, evidence, 0.95,
                reflection_type, surviving_chars, [bypass_payload],
                injection_ctx, "waf_bypass",
                bypass_response.get("reasoning", "LLM generated WAF bypass.")
            )

        return None

