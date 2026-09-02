"""
XSSVerifier checks/interactions mixin (Playwright DOM probes).

Composed into XSSVerifier in verifier.py.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple

from bugtrace.utils.logger import get_logger
from bugtrace.tools.visual.verifier_evidence import (
    _MARKER_EVIDENCE_NODE_LIMIT,
    _MARKER_EVIDENCE_JS,
    _POC_ELEMENT_ID_HINTS,
    _DEFACEMENT_TEXT_MARKERS,
    _BANNER_STYLE_TOKENS,
    _MIN_BANNER_STYLE_TOKENS,
    _SOURCE_SYNTAX_CHARS,
    _OVERLAY_MIN_VIEWPORT_COVERAGE,
    _OVERLAY_MAX_TEXT_SHARE,
    _OCCLUSION_MAX_ROUNDS,
    _OCCLUSION_SAMPLE_COLS,
    _OCCLUSION_SAMPLE_ROWS,
    _OCCLUSION_TIMEOUT_S,
    _STACKING_RESET_DECLARATIONS,
    _BANNER_LOCK_DECLARATIONS,
    _NEUTRALIZE_OCCLUDERS_JS,
    decode_js_escapes,
    decoded_payload_sources,
    normalize_style,
    _node_attrs,
    has_poc_element_id,
    has_banner_style,
    marker_sent_as_string_literal,
    is_execution_evidence,
    node_execution_evidence,
    evaluate_marker_evidence,
    payload_carries_marker,
    VerificationResult,
)

logger = get_logger("tools.browser_verifier")


class VerifierChecksMixin:
    """DOM indicator checks and user-interaction simulation for XSSVerifier."""

    async def _simulate_user_interactions(self, page, url: str, console_logs: List, dialog_detected: List):
        """Simulate user interactions to trigger XSS."""
        try:
            logger.info(f"[{url}] 🖱️ Simulating User Interactions...")

            # Try focus events
            if await self._simulate_focus_events(page, dialog_detected):
                return self._make_early_result(console_logs)

            # Try hover events
            if await self._simulate_hover_events(page, dialog_detected):
                return self._make_early_result(console_logs)

            # Try click events
            if await self._simulate_click_events(page, url, dialog_detected):
                return self._make_early_result(console_logs)
        except Exception as e:
            logger.warning(f"Interaction simulation error: {e}")

        return None


    async def _simulate_focus_events(self, page, dialog_detected: List) -> bool:
        """Simulate focus events on inputs."""
        inputs = await page.query_selector_all("input, textarea, select")
        for i, inp in enumerate(inputs[:5]):
            if dialog_detected[0]:
                return True
            if not await inp.is_visible():
                continue

            await self._trigger_focus_event(page, inp, i)

        return dialog_detected[0]


    async def _trigger_focus_event(self, page, element, index: int):
        """Trigger focus event on a single element."""
        try:
            logger.debug(f"Forcing focus on input {index}")
            await page.evaluate('''(el) => {
                el.focus();
                el.dispatchEvent(new FocusEvent('focus', { bubbles: true }));
                el.dispatchEvent(new FocusEvent('focusin', { bubbles: true }));
            }''', element)
            await asyncio.sleep(0.8)
        except Exception as e:
            logger.debug(f"Focus event failed: {e}")


    async def _simulate_hover_events(self, page, dialog_detected: List) -> bool:
        """Simulate hover events on elements."""
        candidates = await page.query_selector_all("img, div, span, a, label")
        for i, cand in enumerate(candidates[:10]):
            if dialog_detected[0]:
                return True
            try:
                if await cand.is_visible():
                    await cand.hover(timeout=500)
            except Exception as e:
                logger.debug(f"Hover action failed: {e}")
        return dialog_detected[0]


    async def _simulate_click_events(self, page, url: str, dialog_detected: List) -> bool:
        """Simulate click events on clickable elements."""
        clickable_selectors = [
            "a[href^='javascript:']", "button[onclick]", "div[onclick]",
            "input[type='submit']", "a:has-text('Back')",
            "button:has-text('Back')", ".back-button"
        ]

        for selector in clickable_selectors:
            if dialog_detected[0]:
                return True
            elements = await page.query_selector_all(selector)
            if await self._click_elements(elements, url, selector, dialog_detected):
                return True
        return dialog_detected[0]


    async def _click_elements(self, elements, url: str, selector: str, dialog_detected: List) -> bool:
        """Click elements and check for dialog detection."""
        for i, elem in enumerate(elements[:3]):
            if dialog_detected[0]:
                return True
            try:
                if await elem.is_visible():
                    logger.info(f"[{url}] Clicking: {selector} [{i}]")
                    await elem.click(timeout=1000)
                    await asyncio.sleep(1.0)
            except Exception as e:
                logger.debug(f"Element click failed: {e}")
        return dialog_detected[0]


    def _make_early_result(self, console_logs: List) -> VerificationResult:
        """Create early success result for user interaction."""
        return VerificationResult(
            success=True,
            method="playwright",
            screenshot_path=None,
            console_logs=console_logs,
            details={"dialog_detected": True, "trigger": "user_interaction"}
        )


    async def _evaluate_xss_indicators(self, page, url: str, dialog_detected: bool,
                                      console_logs: List, expected_marker: Optional[str]) -> Tuple[bool, Dict]:
        """Evaluate all XSS indicators in the page."""
        if dialog_detected:
            return True, {}

        try:
            marker_found = await self._check_expected_marker(page, expected_marker)
            xss_in_dom = await self._check_xss_in_dom(page, url)
            xss_var_confirmed = await self._check_window_variable(page, url)
            csti_confirmed = await self._check_csti(page, url)
            visual_confirmed = await self._check_visual_defacement(page, url)
            xss_in_console = self._check_console_logs(console_logs)

            xss_confirmed = (marker_found or xss_in_dom or xss_in_console or
                           csti_confirmed or visual_confirmed or xss_var_confirmed)

            return xss_confirmed, {"marker_found": marker_found}
        except Exception as e:
            logger.debug(f"DOM evaluation failed: {e}")
            return False, {}


    async def _check_expected_marker(self, page, expected_marker: Optional[str]) -> bool:
        """Check if expected marker exists."""
        if expected_marker:
            return await page.evaluate(f'document.getElementById("{expected_marker}") !== null')
        return False


    async def _check_xss_in_dom(self, page, url: str = "") -> bool:
        """Check the DOM for markers PRODUCED BY EXECUTION, not merely echoed.

        The marker is part of the payload, so a substring match over innerHTML
        confirms a plain reflection as XSS. Mirrors cdp_client: structural proof
        (an element whose own text is the marker) instead of a substring hit.
        Fails OPEN (previous innerHTML behaviour) whenever the DOM probe cannot
        run - CSP, navigation, detached page - so no real finding is dropped.
        """
        markers = [self.XSS_MARKER, "XSS-HACKED"]
        try:
            data = await page.evaluate(_MARKER_EVIDENCE_JS, markers)
        except Exception as e:
            logger.debug(f"Marker evidence probe failed ({e}); falling back to raw DOM match")
            return await self._check_marker_in_html(page, markers)

        if not isinstance(data, dict):
            return await self._check_marker_in_html(page, markers)

        echo_source = decoded_payload_sources(url)
        executed, marker_in_text = evaluate_marker_evidence(data.get("nodes"), markers, echo_source)
        marker_in_html = bool(data.get("markers_in_html"))

        if executed:
            return True

        # The request never carried the marker, so the DOM cannot have echoed it.
        if (marker_in_html or marker_in_text) and not payload_carries_marker(markers, echo_source):
            return True

        # Collection hit the node cap: the proving element may be one we never
        # looked at, so a negative here would be an artefact. Fail OPEN.
        if data.get("truncated"):
            logger.debug(
                f"[{url}] Marker evidence collection truncated at "
                f"{_MARKER_EVIDENCE_NODE_LIMIT} nodes; falling back to raw DOM match"
            )
            return await self._check_marker_in_html(page, markers)

        if marker_in_html or marker_in_text:
            logger.info(f"[{url}] Marker found in DOM but no JS execution - may be HTML injection, not XSS")
        return False


    async def _check_marker_in_html(self, page, markers: List[str]) -> bool:
        """Legacy raw innerHTML match, kept as the fail-open path only."""
        for marker in markers:
            try:
                if await page.evaluate(f'document.body.innerHTML.includes("{marker}")'):
                    return True
            except Exception as e:
                # Keep trying the remaining markers: one failed evaluation must not
                # discard the others.
                logger.debug(f"Raw DOM marker match failed: {e}")
        return False


    async def _check_window_variable(self, page, url: str) -> bool:
        """Check for XSS_CONFIRMED window variable."""
        xss_var = await page.evaluate('window.XSS_CONFIRMED === true')
        if xss_var:
            logger.info(f"[{url}] Window variable XSS_CONFIRMED found!")
        return xss_var


    async def _check_csti(self, page, url: str) -> bool:
        """Check for CSTI arithmetic expression evaluation in rendered DOM.

        Uses page.content() (rendered DOM) instead of innerText because Angular/Vue
        may evaluate {{7*7}} in attributes (e.g., hidden input value="49") that
        aren't visible in innerText. Strips <script> tags since template markers
        in JS variables are NOT evaluated by client-side engines.
        """
        import re
        from urllib.parse import unquote
        decoded_url = unquote(url)

        # Arithmetic markers: (payload_expression, evaluated_result).
        # The distinctive 1000003*1000003 → 1000006000009 marker is the CURRENT CSTI
        # probe (commit bf8ba65) — chosen so a stray short "49" can't false-confirm.
        # The 7*7 → 49 forms are kept for backward compatibility with legacy payloads.
        # NOTE: this browser-side detector previously only knew 7*7/49 and silently
        # failed to confirm every 1000003*1000003 payload the CSTI agent actually sends.
        arithmetic_markers = [
            ("1000003*1000003", "1000006000009"),
            ("7*7", "49"),
            ("7*'7'", "49"),
            ("'7'*7", "49"),
        ]
        present = [(m, r) for (m, r) in arithmetic_markers if m in decoded_url]
        has_arithmetic = bool(present)
        has_constructor = "constructor" in decoded_url

        if not has_arithmetic and not has_constructor:
            return False

        # Get rendered DOM and strip <script> tags (JS vars aren't template-evaluated)
        page_content = await page.content()
        page_content_no_scripts = re.sub(
            r'<script[^>]*>.*?</script>', '', page_content,
            flags=re.DOTALL | re.IGNORECASE
        )

        # Also get visible text for string multiply / constructor checks
        page_text = await page.evaluate("document.body.innerText")

        # Literal template markers (payload reflected but NOT evaluated). If any is
        # present, the engine echoed the source verbatim — that is NOT evaluation.
        template_markers = [
            "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}", "{{7*'7'}}", "{{'7'*7}}",
            "{{1000003*1000003}}", "${1000003*1000003}", "<%= 1000003*1000003 %>",
            "#{1000003*1000003}", "[[1000003*1000003]]", "{1000003*1000003}",
        ]

        # Check 1: arithmetic eval → evaluated result present in DOM, literal NOT present.
        # Use DOM content (not just innerText) because Angular evaluates {{expr}} in
        # attributes like value="1000006000009" which innerText doesn't include.
        for marker, result in present:
            if result in page_content_no_scripts:
                if not any(m in page_content_no_scripts for m in template_markers):
                    logger.info(f"[{url}] CSTI Confirmed: arithmetic eval {marker} → {result}")
                    return True

        # Check 2: '7'*7 → 7777777 (string multiply)
        if "7777777" in page_text or "7777777" in page_content_no_scripts:
            logger.info(f"[{url}] CSTI Confirmed: string multiply → 7777777")
            return True

        # Check 3: constructor eval — the literal constructor payload carries only the
        # SOURCE expression (e.g. 'return 1000003*1000003'), never the RESULT, so a
        # result match means it executed. Gate on markers actually in the payload.
        if has_constructor and present:
            for _marker, result in present:
                if result in page_text or result in page_content_no_scripts:
                    if not any(m in page_content_no_scripts for m in template_markers):
                        logger.info(f"[{url}] CSTI Confirmed: constructor eval → {result}")
                        return True

        return False


    async def _check_visual_defacement(self, page, url: str) -> bool:
        """Check for visual defacement markers."""
        try:
            pwn_elements = await page.evaluate('''() => {
                const allElements = document.querySelectorAll('[id*="bt-pwn"]');
                return allElements.length;
            }''')
            if pwn_elements > 0:
                logger.info(f"[{url}] Visual Defacement Confirmed (count: {pwn_elements})!")
                return True
        except Exception as e:
            logger.debug(f"Visual defacement check failed: {e}")
            if await self._check_specific_pwn_ids(page, url):
                return True

        return await self._check_text_based_markers(page, url)


    async def _check_specific_pwn_ids(self, page, url: str) -> bool:
        """Check for specific bt-pwn ID variants."""
        for pwn_id in ["#bt-pwn", "#bt-pwn-l8", "#bt-pwn-l7"]:
            if await page.locator(pwn_id).count() > 0:
                logger.info(f"[{url}] Visual Defacement Confirmed: '{pwn_id}' element found!")
                return True
        return False


    async def _check_text_based_markers(self, page, url: str) -> bool:
        """Check for text-based defacement markers."""
        markers = _DEFACEMENT_TEXT_MARKERS

        for marker in markers:
            if await page.locator(f"div:has-text('{marker}')").count() > 0:
                if await self._check_marker_divs(page, url, marker):
                    return True
        return False


    async def _check_marker_divs(self, page, url: str, marker: str) -> bool:
        """Check divs containing marker for XSS confirmation."""
        pwn_divs = await page.locator(f"div:has-text('{marker}')").all()
        for div in pwn_divs:
            # Normalised comparison: the CSSOM re-serialises `d.style=...` to
            # "background: red;", so a literal "background:red" match would miss
            # every payload that assigns the style property instead of the attribute.
            style = normalize_style(await div.get_attribute("style"))
            div_id = await div.get_attribute("id")
            if ("background:red" in style or "background-color:red" in style) or (div_id and "bt-pwn" in div_id):
                logger.info(f"[{url}] Visual Defacement Confirmed: '{marker}' banner!")
                return True
        return False


    def _check_console_logs(self, console_logs: List) -> bool:
        """Check console logs for XSS markers."""
        return any((self.XSS_MARKER in log.get("text", "") or
                   "XSS-VERIFIED" in log.get("text", "")) for log in console_logs)


    async def _extract_impact_data(self, page, url: str, xss_confirmed: bool) -> Dict:
        """Extract impact data if XSS is confirmed."""
        if not xss_confirmed:
            return {}

        try:
            impact_data = await page.evaluate('''() => {
                return {
                    cookie_count: document.cookie ? document.cookie.split(';').length : 0,
                    cookies: document.cookie,
                    origin: window.origin,
                    localStorageKeys: Object.keys(localStorage),
                    sessionStorageKeys: Object.keys(sessionStorage),
                    has_sensitive_tokens: (document.cookie + JSON.stringify(localStorage)).match(/token|jwt|session|auth|key/i) !== null
                }
            }''')

            has_storage_access = (impact_data.get('cookies') or impact_data.get('localStorageKeys'))
            is_sandboxed = impact_data.get('origin') == "null" or not has_storage_access

            if is_sandboxed:
                logger.warning(f"[{url}] ⚠️ XSS confirmed but SANDBOXED. Impact is LOW.")

            if impact_data.get('has_sensitive_tokens'):
                logger.info(f"[{url}] 💰 CRITICAL IMPACT: Sensitive tokens found!")

            impact_data['is_sandboxed'] = is_sandboxed
            return impact_data
        except Exception as e:
            logger.warning(f"Impact extraction failed: {e}")
            return {}


    async def _neutralize_occluders(self, page) -> Dict:
        """Clear whatever buries the PoC banner, right before the screenshot.

        Structural only (`getComputedStyle`, `getBoundingClientRect`, `:modal`,
        `:popover-open`) — see `_NEUTRALIZE_OCCLUDERS_JS`. Best effort: a page that
        refuses the probe (CSP, navigation, detached frame) still gets its
        screenshot, just without the cleanup.

        Returns the probe's report, or an empty dict when it could not run.
        """
        cfg = {
            "idHints": [h.lower() for h in _POC_ELEMENT_ID_HINTS],
            "textMarkers": [m.upper() for m in _DEFACEMENT_TEXT_MARKERS],
            "stackingResets": [list(d) for d in _STACKING_RESET_DECLARATIONS],
            "bannerLocks": [list(d) for d in _BANNER_LOCK_DECLARATIONS],
            "coverage": _OVERLAY_MIN_VIEWPORT_COVERAGE,
            "textShare": _OVERLAY_MAX_TEXT_SHARE,
            "maxRounds": _OCCLUSION_MAX_ROUNDS,
            "cols": _OCCLUSION_SAMPLE_COLS,
            "rows": _OCCLUSION_SAMPLE_ROWS,
        }
        try:
            report = await asyncio.wait_for(
                page.evaluate(_NEUTRALIZE_OCCLUDERS_JS, cfg),
                timeout=_OCCLUSION_TIMEOUT_S,
            )
        except Exception as e:
            logger.debug(f"Occluder neutralisation skipped: {e}")
            return {}
        if not isinstance(report, dict):
            return {}
        cleared = (report.get("top_layer", 0) + report.get("overlays", 0) +
                   report.get("occluders", 0) + report.get("ancestors_reset", 0))
        if cleared or report.get("reparented"):
            logger.info(
                f"Screenshot cleanup: {report.get('top_layer', 0)} top-layer, "
                f"{report.get('overlays', 0)} full-viewport overlay(s), "
                f"{report.get('occluders', 0)} direct occluder(s), "
                f"{report.get('ancestors_reset', 0)} dimmed ancestor(s)"
                f"{', banner re-parented' if report.get('reparented') else ''}"
            )
        if report.get("banner") and report.get("samples") and \
                report.get("clear", 0) < report.get("samples", 0):
            logger.warning(
                f"PoC banner still occluded at "
                f"{report['samples'] - report['clear']}/{report['samples']} "
                f"sampled points after cleanup"
            )
        return report


