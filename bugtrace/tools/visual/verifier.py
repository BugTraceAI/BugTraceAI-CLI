"""
Browser Verification Module - CDP + Playwright Hybrid.

Provides robust XSS verification using multiple methods:
1. CDP (Chrome DevTools Protocol) - Primary, more reliable
2. Playwright - Fallback if CDP fails

Author: BugtraceAI Team
Date: 2026-01-08
"""

import os
import re
import asyncio
from typing import Tuple, List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings

logger = get_logger("tools.browser_verifier")


# =============================================================================
# MARKER EVIDENCE: execution vs echo (pure helpers + one DOM probe)
# =============================================================================
# The XSS marker string travels INSIDE the payload, so finding it in
# document.body.innerHTML proves nothing: a server that echoes the payload back
# inert produces exactly the same substring. cdp_client._check_xss_in_dom_executed()
# already discriminates STRUCTURALLY (an element only script could have created vs
# a raw echo); the helpers below mirror that logic for the Playwright path.
#
# What proves execution, in order of strength:
#   1. The element bears our PoC element id (bt-pwn / BTPOE_) - script-only.
#   2. The element carries a marker AND the inline style of a defacement banner
#      (fixed overlay + red background + z-index): the browser re-serialises both
#      `d.style=...` and setAttribute('style', ...) into the same declarations, so
#      the comparison is normalised, never a literal substring.
#   3. Every character of the marker-bearing text (or of a non-handler attribute
#      value) was sent by us as a literal, i.e. the script wrote the label. A
#      server echo instead WRAPS the marker in text we never sent.
# A banner whose label merely CONTAINS the marker is therefore still execution,
# while a plain reflection ("You searched for: <marker>") is not.
#
# One JS evaluation collects, for every element carrying a marker in its OWN text
# nodes or in an attribute value (plus document.title), the raw material.
# Decision logic is pure Python.

# Cap on collected elements. Hitting it is reported so the caller can FAIL OPEN
# instead of turning a truncated collection into a negative verdict.
_MARKER_EVIDENCE_NODE_LIMIT = 200

_MARKER_EVIDENCE_JS = """(markers) => {
    const body = document.body;
    const html = body ? (body.innerHTML || "") : "";
    const nodes = [];
    let truncated = false;
    if (body) {
        const elements = [body].concat(Array.from(body.querySelectorAll('*')));
        for (const el of elements) {
            let own = "";
            for (const child of el.childNodes) {
                if (child.nodeType === 3) { own += child.nodeValue; }
            }
            const attrs = {};
            let carries = markers.some(m => own.includes(m));
            for (const a of Array.from(el.attributes || [])) {
                attrs[a.name] = a.value;
                if (markers.some(m => (a.value || "").includes(m))) { carries = true; }
            }
            // Inline style in the browser's canonical spelling: `el.style = "..."`
            // and setAttribute('style', "...") both serialise identically here.
            const style = (el.style && el.style.cssText) || attrs["style"] || "";
            // Marker-less elements are kept only when they bear our PoC id.
            if (!carries && !/bt-pwn|BTPOE_/i.test(attrs["id"] || "")) { continue; }
            nodes.push({tag: (el.tagName || "").toLowerCase(), own: own,
                        attrs: attrs, style: style});
            if (nodes.length >= __NODE_LIMIT__) { truncated = true; break; }
        }
    }
    const title = document.title || "";
    if (markers.some(m => title.includes(m))) {
        nodes.push({tag: "title", own: title, attrs: {}, style: ""});
    }
    return {markers_in_html: markers.filter(m => html.includes(m)),
            nodes: nodes, truncated: truncated};
}""".replace("__NODE_LIMIT__", str(_MARKER_EVIDENCE_NODE_LIMIT))

# Element ids that only our own payloads create (same convention cdp_client uses).
_POC_ELEMENT_ID_HINTS = ("bt-pwn", "btpoe_")

# Labels our defacement payloads print. Used both to read a banner back out of the
# DOM (`_check_text_based_markers`) and to recognise our own element in the
# screenshot path when the payload that fired carried no PoC id.
_DEFACEMENT_TEXT_MARKERS = (
    "HACKED BY BUGTRACEAI", "FRAGMENT XSS", "MXSS DETECTED",
    "XSS DETECTED", "PWNED BY BUGTRACE",
)

# Declarations that make up a defacement banner. Compared against the NORMALISED
# (whitespace-free, lowercased) inline style, so `d.style=...` re-serialised by the
# CSSOM ("background: red;") and setAttribute('style','background:red') both match.
_BANNER_STYLE_TOKENS = (
    "position:fixed", "z-index:", "background:red", "background-color:red",
    "width:100%", "top:0",
)
_MIN_BANNER_STYLE_TOKENS = 2

# A rendered banner label is plain text. These characters mean we are looking at
# payload SOURCE reflected inert, not at something a script printed.
_SOURCE_SYNTAX_CHARS = "<>(){}[];=`"

# Quote characters that open a JS string literal, and the characters that separate
# one datum from the next in a request (query syntax / markup). See
# `marker_sent_as_string_literal`.
_JS_STRING_DELIMITERS = "'\"`"
_ECHO_DATA_BOUNDARY = "=&?#<>"
# How far back to look for the opening quote. A banner label sits at the head of its
# own literal, so the delimiter is a handful of characters away; scanning further
# would only let an unrelated quote elsewhere in the request vouch for it.
_ECHO_LITERAL_SCAN_WINDOW = 64

_JS_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})")


# =============================================================================
# SCREENSHOT LEGIBILITY: clear whatever buries the PoC banner
# =============================================================================
# A confirmed XSS is worth nothing in the report if the proof screenshot shows the
# banner dimmed under a consent backdrop: the Vision pass reads that as "no visible
# exploitation". The payload already claims the maximum z-index in the ROOT stacking
# context, which beats every in-page overlay — but NOT the top layer (`dialog`
# opened with `showModal()`, an open popover, a fullscreen element), which paints
# above every z-index by spec, and not a dimmer that our own ancestors apply.
#
# This runs ONLY on the screenshot path, AFTER every detection probe has already
# read the DOM (`_evaluate_xss_indicators` → `_extract_impact_data` →
# `_capture_screenshot`), so it can never change a verdict — only what the evidence
# image shows.
#
# Everything below is decided STRUCTURALLY, from `getComputedStyle` /
# `getBoundingClientRect` / standard pseudo-classes (`:modal`, `:popover-open`).
# There is deliberately not a single class name, id or vendor string of a target
# site in it: a consent widget is recognised by BEING a full-viewport stacked
# overlay, not by being called one. The only names it matches are OUR OWN PoC
# markers, so it never hides the very banner it is protecting.

# An element must cover at least this share of the viewport to count as a blocking
# overlay rather than as page furniture (a top bar, a cookie strip at the bottom,
# a sticky header — none of which bury a full-width banner at y=0).
_OVERLAY_MIN_VIEWPORT_COVERAGE = 0.5
# ...and must hold at most this share of the page's visible text. A backdrop is
# empty or near-empty; an element holding most of the copy IS the page.
_OVERLAY_MAX_TEXT_SHARE = 0.5
# Hide-and-remeasure rounds. Each round can only reveal a deeper layer, so this is
# a hard bound on a loop that is otherwise driven by the page.
_OCCLUSION_MAX_ROUNDS = 8
# Sample grid over the banner used to measure occlusion (columns x rows).
_OCCLUSION_SAMPLE_COLS = 9
_OCCLUSION_SAMPLE_ROWS = 3
# Hard bound on the probe. It measures 26-135 ms on 100-5000 element pages, so this
# only ever fires on a wedged renderer — where an unbounded evaluate() would hang the
# screenshot, and with it the scan, for evidence polish nobody asked to wait for.
_OCCLUSION_TIMEOUT_S = 5.0

# Properties that either DIM the banner or trap it in an ancestor's stacking
# context, with the value that neutralises each one.
_STACKING_RESET_DECLARATIONS = (
    ("opacity", "1"), ("filter", "none"), ("backdrop-filter", "none"),
    ("transform", "none"), ("perspective", "none"), ("mix-blend-mode", "normal"),
    ("contain", "none"), ("will-change", "auto"), ("clip-path", "none"),
    ("isolation", "auto"),
)

# Properties pinned on the banner itself so page CSS cannot fade, blur, displace,
# clip or collapse the proof.
_BANNER_LOCK_DECLARATIONS = (
    ("position", "fixed"), ("z-index", "2147483647"), ("opacity", "1"),
    ("filter", "none"), ("visibility", "visible"), ("display", "block"),
    ("transform", "none"), ("mix-blend-mode", "normal"), ("clip-path", "none"),
)

_NEUTRALIZE_OCCLUDERS_JS = """(cfg) => {
    const doc = document;
    const root = doc.documentElement;
    const vw = Math.max(root ? root.clientWidth : 0, window.innerWidth || 0);
    const vh = Math.max(root ? root.clientHeight : 0, window.innerHeight || 0);
    const viewport = Math.max(vw * vh, 1);
    const report = {banner: false, top_layer: 0, overlays: 0, reparented: false,
                    ancestors_reset: 0, occluders: 0, samples: 0, clear: 0};

    // --- our own PoC element (never a victim of the cleanup) -----------------
    const isOurs = (el) => {
        const id = (el.getAttribute && el.getAttribute('id')) || '';
        if (cfg.idHints.some(h => id.toLowerCase().includes(h))) { return true; }
        let own = '';
        for (const c of el.childNodes) { if (c.nodeType === 3) { own += c.nodeValue; } }
        own = own.replace(/\\s+/g, ' ').trim().toUpperCase();
        return cfg.textMarkers.some(m => own === m);
    };
    let banner = null;
    for (const el of Array.from(doc.querySelectorAll('*'))) {
        if (isOurs(el)) { banner = el; }   // last match wins: the newest banner
    }
    const keep = new Set();
    if (banner) {
        report.banner = true;
        for (let n = banner; n; n = n.parentElement) { keep.add(n); }
    }
    const spare = (el) => !el || el === doc.body || el === root || el === doc.head ||
                          keep.has(el) || (banner && banner.contains(el));
    const hide = (el) => {
        if (spare(el)) { return false; }
        try { el.style.setProperty('display', 'none', 'important'); return true; }
        catch (e) { return false; }
    };

    // --- 1. top layer: beats every z-index, so it must go first --------------
    try { if (doc.fullscreenElement) { doc.exitFullscreen(); } } catch (e) {}
    for (const dlg of Array.from(doc.querySelectorAll('dialog'))) {
        if (spare(dlg)) { continue; }
        let modal = false;
        try { modal = dlg.matches(':modal'); } catch (e) { modal = false; }
        if (!modal) { continue; }
        try { dlg.close(); } catch (e) { hide(dlg); }
        report.top_layer++;
    }
    for (const el of Array.from(doc.querySelectorAll('[popover]'))) {
        if (spare(el)) { continue; }
        let open = false;
        try { open = el.matches(':popover-open'); } catch (e) { open = false; }
        if (!open) { continue; }
        try { el.hidePopover(); } catch (e) { hide(el); }
        report.top_layer++;
    }

    // --- 2. put the banner in the root stacking context, undimmed -----------
    if (banner && root && banner.parentElement !== root) {
        try { root.appendChild(banner); report.reparented = true; } catch (e) {}
    }
    if (banner) {
        keep.clear();
        for (let n = banner; n; n = n.parentElement) { keep.add(n); }
        for (let n = banner.parentElement; n; n = n.parentElement) {
            const cs = getComputedStyle(n);
            let touched = false;
            for (const [prop, def] of cfg.stackingResets) {
                const v = (cs.getPropertyValue(prop) || '').trim();
                if (!v || v === def) { continue; }
                if (prop === 'opacity' && parseFloat(v) >= 1) { continue; }
                n.style.setProperty(prop, def, 'important');
                touched = true;
            }
            if (touched) { report.ancestors_reset++; }
        }
        for (const [prop, val] of cfg.bannerLocks) {
            try { banner.style.setProperty(prop, val, 'important'); } catch (e) {}
        }
    }

    // --- 3. full-viewport stacked overlays (the consent backdrop shape) ------
    const pageText = ((doc.body && doc.body.innerText) || '').length;
    for (const el of Array.from(doc.querySelectorAll('*'))) {
        if (spare(el)) { continue; }
        const cs = getComputedStyle(el);
        if (cs.position !== 'fixed' && cs.position !== 'sticky') { continue; }
        if (cs.display === 'none' || cs.visibility === 'hidden') { continue; }
        if (parseFloat(cs.opacity || '1') === 0) { continue; }
        const r = el.getBoundingClientRect();
        const w = Math.min(r.right, vw) - Math.max(r.left, 0);
        const h = Math.min(r.bottom, vh) - Math.max(r.top, 0);
        if (w <= 0 || h <= 0) { continue; }
        if ((w * h) / viewport < cfg.coverage) { continue; }
        const z = parseInt(cs.zIndex, 10);
        const backdrop = (cs.backdropFilter || cs.webkitBackdropFilter || 'none');
        const stacked = Number.isFinite(z) ? z >= 1 : backdrop !== 'none';
        if (!stacked) { continue; }
        if (pageText > 0 &&
            ((el.innerText || '').length / pageText) > cfg.textShare) { continue; }
        if (hide(el)) { report.overlays++; }
    }

    // --- 4. measure, then clear whatever still covers the banner -------------
    if (banner) {
        const probe = () => {
            const r = banner.getBoundingClientRect();
            const blockers = new Set();
            let total = 0, clear = 0;
            for (let i = 1; i <= cfg.cols; i++) {
                for (let j = 1; j <= cfg.rows; j++) {
                    const x = r.left + (r.width * i) / (cfg.cols + 1);
                    const y = r.top + (r.height * j) / (cfg.rows + 1);
                    if (x < 0 || y < 0 || x >= vw || y >= vh) { continue; }
                    total++;
                    const hit = doc.elementFromPoint(x, y);
                    if (hit === banner || (hit && banner.contains(hit))) { clear++; }
                    else if (hit) { blockers.add(hit); }
                }
            }
            return {total: total, clear: clear, blockers: blockers};
        };
        let m = probe();
        for (let round = 0; round < cfg.maxRounds && m.blockers.size; round++) {
            let progress = false;
            for (const b of m.blockers) { if (hide(b)) { progress = true; report.occluders++; } }
            if (!progress) { break; }
            m = probe();
        }
        report.samples = m.total;
        report.clear = m.clear;
    }
    return report;
}"""


def decode_js_escapes(text: str) -> str:
    """Pure: resolve \\xNN / \\uNNNN escapes the way a JS engine would.

    Visual payloads spell the banner label with `\\x20` instead of spaces (an
    unquoted HTML attribute ends at the first whitespace), so the RENDERED text
    only matches the request once those escapes are resolved.
    """
    def _sub(match) -> str:
        code = match.group(1) or match.group(2)
        try:
            return chr(int(code, 16))
        except Exception:
            return match.group(0)

    try:
        return _JS_ESCAPE_RE.sub(_sub, text or "")
    except Exception:
        return text or ""


def decoded_payload_sources(url: str) -> str:
    """Pure: every decoded form of the request URL, used as the 'echo' haystack.

    If a chunk of rendered text also appears here, the browser got those characters
    from what we sent; if it does not, the server produced that text itself.
    """
    from urllib.parse import unquote, unquote_plus
    raw = url or ""
    try:
        variants = [raw, unquote(raw), unquote_plus(raw)]
    except Exception:
        variants = [raw]
    variants.extend(decode_js_escapes(v) for v in list(variants))
    return "\n".join(variants)


def normalize_style(style: str) -> str:
    """Pure: whitespace-free lowercase form of an inline style, for token matching."""
    return "".join((style or "").split()).lower()


def _node_attrs(node: Dict) -> Dict:
    attrs = node.get("attrs")
    return attrs if isinstance(attrs, dict) else {}


def has_poc_element_id(node: Dict) -> bool:
    """Pure: True when the element carries an id only our own payloads create."""
    element_id = str(_node_attrs(node).get("id") or "").lower()
    return any(hint in element_id for hint in _POC_ELEMENT_ID_HINTS)


def has_banner_style(node: Dict) -> bool:
    """Pure: True when the element's inline style is that of a defacement banner."""
    style = normalize_style(node.get("style") or _node_attrs(node).get("style") or "")
    if not style:
        return False
    return sum(1 for token in _BANNER_STYLE_TOKENS if token in style) >= _MIN_BANNER_STYLE_TOKENS


def marker_sent_as_string_literal(marker: str, echo_source: str) -> bool:
    """Pure: True when the request spells `marker` INSIDE a JS string literal.

    Second provenance test, for the (common) scripts whose rendered text cannot be
    found back in the request as a whole because part of it is derived at RUNTIME -
    `document.title + ' MARKER'`, `'MARKER' + Date.now()`, a `body.prepend()` that
    lands next to text the page already had. Those characters were never in the
    request, but the label itself still travels as a quoted literal in the code we
    sent, e.g. `d.innerText='MARKER'`.

    A plain reflection carries the same characters as a bare datum instead: the
    marker is preceded by request syntax (`?q=`, `&`) or by markup (`>`), never by a
    quote opening a literal. Scanning left from the marker therefore has to reach a
    string delimiter WITHOUT crossing a datum boundary first.
    """
    if not marker:
        return False
    echo = " ".join((echo_source or "").split())
    start = echo.find(marker)
    while start != -1:
        limit = max(0, start - _ECHO_LITERAL_SCAN_WINDOW)
        for i in range(start - 1, limit - 1, -1):
            char = echo[i]
            if char in _JS_STRING_DELIMITERS:
                return True
            if char in _ECHO_DATA_BOUNDARY:
                break
        start = echo.find(marker, start + 1)
    return False


def is_execution_evidence(own_text: str, marker: str, echo_source: str) -> bool:
    """Pure: True when marker-bearing text was WRITTEN by script, not wrapped by the server.

    The marker travels inside the payload, so its presence proves nothing; what
    discriminates is where the SURROUNDING characters come from:
      * script-written label -> the characters around the marker are ours, either
        because the whole rendered text is found back in the request
        (`d.innerText=\\`HACKED BY BUGTRACEAI OWNED\\``, so extra words in the banner
        are still evidence) or because the script derived them at runtime and the
        label itself was sent as a string literal (`marker_sent_as_string_literal`).
      * server echo -> the server wrapped the reflected marker in text of its own
        ("You searched for: ..."), which we never sent, and the marker travelled as
        a bare parameter value rather than as a literal inside code.
    Text that looks like source (brackets, semicolons, backticks) is rejected: that
    is the payload reflected inert, not a rendered label.
    """
    if not own_text or not marker or marker not in own_text:
        return False

    text = " ".join(own_text.split())
    if not text or any(c in text for c in _SOURCE_SYNTAX_CHARS):
        return False

    if text in " ".join((echo_source or "").split()):
        return True

    return marker_sent_as_string_literal(marker, echo_source)


def node_execution_evidence(node: Dict, markers: List[str],
                            echo_source: str) -> Tuple[bool, bool]:
    """Pure: (execution_proven, marker_present) for ONE collected element."""
    own = node.get("own") or ""
    attrs = _node_attrs(node)
    values = {str(name): str(value or "") for name, value in attrs.items()}

    marker_present = (any(m in own for m in markers) or
                      any(m in v for v in values.values() for m in markers))

    # 1. Structural: an element only script could have put in the document.
    if has_poc_element_id(node):
        return True, marker_present
    if marker_present and has_banner_style(node):
        return True, True

    # 2. Provenance: the marker-bearing label was printed from a literal we sent.
    #    Event-handler attributes are skipped - an inert echo of the payload keeps
    #    the whole banner source inside `onerror=`/`onload=`, which proves nothing.
    for marker in markers:
        if is_execution_evidence(own, marker, echo_source):
            return True, True
        for name, value in values.items():
            if name.lower().startswith("on"):
                continue
            if is_execution_evidence(value, marker, echo_source):
                return True, True

    return False, marker_present


def evaluate_marker_evidence(nodes: Optional[List[Dict]], markers: List[str],
                             echo_source: str) -> Tuple[bool, bool]:
    """Pure: (execution_proven, marker_present) over ALL collected nodes."""
    marker_present = False
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        executed, present = node_execution_evidence(node, markers, echo_source)
        marker_present = marker_present or present
        if executed:
            return True, True
    return False, marker_present


def payload_carries_marker(markers: List[str], echo_source: str) -> bool:
    """Pure: True if the request itself contained a marker (so a DOM hit may be an echo)."""
    return any(m in echo_source for m in markers)


@dataclass
class VerificationResult:
    """Result of XSS verification."""
    success: bool
    method: str  # "cdp", "playwright", or "none"
    screenshot_path: Optional[str] = None
    console_logs: List[Dict] = None
    details: Dict[str, Any] = None
    alert_message: Optional[str] = None
    error: Optional[str] = None


class XSSVerifier:
    """
    Hybrid XSS Verifier using CDP (primary) and Playwright (fallback).
    
    CDP provides more reliable detection through:
    - Direct console.log monitoring
    - DOM inspection without race conditions
    - Network request visibility
    
    Playwright is used as fallback when CDP is unavailable.
    """
    
    # XSS MARKER
    XSS_MARKER = "HACKED BY BUGTRACEAI"
    
    def __init__(self, headless: bool = True, prefer_cdp: bool = False):
        self.headless = headless
        self.prefer_cdp = prefer_cdp
        self._cdp_available = None  # Lazy check
        
    async def _check_cdp_available(self) -> bool:
        """Check if CDP client can be initialized."""
        if not self.prefer_cdp:
            return False

        if self._cdp_available is not None:
            return self._cdp_available
            
        try:
            from bugtrace.core.cdp_client import CDPClient
            # Quick test to see if Chrome is available
            cdp = CDPClient(headless=True)
            chrome_path = cdp._find_chrome()
            self._cdp_available = chrome_path is not None
            logger.info(f"CDP available: {self._cdp_available}")
        except Exception as e:
            logger.warning(f"CDP not available: {e}")
            self._cdp_available = False
            
        return self._cdp_available
    
    async def verify_xss(
        self,
        url: str,
        screenshot_dir: Optional[str] = None,
        timeout: float = 15.0,
        expected_marker: Optional[str] = None,
        max_level: int = 4
    ) -> VerificationResult:
        """
        Verify XSS at URL using best available method up to max_level.
        
        Args:
            url: URL with XSS payload to verify
            screenshot_dir: Directory to save evidence screenshots
            timeout: Time to wait for XSS execution
            max_level: Maximum level to try (3=Playwright, 4=CDP)
            
        Returns:
            VerificationResult with outcome and evidence
        """
        # Level 3: Try Playwright first (Lighter, handles most cases)
        if max_level >= 3:
            result = await self._verify_with_playwright(url, screenshot_dir, timeout, expected_marker)
            if result.success:
                return result

        # Level 4: If Playwright failed or was inconclusive, try CDP as a specialized fallback
        if max_level >= 4 and self.prefer_cdp and await self._check_cdp_available():
            logger.info("Playwright inconclusive (L3), attempting deep validation via CDP (L4)...")
            cdp_result = await self._verify_with_cdp(url, screenshot_dir, timeout, expected_marker)
            if cdp_result.success:
                return cdp_result
        
        # If we only wanted L3 and it failed, or L3 and L4 both failed
        return result if max_level >= 3 else VerificationResult(success=False, method="none", error="Level limit reached")
    
    async def _verify_with_cdp(
        self,
        url: str,
        screenshot_dir: Optional[str],
        timeout: float,
        expected_marker: Optional[str] = None
    ) -> VerificationResult:
        """Verify XSS using CDP."""
        try:
            from bugtrace.core.cdp_client import CDPClient

            async with CDPClient(headless=self.headless) as cdp:
                return await self._execute_cdp_validation(cdp, url, screenshot_dir, timeout, expected_marker)

        except Exception as e:
            logger.error(f"CDP verification error: {e}", exc_info=True)
            return VerificationResult(
                success=False,
                method="cdp",
                error=str(e)
            )

    async def _execute_cdp_validation(self, cdp, url: str, screenshot_dir: Optional[str],
                                       timeout: float, expected_marker: Optional[str]) -> VerificationResult:
        """Execute CDP validation with timeout protection."""
        # Wrap with timeout to prevent infinite hangs from alert() popups
        try:
            result = await asyncio.wait_for(
                cdp.validate_xss(
                    url=url,
                    xss_marker=self.XSS_MARKER,
                    timeout=min(timeout, 5.0), # Cap execution wait at 5s to leave room for setup
                    screenshot_dir=screenshot_dir,
                    expected_marker=expected_marker
                ),
                timeout=timeout + 30.0  # Extra 30s for CDP overhead
            )
        except asyncio.TimeoutError:
            logger.error(f"CDP validation timed out after {timeout + 30}s - likely alert() popup hang", exc_info=True)
            return VerificationResult(
                success=False,
                method="cdp",
                error=f"Timeout after {timeout + 30}s - alert() popup likely blocked CDP"
            )

        return VerificationResult(
            success=result.success,
            method="cdp",
            screenshot_path=result.screenshot_path,
            console_logs=result.console_logs,
            details=result.data,
            alert_message=result.alert_message,
            error=result.error
        )
    
    async def _verify_with_playwright(
        self,
        url: str,
        screenshot_dir: Optional[str],
        timeout: float,
        expected_marker: Optional[str] = None
    ) -> VerificationResult:
        """Verify XSS using Playwright (fallback)."""
        from playwright.async_api import async_playwright

        browser = None
        context = None
        page = None

        try:
            async with async_playwright() as p:
                result = await self._run_playwright_verification(
                    p, url, screenshot_dir, timeout, expected_marker
                )
                browser, context, page = result.get("browser_refs", (None, None, None))
                return result.get("verification_result")

        except Exception as e:
            logger.error(f"Playwright critical error: {e}", exc_info=True)
            return VerificationResult(success=False, method="playwright", error=str(e))
        finally:
            await self._cleanup_browser(page, context, browser)

    async def _run_playwright_verification(self, p, url: str, screenshot_dir: Optional[str],
                                             timeout: float, expected_marker: Optional[str]) -> dict:
        """Run Playwright verification workflow."""
        browser, context, page = await self._setup_browser(p, url)
        console_logs = []
        dialog_detected = await self._setup_page_handlers(page, console_logs)

        # FIX: Increased navigation timeout
        await self._navigate_to_url(page, url, timeout=60000)  # Changed from default 20s
        
        # FIX: Increased wait time for payload execution
        await asyncio.sleep(min(timeout, 8.0))  # Changed from 5.0 to 8.0

        if not dialog_detected[0]:
            early_result = await self._simulate_user_interactions(page, url, console_logs, dialog_detected)
            if early_result:
                # Capture evidence screenshot before returning early
                screenshot_path = await self._capture_screenshot(page, screenshot_dir, True)
                early_result.screenshot_path = screenshot_path
                return {
                    "verification_result": early_result,
                    "browser_refs": (browser, context, page)
                }

        xss_confirmed, evaluation_data = await self._evaluate_xss_indicators(
            page, url, dialog_detected[0], console_logs, expected_marker
        )

        impact_data = await self._extract_impact_data(page, url, xss_confirmed)
        screenshot_path = await self._capture_screenshot(page, screenshot_dir, xss_confirmed)

        result = self._build_verification_result(
            xss_confirmed, screenshot_path, console_logs,
            dialog_detected[0], dialog_detected[1] if len(dialog_detected) > 1 else None,
            evaluation_data, impact_data
        )

        return {
            "verification_result": result,
            "browser_refs": (browser, context, page)
        }

    def _build_verification_result(self, xss_confirmed, screenshot_path, console_logs,
                                   dialog_detected, dialog_message, evaluation_data, impact_data) -> VerificationResult:
        """Build final verification result."""
        return VerificationResult(
            success=xss_confirmed,
            method="playwright",
            screenshot_path=screenshot_path,
            console_logs=console_logs,
            alert_message=dialog_message,
            details={
                "dialog_detected": dialog_detected,
                "marker_found": evaluation_data.get("marker_found", False),
                "impact_data": impact_data
            }
        )

    async def _setup_browser(self, p, url: str):
        """Setup browser, context and page."""
        logger.info(f"[{url}] Launching browser...")
        browser = await p.chromium.launch(
            headless=self.headless,
            # --disable-dev-shm-usage: use /tmp instead of the tiny 64MB /dev/shm in Docker,
            # which otherwise exhausts and wedges the renderer (screenshot/close hang forever).
            args=['--no-sandbox', '--disable-dev-shm-usage', '--disable-setuid-sandbox'],
        )
        context = await browser.new_context(viewport={"width": 1280, "height": 720})
        page = await context.new_page()
        return browser, context, page

    async def _setup_page_handlers(self, page, console_logs: List):
        """Setup console logging and dialog handlers."""
        page.on("console", lambda msg: console_logs.append({
            "type": msg.type,
            "text": msg.text,
            "source": "playwright"
        }))

        dialog_detected = [False, None]  # Use list for mutability in closure: [triggered, message]
        async def handle_dialog(dialog):
            dialog_detected[0] = True
            dialog_detected[1] = dialog.message
            await dialog.dismiss()
 
        page.on("dialog", handle_dialog)
        return dialog_detected

    async def _navigate_to_url(self, page, url: str, timeout: int = 60000):
        """
        Navigate to target URL.
        
        FIX: Increased default timeout from 20s to 60s.
        """
        try:
            logger.info(f"[{url}] Navigating to target...")
            # FIX: Increased timeout and use domcontentloaded for faster initial load
            await page.goto(url, timeout=timeout, wait_until="domcontentloaded")
            # Wait for network to settle after initial load
            await page.wait_for_load_state("networkidle", timeout=30000)
        except Exception as e:
            logger.warning(f"Playwright navigation warning: {e}")
            # Fallback: try with just 'load' event
            try:
                await page.goto(url, timeout=timeout, wait_until="load")
            except Exception as fallback_e:
                logger.error(f"Navigation failed completely: {fallback_e}")

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

    async def _capture_screenshot(self, page, screenshot_dir: Optional[str], xss_confirmed: bool) -> Optional[str]:
        """Capture screenshot as evidence."""
        if not screenshot_dir:
            return None

        # Every detection probe has already read the DOM by now, so clearing site
        # chrome here can only change the IMAGE, never the verdict. Run it for the
        # failed attempts too: a `repro_attempt` shot of a consent modal tells the
        # triager nothing either.
        await self._neutralize_occluders(page)

        import time
        prefix = "playwright_xss" if xss_confirmed else "repro_attempt"
        screenshot_path = f"{screenshot_dir}/{prefix}_{int(time.time())}_{os.getpid()}.png"

        # FIX: Retry logic with increased timeout
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # FIX: Increased timeout from 5s to 15s
                await page.screenshot(path=screenshot_path, timeout=15000, full_page=False)
                logger.info(f"Playwright screenshot captured: {screenshot_path}")
                return screenshot_path
            except Exception as e:
                if attempt == max_retries - 1:
                    logger.warning(f"Screenshot failed after {max_retries} attempts: {e}")
                    return None
                logger.warning(f"Screenshot attempt {attempt + 1} failed, retrying...: {e}")
                await asyncio.sleep(1.0 * (attempt + 1))
        
        return None

    async def _cleanup_browser(self, page, context, browser):
        """Clean up browser resources."""
        for resource, name in [(page, "Page"), (context, "Context"), (browser, "Browser")]:
            if not resource:
                continue
            await self._close_resource(resource, name)

    async def _close_resource(self, resource, name: str):
        """Close a browser resource with a HARD timeout.

        A wedged chromium (e.g. /dev/shm exhausted) makes resource.close() block
        forever waiting for a CDP ack that never comes. Because this runs inside a
        finally during cancellation it cannot be cancelled again, so an unbounded
        close() freezes the whole scan. Bound it: a dead browser degrades to a
        logged warning instead of an eternal hang.
        """
        try:
            await asyncio.wait_for(resource.close(), timeout=5.0)
        except asyncio.TimeoutError:
            logger.warning(f"{name} close timed out after 5s (browser wedged); abandoning it")
        except Exception as e:
            logger.debug(f"{name} close error: {e}")


# Convenience function
async def verify_xss(
    url: str,
    screenshot_dir: Optional[str] = None,
    timeout: float = 15.0,
    expected_marker: Optional[str] = None
) -> VerificationResult:
    """
    Quick XSS verification using best available method.
    
    Example:
        result = await verify_xss("http://vuln.site/?q=<script>console.log('BUGTRACE-XSS-CONFIRMED')</script>")
        if result.success:
            print(f"XSS confirmed via {result.method}")
    """
    verifier = XSSVerifier(headless=settings.HEADLESS_BROWSER)
    return await verifier.verify_xss(url, screenshot_dir)
