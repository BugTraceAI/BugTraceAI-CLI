"""
XSS verifier pure helpers: marker evidence, banner style, occlusion probe JS.

Extracted from verifier.py for LOC comfort. Public symbols re-exported by
``bugtrace.tools.visual.verifier``.
"""

import re
from typing import List, Optional, Dict, Any, Tuple

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


from dataclasses import dataclass


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

