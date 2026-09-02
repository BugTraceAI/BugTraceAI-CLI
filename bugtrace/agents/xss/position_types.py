"""Pure HTML/JS reflection-position classification for XSS confirmation.

Extracted from xss_agent.py (P4-XSS-8). Owns:

- HTML region tokenizer and reflection position labels
- JS tokenisation helpers used by script_js_* positions
- Attribute / CSP pure helpers that depend on the region map
- Document-body lru_cache registry + release_document_caches()

No network, agent state, or settings. xss_agent re-exports symbols for
compatibility; smoke_cache_release may import via the monolith facade.
"""

from __future__ import annotations

import html as html_module
import re
import urllib.parse
from bisect import bisect_right
from functools import lru_cache
from operator import itemgetter as _itemgetter
from typing import Dict, List, NamedTuple, Optional, Tuple

from bugtrace.agents.xss.position_js import (
    _JS_SCRIPT_TYPES,
    _JS_REGEX_KEYWORDS,
    _JS_IDENT_CHARS,
    _JS_SPACE,
    _JsToken,
    _js_scan_quoted,
    _js_scan_regex,
    _js_regex_allowed,
    _js_tokens,
    _js_index,
    _js_span_escapes,
    _JS_BRACKET_RE,
    _JS_BRACKET_OPENER,
    _JS_HTML_SINK_RE,
    _JS_ESCAPE_RE,
    _JS_ESCAPE_SHORT,
    _js_unescape,
    _js_wrapping_token,
    _js_literal_reaches_html_sink,
    _js_code_balanced,
    _js_breakout_parses,
    _EVENT_HANDLER_NAME_RE,
    _URL_LEADING_STRIP,
    _js_value_executes,
)

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


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


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


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE




# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


# PURE


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


# PURE


# PURE

__all__ = [n for n in globals() if not n.startswith('__')]
