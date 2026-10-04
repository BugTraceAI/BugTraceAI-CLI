"""XSS position helpers (split from position.py)."""
from __future__ import annotations

from bugtrace.agents.xss.position_types import *  # noqa: F403
from bugtrace.agents.xss.position_js import (
    _JS_SCRIPT_TYPES, _JS_REGEX_KEYWORDS, _JS_IDENT_CHARS, _JS_SPACE, _JsToken,
    _js_scan_quoted, _js_scan_regex, _js_regex_allowed, _js_tokens, _js_index,
    _js_span_escapes, _JS_BRACKET_RE, _JS_BRACKET_OPENER, _JS_HTML_SINK_RE,
    _JS_ESCAPE_RE, _JS_ESCAPE_SHORT, _js_unescape, _js_wrapping_token,
    _js_literal_reaches_html_sink, _js_code_balanced, _js_breakout_parses,
    _EVENT_HANDLER_NAME_RE, _URL_LEADING_STRIP, _js_value_executes,
)
import html as html_module
import re
import urllib.parse
from bisect import bisect_right
from functools import lru_cache
from operator import itemgetter as _itemgetter
from typing import Dict, List, NamedTuple, Optional, Tuple

from bugtrace.agents.xss.position_exec import (
    _has_attribute, _element_name, _payload_opens_element, _payload_escapes_tag,
    _element_is_focusable, _payload_handler_fires, _position_executes,
)

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

def _html_regions(html: str) -> Tuple[_HtmlRegion, ...]:
    """Every parse-state region of the whole document, in document order."""
    return _html_index(html, len(html), False)[0]

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

def _inline_script_bodies(html: str) -> List[Tuple[str, int]]:
    """(body, document offset) of every inline <script> that the browser runs as JS."""
    if _SCRIPT_OPEN_RE.search(html) is None:
        return []  # no <script> anywhere: nothing to tokenize the document for
    regions, _starts, inert, _fs = _html_index(html, len(html), False)
    return [(html[r[_R_START]:r[_R_END]], r[_R_START]) for r in regions
            if r[_R_KIND] == "rawtext" and r[_R_TAG] == "script"
            and r[_R_ATTR] in _JS_SCRIPT_TYPES
            and not _in_inert_subtree(inert, r[_R_START], r[_R_END])]

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

