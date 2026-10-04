"""Pure HTML/JS reflection-position classification for XSS confirmation (facade)."""
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
from bugtrace.agents.xss.position_exec import (
    _has_attribute, _element_name, _payload_opens_element, _payload_escapes_tag,
    _element_is_focusable, _payload_handler_fires, _position_executes,
)
from bugtrace.agents.xss.position_scan import (
    _scan_tag, _scan_html, _comment_end, _script_body_type,
    _apply_input_state, _apply_iframe_sandbox, _apply_meta_csp,
    _html_regions, _attribute_injection_contexts, _url_payload_forms,
    _attribute_candidates, _inline_script_bodies, _reflected_forms,
    _find_appropriate_end_tag, _html_index, _in_inert_subtree,
    _region_index_at, _tag_name_runs, _host_attribute_names, _classify_region,
)

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
        # Offset zero is a valid reflection position, not a missing index.
        idx = _region_index_at(regions, starts, at if at else -1, html)
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
