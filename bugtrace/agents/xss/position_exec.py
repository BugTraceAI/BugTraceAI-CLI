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

def _element_name(tag: str) -> str:
    """The bare element name of a tokenizer tag label ("input\\x00hidden" -> "input")."""
    if _ELEMENT_STATE_SEP in tag:
        return tag.split(_ELEMENT_STATE_SEP, 1)[0]
    return tag

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

def _payload_escapes_tag(text: str, tail_closes: bool = False) -> bool:
    """True when `text`, injected INSIDE a start tag, gets back out and opens an element.

    Everything before the payload's first '>' is still attributes of the element the
    server wrote; only what follows that '>' is document text again.
    """
    gt = text.find(">")
    return gt != -1 and _payload_opens_element(text[gt + 1:], tail_closes)

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

