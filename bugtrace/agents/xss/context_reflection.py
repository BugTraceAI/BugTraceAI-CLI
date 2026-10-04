"""Pure multi-context XSS reflection analysis (Phase 4 XSS extraction).

Owns the LIVE analysis contract used by XSSAgent escalation:

- Default search marker is LEGACY_PROBE_MARKER (BT7331) unless ``marker=`` is set.
- Returns EVERY reflection context label (text nodes + attributes), not only one.
- Winner label is most_exploitable_context(contexts).

No network, browser, settings, or agent state. BeautifulSoup is the only HTML
parser dependency (same as the historical monolith methods).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Union

from bs4 import BeautifulSoup, Comment

# Historical hardcoded reflection marker. Callers that pass a full payload as
# probe_prefix still search for THIS unless they pass marker= explicitly.
LEGACY_PROBE_MARKER = "BT7331"
REFLECTION_SNIPPET_RADIUS = 250

RAW_TEXT_ELEMENTS = frozenset({
    "script", "style", "title", "textarea", "noscript", "xmp",
    "iframe", "noembed", "noframes",
})

# (element, attribute) pairs whose processing model is NAVIGATE → url_context.
NAVIGATING_URL_ATTRIBUTES = frozenset({
    ("a", "href"), ("a", "xlink:href"),
    ("area", "href"), ("area", "xlink:href"),
    ("form", "action"),
    ("button", "formaction"), ("input", "formaction"),
    ("iframe", "src"), ("frame", "src"),
})

CONTEXT_EXPLOITABILITY = (
    "script",
    "event_handler",
    "html_text",
    "attribute_value",
    "style",
    "comment",
    "tag_name",
    "url_context",
    "raw_text",
)

_PROBE_CONTEXT_ALIASES = {
    "script_block": "script",
    "javascript": "script",
    "html_attribute": "attribute_value",
    "attribute": "attribute_value",
    "html_body": "html_text",
    "body": "html_text",
    "css": "style",
}


def canonical_probe_context(context: object) -> str:
    """Translate probe labels into the XSS agent's canonical vocabulary.

    Empty, placeholder, and unrecognised labels intentionally return an empty
    string so an LLM-generated value cannot overwrite a measured context.
    """
    label = str(context or "").strip().lower().replace("-", "_")
    if not label or label in {
        "html", "unknown", "none", "no_reflection", "response_header", "error", "wat",
    }:
        return ""
    label = _PROBE_CONTEXT_ALIASES.get(label, label)
    return label if label in CONTEXT_EXPLOITABILITY else ""


def as_context_set(contexts: Union[str, Iterable[str], None]) -> frozenset:
    """Normalise one context label — or any iterable of labels — to a lowercase set.

    A reflection almost always has several contexts at once. Consumers that must not
    lose any take the whole set; single-label consumers use most_exploitable_context().
    Accepting a bare string keeps existing callers valid.
    """
    if not contexts:
        return frozenset()
    if isinstance(contexts, str):
        contexts = (contexts,)
    return frozenset((c or "").lower() for c in contexts if c)

FILTERABLE_CONTEXTS = frozenset({
    "script", "html_text", "attribute_value", "comment", "style", "tag_name",
})

WAF_BLOCK_SIGNATURES = (
    "blocked:",
    "waf block",
    "security violation",
    "forbidden",
    "not acceptable",
    "access denied",
)


def is_waf_blocked(html: str | None) -> bool:
    lower_html = (html or "").lower()
    return any(sig in lower_html for sig in WAF_BLOCK_SIGNATURES)


def most_exploitable_context(contexts: List[str]) -> str:
    """Pick the most exploitable label out of every context a probe reflected in."""
    for label in CONTEXT_EXPLOITABILITY:
        if label in contexts:
            return label
    for label in contexts:
        if label:
            return label
    return "unknown"


def reflection_snippet(html: str | None, marker: str, radius: int = REFLECTION_SNIPPET_RADIUS) -> str:
    """HTML window around the first reflection of ``marker``."""
    text = html or ""
    idx = text.find(marker)
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(marker) + radius)
    return text[start:end]


def context_from_text_node(text_node) -> str:
    """Determine context from a BeautifulSoup text/comment node."""
    if isinstance(text_node, Comment):
        return "comment"
    parent = getattr(text_node.parent, "name", None)
    if parent in ("script", "style"):
        return parent
    if parent in RAW_TEXT_ELEMENTS:
        return "raw_text"
    return "html_text"


def contexts_from_soup_attributes(soup, prefix: str) -> List[str]:
    """Context label for every attribute value carrying the probe."""
    contexts: List[str] = []
    for tag in soup.find_all(True):
        for attr, value in (tag.attrs or {}).items():
            raw = (
                " ".join(v for v in value if isinstance(v, str))
                if isinstance(value, list)
                else value
            )
            if not isinstance(raw, str) or prefix not in raw:
                continue
            name = (attr or "").lower()
            if name.startswith("on"):
                contexts.append("event_handler")
            elif ((tag.name or "").lower(), name) in NAVIGATING_URL_ATTRIBUTES:
                contexts.append("url_context")
            else:
                contexts.append("attribute_value")
    return contexts


def context_from_attributes(html: str, prefix: str) -> str:
    """Raw-string attribute heuristics when the parser finds no node."""
    if f"={prefix}" in html or f'="{prefix}' in html or f"='{prefix}" in html:
        return "attribute_value"
    if f"<!-- {prefix}" in html or f"<!--{prefix}" in html:
        return "comment"
    if f"<{prefix}" in html:
        return "tag_name"
    return "unknown"


def find_reflection_contexts(html: str | None, prefix: str) -> List[str]:
    """EVERY HTML context the probe reflected in — text nodes and attributes."""
    try:
        soup = BeautifulSoup(html or "", "html.parser")
        contexts = [
            context_from_text_node(node)
            for node in soup.find_all(string=lambda t: t and prefix in t)
        ]
        contexts.extend(contexts_from_soup_attributes(soup, prefix))
        if not contexts:
            return [context_from_attributes(html or "", prefix)]
        return contexts
    except Exception:
        return ["unknown"]


def analyze_reflection_contexts(
    html: str | None,
    probe_prefix: str,
    marker: Optional[str] = None,
) -> Dict[str, Any]:
    """Live multi-context reflection analysis (monolith contract).

    ``marker`` is the literal string to locate. Defaults to LEGACY_PROBE_MARKER
    (not probe_prefix) so call sites that pass a full payload as probe_prefix do
    not silently lose reflections.
    """
    search = marker or LEGACY_PROBE_MARKER
    blocked = is_waf_blocked(html)
    if search not in (html or ""):
        return {
            "reflected": False,
            "is_blocked": blocked,
            "context": "blocked" if blocked else "none",
            "contexts": [],
        }
    contexts = find_reflection_contexts(html, search)
    return {
        "reflected": True,
        "context": most_exploitable_context(contexts),
        "contexts": contexts,
        "probe_found": True,
        "snippet": reflection_snippet(html, search),
        "is_blocked": blocked,
    }


def is_payload_relevant(payload: str, context: str) -> bool:
    """Whether a payload is relevant for a filterable reflection context."""
    p_lower = payload.lower()
    if context == "script":
        breakout_chars = ["'", "\"", "</script>", ";", "-", "+", "*", "\\"]
        if not any(x in payload for x in breakout_chars):
            return False
        if not payload.startswith("<"):
            return True
        if p_lower.startswith("</script>"):
            return True
        return any(payload.startswith(q) for q in ["'", "\"", "'; ", "\"; "])
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


def filter_payloads_by_context(
    payloads: List[str],
    context: str,
    max_payloads: int = 100,
) -> List[str]:
    """Filter payloads by context; non-filterable contexts keep a broad set."""
    if (
        context.startswith("unknown")
        or context in ("waf_blocked", "blocked")
        or context not in FILTERABLE_CONTEXTS
    ):
        return payloads[:max_payloads]
    filtered = [p for p in payloads if is_payload_relevant(p, context)]
    for sn in payloads[:10]:
        if sn not in filtered:
            filtered.append(sn)
    return filtered[:max_payloads]
