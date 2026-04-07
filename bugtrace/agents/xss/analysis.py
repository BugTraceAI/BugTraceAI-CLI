"""
XSS Agent Analysis Module

Reflection analysis and context detection for XSS payloads.
Provides utilities for:
- Detecting where probes are reflected
- Identifying injection contexts (script, attribute, text, etc.)
- Filtering payloads by context relevance
- WAF detection
"""

from typing import Dict, List, Optional, Any
from bs4 import BeautifulSoup

from bugtrace.utils.logger import get_logger

logger = get_logger("agents.xss.analysis")


# WAF block signatures
WAF_BLOCK_SIGNATURES = [
    "blocked:",
    "waf block",
    "security violation",
    "forbidden",
    "not acceptable",
    "access denied",
    "cloudflare",
    "mod_security",
    "request blocked",
]

# Characters to test for survival
TEST_CHARS = ["'", "\"", "<", ">", "&", "{", "}", "\\", "`"]


def analyze_reflection_context(
    html: str,
    probe_prefix: str = "BT7331"
) -> Dict[str, Any]:
    """
    Analyze the reflection point of a probe in HTML.

    Detects:
    - Whether the probe was reflected
    - In what context (script, attribute, text, comment, etc.)
    - Which special characters survived encoding
    - Whether a WAF blocked the request

    Args:
        html: HTML response to analyze
        probe_prefix: The probe prefix to search for

    Returns:
        Dict with reflection analysis:
        - reflected: bool
        - context: str (script, html_text, attribute_value, etc.)
        - surviving_chars: str (characters that weren't encoded)
        - is_blocked: bool (WAF detection)
    """
    is_blocked = is_waf_blocked(html)

    # Early return if probe not reflected
    if probe_prefix not in html:
        return {
            "reflected": False,
            "is_blocked": is_blocked,
            "context": "blocked" if is_blocked else "none"
        }

    # Detect surviving characters
    surviving = detect_surviving_chars(html, probe_prefix)

    # Find context via BeautifulSoup
    context = find_reflection_context(html, probe_prefix)

    return {
        "reflected": True,
        "context": context,
        "probe_found": True,
        "surviving_chars": surviving,
        "is_blocked": is_blocked
    }


def is_waf_blocked(html: str) -> bool:
    """Check if response contains WAF block signatures."""
    if not html:
        return False
    lower_html = html.lower()
    return any(sig in lower_html for sig in WAF_BLOCK_SIGNATURES)


def detect_surviving_chars(html: str, probe_prefix: str) -> str:
    """
    Detect which special characters survived reflection without encoding.

    Args:
        html: HTML response
        probe_prefix: The probe prefix used

    Returns:
        String of characters that survived (e.g., "'<>")
    """
    surviving = ""
    for char in TEST_CHARS:
        # Check if char appears adjacent to probe or anywhere in response with probe
        if f"{probe_prefix}{char}" in html:
            surviving += char
        elif char in html and probe_prefix in html:
            # More lenient check for chars that might be separated
            surviving += char
    return surviving


def find_reflection_context(html: str, probe_prefix: str) -> str:
    """
    Find the HTML context where the probe was reflected.

    Contexts:
    - script: Inside <script> tag
    - style: Inside <style> tag
    - html_text: Regular text content
    - attribute_value: Inside an HTML attribute
    - comment: Inside an HTML comment
    - tag_name: As a tag name
    - unknown: Could not determine

    Args:
        html: HTML response
        probe_prefix: The probe prefix to locate

    Returns:
        Context type string
    """
    try:
        soup = BeautifulSoup(html, 'html.parser')
        text_node = soup.find(string=lambda t: t and probe_prefix in t)

        if text_node:
            return _context_from_text_node(text_node)
        else:
            return _context_from_attributes(html, probe_prefix)

    except Exception as e:
        logger.debug(f"Context analysis failed: {e}")
        return "unknown"


def _context_from_text_node(text_node) -> str:
    """Determine context from text node parent element."""
    if text_node.parent is None:
        return "html_text"

    parent = text_node.parent.name
    if parent in ['script']:
        return "script"
    elif parent in ['style']:
        return "style"
    elif parent in ['textarea', 'title', 'noscript']:
        return "raw_text"
    return "html_text"


def _context_from_attributes(html: str, probe_prefix: str) -> str:
    """Determine context from attribute heuristics when not in text."""
    # Check for attribute patterns
    if f'="{probe_prefix}' in html or f"='{probe_prefix}" in html:
        return "attribute_value"
    if f"={probe_prefix}" in html:
        return "attribute_value_unquoted"

    # Check for comment
    if f"<!-- {probe_prefix}" in html or f"<!--{probe_prefix}" in html:
        return "comment"

    # Check for tag name context
    if f"<{probe_prefix}" in html:
        return "tag_name"

    return "unknown"


def filter_payloads_by_context(
    payloads: List[str],
    context: str,
    max_payloads: int = 100
) -> List[str]:
    """
    Filter and prioritize payloads based on the detected reflection context.

    This prevents testing 800+ payloads when only ~50 are relevant.

    Args:
        payloads: Full list of payloads
        context: Detected reflection context
        max_payloads: Maximum payloads to return

    Returns:
        Filtered list of relevant payloads
    """
    # For unknown/blocked contexts, use broader set
    if context.startswith("unknown") or context in ["waf_blocked", "blocked"]:
        return payloads[:max_payloads]

    # Filter by context relevance
    filtered = [p for p in payloads if is_payload_relevant(p, context)]

    # Add safety net of top killer payloads
    filtered = _add_safety_net_payloads(filtered, payloads)

    return filtered[:max_payloads]


def is_payload_relevant(payload: str, context: str) -> bool:
    """
    Check if a payload is relevant for the given injection context.

    Args:
        payload: The payload string
        context: The detected context

    Returns:
        True if payload is appropriate for this context
    """
    p_lower = payload.lower()

    if context == "script":
        return _is_relevant_for_script_context(payload, p_lower)

    if context == "html_text":
        return any(payload.startswith(x) for x in ["<", "\">", "'>", "{{", "[["])

    if context == "attribute_value":
        return any(p_lower.startswith(x) for x in ["on", "\"", "'", " javascript:", "data:"])

    if context == "attribute_value_unquoted":
        return any(x in payload for x in [" ", ">", "onfocus", "autofocus"])

    if context == "comment":
        return "-->" in payload or "--!>" in payload

    if context == "style":
        return any(x in payload for x in ["</style>", "expression", "url", "'", "\""])

    if context == "tag_name":
        return any(x in payload for x in [" ", ">", "/"])

    if context == "raw_text":
        return "</textarea>" in payload or "</title>" in payload

    return False


def _is_relevant_for_script_context(payload: str, p_lower: str) -> bool:
    """Check if payload is relevant for script context."""
    # Must have script breakout chars
    breakout_chars = ["'", "\"", "</script>", ";", "-", "+", "*", "\\"]
    if not any(x in payload for x in breakout_chars):
        return False

    # If HTML tag, needs proper breakout
    if payload.startswith("<"):
        if p_lower.startswith("</script>"):
            return True
        # Check if has quote before tag (breakout)
        return any(payload.startswith(q) for q in ["'", "\"", "'; ", "\"; "])

    return True


def _add_safety_net_payloads(
    filtered: List[str],
    all_payloads: List[str],
    safety_count: int = 10
) -> List[str]:
    """Add top killer payloads as safety net if not already included."""
    safety_net = all_payloads[:safety_count]
    for sn in safety_net:
        if sn not in filtered:
            filtered.append(sn)
    return filtered


def analyze_global_context(html: str) -> str:
    """
    Analyze the full HTML for global technology signatures.

    Detects: AngularJS, React, Vue, jQuery

    Args:
        html: Full HTML content

    Returns:
        Comma-separated string of detected technologies
    """
    if not html:
        return "No HTML content"

    context = []
    lower_html = html.lower()

    # AngularJS 1.x
    if any(x in lower_html for x in ["ng-app", "angular.js", "angular.min.js", "angular_1"]):
        context.append("AngularJS (CSTI Risk!)")

    # React
    if "react" in lower_html and "component" in lower_html:
        context.append("React")

    # Vue
    if any(x in lower_html for x in ["vue.js", "vue.min.js", "v-if", "v-for"]):
        context.append("Vue.js")

    # jQuery
    if "jquery" in lower_html:
        context.append("jQuery")

    return ", ".join(context) if context else "Vanilla JS / Unknown"


def get_dom_snippet(html: str, probe_prefix: str, context_size: int = 200) -> str:
    """
    Extract a snippet of HTML around the reflection point.

    Useful for LLM analysis and reporting.

    Args:
        html: Full HTML content
        probe_prefix: The probe to find
        context_size: Characters before and after to include

    Returns:
        HTML snippet around the reflection point
    """
    if not html or probe_prefix not in html:
        return ""

    idx = html.find(probe_prefix)
    start = max(0, idx - context_size)
    end = min(len(html), idx + len(probe_prefix) + context_size)

    snippet = html[start:end]

    # Add ellipsis if truncated
    if start > 0:
        snippet = "..." + snippet
    if end < len(html):
        snippet = snippet + "..."

    return snippet


__all__ = [
    "analyze_reflection_context",
    "is_waf_blocked",
    "detect_surviving_chars",
    "find_reflection_context",
    "filter_payloads_by_context",
    "is_payload_relevant",
    "analyze_global_context",
    "get_dom_snippet",
    "WAF_BLOCK_SIGNATURES",
    "TEST_CHARS",
]
