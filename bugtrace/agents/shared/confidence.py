"""
Pure confidence scoring and testing decision functions.

These functions calculate confidence scores for reflections, determine payload
impact tiers, and decide whether to stop testing based on a Victory Hierarchy.
No I/O, no state mutation, no logging -- just numeric/boolean decisions.

Extracted from xss_agent.py for reuse across agents.
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Impact indicator lists (module-level constants)
# ---------------------------------------------------------------------------

HIGH_IMPACT_INDICATORS = [
    "document.cookie",       # Cookie theft - MAXIMUM IMPACT
    "document.domain",       # Domain access proof - MAXIMUM IMPACT
    "localStorage",          # Storage access
    "sessionStorage",        # Session storage access
    "fetch(",                # Data exfiltration capability
    "XMLHttpRequest",        # Data exfiltration capability
]

MEDIUM_IMPACT_INDICATORS = [
    "alert(",                # Basic execution proof
    "confirm(",              # Basic execution proof
    "prompt(",               # Basic execution proof
    "console.log",           # Console output
    "eval(",                 # Code execution
]


# ---------------------------------------------------------------------------
# Confidence calculation
# ---------------------------------------------------------------------------

def calculate_confidence(reflection: Any) -> float:
    """
    Calculate a confidence score for a Go fuzzer reflection.

    The score starts at a 0.5 base and is boosted by:
    - +0.30 if the reflection is not encoded (raw characters survived)
    - +0.05 to +0.15 depending on the injection context
    - +0.05 if the payload contains a BUGTRACE visual banner marker

    The reflection object is expected to have these attributes (duck-typed):
    - ``encoded`` (bool): Whether the reflection was HTML/URL encoded
    - ``context`` (str): Where the reflection appeared (e.g. "javascript",
      "script", "event_handler", "attribute_value", "html_text", "html_body")
    - ``payload`` (str): The payload string that was reflected

    Args:
        reflection: A Reflection-like object (e.g. from ``go_bridge.Reflection``).

    Returns:
        A float between 0.0 and 1.0 representing the confidence that this
        reflection is exploitable.
    """
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


# ---------------------------------------------------------------------------
# Payload impact tiers
# ---------------------------------------------------------------------------

def get_payload_impact_tier(payload: str, evidence: Optional[Dict[str, Any]] = None) -> int:
    """
    Determine the impact tier of a successful XSS payload.

    The tier system enables a Victory Hierarchy -- once a high-impact payload
    succeeds, there is no need to keep testing lower-tier payloads.

    Tiers:
        3 = MAXIMUM IMPACT (document.cookie, document.domain) -- stop immediately
        2 = HIGH IMPACT (fetch, XMLHttpRequest, storage) -- stop immediately
        1 = MEDIUM IMPACT (alert executed) -- try one more to escalate
        0 = LOW IMPACT (reflection only) -- continue testing

    Args:
        payload: The XSS payload string.
        evidence: Optional evidence dictionary with execution details.

    Returns:
        An integer 0-3 indicating the impact tier.
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
        if evidence and isinstance(evidence, dict) and (
            evidence.get("dialog_detected") or
            evidence.get("interactsh_hit") or
            evidence.get("vision_confirmed") or
            evidence.get("console_output")
        ):
            return 1
        return 1  # Still medium even if just reflected with these

    # TIER 0: Low Impact - Just reflection
    return 0


# ---------------------------------------------------------------------------
# Stop-testing decision
# ---------------------------------------------------------------------------

def should_stop_testing(
    payload: str,
    evidence: Dict[str, Any],
    successful_count: int,
) -> Tuple[bool, str]:
    """
    Determine whether to stop testing based on the Victory Hierarchy.

    This function prevents wasting time on lower-tier payloads once a
    high-impact payload has already succeeded.

    Decision rules:
    - Tier >= 3 (cookie/domain access): stop immediately
    - Tier >= 2 (data exfiltration): stop immediately
    - Tier >= 1 with at least 1 prior success: stop (gave it a chance to escalate)
    - 2+ successful payloads regardless of tier: stop
    - Otherwise: continue testing

    Note: Unlike the original method, this pure version does NOT set any
    instance flag (``_max_impact_achieved``). The caller is responsible for
    tracking that state if needed.

    Args:
        payload: The XSS payload that just succeeded.
        evidence: Evidence dictionary for this payload.
        successful_count: Number of successful payloads found so far
            (before this one).

    Returns:
        A tuple of (should_stop, reason) where reason is a human-readable
        string explaining why testing should stop, or an empty string if
        testing should continue.
    """
    impact_tier = get_payload_impact_tier(payload, evidence)

    if impact_tier >= 3:
        return True, "MAXIMUM IMPACT: Cookie/Domain access achieved"

    if impact_tier >= 2:
        return True, "HIGH IMPACT: Data exfiltration capability confirmed"

    if impact_tier >= 1 and successful_count >= 1:
        # Medium impact + already have 1 success = stop (gave it a chance to escalate)
        return True, "Execution confirmed, escalation attempted"

    # Low impact or first medium impact - continue but with limit
    if successful_count >= 2:
        return True, "2 successful payloads found, moving on"

    return False, ""
