"""
Pure XSS finding construction and serialization.

Creates and converts XSS finding objects without side effects.
All functions are pure - they take explicit data and return results.

Extracted from xss_agent.py:
- _validate_before_emit (line 798) -> validate_before_emit (PURE)
- _emit_xss_finding (line 840) - partially, event emission stays in agent
- _update_learned_breakouts (line 867) -> update_learned_breakouts (PURE)
- _add_safety_net_payloads (line 6847) -> add_safety_net_payloads (PURE)
- _finding_to_dict (line 8873) -> finding_to_dict (PURE)
- _fragment_build_finding - build_fragment_finding (PURE)
"""

from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.utils.logger import get_logger
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)

logger = get_logger("agents.xss.finding_builder")


# =========================================================================
# FINDING VALIDATION (PURE)
# =========================================================================

def validate_before_emit(
    finding: Dict,
    base_is_valid: bool = True,
    base_error: str = "",
) -> Tuple[bool, str]:
    """
    XSS-specific validation before emitting a finding.

    Requirements for XSS findings:
    1. Base validation passed (type, url)
    2. Must have evidence dict
    3. Evidence should have confirmation (screenshot, alert, vision, etc.)
    4. Payload should look like XSS (not conversational)

    PURE function.

    Args:
        finding: Finding dict with type, url, parameter, payload, evidence.
        base_is_valid: Whether base (parent) validation passed.
        base_error: Error message from base validation.

    Returns:
        Tuple of (is_valid: bool, error_message: str).
    """
    # Check parent validation first
    if not base_is_valid:
        return False, base_error

    # XSS-specific validation
    evidence = finding.get("evidence", {})

    # Check for proof of execution
    has_screenshot = evidence.get("screenshot") or evidence.get("screenshot_path")
    has_alert = evidence.get("alert_triggered")
    has_vision = evidence.get("vision_confirmed")
    has_interactsh = evidence.get("interactsh_callback")
    has_http_confirmed = (
        evidence.get("http_confirmed") or evidence.get("manipulator_confirmed")
    )

    if not (has_screenshot or has_alert or has_vision or has_interactsh or has_http_confirmed):
        return False, (
            "XSS requires proof: screenshot, alert, vision confirmation, "
            "HTTP confirmation, or Interactsh callback"
        )

    # Payload sanity check (should have XSS chars)
    payload = finding.get("payload", "")
    if payload and not any(c in str(payload) for c in '<>\'"();`'):
        return False, f"XSS payload missing attack characters: {payload[:50]}"

    # All checks passed
    return True, ""


# =========================================================================
# FINDING SERIALIZATION (PURE)
# =========================================================================

def finding_to_dict(finding) -> Dict:
    """
    Convert an XSSFinding dataclass to dictionary for JSON output.

    Generates reproduction URL/command based on HTTP method.

    PURE function.

    Args:
        finding: XSSFinding dataclass instance with url, parameter, payload,
            context, reflection_context, surviving_chars, validation_method,
            evidence, confidence, screenshot_path, validated, status,
            xss_type, injection_context_type, vulnerable_code_snippet,
            server_escaping, escape_bypass_technique, bypass_explanation,
            exploit_url, exploit_url_encoded, verification_methods,
            verification_warnings, reproduction_steps, successful_payloads,
            http_method.

    Returns:
        Dict suitable for JSON serialization.
    """
    # Generate reproduction URL/command
    try:
        if finding.http_method == "POST":
            reproduction = (
                f"# POST request to trigger XSS:\n"
                f"curl -X POST -d '{finding.parameter}={finding.payload}' '{finding.url}'"
            )
            test_url = finding.url
        else:
            parsed = urlparse(finding.url)
            qs = parse_qs(parsed.query)
            qs[finding.parameter] = [finding.payload]
            new_query = urlencode(qs, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path, '', new_query, '',
            ))
            reproduction = f"# Open in browser to trigger XSS:\n{test_url}"
    except Exception:
        reproduction = (
            f"# XSS: Inject payload '{finding.payload}' "
            f"in parameter '{finding.parameter}'"
        )
        test_url = finding.url

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
        "screenshot_path": finding.screenshot_path,
        "validated": finding.validated,
        "status": finding.status,
        "severity": normalize_severity("HIGH").value,
        "cwe_id": get_cwe_for_vuln("XSS"),
        "cve_id": "N/A",
        "remediation": get_remediation_for_vuln("XSS"),
        "description": (
            f"Reflected XSS confirmed in parameter '{finding.parameter}'. "
            f"Context: {finding.reflection_context}. "
            f"Payload executed successfully via {finding.validation_method}."
        ),
        "reproduction": reproduction,
        # HTTP evidence fields
        "http_request": finding.evidence.get(
            "http_request", f"{finding.http_method} {test_url}"
        ),
        "http_response": finding.evidence.get(
            "http_response",
            finding.evidence.get("page_html", "")[:500]
            if finding.evidence.get("page_html")
            else "",
        ),
        # Enhanced fields
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
        "http_method": finding.http_method,
    }


# =========================================================================
# FRAGMENT FINDING BUILDER (PURE)
# =========================================================================

def build_fragment_finding(
    url: str,
    param: str,
    payload: str,
    result: Any,
) -> Dict:
    """
    Build XSS finding dict from a validated fragment injection result.

    Fragment-based XSS uses location.hash to bypass WAFs.

    PURE function.

    Args:
        url: Target URL.
        param: Parameter that was bypassed.
        payload: Fragment payload that succeeded.
        result: Verification result with .details, .method, .screenshot_path,
            .console_logs attributes.

    Returns:
        Dict with all fields needed to create an XSSFinding.
    """
    evidence = result.details or {}
    evidence["method"] = result.method
    evidence["screenshot_path"] = result.screenshot_path
    if result.console_logs:
        evidence["console_logs"] = result.console_logs

    return {
        "url": url,
        "parameter": f"#fragment (bypassed {param})",
        "payload": payload,
        "context": "dom_xss_fragment",
        "validation_method": f"vision+{result.method}",
        "evidence": evidence,
        "confidence": 1.0,
        "status": "VALIDATED_CONFIRMED",
        "validated": True,
        "screenshot_path": result.screenshot_path,
        "reflection_context": "location.hash -> innerHTML",
        "surviving_chars": "N/A (client-side)",
    }


# =========================================================================
# LEARNED BREAKOUTS (PURE)
# =========================================================================

def update_learned_breakouts(
    learned_breakouts: Dict,
    payload: str,
    prefixes: List[str],
) -> Dict:
    """
    Return a NEW dict with updated breakout success counts.

    Extracts the breakout prefix from a successful payload and
    increments its success_count for future prioritization.
    Does NOT mutate the input dict.

    PURE function.

    Args:
        learned_breakouts: Current breakout success counts dict.
        payload: Successful payload string.
        prefixes: List of known breakout prefixes.

    Returns:
        New dict with updated success counts.
    """
    new_breakouts = dict(learned_breakouts)

    for prefix in prefixes:
        if prefix and payload.startswith(prefix):
            current_count = new_breakouts.get(prefix, 0)
            new_breakouts[prefix] = current_count + 1
            logger.debug(f"Learned successful breakout: {prefix}")
            break

    return new_breakouts


# =========================================================================
# SAFETY NET PAYLOADS (PURE)
# =========================================================================

def add_safety_net_payloads(
    filtered: List[str],
    all_payloads: List[str],
    safety_net_count: int = 10,
) -> List[str]:
    """
    Add top killer payloads as safety net if not already included.

    Ensures the top N payloads from the full list are present in
    the filtered list, adding any that are missing.

    PURE function.

    Args:
        filtered: Current filtered payload list.
        all_payloads: Full payload list (safety net drawn from top N).
        safety_net_count: Number of top payloads to ensure are included.

    Returns:
        New list with safety net payloads appended if needed.
    """
    result = list(filtered)
    safety_net = all_payloads[:safety_net_count]
    for sn in safety_net:
        if sn not in result:
            result.append(sn)
    return result


__all__ = [
    # Validation
    "validate_before_emit",
    # Serialization
    "finding_to_dict",
    # Building
    "build_fragment_finding",
    # Learned breakouts
    "update_learned_breakouts",
    # Safety net
    "add_safety_net_payloads",
]
