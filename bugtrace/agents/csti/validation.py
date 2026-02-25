"""
CSTI Validation

PURE functions for verifying CSTI/SSTI exploitation success.
Includes arithmetic evaluation, engine signature detection,
error signature matching, and finding validation.
"""

import re
from typing import Dict, List, Tuple, Any, Optional

from bugtrace.agents.csti.payloads import HIGH_IMPACT_INDICATORS


# =========================================================================
# TEMPLATE SYNTAX MARKERS (for payload validation)
# =========================================================================

TEMPLATE_MARKERS = ["{{", "}}", "${", "}", "#{", "<%", "%>", "#set", "$x"]


# =========================================================================
# ERROR SIGNATURES: Template engine error messages
# =========================================================================

ERROR_SIGNATURES = [
    "jinja2.exceptions",
    "Twig_Error_Syntax",
    "FreeMarker template error",
    "VelocityException",
    "org.apache.velocity",
    "mako.exceptions",
]


# =========================================================================
# PURE VALIDATION FUNCTIONS
# =========================================================================

def check_csti_confirmed(
    payload: str, response_html: str, baseline_html: str
) -> Tuple[bool, Dict]:  # PURE
    """
    Check if CSTI is confirmed in HTTP response.

    Performs all validation checks:
    1. Arithmetic evaluation (7*7=49)
    2. Constructor evaluation (return 7*7 -> 49)
    3. String multiplication ('7'*7 -> 7777777)
    4. Config reflection (Jinja2)
    5. Engine signatures (Twig, Smarty, Freemarker)
    6. Error signatures
    7. Conditional evaluation
    8. RCE indicators

    Args:
        payload: The CSTI payload sent
        response_html: The HTTP response body
        baseline_html: The baseline response (no injection)

    Returns:
        Tuple of (confirmed: bool, evidence: dict)
    """
    if not response_html:
        return False, {}

    evidence: Dict[str, Any] = {"payload": payload}

    # 1. Arithmetic evaluation (7*7=49)
    if "49" in response_html and "7*7" in payload:
        if payload not in response_html:
            if "49" not in baseline_html:
                evidence["method"] = "arithmetic_eval"
                evidence["proof"] = "7*7 evaluated to 49"
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True, evidence

    # 2. Constructor evaluation (return 7*7 -> 49)
    if "constructor" in payload and "49" in response_html:
        if payload not in response_html and "49" not in baseline_html:
            evidence["method"] = "constructor_eval"
            evidence["proof"] = "Constructor payload evaluated to 49"
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True, evidence

    # 3. String multiplication ('7'*7 -> 7777777)
    if "7777777" in response_html and "'7'*7" in payload:
        if payload not in response_html:
            evidence["method"] = "string_multiplication"
            evidence["proof"] = "'7'*7 evaluated to 7777777"
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True, evidence

    # 4. Config reflection (Jinja2)
    if "{{config}}" in payload and ("Config" in response_html or "&lt;Config" in response_html):
        if payload not in response_html:
            evidence["method"] = "config_reflection"
            evidence["proof"] = "{{config}} accessed Config object"
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True, evidence

    # 5. Engine signatures
    if ("{{dump(app)}}" in payload or "{{app.request}}" in payload) and (
        "Symfony" in response_html or "Twig" in response_html
    ):
        evidence["method"] = "engine_signature_twig"
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True, evidence

    if "{$smarty.version}" in payload and re.search(r"Smarty[- ]\d", response_html):
        evidence["method"] = "engine_signature_smarty"
        evidence["status"] = "VALIDATED_CONFIRMED"
        return True, evidence

    # 6. Error signatures (template engine errors indicate processing)
    for sig in ERROR_SIGNATURES:
        if sig in response_html:
            evidence["method"] = "error_signature"
            evidence["proof"] = f"Template error: {sig}"
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True, evidence

    # 7. Conditional evaluation ({% if %})
    if "{% if" in payload and "49" in payload:
        if "{%" not in response_html and "%}" not in response_html and "49" in response_html:
            evidence["method"] = "conditional_eval"
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True, evidence

    # 8. RCE indicators (command output in response)
    # IMPORTANT: Skip indicators that are part of the payload itself.
    # If we sent "java.lang.Runtime" and it reflects back, that's NOT proof
    # of execution - only genuine command OUTPUT (uid=, root:) counts.
    for indicator in HIGH_IMPACT_INDICATORS:
        if indicator in response_html and indicator not in baseline_html:
            if any(rce in payload for rce in ["popen", "exec", "system", "Runtime", "subprocess"]):
                # Guard: indicator must NOT be a substring of the payload
                if indicator in payload:
                    continue
                evidence["method"] = "rce_indicator"
                evidence["proof"] = f"RCE indicator: {indicator}"
                evidence["status"] = "VALIDATED_CONFIRMED"
                return True, evidence

    return False, evidence


def check_arithmetic_evaluation(
    content: str, payload: str, baseline: str
) -> bool:  # PURE
    """
    Check for arithmetic evaluation (7*7=49).

    Args:
        content: Response HTML
        payload: The payload sent
        baseline: Baseline content (no injection)

    Returns:
        True if arithmetic evaluation confirmed
    """
    if "49" not in content:
        return False

    if "7*7" in payload:
        if payload in content:
            return False
        return "49" not in baseline

    if "{% if" in payload and "49" in payload:
        return "{%" not in content and "%}" not in content

    if "print" in payload:
        return "{%" not in content

    return False


def check_string_multiplication(content: str, payload: str) -> bool:  # PURE
    """Check for string multiplication (7777777)."""
    if "7777777" not in content:
        return False
    return "'7'*7" in payload and payload not in content


def check_config_reflection(content: str, payload: str) -> bool:  # PURE
    """Check for Config reflection (Jinja2)."""
    if "{{config}}" not in payload:
        return False
    has_config = "Config" in content or "&lt;Config" in content
    return has_config and payload not in content


def check_engine_signatures(content: str, payload: str) -> bool:  # PURE
    """Check for engine-specific signatures."""
    # Twig
    if "{{dump(app)}}" in payload or "{{app.request}}" in payload:
        return "Symfony" in content or "Twig" in content

    # Smarty
    if "{$smarty.version}" in payload:
        return re.search(r"Smarty[- ]\d", content) is not None

    # Freemarker
    if "freemarker" in payload.lower():
        return "freemarker" in content.lower()

    return False


def check_error_signatures(content: str) -> bool:  # PURE
    """Check for template error signatures."""
    for sig in ERROR_SIGNATURES:
        if sig in content:
            return True
    return False


def validate_finding_before_emit(
    finding: Dict, parent_is_valid: bool, parent_error: str
) -> Tuple[bool, str]:  # PURE
    """
    CSTI-specific validation before emitting a finding.

    Validates:
    1. Basic requirements (type, url) via parent validation result
    2. Template engine is identified
    3. Has arithmetic proof or engine fingerprint evidence
    4. Payload contains template syntax

    Args:
        finding: The finding dictionary to validate
        parent_is_valid: Result of parent (BaseAgent) validation
        parent_error: Error message from parent validation

    Returns:
        Tuple of (is_valid, error_message)
    """
    if not parent_is_valid:
        return False, parent_error

    # CSTI-specific: Must have template engine identified
    template_engine = finding.get("template_engine", "unknown")
    if template_engine == "unknown":
        nested = finding.get("finding", {})
        template_engine = nested.get("template_engine", "unknown")

    if template_engine == "unknown":
        return False, "CSTI requires identified template engine"

    # CSTI-specific: Must have proof (arithmetic, fingerprint, or Interactsh)
    evidence = finding.get("evidence", {})
    has_arithmetic = evidence.get("arithmetic_proof") or finding.get("arithmetic_proof")
    has_fingerprint = evidence.get("fingerprint") or template_engine != "unknown"
    has_interactsh = evidence.get("interactsh_callback")

    if not (has_arithmetic or has_fingerprint or has_interactsh):
        return False, "CSTI requires proof: arithmetic evaluation, fingerprint, or Interactsh callback"

    # CSTI-specific: Payload should contain template syntax
    payload = finding.get("payload", "")
    if not payload:
        nested = finding.get("finding", {})
        payload = nested.get("payload", "")

    if payload and not any(m in str(payload) for m in TEMPLATE_MARKERS):
        return False, f"CSTI payload missing template syntax: {payload[:50]}"

    return True, ""


def is_client_side_payload(payload: str) -> bool:  # PURE
    """Check if a payload targets client-side template engines."""
    return any(marker in payload for marker in ["{{", "${", "constructor", "$eval", "$on"])
