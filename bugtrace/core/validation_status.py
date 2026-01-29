"""
Validation Status Module (Phase 21: Validation Optimization)

This module provides centralized validation status infrastructure for the tiered
validation system. The goal is to reduce CDP (Chrome DevTools Protocol) validation
load by 99% through smart classification of findings.

Tiered Validation System:
- TIER 1 (VALIDATED_CONFIRMED): High confidence findings that can skip CDP
  - Interactsh OOB hits, dialog detection, vision proof, DOM mutations, console execution
- TIER 2 (PENDING_VALIDATION): Findings that require CDP validation
  - Edge cases: DOM XSS, complex event handlers, sink analysis
- TIER 3 (FINDING_VALIDATED/FINDING_REJECTED): Post-CDP validation results

Usage:
    from bugtrace.core.validation_status import (
        ValidationStatus,
        EDGE_CASE_PATTERNS,
        requires_cdp_validation,
        get_validation_status
    )

    # Check if finding needs CDP
    if requires_cdp_validation(finding):
        # Send to AgenticValidator with CDP
        pass
    else:
        # Mark as VALIDATED_CONFIRMED
        finding['status'] = ValidationStatus.VALIDATED_CONFIRMED
"""

from enum import Enum
from typing import Dict, Any, Optional


class ValidationStatus(str, Enum):
    """
    Validation status for security findings.

    Using str mixin allows direct comparison with string values and
    JSON serialization without explicit .value access.
    """
    VALIDATED_CONFIRMED = "VALIDATED_CONFIRMED"  # High confidence, skip CDP validation
    PENDING_VALIDATION = "PENDING_VALIDATION"    # Needs CDP validation (edge cases)
    VALIDATION_ERROR = "VALIDATION_ERROR"        # Validation process failed
    FINDING_VALIDATED = "FINDING_VALIDATED"      # CDP confirmed as real vulnerability
    FINDING_REJECTED = "FINDING_REJECTED"        # CDP rejected as false positive


# Edge case patterns that REQUIRE CDP validation
# These patterns are unreliable with HTTP-only validation and need
# browser execution context to verify exploitability
EDGE_CASE_PATTERNS: Dict[str, list] = {
    # DOM-based XSS - source/sink analysis requires JavaScript execution
    "dom_based_xss": [
        "location.hash",       # Fragment-based XSS
        "document.URL",        # Full URL access
        "document.referrer",   # Referrer injection
        "window.name",         # Cross-window data
        "postMessage",         # Cross-origin messaging
    ],

    # Complex event handlers that bypass WAFs but need visual confirmation
    "complex_event_handlers": [
        "autofocus",           # Auto-triggers onfocus
        "onfocus",             # Focus-based execution
        "onblur",              # Blur-based execution
        "onanimationend",      # CSS animation triggers
        "ontransitionend",     # CSS transition triggers
    ],

    # Sink analysis - dangerous sinks need execution context
    "sink_analysis": [
        "eval(",               # Direct code execution
        "innerHTML",           # DOM injection
        "outerHTML",           # DOM replacement
        "document.write",      # Document rewriting
        "setTimeout(",         # Delayed execution
        "setInterval(",        # Recurring execution
    ],
}


def requires_cdp_validation(finding: Dict[str, Any]) -> bool:
    """
    Determine if a finding requires CDP (browser) validation.

    Returns True if the finding matches any edge case pattern that cannot
    be reliably validated with HTTP-only techniques.

    Args:
        finding: Dictionary containing finding details with keys like:
            - validation_method: How the finding was validated (e.g., 'interactsh')
            - context: Reflection/execution context
            - payload: The injected payload
            - reflection_context: Where the payload reflected
            - evidence: Evidence dictionary from initial detection

    Returns:
        True if CDP validation required, False if HTTP validation sufficient
    """
    # If already validated via Interactsh OOB, no CDP needed
    validation_method = finding.get("validation_method", "").lower()
    if validation_method == "interactsh":
        return False

    # Check evidence for high-confidence validation methods that skip CDP
    evidence = finding.get("evidence", {})
    if evidence.get("interactsh_hit"):
        return False
    if evidence.get("dialog_detected"):
        return False
    if evidence.get("dom_mutation_proof"):
        return False
    if evidence.get("console_execution_proof"):
        return False

    # Gather searchable text from finding
    searchable_parts = [
        str(finding.get("context", "")).lower(),
        str(finding.get("payload", "")).lower(),
        str(finding.get("reflection_context", "")).lower(),
        str(finding.get("vuln_type", "")).lower(),
        str(finding.get("detection_method", "")).lower(),
    ]
    searchable_text = " ".join(searchable_parts)

    # Check for DOM-based XSS indicators
    if "dom" in searchable_text or "fragment" in searchable_text:
        return True

    # Check each edge case category
    for category, patterns in EDGE_CASE_PATTERNS.items():
        for pattern in patterns:
            pattern_lower = pattern.lower()
            if pattern_lower in searchable_text:
                return True

    # Default: No edge case patterns found, HTTP validation sufficient
    return False


def get_validation_status(
    finding: Dict[str, Any],
    confidence: float = 0.0
) -> ValidationStatus:
    """
    Determine the appropriate validation status for a finding.

    Args:
        finding: Dictionary containing finding details
        confidence: Confidence score from detection (0.0-1.0)

    Returns:
        ValidationStatus based on evidence quality and edge case detection
    """
    # Check for high-confidence evidence first
    evidence = finding.get("evidence", {})

    # High-confidence validation methods → VALIDATED_CONFIRMED
    if evidence.get("interactsh_hit"):
        return ValidationStatus.VALIDATED_CONFIRMED
    if evidence.get("dialog_detected"):
        return ValidationStatus.VALIDATED_CONFIRMED
    if evidence.get("vision_proof"):
        return ValidationStatus.VALIDATED_CONFIRMED
    if evidence.get("dom_mutation_proof"):
        return ValidationStatus.VALIDATED_CONFIRMED
    if evidence.get("console_execution_proof"):
        return ValidationStatus.VALIDATED_CONFIRMED

    # Check for edge cases that require CDP
    if requires_cdp_validation(finding):
        return ValidationStatus.PENDING_VALIDATION

    # High confidence without edge cases → VALIDATED_CONFIRMED
    if confidence > 0.9:
        return ValidationStatus.VALIDATED_CONFIRMED

    # Medium confidence → still needs validation
    if confidence > 0.7:
        # Check if we have strong HTTP evidence
        if evidence.get("dangerous_unencoded_reflection"):
            return ValidationStatus.VALIDATED_CONFIRMED
        return ValidationStatus.PENDING_VALIDATION

    # Low confidence → needs validation
    return ValidationStatus.PENDING_VALIDATION
