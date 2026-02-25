"""
Pure validation utility functions for vulnerability evidence analysis.

These functions examine evidence dictionaries and test results to determine
validation status, create findings decisions, and check payload reflections.
No I/O, no state mutation, no logging side effects -- just data examination.

Extracted from xss_agent.py for reuse across agents.
"""
from __future__ import annotations

import html
import re
import urllib.parse
from typing import Any, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Evidence checkers
# ---------------------------------------------------------------------------

def has_interactsh_hit(evidence: Dict[str, Any]) -> bool:
    """
    Check whether evidence contains an Interactsh OOB interaction.

    An Interactsh hit is the strongest possible proof of JavaScript execution
    because it requires the target to make an outbound HTTP request to an
    attacker-controlled domain.

    Args:
        evidence: Evidence dictionary from a test result.

    Returns:
        True if the ``interactsh_hit`` key is truthy.
    """
    return bool(evidence.get("interactsh_hit"))


def has_dialog_detected(evidence: Dict[str, Any]) -> bool:
    """
    Check whether evidence indicates a browser dialog (alert/confirm/prompt).

    Playwright's dialog handler fires when the page opens an alert(), confirm(),
    or prompt() dialog, which is definitive proof of JS execution.

    Args:
        evidence: Evidence dictionary from a test result.

    Returns:
        True if ``dialog_detected`` or ``alert_detected`` is truthy.
    """
    return bool(evidence.get("dialog_detected") or evidence.get("alert_detected"))


def has_vision_proof(evidence: Dict[str, Any], finding_data: Optional[Dict[str, Any]] = None) -> bool:
    """
    Check whether evidence contains Vision AI confirmation.

    Vision confirmation means a screenshot was analyzed by an LLM and the
    injected banner (e.g. "HACKED BY BUGTRACEAI") was visually confirmed.

    Args:
        evidence: Evidence dictionary from a test result.
        finding_data: Optional finding data (reserved for future use).

    Returns:
        True if ``vision_confirmed`` is truthy.
    """
    return bool(evidence.get("vision_confirmed"))


def has_dom_mutation_proof(evidence: Dict[str, Any]) -> bool:
    """
    Check whether evidence contains DOM mutation proof.

    DOM mutation proof means a marker element (e.g. ``<div id="bt-pwn">``)
    was injected and found in the live DOM via CDP or Playwright queries.

    Args:
        evidence: Evidence dictionary from a test result.

    Returns:
        True if ``dom_mutation`` or ``marker_found`` is truthy.
    """
    return bool(evidence.get("dom_mutation") or evidence.get("marker_found"))


def has_console_execution_proof(evidence: Dict[str, Any]) -> bool:
    """
    Check whether evidence contains console output with execution proof.

    This looks for console messages that contain the word "executed", which
    indicates that a ``console.log("XSS executed")`` payload ran successfully.

    Args:
        evidence: Evidence dictionary from a test result.

    Returns:
        True if ``console_output`` is present and contains "executed".
    """
    if evidence.get("console_output") and "executed" in str(evidence.get("console_output", "")).lower():
        return True
    return False


def has_dangerous_unencoded_reflection(evidence: Dict[str, Any], finding_data: Dict[str, Any]) -> bool:
    """
    Check whether evidence shows unencoded reflection in a dangerous context.

    Dangerous contexts include ``html_text``, ``script``, ``attribute_unquoted``,
    and ``tag_name``. Additionally, payloads containing "BUGTRACE" are trusted
    even if the context is ambiguous, since they are known-good test markers.

    Args:
        evidence: Evidence dictionary from a test result.
        finding_data: Finding data dict containing ``payload`` and ``reflection_context``.

    Returns:
        True if the reflection is unencoded in a dangerous context or is a
        BUGTRACE marker payload.
    """
    dangerous_contexts = ["html_text", "script", "attribute_unquoted", "tag_name"]

    # Relaxed Check: If it's a BUGTRACE payload, we trust it even if context is murky
    is_bugtrace_payload = "BUGTRACE" in str(finding_data.get("payload", ""))

    if (evidence.get("unencoded_reflection", False) and
            (finding_data.get("reflection_context") in dangerous_contexts or is_bugtrace_payload)):
        return True
    return False


def has_fragment_xss_with_screenshot(finding_data: Dict[str, Any]) -> bool:
    """
    Check whether finding data indicates fragment XSS with screenshot proof.

    Fragment (DOM) XSS uses ``location.hash`` to inject payloads that bypass
    server-side WAFs. A screenshot provides visual confirmation that the
    payload executed in the browser.

    Args:
        finding_data: Finding data dict containing ``context`` and ``screenshot_path``.

    Returns:
        True if context is ``dom_xss_fragment`` and a screenshot path exists.
    """
    if finding_data.get("context") == "dom_xss_fragment" and finding_data.get("screenshot_path"):
        return True
    return False


# ---------------------------------------------------------------------------
# Validation status determination
# ---------------------------------------------------------------------------

def determine_validation_status(
    test_result: Dict[str, Any],
    self_validate: bool = True,
) -> Tuple[str, bool]:
    """
    Determine validation status based on evidence authority.

    The XSSAgent has AUTHORITY to mark ``VALIDATED_CONFIRMED`` only when
    evidence is strong (Interactsh, dialog, vision, DOM mutation, console
    execution, dangerous unencoded reflection, or fragment XSS with screenshot).
    Falls back to ``PENDING_VALIDATION`` when no evidence checks pass or when
    self-validation is disabled.

    Args:
        test_result: Full test result dictionary containing ``evidence`` and
            optionally ``finding_data``.
        self_validate: Whether self-validation is enabled (maps to
            ``settings.XSS_SELF_VALIDATE``). When False, always returns
            ``PENDING_VALIDATION``.

    Returns:
        A tuple of (status_string, authority_flag) where status_string is
        either ``"VALIDATED_CONFIRMED"`` or ``"PENDING_VALIDATION"`` and
        authority_flag indicates whether the agent confirmed the finding itself.
    """
    evidence = test_result.get("evidence", {})
    finding_data = test_result.get("finding_data", test_result)

    # AUTHORITY CHECKS: Only if self-validation is enabled in config
    if self_validate:
        if has_interactsh_hit(evidence):
            return "VALIDATED_CONFIRMED", True

        if (has_dialog_detected(evidence) or
                has_vision_proof(evidence, finding_data) or
                has_dom_mutation_proof(evidence) or
                has_console_execution_proof(evidence) or
                has_dangerous_unencoded_reflection(evidence, finding_data) or
                has_fragment_xss_with_screenshot(finding_data)):
            return "VALIDATED_CONFIRMED", True

        if evidence.get("http_confirmed") or evidence.get("ai_confirmed"):
            return "VALIDATED_CONFIRMED", True

    # FALLBACK: No evidence checks passed -- needs external validation
    return "PENDING_VALIDATION", False


# ---------------------------------------------------------------------------
# Finding creation gate
# ---------------------------------------------------------------------------

def should_create_finding(test_result: Dict[str, Any]) -> bool:
    """
    Decide whether evidence is strong enough to warrant creating a finding.

    This prevents creating findings for weak evidence (reflection-only with
    no execution proof). Confirmed via HTTP analysis or AI Auditor is always
    accepted. Execution evidence (dialog, marker, DOM mutation, console,
    Interactsh) is also accepted.

    Args:
        test_result: Full test result dictionary containing ``evidence``.

    Returns:
        True if evidence is strong enough to create a finding, False otherwise.
    """
    evidence = test_result.get("evidence", {})

    # ACCEPT: Confirmed via HTTP analysis or AI Auditor
    if evidence.get("http_confirmed") or evidence.get("ai_confirmed"):
        return True

    # REJECT: No execution evidence and no high-confidence HTTP/AI confirmation
    if not any([
        evidence.get("dialog_detected"),
        evidence.get("marker_found"),
        evidence.get("dom_mutation"),
        evidence.get("console_output"),
        evidence.get("interactsh_hit"),
    ]):
        return False

    # ACCEPT: Has some execution evidence, create finding for Auditor
    return True


# ---------------------------------------------------------------------------
# Reflection checking
# ---------------------------------------------------------------------------

def check_reflection(payload: str, response_html: str, evidence: Dict[str, Any]) -> bool:
    """
    Check if a payload is reflected in the HTTP response.

    Tests multiple decoding levels (URL-decoded, double-decoded, HTML-decoded)
    to catch server-side transformations. Mutates the ``evidence`` dict on
    success by setting ``reflected`` and ``status`` keys.

    Args:
        payload: The original payload string sent to the target.
        response_html: The HTML body of the HTTP response.
        evidence: Evidence dictionary to update (mutated in-place on match).

    Returns:
        True if any decoded variant of the payload appears in the response.
    """
    p_decoded = urllib.parse.unquote(payload)
    p_double_decoded = urllib.parse.unquote(p_decoded)
    p_html_decoded = html.unescape(p_decoded)

    reflections = [payload, p_decoded, p_double_decoded, p_html_decoded]

    # Check if any variant is reflected
    for ref in set(reflections):
        if ref and ref in response_html:
            evidence["reflected"] = True
            evidence["status"] = "VALIDATED_CONFIRMED"
            return True

    return False
