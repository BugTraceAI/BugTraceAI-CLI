"""
IDOR Validation - Pure Functions

Pure functions for IDOR response comparison, access control verification,
differential analysis, and finding validation.

All functions are PURE: no side effects, no self, data as parameters.
"""

import re
from typing import Dict, List, Tuple

from bugtrace.agents.idor.types import SENSITIVE_MARKERS, USER_PATTERNS


def validate_idor_finding(finding: Dict) -> Tuple[bool, str]:
    """IDOR-specific validation before emitting finding.

    Validates:
    1. Has differential evidence (status change, content change)
    2. Involves ID parameter manipulation

    Args:
        finding: Finding dict to validate

    Returns:
        Tuple of (is_valid, error_message)
    """  # PURE
    nested = finding.get("finding", {})
    evidence = finding.get("evidence", nested.get("evidence", {}))
    status = finding.get("status", nested.get("status", ""))

    # IDOR-specific: Must have differential evidence or confirmed status
    if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
        has_differential = evidence.get("differential_analysis") if isinstance(evidence, dict) else False
        has_status_change = evidence.get("status_change") if isinstance(evidence, dict) else False
        has_data_leak = evidence.get("user_data_leakage") if isinstance(evidence, dict) else False
        if not (has_differential or has_status_change or has_data_leak):
            return False, "IDOR requires proof: differential analysis, status change, or data leakage"

    # IDOR-specific: Should have tested_value or modified ID
    tested_value = finding.get("tested_value", nested.get("tested_value", ""))
    payload = finding.get("payload", nested.get("payload", ""))
    if not tested_value and not payload:
        return False, "IDOR requires tested_value or payload showing ID manipulation"

    return True, ""


def determine_validation_status(evidence_type: str, confidence: str) -> str:
    """Determine IDOR validation status.

    IDOR validation is purely HTTP-based (semantic differential analysis).
    No CDP/browser validation needed.

    TIER 1 (VALIDATED_CONFIRMED):
        - HIGH confidence differential analysis
        - Robust semantic indicators

    TIER 2 (PENDING_VALIDATION):
        - MEDIUM confidence (single weak indicator)

    Args:
        evidence_type: Type of evidence ("differential", etc.)
        confidence: Confidence level ("HIGH", "MEDIUM", "LOW")

    Returns:
        Validation status string
    """  # PURE
    if evidence_type == "differential" and confidence == "HIGH":
        return "VALIDATED_CONFIRMED"
    return "PENDING_VALIDATION"


def analyze_differential(
    baseline_status: int,
    baseline_body: str,
    baseline_length: int,
    test_status: int,
    test_body: str,
    test_length: int,
    test_id: str,
) -> Tuple[bool, str, str]:
    """Simplified semantic analysis (Python port of Go fuzzer logic).

    Compares baseline and test responses to detect IDOR vulnerabilities
    based on status codes, content length, user data patterns, and
    sensitive data markers.

    Args:
        baseline_status: Baseline HTTP status code
        baseline_body: Baseline response body
        baseline_length: Baseline response length
        test_status: Test HTTP status code
        test_body: Test response body
        test_length: Test response length
        test_id: The test ID value being evaluated

    Returns:
        Tuple of (is_idor, severity, indicators_string)
    """  # PURE
    indicators = []

    # 1. Permission bypass (CRITICAL)
    if baseline_status in [401, 403] and test_status == 200:
        return True, "CRITICAL", "permission_bypass"

    # 2. Status code change to success
    if baseline_status >= 400 and test_status == 200:
        indicators.append("status_change")

    # 3. Significant length difference (>30%)
    if baseline_length > 0:
        diff_ratio = abs(test_length - baseline_length) / baseline_length
        if diff_ratio > 0.3:
            indicators.append("length_change")

    # 4. User-specific data patterns
    baseline_users = set()
    test_users = set()

    for pattern in USER_PATTERNS:
        baseline_users.update(re.findall(pattern, baseline_body))
        test_users.update(re.findall(pattern, test_body))

    if test_users and test_users != baseline_users:
        indicators.append("user_data_leakage")
        return True, "CRITICAL", ",".join(indicators)

    # 5. Sensitive data markers
    test_has_sensitive = any(marker in test_body.lower() for marker in SENSITIVE_MARKERS)
    baseline_has_sensitive = any(marker in baseline_body.lower() for marker in SENSITIVE_MARKERS)

    if test_has_sensitive or baseline_has_sensitive:
        indicators.append("sensitive_data_exposure")

    # 6. Content divergence: both 200, different resource data with PII
    if baseline_status == 200 and test_status == 200:
        if (test_has_sensitive or baseline_has_sensitive) and baseline_body != test_body:
            import json
            try:
                b_json = json.loads(baseline_body)
                t_json = json.loads(test_body)
                if isinstance(b_json, dict) and isinstance(t_json, dict):
                    b_norm = {k: v for k, v in b_json.items() if k != 'id'}
                    t_norm = {k: v for k, v in t_json.items() if k != 'id'}
                    if b_norm != t_norm:
                        indicators.append("pii_content_divergence")
            except (ValueError, TypeError):
                indicators.append("pii_content_divergence")

    # Decision logic
    if len(indicators) >= 2:
        return True, "HIGH", ",".join(indicators)
    elif len(indicators) == 1:
        return True, "MEDIUM", indicators[0]

    return False, "LOW", ""


def analyze_response_diff(baseline: str, exploit: str) -> str:
    """Analyze response differences for reporting.

    Args:
        baseline: Baseline response body
        exploit: Exploit response body

    Returns:
        String describing the differences
    """  # PURE
    baseline_users = set(re.findall(r'"user_id":\s*"?(\d+)"?', baseline))
    exploit_users = set(re.findall(r'"user_id":\s*"?(\d+)"?', exploit))

    baseline_emails = set(re.findall(r'"email":\s*"([^"]+@[^"]+)"', baseline))
    exploit_emails = set(re.findall(r'"email":\s*"([^"]+@[^"]+)"', exploit))

    diffs = []
    if baseline_users != exploit_users:
        diffs.append(f"user_id: {baseline_users} -> {exploit_users}")
    if baseline_emails != exploit_emails:
        diffs.append(f"email: {baseline_emails} -> {exploit_emails}")

    return "; ".join(diffs) if diffs else "Different content"


def phase3_impact_analysis(phase1: Dict, phase2: Dict) -> Dict:
    """Phase 3: Analyze impact based on retest and HTTP methods results.

    Args:
        phase1: Phase 1 retest results dict
        phase2: Phase 2 HTTP methods results dict

    Returns:
        Impact analysis dict
    """  # PURE
    read_capability = phase1.get("confirmed", False)
    write_capability = any(
        method in phase2.get("accessible_methods", [])
        for method in ["PUT", "PATCH", "POST"]
    )
    delete_capability = "DELETE" in phase2.get("accessible_methods", [])

    impact_score = 0.0
    if read_capability:
        impact_score += 4.0
    if write_capability:
        impact_score += 3.0
    if delete_capability:
        impact_score += 3.0

    capabilities = []
    if read_capability:
        capabilities.append("read unauthorized data")
    if write_capability:
        capabilities.append("modify data")
    if delete_capability:
        capabilities.append("delete data")

    return {
        "read_capability": read_capability,
        "write_capability": write_capability,
        "delete_capability": delete_capability,
        "impact_score": impact_score,
        "impact_description": f"Attacker can: {', '.join(capabilities)}",
    }


__all__ = [
    "validate_idor_finding",
    "determine_validation_status",
    "analyze_differential",
    "analyze_response_diff",
    "phase3_impact_analysis",
]
