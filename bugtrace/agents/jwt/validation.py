"""
JWT Validation - Pure Functions

Pure functions for JWT token validation, validation status determination,
and finding validation logic.

All functions are PURE: no side effects, no self, data as parameters.
"""

from typing import Dict, Tuple, Optional

from bugtrace.core.validation_status import ValidationStatus


# =========================================================================
# Finding Validation (PURE)
# =========================================================================

def validate_jwt_finding(finding: Dict) -> Tuple[bool, str]:
    """JWT-specific validation before emitting finding.

    Validates:
    1. Has attack evidence (alg:none, weak secret, key confusion)
    2. Has token or attack type specified

    Args:
        finding: Finding dict to validate

    Returns:
        Tuple of (is_valid, error_message)
    """  # PURE
    # Extract from nested structure if needed
    nested = finding.get("finding", {})
    evidence = finding.get("evidence", nested.get("evidence", {}))
    if not isinstance(evidence, dict):
        evidence = {}  # Evidence may be a string description, not a dict

    # JWT-specific: Must have attack type or vulnerability type
    attack_type = finding.get("attack_type", nested.get("attack_type", ""))
    vuln_type = finding.get("vulnerability_type", nested.get("vulnerability_type", ""))

    if not (attack_type or vuln_type):
        return False, "JWT requires attack_type or vulnerability_type"

    # JWT-specific: Must have some evidence
    has_token = finding.get("token") or nested.get("token")
    has_proof = evidence.get("forged_token") or evidence.get("cracked_secret") or attack_type
    if not (has_token or has_proof):
        return False, "JWT requires token evidence or attack proof"

    return True, ""


# =========================================================================
# Validation Status (PURE)
# =========================================================================

def get_validation_status(finding: Dict) -> str:
    """Determine tiered validation status for JWT finding.

    TIER 1 (VALIDATED_CONFIRMED): Definitive proof
        - alg=none bypass works (token accepted without signature)
        - Key confusion exploit succeeds (valid forged signature)
        - Weak secret cracked and admin token accepted
        - KID injection successful

    TIER 2 (PENDING_VALIDATION): Needs verification
        - Algorithm confusion detected but not confirmed
        - Signature not verified by server (ambiguous behavior)
        - JWT structure vulnerable but exploit not confirmed

    Args:
        finding: Finding dict

    Returns:
        Validation status string
    """  # PURE
    vuln_type = finding.get("type", "").lower()

    # TIER 1: None algorithm bypass confirmed
    if "none" in vuln_type and finding.get("validated"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: Key confusion attack confirmed
    if "confusion" in vuln_type and finding.get("validated"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: Weak secret cracked
    if "weak" in vuln_type or "secret" in vuln_type:
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: KID injection successful
    if "kid" in vuln_type and finding.get("validated"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 1: Generic validated finding
    if finding.get("validated") and finding.get("status") == "VALIDATED_CONFIRMED":
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # TIER 2: Algorithm confusion detected but not exploited
    if "confusion" in vuln_type or "algorithm" in vuln_type:
        return ValidationStatus.PENDING_VALIDATION.value

    # TIER 2: JWT vulnerability detected but needs confirmation
    if not finding.get("validated"):
        return ValidationStatus.PENDING_VALIDATION.value

    # Default: Specialist trust
    return ValidationStatus.VALIDATED_CONFIRMED.value


__all__ = [
    "validate_jwt_finding",
    "get_validation_status",
]
