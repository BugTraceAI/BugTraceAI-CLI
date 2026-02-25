"""
Mass Assignment Agent — PURE functions.

All functions in this module are free functions (no self), side-effect free,
and receive all data as explicit parameters. They return new data rather
than mutating state.

Contents:
    - PRIVILEGE_FIELDS: Privilege-escalation fields to inject
    - group_privilege_fields: Group fields into logical test batches
    - check_field_acceptance: Check if server accepted injected fields
    - build_finding: Build a validated mass assignment finding dict
    - generate_fingerprint: Generate dedup fingerprint tuple
    - check_followup_fields: Compare baseline vs follow-up for silent persistence
"""

import json
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urlparse

from bugtrace.core.validation_status import ValidationStatus


# Privilege-escalation fields to inject — universal across frameworks
PRIVILEGE_FIELDS: Dict[str, Any] = {
    # Role / permission escalation
    "role": "admin",
    "is_admin": True,
    "isAdmin": True,
    "admin": True,
    "is_staff": True,
    "isStaff": True,
    "is_superuser": True,
    "isSuperuser": True,
    "user_type": "admin",
    "userType": "admin",
    "permissions": ["admin", "write", "delete"],
    "group": "administrators",
    "groups": ["admin"],
    "privilege": "elevated",
    "access_level": 999,
    "accessLevel": 999,

    # Financial manipulation
    "price": 0.01,
    "total": 0.01,
    "amount": 0.01,
    "discount": 100,
    "balance": 999999,

    # Account status manipulation
    "verified": True,
    "is_verified": True,
    "isVerified": True,
    "email_verified": True,
    "emailVerified": True,
    "active": True,
    "is_active": True,
    "isActive": True,
    "approved": True,
    "status": "active",
    "account_status": "premium",

    # ID tampering
    "user_id": 1,
    "userId": 1,
    "owner_id": 1,
    "ownerId": 1,
    "created_by": 1,
    "createdBy": 1,
}


def group_privilege_fields() -> Dict[str, Dict[str, Any]]:  # PURE
    """Group PRIVILEGE_FIELDS into logical test batches.

    Returns:
        Dictionary mapping group name to a subset of PRIVILEGE_FIELDS.
    """
    return {
        "role_escalation": {
            k: v for k, v in PRIVILEGE_FIELDS.items()
            if any(kw in k.lower() for kw in
                   ["role", "admin", "staff", "super", "priv", "access",
                    "group", "permission", "user_type", "userType"])
        },
        "financial": {
            k: v for k, v in PRIVILEGE_FIELDS.items()
            if any(kw in k.lower() for kw in
                   ["price", "total", "amount", "discount", "balance"])
        },
        "account_status": {
            k: v for k, v in PRIVILEGE_FIELDS.items()
            if any(kw in k.lower() for kw in
                   ["verified", "active", "approved", "status"])
        },
        "id_tampering": {
            k: v for k, v in PRIVILEGE_FIELDS.items()
            if any(kw in k.lower() for kw in
                   ["user_id", "userId", "owner", "created"])
        },
    }


def check_field_acceptance(
    status_code: int,
    resp_text: str,
    resp_body: Optional[Dict],
    injected_fields: Dict[str, Any],
    baseline_body: Dict,
) -> List[Tuple[str, Any]]:  # PURE
    """Check if the server accepted any injected fields.

    Acceptance indicators:
    1. Field appears in response body (wasn't there in baseline)
    2. Response is 200/201 and response body contains the injected value
    3. Response doesn't contain validation error for the field

    Args:
        status_code: HTTP response status code.
        resp_text: Raw response text (lowercased externally or here).
        resp_body: Parsed JSON response body (or empty dict).
        injected_fields: The fields that were injected.
        baseline_body: The original baseline response body.

    Returns:
        List of (field_name, field_value) tuples for accepted fields.
    """
    accepted: List[Tuple[str, Any]] = []

    if status_code not in (200, 201, 204):
        return accepted

    if not isinstance(resp_body, dict):
        resp_body = {}

    resp_text_lower = resp_text.lower()

    for field_name, field_value in injected_fields.items():
        # Check if field appears in response
        field_in_response = field_name in resp_body

        # Check if field was NOT in baseline (new field accepted)
        field_was_absent = (
            field_name not in baseline_body if isinstance(baseline_body, dict) else True
        )

        # Check if the value matches what we sent
        value_matches = False
        if field_in_response:
            resp_val = resp_body.get(field_name)
            value_matches = (
                (resp_val == field_value)
                or (str(resp_val).lower() == str(field_value).lower())
            )

        # Acceptance: field in response AND (wasn't in baseline OR value matches injection)
        if field_in_response and (field_was_absent or value_matches):
            accepted.append((field_name, field_value))
        elif status_code in (200, 201) and field_was_absent:
            # Even if field not explicitly in response, a 200 on a PUT/PATCH
            # with extra fields suggests the server didn't reject them.
            # Check for error keywords that indicate rejection
            rejection_keywords = [
                "invalid", "not allowed", "unknown field",
                "unexpected", "validation error",
            ]
            if not any(kw in resp_text_lower for kw in rejection_keywords):
                # Server silently accepted — don't report (too many FP)
                pass

    return accepted


def check_followup_fields(
    injected_fields: Dict[str, Any],
    baseline_body: Dict,
    followup_body: Dict,
) -> List[Tuple[str, Any]]:  # PURE
    """Compare baseline vs post-mutation follow-up for silent field persistence.

    Args:
        injected_fields: Fields that were injected in the mutation request.
        baseline_body: Response body from the initial GET.
        followup_body: Response body from the follow-up GET after mutation.

    Returns:
        List of (field_name, field_value) tuples for fields that persisted.
    """
    accepted: List[Tuple[str, Any]] = []

    if not isinstance(followup_body, dict):
        return accepted

    for field_name, field_value in injected_fields.items():
        baseline_val = (
            baseline_body.get(field_name) if isinstance(baseline_body, dict) else None
        )
        followup_val = followup_body.get(field_name)

        if followup_val is None:
            continue

        # Field exists in follow-up — check if it changed to our injected value
        injected_str = str(field_value).lower()
        followup_str = str(followup_val).lower()
        baseline_str = str(baseline_val).lower() if baseline_val is not None else ""

        if followup_str == injected_str and followup_str != baseline_str:
            accepted.append((field_name, field_value))

    return accepted


def build_finding(
    url: str,
    method: str,
    field_name: str,
    field_value: Any,
    status_code: int,
) -> Dict:  # PURE
    """Build a validated mass assignment finding dictionary.

    Args:
        url: The tested endpoint URL.
        method: HTTP method used (POST/PUT/PATCH).
        field_name: The privilege field that was accepted.
        field_value: The value that was accepted.
        status_code: The HTTP response status code.

    Returns:
        Finding dictionary with all required fields.
    """
    return {
        "validated": True,
        "type": "Mass Assignment",
        "severity": "HIGH",
        "url": url,
        "method": method,
        "parameter": field_name,
        "injected_value": str(field_value),
        "status_code": status_code,
        "status": ValidationStatus.VALIDATED_CONFIRMED.value,
        "description": (
            f"Mass assignment vulnerability: the field '{field_name}' was "
            f"accepted via {method} request. An attacker can modify "
            f"privileged fields by including them in the request body."
        ),
        "reproduction": (
            f"curl -X {method} '{url}' "
            f"-H 'Content-Type: application/json' "
            f"-d '{{\"{ field_name}\": {json.dumps(field_value)}}}'"
        ),
        "cwe": "CWE-915",
        "remediation": (
            "Implement allowlisting (whitelist) of accepted fields in your "
            "API endpoint handlers. Use DTOs or serializer classes that "
            "explicitly define which fields are writable. Never bind "
            "request body directly to database models."
        ),
    }


def generate_fingerprint(url: str, field: str) -> tuple:  # PURE
    """Generate dedup fingerprint for mass assignment finding.

    Args:
        url: The endpoint URL.
        field: The field name that was accepted.

    Returns:
        Tuple of (type, netloc, path, field) for deduplication.
    """
    parsed = urlparse(url)
    return ("MASS_ASSIGNMENT", parsed.netloc, parsed.path.rstrip('/'), field.lower())
