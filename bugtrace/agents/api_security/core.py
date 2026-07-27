"""
API Security Agent — PURE functions.

All functions in this module are free functions (no self), side-effect free,
and receive all data as explicit parameters.

Contents:
    - WEBSOCKETS_AVAILABLE: Flag for websockets module availability
    - is_api_url: Check if URL looks like an API endpoint
    - parse_introspection_response: Parse GraphQL introspection response
    - check_injection_response: Check GraphQL response for injection indicators
    - check_bypass_response: Check if authentication was bypassed
    - check_idor_response: Check IDOR test response
    - check_verb_tampering: Check if DELETE verb tampering is present
    - create_introspection_vuln: Build GraphQL introspection vulnerability dict
    - create_injection_vuln: Build GraphQL injection vulnerability dict
    - create_idor_finding: Build IDOR vulnerability finding dict
"""

import json
import re
from typing import Dict, List, Optional, Any

# Optional websockets support
try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


def is_api_url(url: str) -> bool:  # PURE
    """Check if URL looks like an API endpoint.

    Args:
        url: The URL to check.

    Returns:
        True if the URL contains API endpoint indicators.
    """
    api_indicators = ["/api/", "/v1/", "/v2/", "/graphql", "/rest/", "/json", "/data/"]
    return any(indicator in url.lower() for indicator in api_indicators)


def parse_introspection_response(
    status_code: int,
    response_data: Dict,
) -> Dict:  # PURE
    """Parse GraphQL introspection response.

    Args:
        status_code: HTTP response status code.
        response_data: Parsed JSON response body.

    Returns:
        Dict with 'enabled' flag, 'schema', and 'type_count'.
    """
    if status_code != 200:
        return {"enabled": False}

    if "data" not in response_data:
        return {"enabled": False}
    if "__schema" not in response_data.get("data", {}):
        return {"enabled": False}

    schema = response_data["data"]["__schema"]
    type_count = len(schema.get("types", []))

    return {
        "enabled": True,
        "schema": schema,
        "type_count": type_count,
    }


def is_graphql_validation_error(status_code: int, response_data: Any) -> bool:  # PURE
    """True if a GraphQL response is just a schema/validation error (not real execution).

    A deeply-nested or unfamiliar-field probe returns errors like "Cannot query field X"
    or "Unknown type" — frequently with HTTP 500. That is the server REJECTING an invalid
    query cheaply, not amplification or injection. Used to stop the DoS/injection checks
    from treating a schema mismatch as a vulnerability.

    Args:
        status_code: HTTP response status code (unused today; kept for future nuance).
        response_data: Parsed JSON response body (or None).

    Returns:
        True if the response looks like a pure GraphQL validation error.
    """
    if not isinstance(response_data, dict):
        return False
    errors = response_data.get("errors")
    if not errors:
        return False
    if response_data.get("data"):  # errors alongside real data → not a pure rejection
        return False
    blob = json.dumps(errors).lower()
    markers = [
        "cannot query field", "unknown type", "unknown argument", "unknown field",
        "syntax error", "must have a selection", "must not have a selection",
        "did you mean", "is not defined", "expected type", "not defined by",
    ]
    return any(m in blob for m in markers)


def check_injection_response(
    response_text: str,
    payload: Dict,
    baseline_text: str = "",
) -> Dict:  # PURE
    """Check GraphQL response for SQL-injection indicators.

    STRICT: only DB-engine-specific error signatures count. Generic GraphQL parser words
    ("syntax error", "unexpected", "exception") are NORMAL for a schema mismatch and are
    NOT injection — matching them made every unfamiliar schema look CRITICAL. A signature
    is a hit only when it is ABSENT from the benign baseline, so an app that legitimately
    echoes a DB name doesn't false-positive.

    Args:
        response_text: Raw response text from the injection attempt.
        payload: The injection payload that was sent.
        baseline_text: Response text from the same query with a benign value.

    Returns:
        Dict with 'vulnerable' flag and optional 'signature'/'payload'/'response' keys.
    """
    # DRY: reuse the canonical SQL-error detector from the SQLi agent instead of a local
    # signature list. Imported lazily so this light PURE module doesn't couple to the heavy
    # sqli package at load time (and to sidestep any import cycle).
    from bugtrace.agents.sqli.validation import has_sql_error_signature

    # A genuine DB error present in the response but ABSENT from the benign baseline means
    # unsanitized input reached a SQL query — not a schema mismatch or an echoed DB name.
    if not has_sql_error_signature(response_text):
        return {"vulnerable": False}
    if baseline_text and has_sql_error_signature(baseline_text):
        return {"vulnerable": False}

    return {
        "vulnerable": True,
        "payload": json.dumps(payload),
        "response": response_text,
    }


def check_bypass_response(
    response_status: int,
    baseline_status: int,
    endpoint: str,
    technique: Dict,
) -> Dict:  # PURE
    """Check if authentication was bypassed.

    Args:
        response_status: Status code of the bypass attempt.
        baseline_status: Status code of the baseline (no-auth) request.
        endpoint: The tested endpoint URL.
        technique: The bypass technique dict used.

    Returns:
        Dict with 'vulnerable' flag and finding details if vulnerable.
    """
    if response_status != 200:
        return {"vulnerable": False}
    if baseline_status not in [401, 403]:
        return {"vulnerable": False}

    return {
        "vulnerable": True,
        "type": "Authentication Bypass",
        "severity": "CRITICAL",
        "technique": str(technique),
        "url": endpoint,
        "description": (
            f"Authentication bypass vulnerability. The endpoint returns 200 OK "
            f"without valid credentials using technique: {technique}. "
            f"Original response was {baseline_status}."
        ),
        "reproduction": f"curl -X GET '{endpoint}' # Returns 200 instead of 401/403",
    }


def check_idor_response(
    test_status: int,
    test_text: str,
    original_data: str,
    endpoint: str,
    original_id: int,
    test_id: int,
    test_endpoint: str,
) -> Dict:  # PURE
    """Check IDOR test response.

    Args:
        test_status: Status code from the IDOR test request.
        test_text: Response text from the IDOR test request.
        original_data: Response text from the original request.
        endpoint: The original endpoint URL.
        original_id: The original object ID.
        test_id: The test object ID.
        test_endpoint: The constructed test endpoint URL.

    Returns:
        Dict with 'vulnerable' flag and finding details if vulnerable.
    """
    if test_status != 200:
        return {"vulnerable": False}
    if test_text == original_data:
        return {"vulnerable": False}

    return create_idor_finding(endpoint, original_id, test_id, test_endpoint)


def check_verb_tampering(
    endpoint: str,
    allow_header: str,
) -> Dict:  # PURE
    """Report advertised state-changing HTTP methods (non-destructive).

    Previously this INVOKED DELETE/PUT/PATCH against the live endpoint (intrusive — could
    actually delete data) and flagged HIGH on a 200/204 without proving anything changed.
    Now it only parses what OPTIONS advertises in the `Allow` header and reports it as a
    LOW lead for manual authorization testing — it never sends a state-changing request.

    Args:
        endpoint: The tested endpoint URL.
        allow_header: The value of the OPTIONS `Allow` response header.

    Returns:
        Dict with 'vulnerable' flag and finding details if state-changing methods are
        advertised.
    """
    methods = [m.strip().upper() for m in (allow_header or "").split(",") if m.strip()]
    state_changing = [m for m in methods if m in ("DELETE", "PUT", "PATCH")]
    if not state_changing:
        return {"vulnerable": False}

    return {
        "vulnerable": True,
        "type": "State-changing HTTP methods advertised",
        "severity": "LOW",
        "allowed_methods": methods,
        "url": endpoint,
        "needs_manual_review": True,
        "description": (
            f"The endpoint advertises state-changing methods via OPTIONS "
            f"(Allow: {', '.join(methods)}). Lead for manual authorization testing — "
            f"confirm whether {state_changing} enforce authz. This is NOT proven "
            f"unauthorized access; no state-changing request was sent."
        ),
        "reproduction": f"curl -X OPTIONS '{endpoint}' -i   # inspect the Allow header",
    }


def create_introspection_vuln(introspection_result: Dict) -> Dict:  # PURE
    """Create vulnerability entry for GraphQL introspection.

    Args:
        introspection_result: The result from parse_introspection_response.

    Returns:
        Vulnerability finding dict.
    """
    return {
        "type": "GraphQL Introspection Enabled",
        "severity": "MEDIUM",
        "description": "Schema can be fully enumerated",
        "schema": introspection_result.get("schema"),
    }


def create_injection_vuln(injection_result: Dict, endpoint: str) -> Dict:  # PURE
    """Create vulnerability entry for GraphQL injection.

    Args:
        injection_result: Result from check_injection_response (must be vulnerable).
        endpoint: The GraphQL endpoint URL.

    Returns:
        Vulnerability finding dict.
    """
    return {
        "type": "GraphQL Injection",
        "severity": "CRITICAL",
        "payload": injection_result["payload"],
        "response": injection_result["response"][:500],
        "description": (
            f"SQL injection reachable through a GraphQL resolver. The payload triggered a "
            f"database error signature that is absent from the benign baseline, indicating "
            f"unsanitized input reaches a SQL query."
        ),
        "reproduction": (
            f"curl -X POST '{endpoint}' -H 'Content-Type: application/json' "
            f"-d '{{\"query\": \"{injection_result['payload'][:100]}...\"}}'"
        ),
    }


def create_idor_finding(
    endpoint: str,
    original_id: int,
    test_id: int,
    test_endpoint: str,
) -> Dict:  # PURE
    """Create IDOR vulnerability finding.

    Args:
        endpoint: The original endpoint URL.
        original_id: The original object ID.
        test_id: The ID that was accessible.
        test_endpoint: The endpoint with the test ID.

    Returns:
        IDOR vulnerability finding dict.
    """
    return {
        "vulnerable": True,
        "type": "IDOR (Insecure Direct Object Reference)",
        "severity": "CRITICAL",
        "original_id": original_id,
        "accessible_id": test_id,
        "url": endpoint,
        "parameter": "id",
        "description": (
            f"Insecure Direct Object Reference (IDOR) vulnerability. "
            f"Changing ID from {original_id} to {test_id} returns different "
            f"user data without authorization checks."
        ),
        "reproduction": (
            f"# Original: curl '{endpoint}'\n# IDOR: curl '{test_endpoint}'"
        ),
    }
