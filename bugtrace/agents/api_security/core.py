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


def check_injection_response(
    response_text: str,
    payload: Dict,
) -> Dict:  # PURE
    """Check GraphQL response for injection indicators.

    Args:
        response_text: Raw response text.
        payload: The injection payload that was sent.

    Returns:
        Dict with 'vulnerable' flag and optional 'payload'/'response' keys.
    """
    error_patterns = [
        "sql", "mysql", "postgresql", "syntax error",
        "unclosed quotation", "unexpected", "exception",
    ]

    response_lower = response_text.lower()
    if not any(pattern in response_lower for pattern in error_patterns):
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
    results_by_method: Dict[str, int],
) -> Dict:  # PURE
    """Check if DELETE verb tampering is present.

    Args:
        endpoint: The tested endpoint URL.
        results_by_method: Dict mapping HTTP method name to status code.

    Returns:
        Dict with 'vulnerable' flag and finding details if vulnerable.
    """
    if "DELETE" not in results_by_method:
        return {"vulnerable": False}
    if results_by_method["DELETE"] not in [200, 204]:
        return {"vulnerable": False}

    return {
        "vulnerable": True,
        "type": "HTTP Verb Tampering",
        "severity": "HIGH",
        "allowed_methods": list(results_by_method.keys()),
        "url": endpoint,
        "description": (
            f"HTTP Verb Tampering vulnerability. The DELETE method is allowed on this endpoint, "
            f"potentially allowing unauthorized resource deletion. "
            f"Allowed methods: {list(results_by_method.keys())}"
        ),
        "reproduction": f"curl -X DELETE '{endpoint}' # Returns {results_by_method['DELETE']}",
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
            f"GraphQL query injection vulnerability detected. Malicious payloads "
            f"can manipulate query structure to access unauthorized data or "
            f"execute unintended operations."
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
