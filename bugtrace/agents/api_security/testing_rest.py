"""
API Security Agent — I/O functions.

All functions in this module perform HTTP I/O. Dependencies (httpx clients,
endpoints) are passed as explicit parameters.

Contents:
    - test_graphql_introspection: Test if GraphQL introspection is enabled
    - test_graphql_injection: Test for injection in GraphQL queries
    - test_graphql_dos: Test for nested query DoS
    - test_graphql_endpoint: Comprehensive GraphQL security testing
    - test_auth_bypass: Test authentication bypass techniques
    - test_idor: Test for Insecure Direct Object Reference
    - test_http_verb_tampering: Test HTTP method override vulnerabilities
    - test_rest_endpoint: Comprehensive REST API testing
    - test_websocket: Test WebSocket security
    - discover_graphql_endpoint: Discover GraphQL endpoint from base URL
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from loguru import logger

import httpx

from bugtrace.agents.api_security.core import (
    WEBSOCKETS_AVAILABLE,
    parse_introspection_response,
    is_graphql_validation_error,
    check_injection_response,
    check_bypass_response,
    check_idor_response,
    check_verb_tampering,
    create_introspection_vuln,
    create_injection_vuln,
    create_idor_finding,
)


# ==================== GRAPHQL TESTING ====================


# ==================== REST / AUTH / WS ====================

async def _test_single_bypass(
    client: httpx.AsyncClient,
    endpoint: str,
    baseline_status: int,
    technique: Dict,
) -> Dict:  # I/O
    """Test a single authentication bypass technique.

    Args:
        client: An httpx async client.
        endpoint: The endpoint URL.
        baseline_status: Status code from baseline request.
        technique: Bypass technique dict with headers etc.

    Returns:
        Dict with 'vulnerable' flag and finding details.
    """
    try:
        response = await client.get(endpoint, **technique, timeout=5)
        return check_bypass_response(
            response.status_code, baseline_status, endpoint, technique
        )
    except Exception:
        return {"vulnerable": False}


async def test_auth_bypass(endpoint: str) -> Dict:  # I/O
    """Test authentication bypass techniques.

    Args:
        endpoint: The endpoint URL.

    Returns:
        Dict with 'vulnerable' flag and finding details if vulnerable.
    """
    bypass_techniques = [
        {"headers": {}},
        {"headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}},
        {"headers": {"Authorization": "Bearer "}},
        {"headers": {"Authorization": "Bearer invalid_token"}},
    ]

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            baseline = await client.get(endpoint, timeout=5)

            for technique in bypass_techniques:
                result = await _test_single_bypass(
                    client, endpoint, baseline.status_code, technique
                )
                if result.get("vulnerable"):
                    return result
    except Exception as e:
        logger.debug(f"operation failed: {e}")

    return {"vulnerable": False}


async def _test_single_idor_id(
    client: httpx.AsyncClient,
    endpoint: str,
    original_id: int,
    test_id: int,
    original_data: str,
    id_pattern: str,
) -> Dict:  # I/O
    """Test a single ID for IDOR vulnerability.

    Args:
        client: An httpx async client.
        endpoint: The original endpoint URL.
        original_id: The original object ID.
        test_id: The ID to test.
        original_data: Response text from the original request.
        id_pattern: Regex pattern for ID replacement.

    Returns:
        Dict with 'vulnerable' flag.
    """
    if test_id == original_id:
        return {"vulnerable": False}

    test_endpoint = re.sub(id_pattern, f'/{test_id}/', endpoint)
    try:
        test_response = await client.get(test_endpoint, timeout=5)
        return check_idor_response(
            test_response.status_code, test_response.text,
            original_data, endpoint, original_id, test_id, test_endpoint,
        )
    except Exception:
        return {"vulnerable": False}


async def test_idor(endpoint: str) -> Dict:  # I/O
    """Test for Insecure Direct Object Reference.

    Args:
        endpoint: The endpoint URL with a numeric ID.

    Returns:
        Dict with 'vulnerable' flag and finding details if vulnerable.
    """
    id_pattern = r'/(\d+)(?:/|$)'
    match = re.search(id_pattern, endpoint)

    if not match:
        return {"vulnerable": False}

    original_id = int(match.group(1))
    test_ids = [original_id - 1, original_id + 1, 1, 999]

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            original_response = await client.get(endpoint, timeout=5)
            if original_response.status_code != 200:
                return {"vulnerable": False}

            original_data = original_response.text

            for test_id in test_ids:
                result = await _test_single_idor_id(
                    client, endpoint, original_id, test_id, original_data, id_pattern
                )
                if result.get("vulnerable"):
                    return result
    except Exception as e:
        logger.debug(f"operation failed: {e}")

    return {"vulnerable": False}


async def test_http_verb_tampering(endpoint: str) -> Dict:  # I/O
    """Report advertised HTTP methods NON-DESTRUCTIVELY via a single OPTIONS request.

    Previously this fired real DELETE/PUT/PATCH at the live endpoint (could actually
    delete data) and flagged on a 200/204. Now it sends only OPTIONS and reads the
    `Allow` header — it never issues a state-changing request.

    Args:
        endpoint: The endpoint URL.

    Returns:
        Dict with 'vulnerable' flag and finding details if state-changing methods are
        advertised.
    """
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.request("OPTIONS", endpoint, timeout=5)
            allow = response.headers.get("Allow", response.headers.get("allow", ""))
            return check_verb_tampering(endpoint, allow)
    except Exception as e:
        logger.debug(f"operation failed: {e}")
        return {"vulnerable": False}


async def test_rest_endpoint(
    endpoint: str,
    log_fn: Any = None,
) -> Dict[str, Any]:  # I/O
    """Comprehensive REST API testing.

    Tests:
    1. Authentication bypass (baseline-gated)
    2. HTTP method exposure (non-destructive OPTIONS probe)

    IDOR is intentionally NOT tested here — see below.

    Args:
        endpoint: The REST API endpoint URL.
        log_fn: Optional callable(message, level) for logging.

    Returns:
        Dict with 'endpoint' and 'vulnerabilities' list.
    """
    if log_fn:
        log_fn(f"REST API Testing: {endpoint}", "INFO")

    results: Dict[str, Any] = {"endpoint": endpoint, "vulnerabilities": []}

    # Test 1: Authentication bypass (only fires if the endpoint actually required auth).
    auth_bypass = await test_auth_bypass(endpoint)
    if auth_bypass["vulnerable"]:
        results["vulnerabilities"].append(auth_bypass)

    # IDOR is delegated to the dedicated IDORAgent. Proving IDOR needs an authenticated
    # session (own-vs-other object); this unauthenticated probe cannot provide that, and
    # "different body for a different id" alone is a false positive on public data.

    # Test 2: HTTP method exposure (non-destructive — reads the OPTIONS Allow header).
    verb_tamper = await test_http_verb_tampering(endpoint)
    if verb_tamper["vulnerable"]:
        results["vulnerabilities"].append(verb_tamper)

    return results


# ==================== WEBSOCKET TESTING ====================


async def test_websocket(ws_url: str) -> Dict:  # I/O
    """Test WebSocket security.

    Args:
        ws_url: The WebSocket URL.

    Returns:
        Dict with 'accessible' flag.
    """
    if not WEBSOCKETS_AVAILABLE:
        return {"accessible": False, "error": "websockets module not installed"}

    try:
        import websockets
        async with websockets.connect(ws_url, timeout=5) as websocket:
            # Test 1: Check if authentication is required
            test_message = json.dumps({"type": "ping", "data": "test"})
            await websocket.send(test_message)

            response = await asyncio.wait_for(websocket.recv(), timeout=3)

            # Test 2: Try injection payloads
            injection_payloads = [
                {"type": "message", "content": "<script>alert(1)</script>"},
                {"type": "message", "content": "' OR '1'='1"},
            ]

            for payload in injection_payloads:
                await websocket.send(json.dumps(payload))

            return {"accessible": True, "authenticated": False}
    except Exception as e:
        logger.debug(f"operation failed: {e}")
        return {"accessible": False}


# ==================== DISCOVERY ====================


async def discover_graphql_endpoint(base_url: str) -> Optional[str]:  # I/O
    """Discover GraphQL endpoint from a base URL by probing common paths.

    Args:
        base_url: The base URL to probe.

    Returns:
        The discovered GraphQL endpoint URL, or None.
    """
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    graphql_paths = [
        parsed.path,
        "/graphql",
        "/api/graphql",
        "/graphql/v1",
        "/api/v1/graphql",
        "/gql",
    ]

    introspection_query = {"query": "{ __typename }"}

    try:
        async with httpx.AsyncClient(timeout=5, verify=False) as client:
            for path in graphql_paths:
                test_url = f"{base}{path}" if path.startswith("/") else path
                try:
                    resp = await client.post(
                        test_url,
                        json=introspection_query,
                        headers={"Content-Type": "application/json"},
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        if "data" in data or "errors" in data:
                            logger.info(f"GraphQL endpoint found: {test_url}")
                            return test_url
                except Exception:
                    continue
    except Exception as e:
        logger.debug(f"GraphQL discovery error: {e}")

    return None
