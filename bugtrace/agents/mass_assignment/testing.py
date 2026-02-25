"""
Mass Assignment Agent — I/O functions.

All functions in this module perform HTTP I/O. Dependencies (httpx client,
auth headers, scan context) are passed as explicit parameters rather than
accessed via self.

Contents:
    - get_baseline: GET endpoint to establish baseline response
    - test_method_with_fields: Test one HTTP method with injected privilege fields
    - check_followup_get: Follow-up GET to detect silent persistence
    - test_endpoint_mass_assignment: Full endpoint test orchestration
    - discover_writable_endpoints: Discover POST/PUT/PATCH endpoints
"""

import logging
from typing import Dict, List, Any, Tuple, Optional
from urllib.parse import urlparse

import httpx

from bugtrace.agents.mass_assignment.core import (
    group_privilege_fields,
    check_field_acceptance,
    check_followup_fields,
    build_finding,
)

logger = logging.getLogger(__name__)


async def get_baseline(
    client: httpx.AsyncClient,
    url: str,
) -> Optional[Dict]:  # I/O
    """GET the endpoint to establish baseline response.

    Args:
        client: An httpx async client with appropriate headers/auth.
        url: The endpoint URL to GET.

    Returns:
        Parsed JSON body as dict, empty dict if non-JSON 200, or None on error/auth failure.
    """
    try:
        resp = await client.get(url)
        if resp.status_code in (200, 201):
            try:
                return resp.json()
            except Exception as e:
                logger.debug(f"JSON parse failed for {url}: {e}")
                return {}
        elif resp.status_code in (401, 403):
            logger.debug(f"Auth required for {url} (status {resp.status_code})")
            return None
        return {}
    except Exception as e:
        logger.debug(f"Baseline GET failed for {url}: {e}")
        return None


async def check_followup_get(
    client: httpx.AsyncClient,
    url: str,
    injected_fields: Dict[str, Any],
    baseline_body: Dict,
) -> List[Tuple[str, Any]]:  # I/O
    """Follow-up GET after mutation to detect silent field persistence.

    Compares baseline vs post-mutation GET response for injected fields.

    Args:
        client: An httpx async client.
        url: The endpoint URL.
        injected_fields: Fields that were injected in the mutation request.
        baseline_body: Response body from the initial baseline GET.

    Returns:
        List of (field_name, field_value) tuples for fields that persisted.
    """
    try:
        resp = await client.get(url)
        if resp.status_code not in (200, 201):
            return []
        followup_body = resp.json() if resp.text.strip() else {}
    except Exception:
        return []

    return check_followup_fields(injected_fields, baseline_body, followup_body)


async def test_method_with_fields(
    client: httpx.AsyncClient,
    url: str,
    method: str,
    baseline_body: Dict,
    log_fn: Any = None,
    memory_fn: Any = None,
) -> List[Dict]:  # I/O
    """Test a specific HTTP method by injecting privilege fields.

    Args:
        client: An httpx async client.
        url: The endpoint URL to test.
        method: HTTP method to use (POST/PUT/PATCH).
        baseline_body: The baseline response body for comparison.
        log_fn: Optional callable(message, level) for dashboard logging.
        memory_fn: Optional callable(field_name, url, method, field_value)
            to store findings in knowledge graph.

    Returns:
        List of validated finding dicts.
    """
    findings: List[Dict] = []

    # Build payload: merge baseline fields + privilege fields
    payload: Dict[str, Any] = {}
    if isinstance(baseline_body, dict):
        payload.update(baseline_body)

    # Inject privilege fields in batches
    field_groups = group_privilege_fields()

    for group_name, fields in field_groups.items():
        test_payload = {**payload, **fields}

        try:
            resp = await client.request(
                method, url,
                json=test_payload,
                headers={"Content-Type": "application/json"},
            )

            # Parse response body safely
            try:
                resp_body = resp.json() if resp.text.strip() else {}
            except Exception:
                resp_body = {}

            # Check 1: Direct response analysis
            accepted_fields = check_field_acceptance(
                resp.status_code, resp.text, resp_body, fields, baseline_body
            )

            # Check 2: Follow-up GET to detect silent persistence
            if not accepted_fields and resp.status_code in (200, 201, 204):
                followup_fields = await check_followup_get(
                    client, url, fields, baseline_body
                )
                accepted_fields.extend(followup_fields)

            for field_name, field_value in accepted_fields:
                finding = build_finding(
                    url, method, field_name, field_value, resp.status_code
                )
                findings.append(finding)

                if log_fn:
                    log_fn(
                        f"  MASS ASSIGNMENT: {field_name}={field_value} "
                        f"accepted via {method} on {url}",
                        "CRITICAL",
                    )

                # Store in knowledge graph if callback provided
                if memory_fn:
                    try:
                        memory_fn(field_name, url, method, field_value)
                    except Exception:
                        pass

        except httpx.TimeoutException:
            logger.debug(f"Timeout on {method} {url}")
        except Exception as e:
            logger.debug(f"{method} {url} failed: {e}")

    return findings


async def test_endpoint_mass_assignment(
    url: str,
    scan_context: str,
    auth_headers_fn: Any = None,
) -> List[Dict]:  # I/O
    """Test a single endpoint for mass assignment vulnerabilities.

    Strategy:
    1. GET the endpoint to understand its current state
    2. POST/PUT/PATCH with injected PRIVILEGE_FIELDS
    3. GET again to check if fields persisted

    Args:
        url: The endpoint URL to test.
        scan_context: Current scan context string.
        auth_headers_fn: Optional callable(scan_context, role) that returns auth headers dict.

    Returns:
        List of validated finding dicts.
    """
    findings: List[Dict] = []

    # Get auth headers from scan context
    auth_headers: Dict[str, str] = {}
    if auth_headers_fn:
        try:
            auth_headers = auth_headers_fn(scan_context, role="user") or {}
        except Exception:
            pass

    headers = {"Content-Type": "application/json"}
    headers.update(auth_headers)

    async with httpx.AsyncClient(
        timeout=10, verify=False, follow_redirects=True, headers=headers
    ) as client:
        # Step 1: Baseline GET
        baseline_body = await get_baseline(client, url)
        if baseline_body is None:
            # Retry with admin role if user auth failed
            if auth_headers and auth_headers_fn:
                try:
                    admin_headers = auth_headers_fn(scan_context, role="admin") or {}
                    if admin_headers and admin_headers != auth_headers:
                        admin_h = {"Content-Type": "application/json"}
                        admin_h.update(admin_headers)
                        async with httpx.AsyncClient(
                            timeout=10, verify=False, follow_redirects=True, headers=admin_h
                        ) as admin_client:
                            baseline_body = await get_baseline(admin_client, url)
                            if baseline_body is not None:
                                # Continue with admin client for remaining tests
                                for method in ["POST", "PUT", "PATCH"]:
                                    method_findings = await test_method_with_fields(
                                        admin_client, url, method, baseline_body
                                    )
                                    findings.extend(method_findings)
                                    if method_findings:
                                        break
                                return findings
                except Exception:
                    pass
            if baseline_body is None:
                return findings

        # Step 2: Try each HTTP method
        for method in ["POST", "PUT", "PATCH"]:
            method_findings = await test_method_with_fields(
                client, url, method, baseline_body
            )
            findings.extend(method_findings)

            # Stop after first successful method to avoid noise
            if method_findings:
                break

    return findings


async def discover_writable_endpoints(base_url: str) -> List[str]:  # I/O
    """Discover POST/PUT/PATCH endpoints from common API paths.

    Universal discovery -- probes common patterns, not target-specific.

    Args:
        base_url: A URL from which to derive the base host.

    Returns:
        List of discovered endpoint URLs that accept write methods.
    """
    discovered: List[str] = []
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Common API paths that accept POST/PUT/PATCH
    common_api_paths = [
        "/api/profile", "/api/user", "/api/account",
        "/api/settings", "/api/preferences",
        "/api/v1/profile", "/api/v1/user", "/api/v1/account",
        "/api/v1/users/me", "/api/me",
        "/api/auth/register", "/api/auth/signup",
        "/api/users", "/api/products", "/api/orders",
    ]

    async with httpx.AsyncClient(
        timeout=5, verify=False, follow_redirects=True
    ) as client:
        for path in common_api_paths:
            test_url = f"{base}{path}"
            try:
                # OPTIONS to check if endpoint exists and accepts POST/PUT
                resp = await client.options(test_url)
                allow = resp.headers.get("allow", "").upper()
                if any(m in allow for m in ["POST", "PUT", "PATCH"]):
                    discovered.append(test_url)
                    continue

                # Fallback: try GET to see if endpoint exists
                resp = await client.get(test_url)
                if resp.status_code in (200, 201, 401, 403):
                    discovered.append(test_url)
            except Exception:
                continue

    if discovered:
        logger.info(f"Discovered {len(discovered)} writable endpoints")

    return discovered
