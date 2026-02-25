"""
Nuclei Agent — I/O functions.

All functions in this module perform HTTP I/O or external tool execution.
Dependencies are passed as explicit parameters.

Contents:
    - fetch_html: Fetch HTML content from a URL
    - check_security_headers: Check for missing security headers via HTTP HEAD
    - check_insecure_cookies: Check for insecure cookie flags across URLs
    - check_graphql_introspection: Check for GraphQL introspection on common paths
    - test_graphql_unauth_access: Test if GraphQL mutations are accessible without auth
    - check_rate_limiting: Check for missing rate limiting on auth endpoints
    - check_access_control: Check for broken access control on admin endpoints
    - verify_waf_detections: Verify WAF detections with WAF Fingerprinter
    - detect_frameworks_from_recon_urls: Detect frameworks from recon-discovered URLs
"""

from typing import Dict, List, Optional, Set
from pathlib import Path
from urllib.parse import urlparse
from loguru import logger

import aiohttp

from bugtrace.agents.nuclei.core import (
    SECURITY_HEADERS,
    check_header_missing,
    parse_cookie_issues,
    detect_frameworks_from_html,
    filter_fp_waf_matchers,
)


async def fetch_html(url: str) -> Optional[str]:  # I/O
    """Fetch HTML content from target URL for framework detection fallback.

    Args:
        url: The URL to fetch.

    Returns:
        HTML content string, or None on failure.
    """
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url, ssl=False) as response:
                if response.status == 200:
                    html = await response.text()
                    logger.debug(f"Fetched {len(html)} bytes HTML for framework detection")
                    return html
                else:
                    logger.warning(f"Failed to fetch HTML: HTTP {response.status}")
                    return None
    except Exception as e:
        logger.warning(f"HTML fetch failed: {e}")
        return None


async def check_security_headers(
    target: str,
    existing_template_ids: Set[str],
) -> List[Dict]:  # I/O
    """Check for missing security headers via a single HEAD request.

    Runs AFTER Nuclei to catch headers that Nuclei templates missed.
    Skips headers already detected by Nuclei (via template_id dedup).

    Args:
        target: The target URL.
        existing_template_ids: Set of template IDs already found (lowercased).

    Returns:
        List of misconfiguration dicts for missing headers.
    """
    findings: List[Dict] = []

    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.head(target, ssl=False, allow_redirects=True) as response:
                response_headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception as e:
        logger.warning(f"Security headers check failed: {e}")
        return findings

    for header_key, header_info in SECURITY_HEADERS.items():
        result = check_header_missing(
            header_key, header_info, response_headers, existing_template_ids, target
        )
        if result:
            findings.append(result)
            logger.info(f"Missing security header: {header_info['name']}")

    if not findings:
        logger.info("All security headers present")

    return findings


async def check_insecure_cookies(
    target: str,
    report_dir: Path,
    existing_template_ids: Set[str],
) -> List[Dict]:  # I/O
    """Check for insecure cookie flags (missing HttpOnly, Secure, SameSite).

    Checks multiple URLs (root + auth/login endpoints + recon URLs) because
    cookies are often only set on specific routes.

    Args:
        target: The target URL.
        report_dir: Path to the report directory containing urls.txt.
        existing_template_ids: Set of template IDs already found.

    Returns:
        List of misconfiguration dicts for insecure cookies.
    """
    findings: List[Dict] = []
    seen_cookies: Set[str] = set()

    if "insecure-cookie-flags" in existing_template_ids:
        return findings

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Build list of URLs to check for cookies
    urls_to_check = [target]

    auth_paths = [
        "/login", "/api/login", "/auth/login", "/signin",
        "/api/auth/login", "/api/session", "/account/login",
    ]
    for path in auth_paths:
        urls_to_check.append(f"{base}{path}")

    recon_urls_path = report_dir / "urls.txt"
    if recon_urls_path.exists():
        for line in recon_urls_path.read_text().splitlines()[:10]:
            line = line.strip()
            if line and line not in urls_to_check:
                urls_to_check.append(line)

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        for url in urls_to_check:
            try:
                async with session.get(url, ssl=False, allow_redirects=True) as response:
                    set_cookies = response.headers.getall("Set-Cookie", [])
                    for cookie_header in set_cookies:
                        cookie_name = (
                            cookie_header.split("=")[0].strip()
                            if "=" in cookie_header else "unknown"
                        )
                        if cookie_name in seen_cookies:
                            continue
                        seen_cookies.add(cookie_name)

                        result = parse_cookie_issues(cookie_header, cookie_name, url)
                        if result:
                            findings.append(result)
                            logger.info(f"Insecure cookie: {cookie_name} on {url}")
            except Exception:
                continue

    return findings


async def check_graphql_introspection(
    target: str,
    report_dir: Path,
    existing_template_ids: Set[str],
) -> List[Dict]:  # I/O
    """Check for GraphQL introspection exposure on common GraphQL paths.

    Args:
        target: The target URL.
        report_dir: Path to report directory containing urls.txt.
        existing_template_ids: Set of template IDs already found.

    Returns:
        List of misconfiguration dicts for GraphQL introspection findings.
    """
    findings: List[Dict] = []

    if "graphql-introspection" in existing_template_ids:
        return findings

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    graphql_paths = ["/graphql", "/api/graphql", "/graphiql", "/v1/graphql"]

    # Also check recon URLs for graphql paths
    if report_dir:
        recon_urls_path = report_dir / "urls.txt"
        if recon_urls_path.exists():
            for line in recon_urls_path.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                p = urlparse(line)
                if "graphql" in p.path.lower() and p.path not in graphql_paths:
                    graphql_paths.append(p.path)

    introspection_query = {
        "query": "{ __schema { queryType { name } types { name kind } } }"
    }

    for path in graphql_paths:
        endpoint = f"{base}{path}"
        try:
            timeout = aiohttp.ClientTimeout(total=8)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    endpoint,
                    json=introspection_query,
                    headers={"Content-Type": "application/json"},
                    ssl=False,
                ) as response:
                    if response.status != 200:
                        continue
                    data = await response.json()
                    schema = data.get("data", {}).get("__schema", {})
                    if not schema:
                        continue
                    type_count = len(schema.get("types", []))
                    type_names = [
                        t["name"] for t in schema.get("types", [])
                        if not t["name"].startswith("__")
                    ]

                    findings.append({
                        "name": f"GraphQL Introspection Enabled ({type_count} types exposed)",
                        "severity": "medium",
                        "description": (
                            f"GraphQL endpoint at {endpoint} has introspection enabled, "
                            f"exposing {type_count} types including: {', '.join(type_names[:10])}. "
                            f"Attackers can map the entire API schema, discover hidden queries/mutations, "
                            f"and enumerate data structures for targeted attacks."
                        ),
                        "tags": ["misconfig", "graphql", "exposure", "api"],
                        "template_id": "graphql-introspection",
                        "matched_at": endpoint,
                    })
                    logger.info(f"GraphQL introspection enabled at {endpoint}: {type_count} types")

                    # Test mutations/queries without auth
                    unauth_findings = await test_graphql_unauth_access(endpoint, schema)
                    if unauth_findings:
                        findings.extend(unauth_findings)

                    break  # Found one, no need to check more paths
        except Exception as e:
            logger.debug(f"GraphQL check failed for {endpoint}: {e}")

    return findings


async def test_graphql_unauth_access(
    endpoint: str,
    schema: Dict,
) -> List[Dict]:  # I/O
    """Test if GraphQL mutations/queries are accessible without authentication.

    Args:
        endpoint: The GraphQL endpoint URL.
        schema: The introspection schema dict.

    Returns:
        List of misconfiguration dicts for unauthenticated access.
    """
    findings: List[Dict] = []

    # Extract mutation type name
    mutation_type_name = None
    types = schema.get("types", [])
    for t in types:
        if t.get("kind") == "OBJECT" and t.get("name") in ("Mutation", "RootMutation"):
            mutation_type_name = t["name"]
            break

    if not mutation_type_name:
        mutation_meta = schema.get("mutationType")
        if mutation_meta:
            mutation_type_name = mutation_meta.get("name", "Mutation")

    if not mutation_type_name:
        return findings

    # Get full mutation type details via deeper introspection
    mutation_query = {
        "query": (
            f'{{ __type(name: "{mutation_type_name}") '
            f'{{ fields {{ name args {{ name type {{ name kind }} }} }} }} }}'
        )
    }
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                endpoint, json=mutation_query,
                headers={"Content-Type": "application/json"}, ssl=False,
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    mutation_fields = (
                        data.get("data", {}).get("__type", {}).get("fields", [])
                    )
                    if mutation_fields:
                        mutation_names = [f["name"] for f in mutation_fields]
                        sensitive_mutations = [
                            m for m in mutation_names if any(
                                kw in m.lower()
                                for kw in ["delete", "update", "create", "admin", "reset", "modify"]
                            )
                        ]
                        if sensitive_mutations:
                            findings.append({
                                "name": (
                                    f"GraphQL Mutations Accessible Without Auth "
                                    f"({len(sensitive_mutations)} sensitive)"
                                ),
                                "severity": "high",
                                "description": (
                                    f"GraphQL endpoint exposes {len(mutation_fields)} mutations "
                                    f"without authentication, including sensitive operations: "
                                    f"{', '.join(sensitive_mutations[:5])}. "
                                    f"Attackers can modify data without credentials."
                                ),
                                "tags": ["misconfig", "graphql", "access-control", "api"],
                                "template_id": "graphql-unauth-mutations",
                                "matched_at": endpoint,
                            })
    except Exception as e:
        logger.debug(f"GraphQL mutation check failed: {e}")

    return findings


async def check_rate_limiting(
    target: str,
    report_dir: Path,
) -> List[Dict]:  # I/O
    """Check for missing rate limiting on authentication endpoints.

    Sends 25 rapid requests to common auth endpoints. If no 429 response
    is received, reports missing rate limiting.

    Args:
        target: The target URL.
        report_dir: Path to report directory containing urls.txt.

    Returns:
        List of misconfiguration dicts for missing rate limiting.
    """
    findings: List[Dict] = []

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    auth_endpoints = [
        "/login", "/api/login", "/api/auth/login", "/auth/login",
        "/signin", "/api/signin", "/api/users/login", "/api/token",
    ]

    recon_urls_path = report_dir / "urls.txt"
    if recon_urls_path.exists():
        for line in recon_urls_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            p = urlparse(line)
            if any(kw in p.path.lower() for kw in ["login", "signin", "auth", "token"]):
                if p.path not in auth_endpoints:
                    auth_endpoints.append(p.path)

    timeout = aiohttp.ClientTimeout(total=3)
    test_body = {"username": "test@test.com", "password": "testpassword123"}
    request_count = 25

    for path in auth_endpoints:
        endpoint = f"{base}{path}"
        got_429 = False
        successful_requests = 0

        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # First check if endpoint exists
                try:
                    async with session.post(endpoint, json=test_body, ssl=False) as resp:
                        if resp.status in (404, 405):
                            continue
                        if resp.status == 429:
                            got_429 = True
                except Exception:
                    continue

                if got_429:
                    continue

                # Send rapid requests
                for _ in range(request_count - 1):
                    try:
                        async with session.post(endpoint, json=test_body, ssl=False) as resp:
                            if resp.status == 429:
                                got_429 = True
                                break
                            successful_requests += 1
                    except Exception:
                        break

            if not got_429 and successful_requests >= 15:
                findings.append({
                    "name": f"No Rate Limiting on {path}",
                    "severity": "medium",
                    "description": (
                        f"Authentication endpoint {endpoint} accepted "
                        f"{successful_requests + 1} rapid requests without returning 429. "
                        f"Missing rate limiting enables credential brute-force and stuffing attacks."
                    ),
                    "tags": ["misconfig", "rate-limiting", "authentication", "security"],
                    "template_id": "no-rate-limiting",
                    "matched_at": endpoint,
                })
                logger.info(
                    f"No rate limiting on {endpoint} "
                    f"({successful_requests + 1} requests accepted)"
                )
                break
        except Exception as e:
            logger.debug(f"Rate limit check failed for {endpoint}: {e}")

    return findings


async def check_access_control(
    target: str,
    report_dir: Path,
) -> List[Dict]:  # I/O
    """Check for broken access control on admin/privileged endpoints.

    Args:
        target: The target URL.
        report_dir: Path to report directory containing urls.txt.

    Returns:
        List of misconfiguration dicts for accessible admin endpoints.
    """
    findings: List[Dict] = []

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    admin_paths = [
        "/admin", "/api/admin", "/admin/dashboard", "/api/admin/stats",
        "/api/admin/users", "/debug", "/api/debug", "/internal",
        "/api/internal", "/actuator", "/actuator/health",
        "/api/admin/config", "/admin/settings",
    ]

    recon_urls_path = report_dir / "urls.txt"
    if recon_urls_path.exists():
        for line in recon_urls_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            p = urlparse(line)
            if any(kw in p.path.lower() for kw in ["admin", "debug", "internal", "actuator", "management"]):
                if p.path not in admin_paths:
                    admin_paths.append(p.path)

    timeout = aiohttp.ClientTimeout(total=5)

    async with aiohttp.ClientSession(timeout=timeout) as session:
        for path in admin_paths:
            endpoint = f"{base}{path}"
            try:
                async with session.get(endpoint, ssl=False, allow_redirects=False) as response:
                    if response.status == 200:
                        body = await response.text()
                        if (len(body) > 50
                                and "not found" not in body.lower()
                                and "404" not in body[:100]):
                            findings.append({
                                "name": f"Admin Endpoint Accessible Without Auth: {path}",
                                "severity": "high",
                                "description": (
                                    f"Administrative endpoint {endpoint} is accessible without "
                                    f"authentication (returned HTTP 200 with {len(body)} bytes). "
                                    f"This may expose sensitive data, debug info, or admin functionality."
                                ),
                                "tags": ["misconfig", "access-control", "admin", "security"],
                                "template_id": "broken-access-control-admin",
                                "matched_at": endpoint,
                            })
                            logger.info(
                                f"Admin endpoint accessible without auth: {endpoint} ({len(body)} bytes)"
                            )
            except Exception:
                continue

    return findings


async def verify_waf_detections(
    waf_names: List[str],
    tech_findings: List[Dict],
    target: str,
) -> List[str]:  # I/O
    """Verify WAF detections from Nuclei using WAF Fingerprinter.

    Args:
        waf_names: List of WAF names detected by Nuclei.
        tech_findings: Raw Nuclei tech findings.
        target: The target URL.

    Returns:
        Verified list of WAF names.
    """
    from bugtrace.tools.waf.fingerprinter import waf_fingerprinter

    all_are_fp, waf_matcher_names = filter_fp_waf_matchers(waf_names, tech_findings)

    if all_are_fp:
        logger.info(
            f"WAF detection matchers are all FP-prone: "
            f"{waf_matcher_names} - verifying with WAF Fingerprinter"
        )
        try:
            waf_name, confidence = await waf_fingerprinter.detect(target, timeout=10.0)
            if waf_name != "unknown" and confidence >= 0.4:
                logger.info(
                    f"WAF Fingerprinter confirmed: {waf_name} "
                    f"(confidence: {confidence:.0%})"
                )
                return [waf_name]
            else:
                logger.info(
                    f"WAF Fingerprinter found no WAF "
                    f"(result: {waf_name}, confidence: {confidence:.0%}) - "
                    f"removing Nuclei FP"
                )
                return []
        except Exception as e:
            logger.warning(f"WAF Fingerprinter failed: {e} - keeping Nuclei result")
            return waf_names

    return waf_names


async def detect_frameworks_from_recon_urls(
    report_dir: Path,
) -> List[str]:  # I/O
    """Detect frontend frameworks by fetching HTML from recon-discovered URLs.

    Args:
        report_dir: Path to report directory containing urls.txt.

    Returns:
        List of detected framework names.
    """
    recon_urls_path = report_dir / "urls.txt"
    if not recon_urls_path.exists():
        return []

    urls = [
        line.strip() for line in recon_urls_path.read_text().splitlines()
        if line.strip()
    ]
    if not urls:
        return []

    # Sample up to 5 diverse URLs
    seen_paths: set = set()
    sample_urls: List[str] = []
    for url in urls:
        path = urlparse(url).path.rstrip("/")
        path_prefix = "/".join(path.split("/")[:2])
        if path_prefix not in seen_paths:
            seen_paths.add(path_prefix)
            sample_urls.append(url)
            if len(sample_urls) >= 5:
                break

    frameworks: List[str] = []
    for url in sample_urls:
        try:
            html = await fetch_html(url)
            if html:
                detected = detect_frameworks_from_html(html)
                if detected:
                    frameworks.extend(detected)
                    logger.info(f"Framework detected from recon URL {url}: {detected}")
                    break
        except Exception as e:
            logger.debug(f"Recon URL framework check failed for {url}: {e}")

    return list(set(frameworks))
