"""
SQLi Agent Discovery (I/O)

I/O functions for SQLi-specific parameter discovery:
- URL query string extraction
- HTML form parameter extraction
- Cookie discovery from HTTP responses
- Injectable header enumeration
- SPA detection and API URL resolution

These functions perform HTTP requests and browser interactions.
"""

import re
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin

from loguru import logger

from bugtrace.agents.sqli.context import should_test_cookie


# =============================================================================
# PARAMETER DISCOVERY
# =============================================================================

async def discover_sqli_params(
    url: str,
    agent_name: str = "SQLiAgent",
) -> Dict[str, str]:
    """
    # I/O
    SQLi-focused parameter discovery for a given URL.

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select)
    3. Link parameters (same-origin <a> tags)
    4. Cookies from HTTP response (Set-Cookie headers)
    5. Common injectable headers

    Architecture Note:
        Specialists must be AUTONOMOUS - they discover their own attack surface.
        The finding from DASTySAST is just a "signal" that the URL is interesting.
        We IGNORE the specific parameter and test ALL discoverable params.

    Args:
        url: Target URL to discover parameters from
        agent_name: Name of the calling agent for logging

    Returns:
        Dict mapping param names to default values
        Example: {"id": "123", "sort": "asc", "Cookie: session": ""}
    """
    from bugtrace.tools.visual.browser import browser_manager
    from bs4 import BeautifulSoup

    all_params: Dict[str, str] = {}
    last_html: Optional[str] = None

    # 1. Extract URL query parameters
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            all_params[param_name] = values[0] if values else ""
    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to parse URL params: {e}")

    # 2. Fetch HTML and extract form parameters + link parameters
    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if html:
            last_html = html
            soup = BeautifulSoup(html, "html.parser")

            # Extract from <input>, <textarea>, <select>
            for tag in soup.find_all(["input", "textarea", "select"]):
                param_name = tag.get("name")
                if param_name and param_name not in all_params:
                    input_type = tag.get("type", "text").lower()

                    # Skip non-testable input types
                    if input_type not in ["submit", "button", "reset"]:
                        # Include CSRF tokens for SQLi (unlike XSS)
                        default_value = tag.get("value", "")
                        all_params[param_name] = default_value

            # Extract params from <a> href links (same-origin only)
            parsed_base = urlparse(url)
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                    continue
                try:
                    resolved = urlparse(urljoin(url, href))
                    if resolved.netloc and resolved.netloc != parsed_base.netloc:
                        continue
                    for p_name, p_vals in parse_qs(resolved.query).items():
                        if p_name not in all_params:
                            all_params[p_name] = p_vals[0] if p_vals else ""
                except Exception:
                    continue

    except Exception as e:
        logger.error(f"[{agent_name}] HTML parsing failed: {e}")

    # 3. Extract cookies from HTTP response (Set-Cookie headers)
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as cookie_session:
            async with cookie_session.get(url, ssl=False, allow_redirects=True) as resp:
                for cookie_header in resp.headers.getall("Set-Cookie", []):
                    cookie_name = cookie_header.split("=", 1)[0].strip()
                    if cookie_name and should_test_cookie(cookie_name):
                        cookie_key = f"Cookie: {cookie_name}"
                        if cookie_key not in all_params:
                            all_params[cookie_key] = ""
                            logger.info(f"[{agent_name}] Discovered cookie param: {cookie_name}")
    except Exception as e:
        logger.warning(f"[{agent_name}] Cookie extraction failed: {e}")

    # 4. Add common injectable headers for testing
    injectable_headers = [
        "X-Forwarded-For",
        "Referer",
        "User-Agent",
    ]
    for header_name in injectable_headers:
        header_key = f"Header: {header_name}"
        if header_key not in all_params:
            all_params[header_key] = ""

    logger.info(f"[{agent_name}] Discovered {len(all_params)} params on {url}: {list(all_params.keys())}")
    return all_params


# =============================================================================
# SPA DETECTION
# =============================================================================

async def detect_and_resolve_spa_url(
    url: str,
    param: str,
    agent_name: str = "SQLiAgent",
) -> Optional[str]:
    """
    # I/O
    Detect SPA frontend routes and resolve to API backend URLs.

    SPA frameworks (React/Vue/Angular) serve identical HTML for all routes
    -- path parameter payloads never reach the database. This method:
    1. Checks if URL is a likely SPA route (no /api/ prefix, has path param)
    2. Sends two requests with different path values, compares responses
    3. If identical -> it's a SPA, tries common API URL patterns
    4. Returns the API URL if found, None otherwise

    Args:
        url: URL to check for SPA behavior
        param: Parameter name being tested
        agent_name: Name for logging

    Returns:
        Resolved API URL or None
    """
    parsed = urlparse(url)
    # Only check non-API URLs with path parameters
    if "/api/" in parsed.path:
        return None
    if not re.search(r'/:\w+|/\d+', parsed.path):
        return None

    # Build two variant URLs to test SPA behavior
    path = parsed.path
    test_paths = []
    if f":{param.lstrip(':')}" in path:
        test_paths.append(path.replace(f":{param.lstrip(':')}", "1"))
        test_paths.append(path.replace(f":{param.lstrip(':')}", "99999"))
    else:
        match = re.search(r'/(\d+)(?=/|$)', path)
        if match:
            test_paths.append(path[:match.start()] + "/1" + path[match.end():])
            test_paths.append(path[:match.start()] + "/99999" + path[match.end():])

    if len(test_paths) < 2:
        return None

    origin = f"{parsed.scheme}://{parsed.netloc}"
    try:
        timeout = aiohttp.ClientTimeout(total=5)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"{origin}{test_paths[0]}", ssl=False) as r1:
                body1 = await r1.text()
                ct1 = r1.headers.get("content-type", "")
            async with session.get(f"{origin}{test_paths[1]}", ssl=False) as r2:
                body2 = await r2.text()

            # SPA detection: identical HTML responses for different IDs
            is_spa = (
                "text/html" in ct1
                and len(body1) > 100
                and body1 == body2
            )
            if not is_spa:
                return None

            logger.info(f"[{agent_name}] SPA detected: {url} returns identical HTML for different path params")

            # Try to resolve API endpoint
            segments = [s for s in parsed.path.strip("/").split("/") if s]
            id_idx = None
            for i, seg in enumerate(segments):
                if seg.startswith(":") or re.match(r'^\d+$', seg):
                    id_idx = i
                    break

            if id_idx is None or id_idx == 0:
                return None

            id_val = "1"
            path_before = segments[:id_idx]

            # Generate candidates
            candidates = []
            candidates.append(f"/api/{'/'.join(path_before)}/{id_val}")
            if path_before:
                last = path_before[-1]
                if not last.endswith("s"):
                    parts = list(path_before)
                    parts[-1] = last + "s"
                    candidates.append(f"/api/{'/'.join(parts)}/{id_val}")
            if len(path_before) >= 2:
                candidates.append(f"/api/{path_before[-1]}/{id_val}")
                if not path_before[-1].endswith("s"):
                    candidates.append(f"/api/{path_before[-1]}s/{id_val}")

            for candidate_path in candidates:
                candidate_url = f"{origin}{candidate_path}"
                try:
                    async with session.get(candidate_url, ssl=False) as resp:
                        if resp.status in (404, 405, 502, 503):
                            continue
                        ct = resp.headers.get("content-type", "")
                        if "json" in ct:
                            api_base = candidate_url.rsplit("/", 1)[0]
                            resolved = f"{api_base}/:{param.lstrip(':')}"
                            logger.info(f"[{agent_name}] SPA->API resolved: {url} -> {resolved}")
                            return resolved
                except Exception:
                    continue

    except Exception as e:
        logger.debug(f"[{agent_name}] SPA detection failed for {url}: {e}")

    return None


__all__ = [
    "discover_sqli_params",
    "detect_and_resolve_spa_url",
]
