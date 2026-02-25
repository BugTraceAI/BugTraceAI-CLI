"""
JWT Discovery - I/O Functions

Async functions for JWT token discovery in URLs, cookies, localStorage,
page content, and protected endpoint scanning.

All functions are I/O: async, dependencies as explicit first params.
"""

import re
import json
import asyncio
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse, parse_qs
from loguru import logger

from bugtrace.agents.jwt.analysis import is_jwt, get_root_url
from bugtrace.agents.jwt.types import AUTH_PATTERNS


# =========================================================================
# URL Parameter Discovery (I/O - reads URL)
# =========================================================================

async def check_url_for_tokens(url: str, discovered: List[Tuple[str, str]]) -> None:
    """Check URL parameters for JWT tokens.

    Args:
        url: URL to check
        discovered: Mutable list to append (token, location) tuples
    """  # I/O
    p_curr = urlparse(url)
    p_params = parse_qs(p_curr.query)
    for val_list in p_params.values():
        for val in val_list:
            if is_jwt(val):
                discovered.append((val, "url_param"))


# =========================================================================
# Page Content Discovery (I/O - browser interaction)
# =========================================================================

def check_page_links_for_tokens(links: List[str], discovered: List[Tuple[str, str]]) -> None:
    """Check page links for JWT tokens in URL parameters.

    Args:
        links: List of link URLs
        discovered: Mutable list to append results
    """  # PURE (but mutates discovered list)
    for link in links:
        _check_single_link_for_tokens(link, discovered)


def _check_single_link_for_tokens(link: str, discovered: List[Tuple[str, str]]) -> None:
    """Check a single link for JWT tokens in URL parameters."""  # PURE
    p_link = urlparse(link)
    l_params = parse_qs(p_link.query)
    for val_list in l_params.values():
        for val in val_list:
            if is_jwt(val):
                discovered.append((val, "link_param"))


def check_page_text_for_tokens(jwt_re, data: Dict, discovered: List[Tuple[str, str]]) -> None:
    """Check page text and HTML for JWT token strings.

    Args:
        jwt_re: Compiled regex pattern for JWT tokens
        data: Dict with 'text' and 'html' keys
        discovered: Mutable list to append results
    """  # PURE
    matches = jwt_re.findall(data.get('text', '')) + jwt_re.findall(data.get('html', ''))
    for m in matches:
        if is_jwt(m):
            discovered.append((m, "body_text"))


async def check_page_content_for_tokens(page, jwt_re, discovered: List[Tuple[str, str]]) -> None:
    """Check page links and text for JWT tokens.

    Args:
        page: Playwright page object
        jwt_re: Compiled JWT regex
        discovered: Mutable list to append results
    """  # I/O
    data = await page.evaluate("""
        () => ({
            links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href),
            text: document.body.innerText,
            html: document.documentElement.innerHTML
        })
    """)

    check_page_links_for_tokens(data['links'], discovered)
    check_page_text_for_tokens(jwt_re, data, discovered)


async def check_storage_for_tokens(page, discovered: List[Tuple[str, str]]) -> None:
    """Check cookies and localStorage for JWT tokens.

    Args:
        page: Playwright page object
        discovered: Mutable list to append results
    """  # I/O
    cookies = await page.context.cookies()
    for cookie in cookies:
        if is_jwt(cookie['value']):
            discovered.append((cookie['value'], "cookie"))

    storage = await page.evaluate("() => JSON.stringify(localStorage)")
    storage_dict = json.loads(storage)
    for k, v in storage_dict.items():
        if isinstance(v, str) and is_jwt(v):
            discovered.append((v, "localStorage"))


async def scan_page_for_tokens(page, target_url: str, jwt_re, discovered: List[Tuple[str, str]]) -> None:
    """Scan a single page for JWT tokens in various locations.

    Args:
        page: Playwright page object
        target_url: URL to scan
        jwt_re: Compiled JWT regex
        discovered: Mutable list to append results
    """  # I/O
    try:
        auth_header_token = None

        async def handle_request(request):
            nonlocal auth_header_token
            auth = request.headers.get("authorization")
            if auth and "Bearer " in auth:
                t = auth.split("Bearer ")[1]
                if is_jwt(t):
                    auth_header_token = t

        page.on("request", handle_request)
        await page.goto(target_url, wait_until="networkidle", timeout=10000)

        await check_url_for_tokens(page.url, discovered)
        await check_page_content_for_tokens(page, jwt_re, discovered)
        await check_storage_for_tokens(page, discovered)

        if auth_header_token:
            discovered.append((auth_header_token, "header"))

    except Exception as e:
        logger.debug(f"Scan failed for {target_url}: {e}")


def deduplicate_tokens(discovered: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Remove duplicate tokens from discovered list.

    Args:
        discovered: List of (token, location) tuples

    Returns:
        Deduplicated list preserving first occurrence
    """  # PURE
    unique = {}
    for t, loc in discovered:
        if t not in unique:
            unique[t] = loc
    return list(unique.items())


async def discover_tokens(url: str) -> List[Tuple[str, str]]:
    """Use browser to find JWTs in URL, cookies, local storage, page links, and body text.

    Args:
        url: Target URL to discover tokens from

    Returns:
        Deduplicated list of (token, location) tuples
    """  # I/O
    from bugtrace.tools.visual.browser import browser_manager

    discovered = []
    jwt_re = re.compile(r'(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*)')

    await check_url_for_tokens(url, discovered)

    async with browser_manager.get_page() as page:
        await scan_page_for_tokens(page, url, jwt_re, discovered)

        if not discovered:
            root_url = get_root_url(url)
            if root_url:
                await scan_page_for_tokens(page, root_url, jwt_re, discovered)

    return deduplicate_tokens(discovered)


# =========================================================================
# Protected Endpoint Discovery (I/O)
# =========================================================================

async def get_protected_endpoints(
    source_url: str,
    report_dir,
    cached_endpoints: List[str],
    already_scanned: bool,
) -> Tuple[List[str], bool]:
    """Discover endpoints that require authentication (return 401/403).

    Args:
        source_url: Source URL to derive base URL from
        report_dir: Report directory Path (or None)
        cached_endpoints: Previously cached endpoints list
        already_scanned: Whether endpoints have already been scanned

    Returns:
        Tuple of (endpoints_list, scanned_flag)
    """  # I/O
    import aiohttp

    if already_scanned:
        return cached_endpoints, already_scanned

    parsed = urlparse(source_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    candidate_urls = set()

    # Read recon URLs if available
    if report_dir:
        from pathlib import Path
        urls_file = Path(report_dir) / "recon" / "urls.txt"
        if urls_file.exists():
            for line in urls_file.read_text().splitlines():
                line = line.strip()
                if not line:
                    continue
                lp = urlparse(line)
                path_lower = lp.path.lower()
                if any(p in path_lower for p in AUTH_PATTERNS):
                    candidate_urls.add(line.split("?")[0])

    # Also try common protected paths directly
    for pattern in AUTH_PATTERNS:
        candidate_urls.add(f"{base}/api{pattern}")
        candidate_urls.add(f"{base}{pattern}")

    # Test candidates for 401/403
    protected = []
    try:
        async with aiohttp.ClientSession() as clean_session:
            for curl in list(candidate_urls)[:20]:
                try:
                    async with clean_session.get(
                        curl,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False,
                    ) as resp:
                        if resp.status in (401, 403):
                            protected.append(curl)
                            logger.info(f"Found protected endpoint: {curl} ({resp.status})")
                            if len(protected) >= 3:
                                break
                except Exception:
                    continue
    except Exception:
        pass

    return protected, True


# =========================================================================
# App Name Extraction from Root Page (I/O)
# =========================================================================

async def extract_app_name_from_root(
    url: str,
    report_dir,
    cached_names: Optional[List[str]],
) -> List[str]:
    """Extract potential app names for JWT secret generation.

    Strategy order (short-circuit on cache hit):
    0. Check pre-fetched cache
    1. Check persisted app_names.json from report_dir
    2. Read recon data from disk (fast, no HTTP needed)
    3. Fetch root URL with retries + backoff
    4. If both empty, retry cache after delay
    5. Persist results to app_names.json

    Args:
        url: Target URL
        report_dir: Report directory Path (or None)
        cached_names: Previously cached names (or None)

    Returns:
        List of extracted name strings
    """  # I/O
    import aiohttp
    from pathlib import Path
    from bugtrace.agents.jwt.analysis import (
        extract_names_from_html,
        extract_names_from_recon_cache,
    )

    # Strategy 0: Return pre-fetched names if available
    if cached_names:
        return cached_names

    names = []

    # Strategy 1: Check persisted app_names.json
    if report_dir:
        cache_file = Path(report_dir) / "recon" / "app_names.json"
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if isinstance(cached, list) and cached:
                    logger.info(f"Loaded {len(cached)} app names from cache: {cached}")
                    return cached
            except Exception:
                pass

    # Strategy 2: Extract from recon data on disk
    if report_dir:
        names.extend(extract_names_from_recon_cache(report_dir))

    # Strategy 3: Fetch root page with retries + backoff
    parsed = urlparse(url)
    root_url = f"{parsed.scheme}://{parsed.netloc}/"
    timeouts = [8, 15, 25]

    for attempt, timeout_sec in enumerate(timeouts):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    root_url,
                    timeout=aiohttp.ClientTimeout(total=timeout_sec),
                    ssl=False,
                ) as resp:
                    text = await resp.text()
            names.extend(extract_names_from_html(text))
            break
        except Exception as e:
            logger.warning(f"Root page fetch attempt {attempt + 1}/{len(timeouts)} failed (timeout={timeout_sec}s): {e}")
            if attempt < len(timeouts) - 1:
                backoff = (attempt + 1) * 3
                await asyncio.sleep(backoff)

    # Strategy 4: Retry cache if nothing found yet
    if not names and report_dir:
        await asyncio.sleep(5)
        names.extend(extract_names_from_recon_cache(report_dir))

    # Deduplicate
    names = list(dict.fromkeys(names))

    # Strategy 5: Persist to app_names.json
    if names and report_dir:
        try:
            cache_file = Path(report_dir) / "recon" / "app_names.json"
            cache_file.parent.mkdir(parents=True, exist_ok=True)
            cache_file.write_text(json.dumps(names, indent=2), encoding="utf-8")
        except Exception:
            pass

    return names


__all__ = [
    "check_url_for_tokens",
    "check_page_links_for_tokens",
    "check_page_text_for_tokens",
    "check_page_content_for_tokens",
    "check_storage_for_tokens",
    "scan_page_for_tokens",
    "deduplicate_tokens",
    "discover_tokens",
    "get_protected_endpoints",
    "extract_app_name_from_root",
]
