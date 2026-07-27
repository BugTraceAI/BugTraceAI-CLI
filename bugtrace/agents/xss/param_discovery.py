"""
XSS-specific parameter discovery and prioritization.

Combines shared discovery with XSS-specific prioritization logic.
Includes the full discovery pipeline that extracts parameters from
URL query strings, HTML forms, JavaScript variables, and internal links.

Extracted from xss_agent.py:
- _discover_params (line 8155) -> discover_params (I/O)
- _prioritize_params (line 8229) -> prioritize_xss_params (PURE)
- _discover_xss_params (line 3601) -> discover_xss_params_full (I/O)
- HIGH_PRIORITY_PARAMS constant (line 8207)
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urljoin

from bs4 import BeautifulSoup

from bugtrace.utils.logger import get_logger
from bugtrace.core.ui import dashboard
from bugtrace.core.http_manager import http_manager, ConnectionProfile

logger = get_logger("agents.xss.param_discovery")


# =========================================================================
# CONSTANTS
# =========================================================================

# Parameters historically more prone to XSS (ordered by likelihood)
HIGH_PRIORITY_PARAMS = [
    # Search/Query - Most common XSS vectors
    "q", "query", "search", "s", "keyword", "keywords", "term", "terms",
    # Common GET params that Burp tests
    "category", "filter", "sort", "type", "action", "mode", "tab",
    # Redirect/URL - Often unvalidated
    "url", "redirect", "redirect_url", "return", "return_url", "returnUrl",
    "next", "goto", "destination", "dest", "target", "redir", "redirect_to",
    "continue", "forward", "ref", "referrer",
    # Callback/JSONP - JavaScript context
    "callback", "cb", "jsonp", "jsonpcallback", "call",
    # Input/Display - User-facing content
    "input", "text", "value", "data", "content", "body", "message", "msg",
    "name", "username", "user", "email", "title", "subject", "comment",
    # File/Path - Sometimes reflected
    "file", "filename", "path", "page", "view", "template",
    # Error/Debug - Often reflected in error messages
    "error", "err", "debug", "msg", "message", "alert",
    # ID/Reference - Sometimes used in display
    "id", "item", "product", "article", "post",
]

# Common vulnerable parameters to aggressively test even if not discovered
COMMON_VULN_PARAMS = [
    "category", "search", "q", "query", "filter", "sort",
    "template", "view", "page", "lang", "theme", "type", "action", "mode", "tab",
]


# =========================================================================
# PARAMETER PRIORITIZATION (PURE)
# =========================================================================

def prioritize_xss_params(
    params: List[str],
    high_priority_list: List[str] = None,
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Sort parameters by XSS likelihood - high-value first.

    Categorizes parameters into high/medium/low priority buckets:
    - High: Known XSS-prone names (search, callback, redirect, etc.)
    - Low: Numeric/pagination params (id, num, count, page, size, etc.)
    - Medium: Everything else

    PURE function (logging is informational only).

    Args:
        params: List of parameter names to prioritize.
        high_priority_list: Custom high priority list. If None, uses
            HIGH_PRIORITY_PARAMS constant.
        agent_name: Agent name for logging.

    Returns:
        Prioritized list: high_priority + medium_priority + low_priority.
    """
    if high_priority_list is None:
        high_priority_list = HIGH_PRIORITY_PARAMS

    high_priority = []
    medium_priority = []
    low_priority = []

    for param in params:
        param_lower = param.lower()

        # Check if it's a high-priority param
        is_high = False
        for hp in high_priority_list:
            if hp in param_lower or param_lower in hp:
                is_high = True
                break

        if is_high:
            high_priority.append(param)
        elif any(
            x in param_lower
            for x in ["id", "num", "count", "page", "size", "limit", "offset"]
        ):
            # Numeric params are usually less vulnerable
            low_priority.append(param)
        else:
            medium_priority.append(param)

    prioritized = high_priority + medium_priority + low_priority

    if high_priority:
        logger.info(f"[{agent_name}] High-priority params detected: {high_priority}")
        dashboard.log(
            f"[{agent_name}] Testing high-priority params first: "
            f"{', '.join(high_priority[:5])}",
            "INFO",
        )

    return prioritized


# =========================================================================
# SIMPLE DISCOVERY (I/O)
# =========================================================================

async def discover_params(
    url: str,
    agent_name: str = "XSSAgent",
) -> List[str]:
    """
    Discover injectable parameters from the page.

    Extracts parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select)
    3. Common vulnerable parameter names (aggressive fuzzing)

    Then prioritizes them for testing.

    I/O function - makes HTTP requests.

    Args:
        url: Target URL to discover parameters from.
        agent_name: Agent name for logging.

    Returns:
        Prioritized list of parameter names.
    """
    discovered = []

    # 1. Extract from URL
    parsed = urlparse(url)
    for param in parse_qs(parsed.query).keys():
        discovered.append(param)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    }

    # 2. Extract from HTML forms
    try:
        async with http_manager.session(ConnectionProfile.STANDARD) as session:
            async with session.get(url, headers=headers, ssl=False) as resp:
                html = await resp.text()

        soup = BeautifulSoup(html, 'html.parser')

        for inp in soup.find_all(['input', 'textarea', 'select']):
            name = inp.get('name')
            if name and name not in discovered:
                discovered.append(name)

    except Exception as e:
        logger.warning(f"Param discovery error: {e}")

    # 3. Aggressively add common vulnerable parameters
    for param in COMMON_VULN_PARAMS:
        if param not in discovered:
            discovered.append(param)
            logger.debug(
                f"[{agent_name}] Added common vuln parameter for fuzzed testing: {param}"
            )

    # Prioritize parameters (high-value first)
    return prioritize_xss_params(discovered, agent_name=agent_name)


# =========================================================================
# FULL XSS DISCOVERY (I/O)
# =========================================================================

async def discover_xss_params_full(
    url: str,
    browser_manager=None,
    extract_param_metadata_fn=None,
    agent_name: str = "XSSAgent",
) -> Dict:
    """
    Full XSS-focused parameter discovery for a given URL.

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (via centralized metadata extraction)
    3. JavaScript variables (var x = "USER_INPUT")
    4. Internal links for DOM XSS coverage

    I/O function - uses browser manager and filesystem.

    Args:
        url: Target URL to discover parameters from.
        browser_manager: Browser manager for HTML fetching. If None, skips HTML.
        extract_param_metadata_fn: Function for centralized param metadata extraction.
            Signature: (html: str, url: str) -> Dict[str, Dict]
        agent_name: Agent name for logging.

    Returns:
        Dict with keys:
            - all_params: Dict[str, str] mapping param names to default values
            - param_methods: Dict[str, str] mapping param names to HTTP method
            - param_metadata: Dict[str, Dict] full metadata per param
            - internal_urls: List[str] discovered internal URLs
            - html: str the fetched HTML (for caching)
    """
    all_params = {}
    param_methods = {}
    param_metadata = {}
    internal_urls = []
    html = ""

    # 1. Extract URL params even without HTML
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            all_params[param_name] = values[0] if values else ""
            param_methods[param_name] = "GET"
    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to parse URL params: {e}")

    # 2-3. Fetch HTML and extract form + JS params
    if browser_manager:
        try:
            state = await browser_manager.capture_state(url)
            html = state.get("html", "")
        except Exception as e:
            logger.warning(f"[{agent_name}] Failed to fetch HTML: {e}")
            html = ""

    if html:
        # Centralized metadata extraction (deterministic ground truth)
        if extract_param_metadata_fn:
            param_metadata = extract_param_metadata_fn(html, url)
            for param_name, meta in param_metadata.items():
                if param_name not in all_params:
                    all_params[param_name] = meta.get("default_value", "")
                param_methods[param_name] = meta["method"]

        # 4. XSS-specific: Extract JavaScript variables
        try:
            js_var_pattern = r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']'
            for match in re.finditer(js_var_pattern, html):
                var_name, var_value = match.groups()
                if var_name not in all_params and len(var_name) > 2:
                    all_params[var_name] = var_value
        except Exception:
            pass

        # 5. XSS-specific: Extract internal links for DOM XSS coverage
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_domain = urlparse(url).netloc
            internal_url_set = set()
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"]
                if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                    continue
                link = urljoin(url, href)
                parsed_link = urlparse(link)
                if (
                    parsed_link.netloc == base_domain
                    and parsed_link.scheme in ("http", "https")
                ):
                    clean_link = (
                        f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                    )
                    if clean_link != url.split("?")[0]:
                        internal_url_set.add(clean_link)
            internal_urls = list(internal_url_set)[:3]
            if internal_urls:
                logger.info(
                    f"[{agent_name}] Discovered {len(internal_urls)} "
                    f"internal URLs for DOM XSS"
                )
        except Exception:
            pass

    # Log detected methods
    post_params = [p for p, m in param_methods.items() if m == "POST"]
    if post_params:
        logger.info(f"[{agent_name}] POST params detected: {post_params}")

    logger.info(
        f"[{agent_name}] Discovered {len(all_params)} params on {url}: "
        f"{list(all_params.keys())}"
    )

    return {
        "all_params": all_params,
        "param_methods": param_methods,
        "param_metadata": param_metadata,
        "internal_urls": internal_urls,
        "html": html,
    }


__all__ = [
    # Constants
    "HIGH_PRIORITY_PARAMS",
    "COMMON_VULN_PARAMS",
    # Pure
    "prioritize_xss_params",
    # I/O
    "discover_params",
    "discover_xss_params_full",
]
