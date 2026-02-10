"""
XSS Agent Discovery Module

Autonomous parameter discovery for XSS testing.
Extracts parameters from URL query strings, HTML forms, and JavaScript variables.

Architecture Note:
    Specialists must be AUTONOMOUS - they discover their own attack surface.
    The finding from DASTySAST is just a "signal" that the URL is interesting.
    We IGNORE the specific parameter and test ALL discoverable params.
"""

import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup

from bugtrace.utils.logger import get_logger

logger = get_logger("agents.xss.discovery")


# Parameters to always exclude (security tokens, submit buttons)
EXCLUDED_PARAM_PATTERNS = [
    "csrf",
    "token",
    "_token",
    "authenticity",
    "nonce",
]

EXCLUDED_INPUT_TYPES = ["submit", "button", "reset", "image"]


async def discover_xss_params(
    url: str,
    browser_manager=None,
    agent_name: str = "XSSAgent"
) -> Dict[str, str]:
    """
    XSS-focused parameter discovery for a given URL.

    Extracts ALL testable parameters from:
    1. URL query string
    2. HTML forms (input, textarea, select)
    3. JavaScript variables (var x = "USER_INPUT")

    Args:
        url: Target URL to discover parameters from
        browser_manager: Optional browser manager for HTML fetching
        agent_name: Name of the calling agent (for logging)

    Returns:
        Dict mapping param names to default values
        Example: {"category": "Juice", "searchTerm": "", "filter": ""}
    """
    all_params = {}

    # 1. Extract URL query parameters
    all_params.update(_extract_url_params(url, agent_name))

    # 2. Fetch HTML and extract form parameters + JS variables
    if browser_manager:
        html_params = await _extract_html_params(url, browser_manager, agent_name)
        all_params.update(html_params)

    logger.info(
        f"[{agent_name}] Discovered {len(all_params)} params on {url}: "
        f"{list(all_params.keys())}"
    )
    return all_params


def _extract_url_params(url: str, agent_name: str) -> Dict[str, str]:
    """Extract parameters from URL query string."""
    params = {}
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            params[param_name] = values[0] if values else ""
    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to parse URL params: {e}")
    return params


async def _extract_html_params(
    url: str,
    browser_manager,
    agent_name: str
) -> Dict[str, str]:
    """Extract parameters from HTML forms and JavaScript variables."""
    params = {}

    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if not html:
            return params

        soup = BeautifulSoup(html, "html.parser")

        # Extract from <input>, <textarea>, <select> with name attribute
        params.update(_extract_form_params(soup))

        # Extract JavaScript variables
        params.update(_extract_js_variables(html))

    except Exception as e:
        logger.warning(f"[{agent_name}] Failed to extract HTML/JS params: {e}")

    return params


def _extract_form_params(soup: BeautifulSoup) -> Dict[str, str]:
    """Extract parameters from HTML form elements."""
    params = {}

    for tag in soup.find_all(["input", "textarea", "select"]):
        param_name = tag.get("name")
        if not param_name:
            continue

        # Skip if already extracted or is excluded type
        input_type = tag.get("type", "text").lower()
        if input_type in EXCLUDED_INPUT_TYPES:
            continue

        # Skip CSRF tokens and security-related fields
        if _is_excluded_param(param_name):
            continue

        # Get default value
        default_value = tag.get("value", "")
        params[param_name] = default_value

    return params


def _extract_js_variables(html: str) -> Dict[str, str]:
    """
    Extract JavaScript variables that might contain user input.

    Looks for patterns like:
    - var searchText = 'USER_INPUT';
    - const query = "USER_INPUT";
    - let term = `USER_INPUT`;
    """
    params = {}

    # Pattern for var/const/let assignments
    js_var_pattern = r'(?:var|const|let)\s+(\w+)\s*=\s*["\']([^"\']*)["\']'

    for match in re.finditer(js_var_pattern, html):
        var_name, var_value = match.groups()
        # Only add if looks like user input (reasonable length name)
        if len(var_name) > 2 and not var_name.startswith("_"):
            params[var_name] = var_value

    return params


def _is_excluded_param(param_name: str) -> bool:
    """Check if parameter should be excluded from testing."""
    param_lower = param_name.lower()
    return any(pattern in param_lower for pattern in EXCLUDED_PARAM_PATTERNS)


def extract_params_from_html(html: str) -> List[str]:
    """
    Quick extraction of parameter names from HTML forms.

    Utility function for when you don't need values, just names.

    Args:
        html: HTML content to parse

    Returns:
        List of parameter names found in forms
    """
    try:
        soup = BeautifulSoup(html, "html.parser")
        params = []

        for tag in soup.find_all(["input", "textarea", "select"]):
            param_name = tag.get("name")
            if param_name and not _is_excluded_param(param_name):
                input_type = tag.get("type", "text").lower()
                if input_type not in EXCLUDED_INPUT_TYPES:
                    params.append(param_name)

        return list(set(params))  # Deduplicate
    except Exception:
        return []


__all__ = [
    "discover_xss_params",
    "extract_params_from_html",
    "EXCLUDED_PARAM_PATTERNS",
    "EXCLUDED_INPUT_TYPES",
]
