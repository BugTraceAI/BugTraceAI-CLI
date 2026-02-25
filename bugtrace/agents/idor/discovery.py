"""
IDOR Discovery - I/O Functions

Async functions for IDOR-specific parameter discovery from URL paths,
query strings, HTML forms, hidden inputs, and page content.

All functions are I/O: async, dependencies as explicit first params.
"""

import re
from typing import Dict, List
from urllib.parse import urlparse, parse_qs
from bugtrace.utils.logger import get_logger

from bugtrace.agents.idor.patterns import is_id_param, is_id_value

logger = get_logger("agents.idor.discovery")


async def discover_idor_params(url: str) -> Dict[str, str]:
    """IDOR-focused parameter discovery.

    Extracts ALL testable parameters from:
    1. URL query string
    2. Path segments (/users/123 -> {"user_id": "123"})
    3. HTML forms (input, textarea, select)
    4. Hidden inputs with numeric/UUID values

    Priority: Numeric params, UUIDs, base64 strings, params ending in _id/Id/ID

    Args:
        url: Target URL to discover parameters from

    Returns:
        Dict mapping param names to default values
    """  # I/O
    from bugtrace.tools.visual.browser import browser_manager
    from bs4 import BeautifulSoup

    all_params = {}

    # 1. Extract URL query parameters
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            all_params[param_name] = values[0] if values else ""
    except Exception as e:
        logger.warning(f"Failed to parse URL params: {e}")

    # 2. Extract path segments (RESTful IDs)
    try:
        parsed = urlparse(url)
        path = parsed.path
        path_segments = [s for s in path.split('/') if s]

        for i, segment in enumerate(path_segments):
            # Numeric IDs
            if segment.isdigit():
                param_name = f"{path_segments[i-1]}_id" if i > 0 else "id"
                all_params[param_name] = segment
            # UUID-like segments
            elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment, re.I):
                param_name = f"{path_segments[i-1]}_id" if i > 0 else "resource_id"
                all_params[param_name] = segment
            # Hash-like segments (MD5/SHA1)
            elif re.match(r'^[a-f0-9]{32,40}$', segment, re.I):
                param_name = f"{path_segments[i-1]}_hash" if i > 0 else "hash"
                all_params[param_name] = segment
    except Exception as e:
        logger.warning(f"Path segment extraction failed: {e}")

    # 3. Fetch HTML and extract form parameters
    last_html = None
    try:
        state = await browser_manager.capture_state(url)
        html = state.get("html", "")

        if html:
            last_html = html
            soup = BeautifulSoup(html, "html.parser")

            for tag in soup.find_all(["input", "textarea", "select"]):
                param_name = tag.get("name")
                if param_name and param_name not in all_params:
                    input_type = tag.get("type", "text").lower()

                    if input_type not in ["submit", "button", "reset"]:
                        if "csrf" not in param_name.lower() and "token" not in param_name.lower():
                            default_value = tag.get("value", "")

                            if is_id_param(param_name) or is_id_value(default_value) or input_type == "hidden":
                                all_params[param_name] = default_value

    except Exception as e:
        logger.error(f"HTML parsing failed: {e}")

    logger.info(f"Discovered {len(all_params)} IDOR params on {url}: {list(all_params.keys())}")
    return all_params


__all__ = [
    "discover_idor_params",
]
