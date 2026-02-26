"""
Pure parameter discovery functions.

These extract parameters from URLs and HTML without any I/O.
The I/O (fetching HTML via browser_manager) stays in the agent layer.

Extracted from the shared pattern across 11+ specialist agents:
- XSSAgent._discover_xss_params
- SQLiAgent._discover_sqli_params
- CSTIAgent._discover_csti_params
- LFIAgent._discover_lfi_params
- specialist_utils.extract_param_metadata (ground truth implementation)

All agents follow the same core flow:
1. Extract URL query parameters (pure)
2. Fetch HTML (I/O -- stays in agent)
3. Extract form inputs from HTML (pure)
4. Extract anchor href params (pure)
5. Filter/prioritize params (pure, agent-specific keywords)
"""

import re
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse


# =========================================================================
# DEFAULT EXCLUSION SETS
# =========================================================================

DEFAULT_EXCLUDED_PARAMS: FrozenSet[str] = frozenset({
    "csrf", "csrftoken", "csrf_token", "_csrf",
    "csrfmiddlewaretoken", "__requestverificationtoken",
    "authenticity_token", "antiforgery",
    "_token", "token",
})

# Parameters that are commonly non-injectable cache-busters / tracking IDs.
# Used by extract_js_params to skip noise in JavaScript URL patterns.
_JS_PARAM_SKIP: FrozenSet[str] = frozenset({
    "v", "ver", "version", "cb", "ts", "timestamp", "t", "hash",
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "nonce", "lang", "locale", "charset", "encoding",
})

# Non-testable HTML input types (buttons, not data inputs).
_SKIP_INPUT_TYPES: FrozenSet[str] = frozenset({
    "submit", "button", "reset",
})


# =========================================================================
# URL PARAMETER EXTRACTION
# =========================================================================

def extract_url_params(url: str) -> Dict[str, str]:
    """
    Extract query parameters from a URL.

    Pure function -- no I/O.

    Args:
        url: Target URL (e.g., "http://example.com/search?q=test&page=1")

    Returns:
        Dict mapping parameter names to their first value.
        Example: {"q": "test", "page": "1"}
    """
    result: Dict[str, str] = {}
    try:
        parsed = urlparse(url)
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            result[param_name] = values[0] if values else ""
    except Exception:
        pass
    return result


# =========================================================================
# HTML FORM PARAMETER EXTRACTION
# =========================================================================

def extract_form_params(
    html: str,
    base_url: str = "",
    exclude_csrf: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Extract parameters from HTML forms (<input>, <textarea>, <select>).

    Returns full metadata per parameter including HTTP method from the parent
    <form> element.  This is the deterministic ground truth for method
    detection -- no LLM involved.

    Pure function -- no I/O.

    Args:
        html: Raw HTML content of the page.
        base_url: Base URL for resolving relative form action attributes.
        exclude_csrf: If True, skip CSRF tokens and similar.

    Returns:
        Dict mapping param names to metadata dicts::

            {
                "searchFor": {
                    "method": "POST",
                    "action_url": "http://example.com/search.php",
                    "enctype": "application/x-www-form-urlencoded",
                    "source": "form_input",
                    "default_value": ""
                }
            }
    """
    from bs4 import BeautifulSoup

    metadata: Dict[str, Dict[str, Any]] = {}

    if not html:
        return metadata

    try:
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup.find_all(["input", "textarea", "select"]):
            param_name = tag.get("name")
            if not param_name:
                continue
            if param_name in metadata:
                continue  # First occurrence wins

            input_type = tag.get("type", "text").lower()
            if input_type in _SKIP_INPUT_TYPES:
                continue

            if exclude_csrf:
                name_lower = param_name.lower()
                if any(tok in name_lower for tok in ("csrf", "token")):
                    continue

            parent_form = tag.find_parent("form")
            if parent_form:
                form_method = (parent_form.get("method") or "GET").upper()
                form_action = parent_form.get("action", "")
                action_url = urljoin(base_url, form_action) if form_action else base_url
                form_enctype = parent_form.get("enctype", "application/x-www-form-urlencoded")
            else:
                form_method = "GET"
                action_url = base_url
                form_enctype = ""

            metadata[param_name] = {
                "method": form_method,
                "action_url": action_url,
                "enctype": form_enctype,
                "source": "form_input",
                "default_value": tag.get("value", ""),
            }

    except Exception:
        pass

    return metadata


# =========================================================================
# JAVASCRIPT PARAMETER EXTRACTION
# =========================================================================

def extract_js_params(html: str, base_url: str = "") -> Dict[str, str]:
    """
    Extract parameters referenced in JavaScript URL construction patterns.

    Catches SPA frameworks (React/Vue/Angular) that build URLs via JS
    instead of HTML forms. For example::

        window.location.href = `/?search=${encodeURIComponent(term)}`

    Also extracts simple JS variable assignments that might be user-controlled::

        var searchTerm = "USER_INPUT"

    Pure function -- no I/O.

    Args:
        html: Raw HTML content (including inline scripts).
        base_url: Base URL for building action_url metadata.

    Returns:
        Dict mapping param names to default values (usually empty string).
    """
    params: Dict[str, str] = {}

    if not html:
        return params

    parsed = urlparse(base_url) if base_url else None
    base_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed and parsed.scheme else ""
    base_path = parsed.path if parsed else ""

    # Pattern 1: URL query parameter patterns in JS/HTML (e.g., ?search= or &filter=)
    for match in re.finditer(r'[?&]([a-zA-Z_]\w{1,30})=', html):
        param_name = match.group(1)
        if param_name.lower() in _JS_PARAM_SKIP:
            continue
        if param_name not in params:
            params[param_name] = ""

    # Pattern 2: JavaScript variable assignments with string values
    # Catches: var searchTerm = "USER_INPUT"
    js_var_pattern = r'var\s+(\w+)\s*=\s*["\']([^"\']*)["\']'
    for match in re.finditer(js_var_pattern, html):
        var_name, var_value = match.groups()
        if var_name not in params and len(var_name) > 2:
            params[var_name] = var_value

    return params


# =========================================================================
# ANCHOR HREF PARAMETER EXTRACTION
# =========================================================================

def extract_anchor_params(
    html: str,
    base_url: str,
    exclude_csrf: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Extract parameters from anchor (<a>) href attributes.

    Only considers same-origin links. External links are skipped.

    Pure function -- no I/O.

    Args:
        html: Raw HTML content of the page.
        base_url: Base URL for resolving relative hrefs and filtering same-origin.
        exclude_csrf: If True, skip CSRF-like parameter names.

    Returns:
        Dict mapping param names to metadata dicts::

            {
                "artist": {
                    "method": "GET",
                    "action_url": "http://example.com/artists.php",
                    "enctype": "",
                    "source": "anchor_href",
                    "default_value": "1"
                }
            }
    """
    from bs4 import BeautifulSoup

    metadata: Dict[str, Dict[str, Any]] = {}

    if not html or not base_url:
        return metadata

    parsed_base = urlparse(base_url)
    base_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

    try:
        soup = BeautifulSoup(html, "html.parser")

        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                continue
            try:
                link = urljoin(base_url, href)
                parsed_link = urlparse(link)
                # Same-origin check
                if parsed_link.netloc and parsed_link.netloc != parsed_base.netloc:
                    continue
                link_params = parse_qs(parsed_link.query)
                for p_name, p_vals in link_params.items():
                    if p_name in metadata:
                        continue
                    if exclude_csrf and "csrf" in p_name.lower():
                        continue
                    metadata[p_name] = {
                        "method": "GET",
                        "action_url": f"{base_origin}{parsed_link.path}",
                        "enctype": "",
                        "source": "anchor_href",
                        "default_value": p_vals[0] if p_vals else "",
                    }
            except Exception:
                continue

    except Exception:
        pass

    return metadata


# =========================================================================
# INTERNAL URL DISCOVERY
# =========================================================================

def extract_internal_urls(
    html: str,
    base_url: str,
    max_urls: int = 10,
) -> List[str]:
    """
    Extract same-origin internal URLs from anchor tags.

    Used by agents (e.g., XSSAgent for DOM XSS coverage) to discover
    additional pages worth testing beyond the initially assigned URL.

    Pure function -- no I/O.

    Args:
        html: Raw HTML content of the page.
        base_url: Base URL for resolving relative hrefs.
        max_urls: Maximum number of internal URLs to return.

    Returns:
        List of unique internal URLs (without query strings), capped at max_urls.
    """
    from bs4 import BeautifulSoup

    if not html or not base_url:
        return []

    base_parsed = urlparse(base_url)
    base_domain = base_parsed.netloc
    base_no_query = base_url.split("?")[0]
    internal_urls: set = set()

    try:
        soup = BeautifulSoup(html, "html.parser")
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                continue
            link = urljoin(base_url, href)
            parsed_link = urlparse(link)
            if parsed_link.netloc == base_domain and parsed_link.scheme in ("http", "https"):
                clean_link = f"{parsed_link.scheme}://{parsed_link.netloc}{parsed_link.path}"
                if clean_link != base_no_query:
                    internal_urls.add(clean_link)
                    if len(internal_urls) >= max_urls:
                        break
    except Exception:
        pass

    return list(internal_urls)


# =========================================================================
# PARAMETER MERGING & METADATA
# =========================================================================

def extract_all_param_metadata(
    html: str,
    url: str,
    exclude_csrf: bool = True,
) -> Dict[str, Dict[str, Any]]:
    """
    Extract deterministic parameter metadata from HTML and URL.

    Combines URL query params, form inputs, anchor hrefs, and JS URL
    patterns into a single metadata dict. This is the unified ground truth
    that replaces ``specialist_utils.extract_param_metadata``.

    Pure function -- no I/O.

    Args:
        html: HTML content of the page.
        url: URL of the page (for query params and resolving relative URLs).
        exclude_csrf: If True, skip CSRF tokens.

    Returns:
        Dict mapping param names to metadata dicts with keys:
        method, action_url, enctype, source, default_value.
    """
    metadata: Dict[str, Dict[str, Any]] = {}
    parsed = urlparse(url)
    base_origin = f"{parsed.scheme}://{parsed.netloc}"

    # 1. URL query parameters (always GET, highest precedence)
    try:
        url_params = parse_qs(parsed.query)
        for param_name, values in url_params.items():
            metadata[param_name] = {
                "method": "GET",
                "action_url": f"{base_origin}{parsed.path}",
                "enctype": "",
                "source": "url_query",
                "default_value": values[0] if values else "",
            }
    except Exception:
        pass

    if not html:
        return metadata

    # 2. Form inputs (method from parent <form>)
    form_params = extract_form_params(html, url, exclude_csrf=exclude_csrf)
    for param_name, meta in form_params.items():
        if param_name not in metadata:
            metadata[param_name] = meta

    # 3. Anchor href params (always GET)
    anchor_params = extract_anchor_params(html, url, exclude_csrf=exclude_csrf)
    for param_name, meta in anchor_params.items():
        if param_name not in metadata:
            metadata[param_name] = meta

    # 4. JavaScript URL construction patterns
    js_params = extract_js_params(html, url)
    for param_name in js_params:
        if param_name not in metadata:
            if exclude_csrf and "csrf" in param_name.lower():
                continue
            metadata[param_name] = {
                "method": "GET",
                "action_url": f"{base_origin}{parsed.path}",
                "enctype": "",
                "source": "js_url_pattern",
                "default_value": js_params[param_name],
            }

    return metadata


def merge_params(*param_dicts: Dict[str, Any]) -> Dict[str, str]:
    """
    Merge multiple parameter dicts, deduplicating by name.

    Earlier dicts take precedence -- if a param appears in dict 1 and
    dict 3, the value from dict 1 is kept.

    Pure function.

    Args:
        *param_dicts: Variable number of dicts mapping param names to values.
                      Values can be strings or metadata dicts (in which case
                      ``default_value`` is extracted).

    Returns:
        Flat dict mapping param names to string default values.
    """
    merged: Dict[str, str] = {}
    for d in param_dicts:
        for name, value in d.items():
            if name not in merged:
                if isinstance(value, dict):
                    merged[name] = value.get("default_value", "")
                else:
                    merged[name] = str(value)
    return merged


# =========================================================================
# PARAMETER FILTERING
# =========================================================================

def filter_excluded_params(
    params: Dict[str, str],
    excluded: Optional[Set[str]] = None,
) -> Dict[str, str]:
    """
    Remove CSRF tokens, submit buttons, and other non-testable parameters.

    Pure function.

    Args:
        params: Dict mapping param names to values.
        excluded: Set of lowercase param names to exclude.
                  If None, uses DEFAULT_EXCLUDED_PARAMS.

    Returns:
        Filtered dict with excluded params removed.
    """
    if excluded is None:
        excluded = DEFAULT_EXCLUDED_PARAMS

    return {
        name: value
        for name, value in params.items()
        if name.lower() not in excluded
    }


# =========================================================================
# PARAMETER PRIORITIZATION
# =========================================================================

def prioritize_params(
    params: List[str],
    high_priority: Optional[List[str]] = None,
    medium_priority: Optional[List[str]] = None,
) -> List[str]:
    """
    Sort parameters by likelihood of vulnerability.

    Parameters whose names match high-priority keywords come first,
    then medium-priority, then the rest.

    Pure function.

    Args:
        params: List of parameter names to sort.
        high_priority: Keywords that indicate high likelihood of injection.
                       Match is case-insensitive substring (either direction).
                       If None, a generic default set is used.
        medium_priority: Keywords for medium likelihood.
                         If None, a generic default set is used.

    Returns:
        Sorted list of parameter names (high -> medium -> low priority).
    """
    if high_priority is None:
        high_priority = [
            "id", "user_id", "userid", "product_id", "productid",
            "item_id", "itemid", "order_id", "orderid",
            "search", "q", "query", "filter", "keyword", "term",
            "sort", "order", "orderby", "sortby",
            "name", "title", "type", "action", "view",
            "file", "path", "template", "page", "document",
            "username", "user", "email", "login",
        ]
    if medium_priority is None:
        medium_priority = [
            "date", "from", "to", "start", "end",
            "price", "amount", "qty", "quantity",
            "lang", "language", "locale",
            "format", "output", "theme", "style",
        ]

    high: List[str] = []
    medium: List[str] = []
    low: List[str] = []

    for param in params:
        param_lower = (param or "").lower()

        is_high = any(
            hp == param_lower or hp in param_lower or param_lower in hp
            for hp in high_priority
        )
        is_medium = any(
            mp == param_lower or mp in param_lower
            for mp in medium_priority
        )

        if is_high:
            high.append(param)
        elif is_medium:
            medium.append(param)
        else:
            low.append(param)

    return high + medium + low
