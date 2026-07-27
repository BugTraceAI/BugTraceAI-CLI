"""
GoSpider Core

PURE functions for URL filtering, scope checking, prioritization,
extension filtering, JavaScript URL extraction, and OpenAPI path resolution.

Extracted from gospider_agent.py for modularity.
"""

import re
from typing import List, Dict, Set, Optional, Any
from urllib.parse import urlparse, urljoin, parse_qs


# =============================================================================
# URL FILTERING (PURE)
# =============================================================================

def should_analyze_url(
    url: str,
    exclude_extensions: List[str],
    include_extensions: List[str],
) -> bool:  # PURE
    """
    Determines if a URL should be analyzed based on extension filtering.
    Excludes static files like .js, .css, .jpg, etc.

    Args:
        url: URL to check
        exclude_extensions: List of extensions to exclude (e.g., ['.js', '.css'])
        include_extensions: List of extensions to include (whitelist mode)

    Returns:
        True if URL should be analyzed
    """
    try:
        parsed = urlparse(url)
        path = parsed.path.lower()

        # Extract extension from path
        if '.' in path.split('/')[-1]:
            ext = '.' + path.rsplit('.', 1)[-1]
        else:
            ext = ''  # No extension (likely dynamic endpoint)

        # If include_extensions is set, only allow those
        if include_extensions:
            if ext and ext not in include_extensions:
                return False
            return True

        # Otherwise, exclude the excluded extensions
        if ext and ext in exclude_extensions:
            return False

        return True

    except Exception:
        return True  # If parsing fails, include the URL


# =============================================================================
# REACHABILITY GATE (PURE) — drop JS-mined phantom endpoints, keep everything real
# =============================================================================

# Only these statuses mean "this path does not exist as an endpoint". Everything
# else is treated as LIVE: 401/403 (auth-gated), 405 (wrong method), 429 (rate-limit),
# 5xx (server error — often the juiciest), and None (timeout/conn-error, unknown) are
# ALL kept, because dropping them would cost recall. Conservative by design.
NOT_FOUND_STATUSES = frozenset({404, 410})


def is_dead_endpoint(status: Optional[int]) -> bool:  # PURE
    """True only for definitively-not-found statuses (404/410).

    This is the whole recall-safety contract: a URL is dropped ONLY when the server
    positively says it isn't there. Unknown (None), auth-gated (401/403), method
    (405), rate-limited (429) and error (5xx) are never dead — they stay in scope.
    """
    return status in NOT_FOUND_STATUSES


def partition_by_reachability(
    url_status_pairs: List[Any],
) -> Any:  # PURE  -> Tuple[List[str], List[str]]
    """Split (url, status) pairs into (kept, dropped) using is_dead_endpoint.

    Structural, list-free replacement for hard-coded JS-artifact name filters: a
    phantom endpoint mined out of a JS bundle (e.g. react-dom/client, /M/d/yy,
    /MyComponent) answers 404 and is dropped; a real page (/catalog, /login) answers
    2xx/3xx/401/403 and is kept. Returns both lists so the caller can log the drops
    (no silent caps).
    """
    kept: List[str] = []
    dropped: List[str] = []
    for url, status in url_status_pairs:
        (dropped if is_dead_endpoint(status) else kept).append(url)
    return kept, dropped


# =============================================================================
# SCOPE CHECKING (PURE)
# =============================================================================

def is_in_scope(url: str, target_domain: str) -> bool:  # PURE
    """Check if URL is in scope (same domain).

    Args:
        url: URL to check
        target_domain: Target domain (hostname only, lowercase)

    Returns:
        True if URL is in scope
    """
    try:
        url_domain = urlparse(url).hostname
        if not url_domain:
            return False
        url_domain_lower = url_domain.lower()
        return url_domain_lower == target_domain or url_domain_lower.endswith('.' + target_domain)
    except Exception:
        return False


def is_same_origin(url: str, target_url: str) -> bool:  # PURE
    """Return whether two HTTP(S) URLs share scheme, host, and effective port."""
    try:
        parsed = urlparse(url)
        target = urlparse(target_url)
        if parsed.scheme not in {"http", "https"} or target.scheme not in {"http", "https"}:
            return False
        parsed_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        target_port = target.port or (443 if target.scheme == "https" else 80)
        return (
            parsed.scheme.lower() == target.scheme.lower()
            and (parsed.hostname or "").lower() == (target.hostname or "").lower()
            and parsed_port == target_port
        )
    except (TypeError, ValueError):
        return False


def is_javascript_asset_url(url: str) -> bool:  # PURE
    """Recognize external JavaScript assets without treating them as DAST targets."""
    try:
        return urlparse(url).path.lower().endswith((".js", ".mjs"))
    except (TypeError, ValueError):
        return False


# =============================================================================
# URL PRIORITIZATION AND FILTERING (PURE)
# =============================================================================

def filter_and_prioritize_urls(
    gospider_urls: List[str],
    target: str,
    max_urls: int,
    exclude_extensions: List[str],
    include_extensions: List[str],
    prioritizer_fn=None,
    dashboard=None,
    agent_name: str = "GoSpiderAgent",
) -> List[str]:  # PURE (with optional side-effect logging via dashboard)
    """Apply scoping, filtering, prioritization and limits to URLs.

    Args:
        gospider_urls: Raw discovered URLs
        target: Original target URL
        max_urls: Maximum number of URLs to return
        exclude_extensions: Extensions to exclude
        include_extensions: Extensions to include
        prioritizer_fn: Optional URL prioritization function
        dashboard: Optional dashboard for logging
        agent_name: Agent name for logging

    Returns:
        Filtered, prioritized, and limited URL list
    """
    if not gospider_urls:
        return []

    # Scope enforcement (same domain only)
    _hostname = urlparse(target).hostname
    if not _hostname:
        return []
    target_domain = _hostname.lower()
    scoped_urls = [
        u for u in gospider_urls
        if urlparse(u).hostname and urlparse(u).hostname.lower().endswith(target_domain)
    ]

    # Extension filtering (exclude static files)
    filtered_urls = [
        u for u in scoped_urls
        if should_analyze_url(u, exclude_extensions, include_extensions)
    ]
    excluded_count = len(scoped_urls) - len(filtered_urls)
    if excluded_count > 0 and dashboard:
        dashboard.log(f"[{agent_name}] Filtered out {excluded_count} static files (.js, .css, .jpg, etc.)", "INFO")

    # Prioritize and limit
    if prioritizer_fn:
        prioritized = prioritizer_fn(filtered_urls)
    else:
        prioritized = filtered_urls
    final_urls = prioritized[:max_urls]

    # Ensure target is always included and at the top
    if target in final_urls:
        final_urls.remove(target)
        final_urls.insert(0, target)
    else:
        # Target was not in top N, force insert it at top
        final_urls.insert(0, target)
        # Resizing to respect max_urls if we exceeded it
        if len(final_urls) > max_urls:
            final_urls.pop()  # Remove lowest priority URL

    return final_urls


# =============================================================================
# JAVASCRIPT URL EXTRACTION (PURE)
# =============================================================================

# Pattern: "/path?param=value" or '/path?param=value'
JS_URL_PATTERN = re.compile(r'["\'](/[^"\']*\?[^"\']+)["\']')
SCRIPT_SRC_PATTERN = re.compile(
    r"<script\b[^>]*\bsrc\s*=\s*([\"'])(.*?)\1",
    re.IGNORECASE | re.DOTALL,
)
# NOTE: the second alternative excludes backslash ([^\\], not `.`) so it never overlaps
# with `\\.` — an overlapping `.` here caused catastrophic backtracking (ReDoS) that hung
# the event loop on minified JS with long/unbalanced quoted strings.
JS_STRING_LITERAL = r"(?P<quote>[\"'`])(?P<url>(?:\\.|(?!(?P=quote))[^\\])*)(?P=quote)"
JS_ENDPOINT_PATTERNS = (
    re.compile(r"\bfetch\s*\(\s*" + JS_STRING_LITERAL, re.IGNORECASE),
    re.compile(r"\baxios\s*\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*" + JS_STRING_LITERAL, re.IGNORECASE),
    re.compile(r"\baxios\s*\(\s*" + JS_STRING_LITERAL, re.IGNORECASE),
    re.compile(r"\b(?:xhr|request|req)\w*\s*\.\s*open\s*\(\s*[\"'`][A-Z]+[\"'`]\s*,\s*" + JS_STRING_LITERAL, re.IGNORECASE),
    re.compile(r"\$\s*\.\s*(?:get|post)\s*\(\s*" + JS_STRING_LITERAL, re.IGNORECASE),
)
JS_STRING_LITERAL_PATTERN = re.compile(JS_STRING_LITERAL, re.IGNORECASE)
STATIC_ENDPOINT_EXTENSIONS = (
    ".js", ".mjs", ".css", ".map", ".jpg", ".jpeg", ".png", ".gif",
    ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip",
)


def extract_script_src_urls(html: str, page_url: str, target_url: str) -> List[str]:  # PURE
    """Extract unique same-origin external script URLs from HTML."""
    scripts: List[str] = []
    seen: Set[str] = set()
    for match in SCRIPT_SRC_PATTERN.finditer(html or ""):
        source = match.group(2).strip()
        if not source or source.startswith(("data:", "blob:", "javascript:")):
            continue
        absolute = urljoin(page_url, source).split("#", 1)[0]
        if not is_same_origin(absolute, target_url) or not is_javascript_asset_url(absolute):
            continue
        if absolute not in seen:
            seen.add(absolute)
            scripts.append(absolute)
    return scripts


def extract_endpoint_urls_from_js(
    js_text: str,
    target_url: str,
    max_endpoints: int = 1000,
    allow_relative: bool = False,
) -> Set[str]:  # PURE
    """Conservatively mine same-origin endpoint URLs from JavaScript source."""
    endpoints: Set[str] = set()
    limit = max(1, max_endpoints)

    def add_candidate(candidate: str, generic_literal: bool = False) -> None:
        value = candidate.strip().replace("\\/", "/")
        if not value or "${" in value or "\\" in value or value.startswith(("data:", "blob:", "javascript:", "//")):
            return
        is_relative_endpoint = value.startswith(("./api", "../api", "api/", "graphql", "rest/")) or re.match(r"^(?:\./|\.\./)?v\d+/", value, re.IGNORECASE)
        if is_relative_endpoint and not allow_relative:
            return
        is_generic_endpoint = bool(
            re.match(r"^/(?:api(?:/|\?|$)|graphql(?:\?|$)|rest(?:/|\?|$)|v\d+(?:/|\?|$))", value, re.IGNORECASE)
            or (value.startswith("/") and "?" in value)
            or value.startswith(("http://", "https://"))
        )
        if generic_literal and not is_generic_endpoint:
            return
        if not (value.startswith("/") or value.startswith("http://") or value.startswith("https://") or is_relative_endpoint):
            return
        absolute = urljoin(target_url, value).split("#", 1)[0]
        if not is_same_origin(absolute, target_url):
            return
        if urlparse(absolute).path.lower().endswith(STATIC_ENDPOINT_EXTENSIONS):
            return
        endpoints.add(absolute)

    for pattern in JS_ENDPOINT_PATTERNS:
        for match in pattern.finditer(js_text or ""):
            add_candidate(match.group("url"))
            if len(endpoints) >= limit:
                return endpoints
    for match in JS_STRING_LITERAL_PATTERN.finditer(js_text or ""):
        add_candidate(match.group("url"), generic_literal=True)
        if len(endpoints) >= limit:
            return endpoints
    return endpoints


def extract_js_urls(html: str, base_url: str, target_domain: str) -> Set[str]:  # PURE
    """Extract parameterized URLs from inline JavaScript.

    Args:
        html: HTML page content
        base_url: Base URL for resolving relative URLs
        target_domain: Target domain for scope checking

    Returns:
        Set of discovered URLs
    """
    urls = set()

    for match in JS_URL_PATTERN.finditer(html):
        relative_url = match.group(1)
        try:
            full_url = urljoin(base_url, relative_url)
            if is_in_scope(full_url, target_domain):
                urls.add(full_url)
        except Exception:
            pass

    return urls


# =============================================================================
# FORM PARAMETER EXTRACTION HELPERS (PURE)
# =============================================================================

# Input types and names to skip during form parameter extraction
SKIP_INPUT_TYPES = {'hidden', 'submit', 'button', 'image', 'reset'}
SKIP_INPUT_NAMES = {'csrf', 'token', '_token', 'csrfmiddlewaretoken'}

# Playwright mode uses shorter skip lists
SKIP_INPUT_TYPES_PW = {'hidden', 'submit', 'button'}
SKIP_INPUT_NAMES_PW = {'csrf', 'token', '_token'}


def build_param_url(action_url: str, param_name: str, fuzz_value: str = "FUZZ") -> str:  # PURE
    """Build a parameterized URL from action URL and parameter name.

    Args:
        action_url: Form action URL
        param_name: Parameter name
        fuzz_value: Value to use for the parameter

    Returns:
        URL with parameter appended
    """
    separator = "&" if "?" in action_url else "?"
    return f"{action_url}{separator}{param_name}={fuzz_value}"


def should_skip_input(
    name: Optional[str],
    inp_type: str,
    skip_types: Set[str] = None,
    skip_names: Set[str] = None,
) -> bool:  # PURE
    """Check if a form input should be skipped.

    Args:
        name: Input name attribute
        inp_type: Input type attribute
        skip_types: Set of input types to skip
        skip_names: Set of input names to skip

    Returns:
        True if input should be skipped
    """
    if not name:
        return True

    if skip_types is None:
        skip_types = SKIP_INPUT_TYPES
    if skip_names is None:
        skip_names = SKIP_INPUT_NAMES

    if inp_type.lower() in skip_types:
        return True
    if name.lower() in skip_names:
        return True

    return False


# =============================================================================
# OPENAPI PATH RESOLUTION (PURE)
# =============================================================================

# Well-known OpenAPI/Swagger spec paths
OPENAPI_SPEC_PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs",
    "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
    "/api/openapi.json", "/api/swagger.json",
    "/swagger/v1/swagger.json", "/docs/openapi.json",
]


def resolve_openapi_path(path_template: str, methods: dict) -> str:  # PURE
    """Replace OpenAPI path template variables with sample values.

    Args:
        path_template: Path with {param} placeholders
        methods: Method definitions from OpenAPI spec

    Returns:
        Resolved path with placeholder values
    """
    resolved = path_template
    # Find all {param_name} in path
    template_vars = re.findall(r'\{(\w+)\}', path_template)

    for var in template_vars:
        # Try to find example/default values in spec parameters
        sample = "1"  # Default: numeric ID
        for method_details in methods.values():
            if not isinstance(method_details, dict):
                continue
            for param in method_details.get("parameters", []):
                if isinstance(param, dict) and param.get("name") == var and param.get("in") == "path":
                    example = param.get("example") or param.get("default")
                    if example:
                        sample = str(example)
                    elif param.get("schema", {}).get("type") == "string":
                        sample = "test"
                    break

        resolved = resolved.replace(f"{{{var}}}", sample)

    return resolved


def extract_openapi_urls(
    spec_data: Dict,
    base_url: str,
    target_domain: str,
) -> Set[str]:  # PURE
    """Extract URLs from OpenAPI spec data.

    Args:
        spec_data: Parsed OpenAPI/Swagger JSON
        base_url: Base URL for the API
        target_domain: Target domain for scope checking

    Returns:
        Set of discovered API URLs
    """
    discovered = set()

    if not spec_data or "paths" not in spec_data:
        return discovered

    for path_template, methods in spec_data["paths"].items():
        if not isinstance(methods, dict):
            continue

        # Build concrete URL from path template
        concrete_path = resolve_openapi_path(path_template, methods)
        url = f"{base_url}{concrete_path}"

        if not is_in_scope(url, target_domain):
            continue

        discovered.add(url)

        # Extract query parameters defined in the spec
        for method, details in methods.items():
            if not isinstance(details, dict):
                continue
            params = details.get("parameters", [])
            for param in params:
                if not isinstance(param, dict):
                    continue
                if param.get("in") == "query" and param.get("name"):
                    param_url = build_param_url(url, param["name"], "test")
                    discovered.add(param_url)

    return discovered
