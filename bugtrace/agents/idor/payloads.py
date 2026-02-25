"""
IDOR Payloads - Pure Functions

Pure functions for URL injection, path segment manipulation,
and ID value injection into requests.

All functions are PURE: no side effects, no self, data as parameters.
"""

import re
from typing import Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.agents.idor.types import PATH_INDICATORS


def inject_id(url: str, val: str, param_name: str, original_val: str) -> str:
    """Inject a test ID value into the appropriate location in the URL.

    Handles three injection modes:
    1. Path-based IDOR (original value found in path)
    2. Path parameter indicators (URL Path, template vars, etc.)
    3. Query-based IDOR (standard query parameter)

    Args:
        url: Target URL
        val: Test ID value to inject
        param_name: Parameter name
        original_val: Original parameter value

    Returns:
        Modified URL string with injected value
    """  # PURE
    parsed = urlparse(url)
    path = parsed.path

    # 0. Auto-extract original_val from URL path when empty
    if not original_val:
        segments = [s for s in path.split("/") if s]
        for seg in reversed(segments):
            if seg.isdigit():
                original_val = seg
                break

    # 1. Path-based IDOR -- original value found in path
    if original_val and str(original_val) in path:
        new_path = re.sub(
            rf'(^|/){re.escape(str(original_val))}(/|$)',
            rf'\g<1>{val}\g<2>',
            path,
        )
        return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))

    # 2. Path-based IDOR -- "URL Path" or template var params
    is_path_param = (
        param_name in PATH_INDICATORS
        or param_name.startswith(":")
        or (param_name.startswith("{") and param_name.endswith("}"))
        or re.search(r'(?i)\burl\s*path\b|\bpath\s*segment\b|\bin\s*path\b', param_name)
    )
    if is_path_param:
        segments = path.rstrip("/").split("/")
        replaced = False
        for i in range(len(segments) - 1, -1, -1):
            seg = segments[i]
            if not seg:
                continue
            if seg.startswith(":") or (seg.startswith("{") and seg.endswith("}")):
                segments[i] = str(val)
                replaced = True
                break
            if seg.isdigit():
                segments[i] = str(val)
                replaced = True
                break
        if not replaced:
            segments.append(str(val))
        new_path = "/".join(segments)
        return urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))

    # 3. Query-based IDOR
    q = parse_qs(parsed.query)
    q[param_name] = [val]
    new_query = urlencode(q, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, path, parsed.params, new_query, parsed.fragment))


def extract_path_id(url: str) -> Optional[str]:
    """Extract the last numeric ID from a URL path.

    Args:
        url: URL string

    Returns:
        Numeric ID string or None
    """  # PURE
    parsed = urlparse(url)
    segments = [s for s in parsed.path.split("/") if s]
    for seg in reversed(segments):
        if seg.isdigit():
            return seg
    return None


__all__ = [
    "inject_id",
    "extract_path_id",
]
