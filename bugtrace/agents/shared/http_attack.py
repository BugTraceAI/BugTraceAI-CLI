"""
Pure URL-building functions for attack payloads.

These functions construct URLs with injected payloads for security testing.
All functions are pure — they take explicit parameters and return strings
with no side effects or dependency on instance state.

Extracted from xss_agent.py to be reusable across agents.
"""
import urllib.parse
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote


def encode_for_url(payload: str) -> str:
    """
    URL-encode a payload string, escaping all special characters.

    Args:
        payload: Raw payload string.

    Returns:
        Percent-encoded payload with no safe characters.
    """
    return quote(payload, safe="")


def build_attack_url(base_url: str, param: str, payload: str) -> str:
    """
    Build an attack URL by injecting a payload into a query parameter.

    Parses the base URL, replaces (or adds) the specified parameter with the
    payload, and reassembles the URL. Multi-value parameters are collapsed to
    their first value before replacement.

    Args:
        base_url: The original target URL (may already have query parameters).
        param: The query parameter name to inject into.
        payload: The payload string to set as the parameter value.

    Returns:
        A fully-assembled URL string with the payload injected and URL-encoded.
    """
    parsed = urlparse(base_url)
    params = {
        k: v[0] if isinstance(v, list) else v
        for k, v in parse_qs(parsed.query).items()
    }
    params[param] = payload

    return urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(params),
        parsed.fragment,
    ))


def build_exploit_url(
    url: str, param: str, payload: str, encoded: bool = False
) -> str:
    """
    Build an exploit URL suitable for PoC reproduction.

    When encoded=True, the URL keeps standard percent-encoding (safe for
    copy-paste into a browser). When encoded=False, the URL is unquoted so
    the raw payload characters are visible (useful for reports).

    Args:
        url: The original target URL.
        param: The query parameter to inject into.
        payload: The payload string.
        encoded: If True, keep URL-encoded form. If False, unquote for readability.

    Returns:
        The assembled URL with the payload injected.
    """
    parsed = urllib.parse.urlparse(url)
    qs = urllib.parse.parse_qs(parsed.query)
    qs[param] = [payload]
    new_query = urllib.parse.urlencode(qs, doseq=True)
    full_url = urllib.parse.urlunparse((
        parsed.scheme, parsed.netloc, parsed.path, "", new_query, ""
    ))
    if not encoded:
        return urllib.parse.unquote(full_url)
    return full_url


def fragment_build_url(base_url: str, payload: str) -> str:
    """
    Build a fragment URL with the payload in the hash portion.

    Fragment-based payloads bypass server-side WAFs because the fragment
    (everything after #) is never sent to the server. Useful for testing
    DOM XSS via location.hash sinks.

    Args:
        base_url: The original target URL.
        payload: The payload to place in the URL fragment.

    Returns:
        URL with the payload appended as a fragment (after #).
    """
    parsed = urlparse(base_url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{payload}"
