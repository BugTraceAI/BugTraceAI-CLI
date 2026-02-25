"""
PURE functions for Open Redirect vector detection and analysis.

All functions depend only on their arguments.  No network I/O.
"""
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs

from bugtrace.agents.openredirect_payloads import (
    REDIRECT_PARAMS, PATH_PATTERNS, JS_REDIRECT_PATTERNS,
    META_REFRESH_PATTERN, DEFAULT_ATTACKER_DOMAIN,
)
from bugtrace.core.validation_status import ValidationStatus


# =========================================================================
# Vector discovery (PURE)
# =========================================================================

def discover_param_vectors(
    url: str, agent_params: List[str] = None,
) -> List[Dict]:
    """
    Discover redirect vectors in query parameters.

    Checks existing URL parameters against known redirect parameter names
    and heuristic keyword matching.

    Args:
        url:          Target URL.
        agent_params: Additional params provided to the agent.

    Returns:
        List of vector dicts with ``type``, ``param``, ``source``, etc.
    """  # PURE
    vectors: List[Dict] = []
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)

    for param in existing_params.keys():
        param_lower = param.lower()

        for redirect_param in REDIRECT_PARAMS:
            if param_lower == redirect_param.lower():
                vectors.append({
                    "type": "QUERY_PARAM",
                    "param": param,
                    "value": existing_params[param][0] if existing_params[param] else "",
                    "source": "URL_EXISTING",
                    "confidence": "HIGH",
                })
                break

        if not any(v["param"] == param for v in vectors):
            keywords = [
                "redirect", "url", "next", "return", "goto",
                "dest", "redir", "callback", "continue",
            ]
            for keyword in keywords:
                if keyword in param_lower:
                    vectors.append({
                        "type": "QUERY_PARAM",
                        "param": param,
                        "value": existing_params[param][0] if existing_params[param] else "",
                        "source": "URL_HEURISTIC",
                        "confidence": "MEDIUM",
                    })
                    break

    if agent_params:
        for param in agent_params:
            if not any(v["param"] == param for v in vectors):
                vectors.append({
                    "type": "QUERY_PARAM",
                    "param": param,
                    "value": "",
                    "source": "AGENT_INPUT",
                    "confidence": "HIGH",
                })

    return vectors


def discover_path_vectors(url: str) -> List[Dict]:
    """
    Discover redirect vectors in URL path segments.

    Args:
        url: Target URL.

    Returns:
        List of vector dicts.
    """  # PURE
    vectors: List[Dict] = []
    parsed = urlparse(url)
    path = parsed.path.lower()

    for pattern in PATH_PATTERNS:
        if pattern.rstrip("?/") in path:
            vectors.append({
                "type": "PATH",
                "param": None,
                "path": parsed.path,
                "pattern_matched": pattern,
                "source": "URL_PATH",
                "confidence": "MEDIUM",
            })
            break

    return vectors


# =========================================================================
# Content analysis (PURE)
# =========================================================================

def analyze_javascript_redirects(html_content: str) -> List[Dict]:
    """
    Analyse HTML for JavaScript-based redirect patterns.

    Args:
        html_content: Raw HTML.

    Returns:
        List of JS redirect vector dicts.
    """  # PURE
    vectors: List[Dict] = []

    for pattern_info in JS_REDIRECT_PATTERNS:
        pattern = pattern_info["pattern"]
        name = pattern_info["name"]

        matches = re.findall(pattern, html_content, re.IGNORECASE)
        for match in matches:
            redirect_url = match if isinstance(match, str) else match[0] if match else None
            if redirect_url:
                vectors.append({
                    "type": "JAVASCRIPT",
                    "param": None,
                    "redirect_url": redirect_url,
                    "pattern_name": name,
                    "source": "JS_ANALYSIS",
                    "confidence": "MEDIUM",
                })

    return vectors


def analyze_meta_refresh(html_content: str) -> List[Dict]:
    """
    Analyse HTML for ``<meta http-equiv="refresh">`` redirect tags.

    Args:
        html_content: Raw HTML.

    Returns:
        List of meta-refresh vector dicts.
    """  # PURE
    from bs4 import BeautifulSoup

    vectors: List[Dict] = []

    # Regex method
    matches = re.findall(META_REFRESH_PATTERN, html_content, re.IGNORECASE)
    for url in matches:
        vectors.append({
            "type": "META_REFRESH",
            "param": None,
            "redirect_url": url,
            "source": "META_TAG",
            "confidence": "HIGH",
        })

    # BeautifulSoup method
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        meta_tags = soup.find_all("meta", attrs={"http-equiv": re.compile(r"refresh", re.I)})
        for meta in meta_tags:
            content = meta.get("content", "")
            url_match = re.search(r"url\s*=\s*([^\s\"']+)", content, re.IGNORECASE)
            if url_match and not any(v.get("redirect_url") == url_match.group(1) for v in vectors):
                vectors.append({
                    "type": "META_REFRESH",
                    "param": None,
                    "redirect_url": url_match.group(1),
                    "source": "META_TAG_BS4",
                    "confidence": "HIGH",
                })
    except Exception:
        pass

    return vectors


# =========================================================================
# Redirect classification (PURE)
# =========================================================================

def is_external_redirect(
    location: str, payload: str, original_url: str,
) -> bool:
    """
    Determine whether a redirect Location is external (attacker-controlled).

    Args:
        location:     Redirect target URL (from Location header).
        payload:      Payload that was injected.
        original_url: The original trusted URL.

    Returns:
        True if the redirect is to an external domain.
    """  # PURE
    if not location:
        return False

    original_host = urlparse(original_url).netloc.lower()

    if location.startswith("//"):
        location = "https:" + location

    try:
        redirect_parsed = urlparse(location)
        redirect_host = redirect_parsed.netloc.lower()

        if not redirect_host:
            return False
        if redirect_host == original_host:
            return False
        if DEFAULT_ATTACKER_DOMAIN in redirect_host:
            return True
        if redirect_host and redirect_host != original_host:
            if not redirect_host.endswith("." + original_host):
                return True
    except Exception:
        pass

    return False


def get_technique_name(payload: str) -> str:
    """
    Map a payload string to a human-readable technique name.

    Args:
        payload: The exploit payload.

    Returns:
        Technique label string.
    """  # PURE
    if payload.startswith("//"):
        return "protocol_relative"
    if "@" in payload:
        return "whitelist_bypass_userinfo"
    if "%" in payload:
        return "encoding_bypass"
    if "javascript:" in payload.lower():
        return "javascript_protocol"
    if "data:" in payload.lower():
        return "data_uri"
    return "direct_url"


def analyze_http_redirect(
    vector: Dict, url: str,
) -> Optional[Dict]:
    """
    Analyse an existing HTTP redirect for exploitability.

    Args:
        vector: HTTP_REDIRECT vector dict.
        url:    Original page URL.

    Returns:
        Finding dict or None.
    """  # PURE
    location = vector.get("location", "")
    status_code = vector.get("status_code")

    original_host = urlparse(url).netloc.lower()
    redirect_parsed = urlparse(location)
    redirect_host = redirect_parsed.netloc.lower()

    if redirect_host and redirect_host != original_host:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        for param, values in params.items():
            for value in values:
                if value and value in location:
                    return {
                        "exploitable": True,
                        "type": "OPEN_REDIRECT",
                        "param": param,
                        "payload": value,
                        "tier": "existing",
                        "technique": "reflected_redirect",
                        "status_code": status_code,
                        "location": location,
                        "test_url": url,
                        "method": "HTTP_HEADER_REFLECTED",
                        "severity": "MEDIUM",
                        "http_request": f"GET {url}",
                        "http_response": f"HTTP/1.1 {status_code}\nLocation: {location}",
                    }

    return None


# =========================================================================
# Fingerprinting and validation status (PURE)
# =========================================================================

def generate_openredirect_fingerprint(url: str, parameter: str) -> tuple:
    """
    Generate a deduplication fingerprint for an Open Redirect finding.

    Args:
        url:       Target URL.
        parameter: Vulnerable parameter name.

    Returns:
        Tuple fingerprint.
    """  # PURE
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")
    return ("OPEN_REDIRECT", parsed.netloc, normalized_path, parameter.lower())


def fallback_fingerprint_dedup(
    wet_findings: List[Dict],
) -> List[Dict]:
    """
    Fingerprint-based deduplication fallback.

    Args:
        wet_findings: List of WET finding dicts.

    Returns:
        Deduplicated list.
    """  # PURE
    seen: set = set()
    dry_list: List[Dict] = []
    for finding_data in wet_findings:
        url = finding_data.get("url", "")
        parameter = finding_data.get("parameter", "")
        if not url or not parameter:
            continue
        fp = generate_openredirect_fingerprint(url, parameter)
        if fp not in seen:
            seen.add(fp)
            dry_list.append(finding_data)
    return dry_list


def get_validation_status(evidence: Dict) -> str:
    """
    Determine tiered validation status for an Open Redirect finding.

    TIER 1 (VALIDATED_CONFIRMED):
        - Location header redirect to external domain.
        - Meta refresh redirect to external domain.
        - HTTP 3xx with external Location.

    TIER 2 (PENDING_VALIDATION):
        - JavaScript-based redirect.
        - Dynamic redirect patterns.

    Args:
        evidence: Evidence dict.

    Returns:
        Validation status string.
    """  # PURE
    if evidence.get("location_header_redirect"):
        return ValidationStatus.VALIDATED_CONFIRMED.value
    if evidence.get("meta_refresh_redirect"):
        return ValidationStatus.VALIDATED_CONFIRMED.value
    if evidence.get("status_code") in (301, 302, 303, 307, 308):
        if evidence.get("external_redirect"):
            return ValidationStatus.VALIDATED_CONFIRMED.value
    if evidence.get("js_redirect"):
        return ValidationStatus.PENDING_VALIDATION.value
    if evidence.get("dynamic_redirect"):
        return ValidationStatus.PENDING_VALIDATION.value
    return ValidationStatus.VALIDATED_CONFIRMED.value


def validate_before_emit(
    finding: Dict, parent_validate_fn,
) -> Tuple[bool, str]:
    """
    Open Redirect-specific pre-emit validation.

    Args:
        finding:           Finding dict.
        parent_validate_fn: Parent class ``_validate_before_emit`` callable.

    Returns:
        (is_valid, error_message) tuple.
    """  # PURE
    is_valid, error = parent_validate_fn(finding)
    if not is_valid:
        return False, error

    nested = finding.get("finding", {})
    evidence = finding.get("evidence", nested.get("evidence", {}))
    status = finding.get("status", nested.get("status", ""))

    if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
        has_location = evidence.get("location_header") if isinstance(evidence, dict) else False
        has_js_redirect = evidence.get("js_redirect") if isinstance(evidence, dict) else False
        has_redirect = evidence.get("redirect_confirmed") if isinstance(evidence, dict) else False
        if not (has_location or has_js_redirect or has_redirect):
            return False, "Open Redirect requires proof: Location header, JS redirect, or redirect confirmed"

    payload = finding.get("payload", nested.get("payload", ""))
    redirect_markers = [
        "http://", "https://", "//", "javascript:", "@",
        "%2f%2f", "//evil.com", "redirect=",
    ]
    if payload and not any(m in str(payload).lower() for m in redirect_markers):
        return False, f"Open Redirect payload missing redirect patterns: {payload[:50]}"

    return True, ""
