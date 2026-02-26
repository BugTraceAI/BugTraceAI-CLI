"""
Pure deduplication functions for vulnerability findings.

Extracted from the shared fingerprint-dedup pattern across 12 specialist agents:
- XSSAgent._fallback_fingerprint_dedup / _generate_xss_fingerprint
- SQLiAgent._fallback_fingerprint_dedup / _generate_sqli_fingerprint
- CSTIAgent._fallback_fingerprint_dedup / _generate_csti_fingerprint
- LFIAgent, RCEAgent, SSRFAgent, IDORAgent, JWTAgent, XXEAgent,
  OpenRedirectAgent, HeaderInjectionAgent, PrototypePollutionAgent

All agents follow the same core dedup pattern:
1. Generate a hashable fingerprint tuple from (vuln_type, url, param, context)
2. Track seen fingerprints in a set
3. Keep only the first finding per fingerprint

The fingerprint schema varies per vulnerability type (e.g., cookie SQLi is
global while URL-param SQLi is path-specific). This module provides the
shared scaffolding and the type-specific fingerprint generators as pure
functions.
"""

import hashlib
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# =========================================================================
# URL / PARAMETER NORMALIZATION
# =========================================================================

def normalize_url_for_dedup(url: str) -> Tuple[str, str]:
    """
    Normalize a URL for deduplication comparison.

    Strips fragments, trailing slashes, and returns (netloc, normalized_path).

    Pure function.

    Args:
        url: Target URL.

    Returns:
        Tuple of (netloc, normalized_path) for use in fingerprints.
    """
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")
    return (parsed.netloc, normalized_path)


def normalize_param_name(param: str) -> str:
    """
    Normalize parameter names for comparison.

    Converts camelCase and kebab-case to snake_case, lowercases.
    Examples: userId -> user_id, user-id -> user_id, User_ID -> user_id

    Pure function.

    Args:
        param: Parameter name.

    Returns:
        Normalized parameter name string.
    """
    # camelCase -> camel_Case
    name = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', param)
    # kebab-case -> kebab_case
    name = name.replace("-", "_")
    return name.lower()


# =========================================================================
# GENERIC FINGERPRINT + DEDUP
# =========================================================================

def generate_fingerprint(
    vuln_type: str,
    url: str,
    param: str,
    context: str = "",
) -> Tuple:
    """
    Generate a generic hashable fingerprint for deduplication.

    This is the simplest fingerprint form: (type, netloc, path, param).
    For vulnerability types that need specialized logic (e.g., cookie SQLi
    is global, XSS includes context), use the type-specific generators
    below.

    Pure function.

    Args:
        vuln_type: Vulnerability type string (e.g., "XSS", "SQLI", "LFI").
        url: Target URL.
        param: Parameter name.
        context: Optional context qualifier (e.g., "html_attribute").

    Returns:
        Hashable tuple fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)

    if context:
        return (vuln_type, netloc, normalized_path, param.lower(), context)
    return (vuln_type, netloc, normalized_path, param.lower())


def dedup_by_fingerprint(
    findings: List[Dict],
    fingerprint_fn: Optional[Callable[[Dict], Tuple]] = None,
) -> List[Dict]:
    """
    Deduplicate findings using a fingerprint function.

    Iterates through findings in order, keeping only the first occurrence
    of each fingerprint. This matches the exact behavior of all 12 agents'
    ``_fallback_fingerprint_dedup`` methods.

    Pure function.

    Args:
        findings: List of finding dicts.
        fingerprint_fn: A callable that takes a finding dict and returns
                        a hashable tuple. If None, uses a default that
                        creates (url, param, type) fingerprints.

    Returns:
        Deduplicated list of findings (order preserved, first wins).
    """
    if fingerprint_fn is None:
        fingerprint_fn = _default_fingerprint

    seen: Set[Tuple] = set()
    dry_list: List[Dict] = []

    for finding in findings:
        fp = fingerprint_fn(finding)
        if fp not in seen:
            seen.add(fp)
            dry_list.append(finding)

    return dry_list


def _default_fingerprint(finding: Dict) -> Tuple:
    """Default fingerprint: (type, netloc, path, param)."""
    url = finding.get("url", "")
    param = finding.get("parameter", "")
    vuln_type = finding.get("type", "UNKNOWN")
    netloc, normalized_path = normalize_url_for_dedup(url)
    return (vuln_type, netloc, normalized_path, param.lower())


# =========================================================================
# TYPE-SPECIFIC FINGERPRINT GENERATORS
# =========================================================================
# Each of these replaces the corresponding agent's _generate_*_fingerprint
# method as a free function with no `self` parameter.
# =========================================================================

def xss_fingerprint(
    url: str,
    parameter: str,
    context: str,
    sink: Optional[str] = None,
    source: Optional[str] = None,
) -> Tuple:
    """
    Generate XSS finding fingerprint for expert deduplication.

    XSS is URL-specific and parameter-specific, but the SAME XSS
    in the SAME parameter with different payloads = DUPLICATE.
    Different contexts in the same parameter = DISTINCT vulnerabilities.

    For global DOM XSS (e.g., postMessage->eval from shared JS), returns
    a root-cause fingerprint that groups findings across different URLs.

    Pure function. Replaces XSSAgent._generate_xss_fingerprint.

    Args:
        url: Target URL.
        parameter: Parameter name.
        context: Reflection context (e.g., "html_attribute", "script_tag", "dom_xss").
        sink: DOM sink (e.g., "eval", "innerHTML") -- for root cause detection.
        source: DOM source (e.g., "postMessage", "location.hash") -- for root cause detection.

    Returns:
        Hashable tuple fingerprint.
    """
    root_cause = _detect_xss_root_cause(url, parameter, context, sink=sink, source=source)
    if root_cause:
        netloc = urlparse(url).netloc
        return ("XSS_GLOBAL", netloc, root_cause, context)

    netloc, normalized_path = normalize_url_for_dedup(url)
    return ("XSS", netloc, normalized_path, parameter.lower(), context)


def _detect_xss_root_cause(
    url: str,
    parameter: str,
    context: str,
    sink: Optional[str] = None,
    source: Optional[str] = None,
) -> Optional[str]:
    """
    Detect if XSS is caused by a global vulnerability affecting multiple pages.

    Some DOM XSS vulnerabilities originate from shared JavaScript files that
    are loaded on every page (e.g., scanme.js with a postMessage->eval handler).
    These should be reported as ONE finding with affected_urls, not N separate
    findings.

    Pure function. Replaces XSSAgent._detect_xss_root_cause.

    Returns:
        Root cause identifier string if global, None if URL-specific.
    """
    # Pattern 1: postMessage -> eval (global event handler in shared JS)
    if parameter in ("postMessage", "window.postMessage") or source in ("postMessage", "window.postMessage"):
        sink_name = str(sink).lower() if sink else "unknown"
        if "eval" in sink_name:
            return "postMessage_eval_global"
        return f"postMessage_{sink_name}_global"

    # Pattern 2: location.search -> document.write (global searchLogger)
    if parameter == "location.search" and context == "dom_xss":
        if sink and "document.write" in str(sink).lower():
            return "location_search_docwrite_global"

    return None


def sqli_fingerprint(parameter: str, url: str) -> Tuple:
    """
    Generate SQLi finding fingerprint for expert deduplication.

    Cookie-based SQLi is GLOBAL (affects all URLs on the domain).
    Header-based SQLi is GLOBAL (same header = same vulnerability).
    URL/POST param SQLi is path-specific (different paths = different vulns).

    Pure function. Replaces SQLiAgent._generate_sqli_fingerprint.

    Args:
        parameter: Parameter name (may include prefix like "Cookie: TrackingId").
        url: Target URL.

    Returns:
        Hashable tuple fingerprint.
    """
    param_lower = parameter.lower()

    # Cookie-based SQLi: Global vulnerability (ignore URL path)
    if "cookie:" in param_lower:
        cookie_name = param_lower.split(":")[-1].strip()
        return ("SQLI", "cookie", cookie_name)

    # Header-based SQLi: Global vulnerability (ignore URL path)
    if "header:" in param_lower:
        header_name = param_lower.split(":")[-1].strip()
        return ("SQLI", "header", header_name)

    # URL/POST param: path-specific vulnerability
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")
    param_name = parameter.split(":")[-1].strip().lower()

    return ("SQLI", "param", parsed.netloc, normalized_path, param_name)


def csti_fingerprint(url: str, parameter: str, template_engine: str) -> Tuple:
    """
    Generate CSTI finding fingerprint for expert deduplication.

    Client-side engines (Angular, Vue, etc.) share a page-level scope,
    so multiple params on the same page = one vulnerability.
    Server-side engines are param-specific.

    Pure function. Replaces CSTIAgent._generate_csti_fingerprint.

    Args:
        url: Target URL.
        parameter: Parameter name.
        template_engine: Detected template engine (e.g., "angular", "jinja2").

    Returns:
        Hashable tuple fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)

    client_side_engines = {"angular", "vue", "knockout", "ember", "react"}
    is_client_side = template_engine.lower() in client_side_engines

    if is_client_side:
        # Same page + same engine = same scope = one finding
        return ("CSTI", netloc, normalized_path, template_engine)
    else:
        # Server-side: each parameter is a separate injection point
        return ("CSTI", netloc, normalized_path, parameter.lower(), template_engine)


def lfi_fingerprint(url: str, parameter: str) -> Tuple:
    """
    Generate LFI finding fingerprint for expert deduplication.

    LFI is URL-specific and parameter-specific.

    Pure function. Replaces LFIAgent._generate_lfi_fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)
    return ("LFI", netloc, normalized_path, parameter.lower())


def rce_fingerprint(url: str, parameter: str) -> Tuple:
    """
    Generate RCE finding fingerprint for expert deduplication.

    RCE is URL-specific and parameter-specific.

    Pure function. Replaces RCEAgent._generate_rce_fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)
    return ("RCE", netloc, normalized_path, parameter.lower())


def ssrf_fingerprint(url: str, parameter: str) -> Tuple:
    """
    Generate SSRF finding fingerprint for expert deduplication.

    SSRF to different callback domains from the same parameter = SAME
    vulnerability (just different proof). So payload is not part of
    the fingerprint.

    Pure function. Replaces SSRFAgent._generate_ssrf_fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)
    return ("SSRF", netloc, normalized_path, parameter.lower())


def idor_fingerprint(url: str, resource_type: str) -> Tuple:
    """
    Generate IDOR finding fingerprint for expert deduplication.

    IDOR is keyed on (endpoint, resource_type).

    Pure function. Replaces IDORAgent._generate_idor_fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)
    return ("IDOR", netloc, normalized_path, resource_type)


def jwt_fingerprint(
    url: str,
    vuln_type: str,
    token: Optional[str] = None,
) -> Tuple:
    """
    Generate JWT finding fingerprint for expert deduplication.

    JWT vulnerabilities are token-specific, not URL-specific.
    Different tokens on the same domain can have different vulnerabilities.

    Pure function. Replaces JWTAgent._generate_jwt_fingerprint.

    Args:
        url: Target URL.
        vuln_type: Vulnerability type (e.g., "none algorithm", "weak secret").
        token: JWT token string (optional, for accurate dedup via hash).

    Returns:
        Hashable tuple fingerprint.
    """
    netloc = urlparse(url).netloc

    if token:
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:8]
        return ("JWT", netloc, vuln_type, token_hash)
    else:
        return ("JWT", netloc, vuln_type)


def xxe_fingerprint(url: str) -> Tuple:
    """
    Generate XXE finding fingerprint for expert deduplication.

    XXE in XML endpoints is tied to the endpoint itself, not specific
    parameters. Multiple findings on the same XML endpoint are duplicates.

    Pure function. Replaces XXEAgent._generate_xxe_fingerprint.
    """
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")
    return (parsed.scheme, parsed.netloc, normalized_path, "XXE")


def openredirect_fingerprint(url: str, parameter: str) -> Tuple:
    """
    Generate Open Redirect finding fingerprint for expert deduplication.

    Pure function. Replaces OpenRedirectAgent._generate_openredirect_fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)
    return ("OPEN_REDIRECT", netloc, normalized_path, parameter.lower())


def header_injection_fingerprint(header_name: str) -> Tuple:
    """
    Generate Header Injection finding fingerprint for expert deduplication.

    Header injection is global (same header = same vulnerability regardless
    of URL).

    Pure function. Replaces HeaderInjectionAgent._generate_headerinjection_fingerprint.
    """
    return ("HEADER_INJECTION", header_name.lower())


def prototype_pollution_fingerprint(url: str, parameter: str) -> Tuple:
    """
    Generate Prototype Pollution finding fingerprint for expert deduplication.

    Pure function. Replaces PrototypePollutionAgent._generate_protopollution_fingerprint.
    """
    netloc, normalized_path = normalize_url_for_dedup(url)
    return ("PROTOTYPE_POLLUTION", netloc, normalized_path, parameter.lower())


# =========================================================================
# CONVENIENCE: FINGERPRINT FUNCTION REGISTRY
# =========================================================================

# Maps vuln type string to the appropriate fingerprint generator.
# Each entry is a callable that takes a finding dict and returns a Tuple.
# Agents can use this to auto-select the right fingerprint function.

def _make_finding_fp(fn: Callable, *keys: str) -> Callable[[Dict], Tuple]:
    """Create a finding-dict adapter for a fingerprint function."""
    def adapter(finding: Dict) -> Tuple:
        args = [finding.get(k, "") for k in keys]
        return fn(*args)
    return adapter


FINGERPRINT_REGISTRY: Dict[str, Callable[[Dict], Tuple]] = {
    "XSS": lambda f: xss_fingerprint(
        f.get("url", ""),
        f.get("parameter", ""),
        f.get("context", "html"),
        sink=(f.get("evidence") if isinstance(f.get("evidence"), dict) else {}).get("sink"),
        source=(f.get("evidence") if isinstance(f.get("evidence"), dict) else {}).get("source"),
    ),
    "SQLI": lambda f: sqli_fingerprint(f.get("parameter", ""), f.get("url", "")),
    "CSTI": lambda f: csti_fingerprint(
        f.get("url", ""),
        f.get("parameter", ""),
        f.get("template_engine", "unknown"),
    ),
    "LFI": lambda f: lfi_fingerprint(f.get("url", ""), f.get("parameter", "")),
    "RCE": lambda f: rce_fingerprint(f.get("url", ""), f.get("parameter", "")),
    "SSRF": lambda f: ssrf_fingerprint(f.get("url", ""), f.get("parameter", "")),
    "IDOR": lambda f: idor_fingerprint(f.get("url", ""), f.get("parameter", "")),
    "JWT": lambda f: jwt_fingerprint(
        f.get("url", ""),
        f.get("vuln_type", f.get("type", "")),
        f.get("token"),
    ),
    "XXE": lambda f: xxe_fingerprint(f.get("url", "")),
    "OPEN_REDIRECT": lambda f: openredirect_fingerprint(f.get("url", ""), f.get("parameter", "")),
    "HEADER_INJECTION": lambda f: header_injection_fingerprint(
        f.get("header_name", f.get("injected_header", f.get("parameter", "X-Injected")))
    ),
    "PROTOTYPE_POLLUTION": lambda f: prototype_pollution_fingerprint(
        f.get("url", ""), f.get("parameter", "")
    ),
}


def get_fingerprint_fn(vuln_type: str) -> Callable[[Dict], Tuple]:
    """
    Get the appropriate fingerprint function for a vulnerability type.

    Falls back to _default_fingerprint if the type is not in the registry.

    Pure function.

    Args:
        vuln_type: Vulnerability type string (e.g., "XSS", "SQLI").

    Returns:
        Callable that takes a finding dict and returns a hashable tuple.
    """
    return FINGERPRINT_REGISTRY.get(vuln_type.upper(), _default_fingerprint)


# =========================================================================
# ROOT CAUSE GROUPING
# =========================================================================

def group_by_root_cause(
    findings: List[Dict],
    fingerprint_fn: Optional[Callable[[Dict], Tuple]] = None,
) -> Dict[Tuple, List[Dict]]:
    """
    Group findings by root cause for aggregated reporting.

    Findings with the same fingerprint are grouped together. This is useful
    for generating summary reports where the same vulnerability across
    multiple URLs (e.g., global DOM XSS) should appear as one entry with
    affected URLs listed.

    Pure function.

    Args:
        findings: List of finding dicts.
        fingerprint_fn: Fingerprint function. If None, auto-selects based
                        on each finding's "type" field using the registry.

    Returns:
        Dict mapping fingerprint tuples to lists of grouped findings.
    """
    groups: Dict[Tuple, List[Dict]] = {}

    for finding in findings:
        if fingerprint_fn:
            fp = fingerprint_fn(finding)
        else:
            vuln_type = finding.get("type", "UNKNOWN").upper()
            fn = get_fingerprint_fn(vuln_type)
            fp = fn(finding)

        if fp not in groups:
            groups[fp] = []
        groups[fp].append(finding)

    return groups
