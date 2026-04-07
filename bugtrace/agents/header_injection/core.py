"""
Header Injection Agent - PURE functions

All functions here are free functions (no self), take all data as parameters,
and perform no I/O. They are deterministic and side-effect free.

Responsibilities:
- CRLF payload definitions and constants
- URL building with payload injection
- Response header analysis for injection evidence
- Finding creation and fingerprinting
- Scope filtering logic
"""

import json
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlunparse, quote


# ============================================================================
# PAYLOAD CONSTANTS
# ============================================================================

# PURE: CRLF payloads - various encodings to bypass filters
CRLF_PAYLOADS: List[str] = [
    # Standard CRLF
    "%0d%0aX-Injected: header",
    "%0d%0aSet-Cookie: injected=true",
    # Double encoding
    "%250d%250aX-Injected: header",
    # Unicode variants
    "%E5%98%8A%E5%98%8DX-Injected: header",
    # Mixed encoding
    "%0d%0a%0d%0a<html>injected</html>",
    # Null byte bypass
    "%00%0d%0aX-Injected: header",
    # Line feed only (some servers)
    "%0aX-Injected: header",
    # Carriage return only
    "%0dX-Injected: header",
    # URL encoded newline
    "\r\nX-Injected: header",
    # Tab + newline
    "%09%0d%0aX-Injected: header",
]

# PURE: Headers to check for injection evidence
INJECTION_MARKERS: List[str] = [
    "X-Injected",
    "Set-Cookie: injected",
    "<html>injected",
]

# PURE: CRLF pattern markers for payload validation
CRLF_PATTERN_MARKERS: List[str] = [
    '%0d', '%0a', '\r', '\n', '%250d', '%250a', '%E5%98%8',
]

# PURE: Default parameters to test when none are found
DEFAULT_TEST_PARAMS: List[str] = [
    "url", "redirect", "next", "return", "callback", "ref", "page",
]


# ============================================================================
# SCOPE FILTERING (PURE)
# ============================================================================

# PURE
def should_test_url(url: str, scope_config: Dict) -> Tuple[bool, str]:
    """
    Determine if Header Injection should be tested on this URL
    based on configurable scope rules.

    Logic:
    1. If url.path is / or empty -> TRUE
    2. If url.path contains any string from patterns.paths -> TRUE
    3. If any GET parameter matches patterns.params -> TRUE
    4. Default: FALSE

    Args:
        url: Target URL to evaluate
        scope_config: Loaded scope configuration dict

    Returns:
        Tuple of (should_test, reason)
    """
    config = scope_config.get("config", {})
    patterns = scope_config.get("patterns", {})
    path_patterns = patterns.get("paths", [])
    param_patterns = patterns.get("params", [])

    parsed = urlparse(url)
    path = parsed.path.lower()
    query_params = parse_qs(parsed.query)

    # Check 1: Root or empty path
    if config.get("always_test_root", True) and (path == "/" or path == ""):
        return True, "root path"

    # Check 2: Path contains sensitive patterns
    for pattern in path_patterns:
        if pattern.lower() in path:
            return True, f"path contains '{pattern}'"

    # Check 3: Query parameters match sensitive patterns
    for param in query_params.keys():
        if param.lower() in [p.lower() for p in param_patterns]:
            return True, f"param '{param}' is redirect-related"

    # Default: Not in scope
    return False, "not in scope"


# PURE
def load_scope_config(scope_config_path: Path) -> Dict:
    """
    Load scope configuration from JSON file.

    Args:
        scope_config_path: Path to header_injection_scope.json

    Returns:
        Scope config dict, or empty dict on failure
    """
    try:
        with open(scope_config_path, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


# ============================================================================
# PARAMETER EXTRACTION (PURE)
# ============================================================================

# PURE
def get_parameters_to_test(
    url: str,
    explicit_params: List[str],
    cookies: List[Dict],
) -> List[str]:
    """
    Get list of parameters to test for CRLF injection.

    Args:
        url: Target URL
        explicit_params: Params explicitly provided to agent
        cookies: List of cookie dicts with 'name' key

    Returns:
        Deduplicated list of parameter names
    """
    params_to_test = list(explicit_params) if explicit_params else []

    # Extract from URL query string
    if not params_to_test:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        params_to_test = list(query_params.keys())

    # Also test cookie names
    if cookies:
        for cookie in cookies:
            cookie_name = cookie.get('name', '')
            if cookie_name and cookie_name not in params_to_test:
                params_to_test.append(cookie_name)

    params_to_test = list(set(params_to_test))

    if not params_to_test:
        # Add common parameters that might be vulnerable
        params_to_test = list(DEFAULT_TEST_PARAMS)

    return params_to_test


# ============================================================================
# URL BUILDING (PURE)
# ============================================================================

# PURE
def build_test_url(url: str, param: str, payload: str) -> str:
    """
    Build URL with CRLF payload in specified parameter.

    FIX (2026-02-12): Build URL manually to avoid double-encoding.
    CRLF payloads are already URL-encoded (e.g., %0d%0a). Using urlencode()
    would re-encode the '%' to '%25', making %0d%0a into %250d%250a which
    the server decodes to literal '%0d%0a' instead of CR LF characters.

    Literal control chars (e.g. \\r\\n from payload #8) are URL-encoded here
    so they travel safely in the URL while pre-encoded sequences like %0d%0a
    are preserved as-is.

    Args:
        url: Base URL
        param: Parameter name to inject into
        payload: CRLF payload string

    Returns:
        URL with payload injected
    """
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    # URL-encode any literal control characters in the payload (bytes 0x00-0x1F, 0x7F)
    # but preserve already-encoded sequences like %0d%0a
    safe_payload = re.sub(
        r'[\x00-\x1f\x7f]',
        lambda m: f'%{ord(m.group()):02X}',
        payload
    )

    # Build query string manually to preserve pre-encoded payloads
    parts = []
    for k, v in query_params.items():
        if k == param:
            continue  # Skip -- we'll add our payload version
        parts.append(f"{k}={quote(v[0], safe='')}")
    parts.append(f"{param}={safe_payload}")

    new_query = "&".join(parts)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))


# ============================================================================
# RESPONSE ANALYSIS (PURE)
# ============================================================================

# PURE
def check_raw_headers_for_crlf(
    raw_headers: List[Tuple[bytes, bytes]],
    param: str,
) -> Optional[Dict]:
    """
    Phase 1: Raw header CRLF detection (Burp-style).

    aiohttp's raw_headers is a list of (name_bytes, value_bytes) tuples
    representing the headers exactly as received over the wire.
    If the server reflects CRLF from our payload, literal \\r or \\n
    bytes will appear inside a header value.

    Args:
        raw_headers: List of (name_bytes, value_bytes) from response
        param: Parameter being tested

    Returns:
        Dict with detection details, or None if no CRLF found
    """
    for raw_name, raw_value in raw_headers:
        # Decode with latin-1 (ISO-8859-1) -- the HTTP header encoding
        header_name_str = raw_name.decode("latin-1")
        header_value_str = raw_value.decode("latin-1")

        # Check if the header VALUE contains literal newline bytes
        if "\r" in header_value_str or "\n" in header_value_str:
            evidence = f"{header_name_str}: {header_value_str[:200]}"
            return {
                "detection_type": "CRLF_NEWLINE",
                "location": "header_value",
                "header_name": header_name_str,
                "evidence": evidence,
                "param": param,
            }

        # Secondary check: if header NAME contains newline bytes
        if "\r" in header_name_str or "\n" in header_name_str:
            evidence = f"Injected header name: {header_name_str[:200]}"
            return {
                "detection_type": "CRLF_NEWLINE",
                "location": "header_name",
                "header_name": header_name_str,
                "evidence": evidence,
                "param": param,
            }

    return None


# PURE
def check_markers_in_response(
    resp_headers: Dict[str, str],
    body: str,
    param: str,
) -> Optional[Dict]:
    """
    Phase 2: Marker-based detection (fallback).

    Check parsed headers for known injection marker strings.
    This catches CRLF that results in new well-formed headers
    (e.g. "X-Injected: header" appearing as a separate header).

    Args:
        resp_headers: Dict of response headers
        body: Response body text
        param: Parameter being tested

    Returns:
        Dict with detection details, or None if no markers found
    """
    for marker in INJECTION_MARKERS:
        # Check in response headers
        for header_name, header_value in resp_headers.items():
            if marker.lower() in header_name.lower() or marker.lower() in header_value.lower():
                return {
                    "detection_type": "marker",
                    "marker": marker,
                    "location": "header",
                    "header_name": header_name,
                    "evidence": header_value,
                    "param": param,
                }

        # Check in body (response splitting)
        if marker.lower() in body.lower():
            # Could be response splitting - check if HTML was injected
            if "<html>injected" in body.lower():
                return {
                    "detection_type": "marker",
                    "marker": marker,
                    "location": "body",
                    "header_name": None,
                    "evidence": body[:500],
                    "param": param,
                }

    return None


# PURE
def check_smart_probe_response(
    resp_headers: Dict[str, str],
    body: str,
) -> Tuple[bool, Optional[Dict]]:
    """
    Analyze smart probe response to determine if CRLF survives.

    Args:
        resp_headers: Dict of response headers
        body: Response body text

    Returns:
        Tuple of (should_continue_testing, probe_finding_or_none)
    """
    # Check 1: Marker in response headers (injection confirmed)
    for header_name, header_value in resp_headers.items():
        if "bt-probe" in header_name.lower() or "bt-probe" in header_value.lower():
            return True, {
                "detection_type": "smart_probe",
                "marker": "BT-Probe",
                "location": "header",
                "header_name": header_name,
                "evidence": header_value,
            }

    # Check 2: Marker in body (response splitting)
    if "bt-probe" in body.lower():
        return True, None  # Continue testing

    # No CRLF survival
    return False, None


# ============================================================================
# FINDING CONSTRUCTION (PURE)
# ============================================================================

# PURE
def create_finding(
    url: str,
    param: str,
    payload: str,
    marker: str,
    location: str,
    header_name: Optional[str],
    evidence: str,
    validation_status: str,
) -> Dict:
    """
    Create a header injection finding dictionary.

    Args:
        url: Target URL
        param: Parameter that was injected
        payload: The CRLF payload used
        marker: The injection marker that was found
        location: Where injection was found (header/body)
        header_name: Name of the injected/affected header
        evidence: Evidence string (header value or body snippet)
        validation_status: ValidationStatus value string

    Returns:
        Finding dict with all required fields
    """
    test_url = build_test_url(url, param, payload)

    return {
        "type": "Header Injection",
        "vulnerability_type": "HTTP_RESPONSE_HEADER_INJECTION",
        "url": url,
        "parameter": param,
        "payload": payload,
        "evidence": f"Injection marker '{marker}' found in {location}: {evidence[:200]}",
        "validated": True,
        "validation_method": "Response Header Analysis",
        "severity": "HIGH",
        "status": validation_status,
        "cwe": "CWE-113",
        "remediation": "Sanitize user input before including in HTTP headers. Remove or encode CR (\\r) and LF (\\n) characters.",
        "reproduction": f"curl -v '{test_url}'",
        "impact": "Response splitting, cache poisoning, XSS via headers, session fixation",
        "header_name": header_name,
    }


# ============================================================================
# VALIDATION (PURE)
# ============================================================================

# PURE
def validate_header_injection_finding(finding: Dict) -> Tuple[bool, str]:
    """
    Header Injection-specific validation logic.

    Validates:
    1. Has header injection evidence (header reflected)
    2. Payload contains CRLF patterns

    Args:
        finding: Finding dict to validate

    Returns:
        Tuple of (is_valid, error_message)
    """
    # Extract from nested structure if needed
    nested = finding.get("finding", {})
    evidence = finding.get("evidence", {})

    # Header injection-specific: Must have header name or evidence
    header_name = finding.get("header_name", nested.get("header_name", ""))
    has_evidence = header_name or (isinstance(evidence, dict) and evidence.get("header_reflected"))
    if not has_evidence:
        return False, "Header Injection requires proof: injected header name or evidence"

    # Header injection-specific: Payload should contain CRLF patterns
    payload = finding.get("payload", nested.get("payload", ""))
    if payload and not any(m in str(payload) for m in CRLF_PATTERN_MARKERS):
        return False, f"Header Injection payload missing CRLF patterns: {payload[:50]}"

    return True, ""


# ============================================================================
# FINGERPRINTING (PURE)
# ============================================================================

# PURE
def generate_headerinjection_fingerprint(header_name: str) -> Tuple:
    """
    Generate Header Injection finding fingerprint for expert deduplication.

    Header injection is global (same header = same vulnerability).

    Args:
        header_name: Name of the injected header

    Returns:
        Tuple fingerprint for deduplication
    """
    return ("HEADER_INJECTION", (header_name or "x-injected").lower())


# PURE
def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
    """
    Fallback fingerprint-based deduplication if LLM fails.

    For autonomous discovery: Uses (url, parameter) as fingerprint.
    This ensures same URL with DIFFERENT params = DIFFERENT findings.

    Args:
        wet_findings: List of WET findings to deduplicate

    Returns:
        Deduplicated list
    """
    seen: set = set()
    dry_list: List[Dict] = []

    for finding in wet_findings:
        # If autonomously discovered, fingerprint by URL+param
        if finding.get("_discovered"):
            url = finding.get("url", "")
            param = finding.get("parameter", "")
            fingerprint = (url, param)
        else:
            # Standard header injection: fingerprint by header name only
            header_name = finding.get("header_name") or finding.get("injected_header") or "X-Injected"
            fingerprint = generate_headerinjection_fingerprint(header_name)

        if fingerprint not in seen:
            seen.add(fingerprint)
            dry_list.append(finding)

    return dry_list


# ============================================================================
# REPORT BUILDING (PURE)
# ============================================================================

# PURE
def build_specialist_report(
    agent_name: str,
    scan_context: str,
    dry_findings: List[Dict],
    validated_findings: List[Dict],
) -> Dict:
    """
    Build specialist report dictionary for Header Injection findings.

    Args:
        agent_name: Name of the agent
        scan_context: Scan identifier
        dry_findings: DRY (deduplicated) findings
        validated_findings: Validated findings from Phase B

    Returns:
        Report dict ready for serialization
    """
    return {
        "agent": agent_name,
        "vulnerability_type": "HEADER_INJECTION",
        "scan_context": scan_context,
        "phase_a": {
            "wet_count": len(dry_findings) + (len(validated_findings) - len(dry_findings)),
            "dry_count": len(dry_findings),
            "deduplication_method": "LLM + fingerprint fallback (header name-only)",
        },
        "phase_b": {
            "exploited_count": len(dry_findings),
            "validated_count": len(validated_findings),
        },
        "findings": validated_findings,
        "summary": {
            "total_validated": len(validated_findings),
            "headers_found": list(set(
                f.get("header_name", "X-Injected") for f in validated_findings
            )),
        },
    }


# PURE
def build_dedup_prompt(
    wet_findings: List[Dict],
    tech_stack: Dict,
    prime_directive: str,
    dedup_context: str,
) -> Tuple[str, str]:
    """
    Build LLM prompt and system prompt for header injection deduplication.

    Args:
        wet_findings: WET findings to deduplicate
        tech_stack: Technology stack context
        prime_directive: Agent-specific prime directive
        dedup_context: Agent-specific dedup context

    Returns:
        Tuple of (user_prompt, system_prompt)
    """
    server = tech_stack.get('server', 'generic')
    cdn = tech_stack.get('cdn')
    waf = tech_stack.get('waf')

    prompt = f"""You are analyzing {len(wet_findings)} potential HTTP Header Injection (CRLF) findings.

{prime_directive}

{dedup_context}

## TARGET CONTEXT
- Server: {server}
- CDN: {cdn or 'None'}
- WAF: {waf or 'None'}

## DEDUPLICATION RULES

1. **CRITICAL - Autonomous Discovery:**
   - If items have "_discovered": true, they are DIFFERENT PARAMETERS discovered autonomously
   - Even if they share the same "finding" object, treat them as SEPARATE based on "parameter" field
   - Same URL + DIFFERENT param -> DIFFERENT (keep all)
   - Same URL + param + DIFFERENT context -> DIFFERENT (keep both)

2. **Standard Deduplication:**
   - Same URL + Same param + Same context -> DUPLICATE (keep best)
   - Different endpoints -> DIFFERENT (keep both)

3. **Prioritization:**
   - Rank by exploitability given the tech stack
   - Remove findings unlikely to succeed

EXAMPLES:
- /page?redirect=X + /page?locale=Y (both _discovered=true) = DIFFERENT (keep both)
- /page?param=X (X-Injected) + /other?param=Y (X-Injected) = DUPLICATE (same param name across URLs)
- /page?param=X (X-Injected) + /page?param=Y (Set-Cookie) = DIFFERENT (different headers)

WET FINDINGS (may contain duplicates):
{json.dumps(wet_findings, indent=2)}

Return ONLY unique findings in JSON format:
{{
  "findings": [
    {{"url": "...", "parameter": "...", "header_name": "...", ...}},
    ...
  ],
  "duplicates_removed": <count>,
  "reasoning": "Brief explanation"
}}"""

    system_prompt = f"""You are an expert CRLF/Header Injection deduplication analyst.

{prime_directive}

Your job is to identify and remove duplicate findings while preserving:
1. Unique parameter names (autonomous discovery)
2. Different injection contexts
3. Different injected headers

Focus on header name-only deduplication UNLESS parameters are different."""

    return prompt, system_prompt
