"""
PURE functions for LFI / Path Traversal detection, classification, and validation.

All functions depend only on their arguments.  No network I/O.
"""
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from bugtrace.core.validation_status import ValidationStatus
from bugtrace.reporting.standards import (
    get_cwe_for_vuln,
    get_remediation_for_vuln,
    normalize_severity,
)


# =========================================================================
# LFI file-content signatures (PURE DATA)
# =========================================================================

LFI_SIGNATURES: Tuple[str, ...] = (
    "root:x:0:0",              # /etc/passwd Linux
    "[extensions]",            # win.ini
    "[fonts]",                 # win.ini
    "PD9waH",                  # Base64 for <?php
    "root:*:0:0",              # /etc/passwd BSD
    "127.0.0.1 localhost",     # /etc/hosts
)

TIER1_SIGNATURES: Tuple[str, ...] = (
    "root:x:0:0",              # /etc/passwd Linux
    "root:*:0:0",              # /etc/passwd BSD
    "[extensions]",            # win.ini
    "[fonts]",                 # win.ini
    "127.0.0.1 localhost",     # /etc/hosts
    "<?php",                   # PHP source code (direct)
)


# =========================================================================
# Validation status (PURE)
# =========================================================================

def determine_validation_status(response_text: str, payload: str) -> str:
    """
    Determine validation status based on response content.

    TIER 1 (VALIDATED_CONFIRMED):
        - /etc/passwd content visible (root:x:0:0)
        - win.ini content visible ([extensions])
        - PHP source code visible (<?php or base64 decoded PHP)

    TIER 2 (PENDING_VALIDATION):
        - Path traversal success but no sensitive file content
        - PHP wrapper returned something but unclear if source code

    Args:
        response_text: The HTTP response body.
        payload:       The LFI payload that was sent.

    Returns:
        Validation status string.
    """  # PURE
    for sig in TIER1_SIGNATURES:
        if sig in response_text:
            return ValidationStatus.VALIDATED_CONFIRMED.value

    # Base64 decoded PHP (from php://filter)
    if "PD9waH" in response_text:  # Base64 for <?php
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # Path traversal worked but didn't get sensitive content
    return ValidationStatus.PENDING_VALIDATION.value


def validate_before_emit(
    finding: Dict, parent_validate_fn,
) -> Tuple[bool, str]:
    """
    LFI-specific pre-emit validation.

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
    evidence = finding.get("evidence", {})
    status = finding.get("status", nested.get("status", ""))

    # LFI-specific: Must have confirmation or status indicating validation
    if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
        has_content = evidence.get("file_content") or evidence.get("signature_found")
        has_interactsh = evidence.get("interactsh_callback")
        if not (has_content or has_interactsh):
            return False, "LFI requires proof: file content leaked or path traversal confirmed"

    # LFI-specific: Payload should contain path traversal patterns
    payload = finding.get("payload", nested.get("payload", ""))
    lfi_markers = [
        "..", "/etc/", "/proc/", "\\windows\\", "php://", "file://",
        "%2e%2e", "%252e%252e", "....//",
    ]
    if payload and not any(m in str(payload).lower() for m in lfi_markers):
        return False, f"LFI payload missing traversal patterns: {payload[:50]}"

    return True, ""


# =========================================================================
# Finding creation (PURE)
# =========================================================================

def create_lfi_finding_from_hit(hit: Dict, param: str, url: str) -> Dict:
    """
    Create LFI finding dict from a Go-fuzzer hit.

    Args:
        hit:   Hit dict from Go fuzzer (payload, file_found, severity, evidence).
        param: Vulnerable parameter name.
        url:   Target URL.

    Returns:
        Finding dict.
    """  # PURE
    return {
        "type": "LFI / Path Traversal",
        "url": url,
        "parameter": param,
        "payload": hit["payload"],
        "description": (
            f"Local File Inclusion success: Found {hit['file_found']}. "
            f"File content leaked in response."
        ),
        "severity": normalize_severity(hit["severity"]).value,
        "cwe_id": get_cwe_for_vuln("LFI"),
        "cve_id": "N/A",
        "remediation": get_remediation_for_vuln("LFI"),
        "validated": True,
        "status": "VALIDATED_CONFIRMED",
        "evidence": hit["evidence"],
        "http_request": f"GET {url}?{param}={hit['payload']}",
        "http_response": (
            hit["evidence"][:500]
            if isinstance(hit["evidence"], str)
            else str(hit["evidence"])[:500]
        ),
        "reproduction": f"curl '{url}?{param}={hit['payload']}'",
    }


def create_lfi_finding_from_wrapper(
    payload: str, param: str, response_text: str, url: str,
) -> Dict:
    """
    Create LFI finding dict from a PHP wrapper test.

    Args:
        payload:       The PHP wrapper payload.
        param:         Vulnerable parameter name.
        response_text: HTTP response body.
        url:           Target URL.

    Returns:
        Finding dict.
    """  # PURE
    return {
        "type": "LFI / Path Traversal",
        "url": url,
        "parameter": param,
        "payload": payload,
        "description": (
            "LFI detected via PHP wrapper. Source code can be read "
            "using base64 encoding filter."
        ),
        "severity": normalize_severity("CRITICAL").value,
        "cwe_id": get_cwe_for_vuln("LFI"),
        "cve_id": "N/A",
        "remediation": get_remediation_for_vuln("LFI"),
        "validated": True,
        "evidence": f"PHP Wrapper matched signature after injecting {payload}",
        "status": determine_validation_status(response_text, payload),
        "http_request": f"GET {url}?{param}={payload}",
        "http_response": response_text[:500],
        "reproduction": f"curl '{url}?{param}={payload}' | base64 -d",
    }


# =========================================================================
# URL manipulation (PURE)
# =========================================================================

def inject_payload(url: str, param: str, payload: str) -> str:
    """
    Inject *payload* into *param* of *url*'s query string.

    Args:
        url:     Target URL.
        param:   Parameter name.
        payload: Value to inject.

    Returns:
        Modified URL string.
    """  # PURE
    parsed = urlparse(url)
    q = parse_qs(parsed.query)
    q[param] = [payload]
    new_query = urlencode(q, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment,
    ))


def resolve_endpoint_url(url: str, param: str, finding: dict) -> str:
    """
    Extract actual endpoint URL from finding data when base URL is generic.

    DASTySAST sometimes reports a documentation/debug URL but includes the
    real API endpoint in the payload or exploitation_strategy fields.
    Resolves when the param isn't present in the URL's query string.

    Args:
        url:     Target URL (may be generic).
        param:   Parameter name.
        finding: DASTySAST finding dict.

    Returns:
        Resolved URL string.
    """  # PURE
    parsed = urlparse(url)
    existing_params = parse_qs(parsed.query)

    # If the URL already has this param in query, it's likely the right endpoint
    if param in existing_params:
        return url

    # Check finding fields for a more specific URL/path
    for field in ("exploitation_strategy", "payload"):
        hint = finding.get(field, "")
        if not hint or not isinstance(hint, str):
            continue
        if f"{param}=" in hint or f"?{param}" in hint:
            hint_parsed = (
                urlparse(hint) if "://" in hint
                else urlparse(f"https://placeholder{hint}")
            )
            if hint_parsed.path and hint_parsed.path != "/":
                resolved = f"{parsed.scheme}://{parsed.netloc}{hint_parsed.path}"
                return resolved

    return url


def extract_traversal_payload(finding: dict) -> Optional[str]:
    """
    Extract a clean LFI traversal payload from DASTySAST finding data.

    DASTySAST sometimes embeds traversal payloads inside full URL paths like:
      /api/products/1/image?file=../../../../etc/passwd
    This extracts just the traversal portion: ../../../../etc/passwd

    Args:
        finding: DASTySAST finding dict.

    Returns:
        Clean traversal payload string, or None.
    """  # PURE
    for field in ("payload", "exploitation_strategy"):
        raw = finding.get(field, "")
        if not raw or not isinstance(raw, str):
            continue
        # If the payload contains a query string, extract the parameter value
        if "?" in raw and "=" in raw:
            from urllib.parse import urlparse as _urlparse, parse_qs as _parse_qs
            parsed = (
                _urlparse(raw) if "://" in raw
                else _urlparse(f"https://x{raw}")
            )
            for _k, vals in _parse_qs(parsed.query).items():
                for v in vals:
                    if ".." in v or v.startswith("/etc/") or v.startswith("/proc/"):
                        return v
        # If it's a plain traversal string, use it directly
        if ".." in raw and "/" in raw and "?" not in raw and " " not in raw:
            return raw
        if raw.startswith("/etc/") or raw.startswith("/proc/"):
            return raw
    return None


# =========================================================================
# Fingerprinting and deduplication (PURE)
# =========================================================================

def generate_lfi_fingerprint(url: str, parameter: str) -> tuple:
    """
    Generate LFI finding fingerprint for expert deduplication.

    LFI is URL-specific and parameter-specific.

    Args:
        url:       Target URL.
        parameter: Parameter name.

    Returns:
        Tuple fingerprint for deduplication.
    """  # PURE
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")
    return ("LFI", parsed.netloc, normalized_path, parameter.lower())


def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
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
        fp = generate_lfi_fingerprint(url, parameter)
        if fp not in seen:
            seen.add(fp)
            dry_list.append(finding_data)
    return dry_list


def check_signature_match(text: str) -> bool:
    """
    Check whether *text* contains any known LFI file-content signature.

    Args:
        text: HTTP response body.

    Returns:
        True if any signature matched.
    """  # PURE
    return any(sig in text for sig in LFI_SIGNATURES)
