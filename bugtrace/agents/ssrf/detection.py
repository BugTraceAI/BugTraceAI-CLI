"""
PURE functions for SSRF detection, classification, and validation.

All functions depend only on their arguments.  No network I/O.
"""
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from bugtrace.core.validation_status import ValidationStatus


# =========================================================================
# Response analysis indicators (PURE DATA)
# =========================================================================

SSRF_INDICATORS: Tuple[str, ...] = (
    "root:x:",
    "connected to internal",
    "aws metadata",
    "metadata-flavor",
    "computeMetadata/v1",
)


# =========================================================================
# Validation (PURE)
# =========================================================================

def validate_before_emit(
    finding: Dict, parent_validate_fn,
) -> Tuple[bool, str]:
    """
    SSRF-specific pre-emit validation.

    Validates:
    1. Basic requirements (type, url) via parent
    2. Has callback evidence OR internal access confirmation
    3. Payload contains URL manipulation patterns

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

    # SSRF-specific: Must have confirmation
    if status not in ["VALIDATED_CONFIRMED", "PENDING_VALIDATION"]:
        has_callback = evidence.get("interactsh_callback") or evidence.get("callback_received")
        has_internal = evidence.get("internal_access") or evidence.get("response_leaked")
        if not (has_callback or has_internal):
            return False, "SSRF requires proof: callback received or internal access confirmed"

    # SSRF-specific: Payload should contain URL patterns
    payload = finding.get("payload", nested.get("payload", ""))
    ssrf_markers = [
        "http://", "https://", "localhost", "127.0.0.1",
        "169.254", "file://", "@", "%40",
    ]
    if payload and not any(m in str(payload).lower() for m in ssrf_markers):
        return False, f"SSRF payload missing URL patterns: {payload[:50]}"

    return True, ""


def determine_validation_status(res: Dict) -> bool:
    """
    Determine if the response indicates a successful SSRF.

    Checks for classic content indicators and timing anomalies.

    Args:
        res: Response dict with ``text`` and ``elapsed`` keys.

    Returns:
        True if the response indicates SSRF success.
    """  # PURE
    text = res.get("text", "").lower()

    for indicator in SSRF_INDICATORS:
        if indicator in text:
            return True

    # Timing indicator (potential)
    if res.get("elapsed", 0) > 3:
        return True

    return False


def get_validation_status(evidence: Dict) -> str:
    """
    Determine tiered validation status for SSRF finding.

    TIER 1 (VALIDATED_CONFIRMED): Definitive proof
        - Interactsh OOB callback received
        - Internal IP response (cloud metadata, internal services)
        - Cloud metadata content (AWS, GCP, Azure)
        - File content retrieved (SSRF to file://)

    TIER 2 (PENDING_VALIDATION): Needs verification
        - DNS rebinding (timing-based)
        - Blind SSRF without OOB confirmation

    Args:
        evidence: Evidence dict.

    Returns:
        Validation status string.
    """  # PURE
    if evidence.get("interactsh_hit"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    if evidence.get("internal_ip_response"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    if evidence.get("cloud_metadata"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    if evidence.get("file_content"):
        return ValidationStatus.VALIDATED_CONFIRMED.value

    # Needs verification (blind SSRF, timing-based)
    return ValidationStatus.PENDING_VALIDATION.value


# =========================================================================
# Fingerprinting and deduplication (PURE)
# =========================================================================

def generate_ssrf_fingerprint(
    url: str, parameter: str, payload: str,
) -> tuple:
    """
    Generate SSRF finding fingerprint for expert deduplication.

    SSRF is URL-specific and parameter-specific. SSRF to different callback
    domains from the same parameter = SAME vulnerability (just different proof).

    Args:
        url:       Target URL.
        parameter: Parameter name.
        payload:   SSRF payload (contains callback domain).

    Returns:
        Tuple fingerprint for deduplication.
    """  # PURE
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")
    # Multiple callbacks from same param = same vulnerability
    return ("SSRF", parsed.netloc, normalized_path, parameter.lower())


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
    for f in wet_findings:
        fp = generate_ssrf_fingerprint(
            f.get("url", ""), f.get("parameter", ""), "",
        )
        if fp not in seen:
            seen.add(fp)
            dry_list.append(f)
    return dry_list


def build_queue_evidence(result: Dict) -> Dict:
    """
    Build evidence dict from a queue result for validation status determination.

    Args:
        result: Raw result dict from payload testing.

    Returns:
        Evidence dict suitable for ``get_validation_status()``.
    """  # PURE
    return {
        "interactsh_hit": result.get("interactsh_hit", False),
        "internal_ip_response": "internal" in result.get("reason", "").lower(),
        "cloud_metadata": any(
            ind in result.get("reason", "").lower()
            for ind in ["metadata", "cloud", "aws", "gcp"]
        ),
        "file_content": "file" in result.get("payload", "").lower(),
    }
