"""
SQLi Agent Deduplication (PURE)

Pure functions for SQLi finding deduplication:
- Fingerprint generation (cookie/header/param scoping)
- Fallback fingerprint-based dedup

All functions are PURE: no self, no I/O, no mutation.
"""

from typing import Dict, List, Tuple
from urllib.parse import urlparse

from loguru import logger


def generate_sqli_fingerprint(parameter: str, url: str) -> Tuple:
    """
    # PURE
    Generate SQLi finding fingerprint for expert deduplication.

    SQLi in COOKIES is GLOBAL (affects all URLs).
    SQLi in URL PARAMS is URL-specific (different URLs = different vulns).

    Examples:
    - Cookie: TrackingId at /blog/post?postId=3 = Cookie: TrackingId at /catalog?id=1 (SAME)
    - URL param 'id' at /blog/post?id=3 != URL param 'id' at /catalog?id=1 (DIFFERENT)

    Args:
        parameter: Parameter name (e.g., "Cookie: TrackingId", "URL param: id")
        url: Target URL

    Returns:
        Tuple fingerprint for deduplication
    """
    param_lower = parameter.lower()

    # Cookie-based SQLi: Global vulnerability (ignore URL)
    if "cookie:" in param_lower:
        cookie_name = param_lower.split(":")[-1].strip()
        return ("SQLI", "cookie", cookie_name)

    # Header-based SQLi: Global vulnerability (ignore URL)
    if "header:" in param_lower:
        header_name = param_lower.split(":")[-1].strip()
        return ("SQLI", "header", header_name)

    # URL/POST param: URL-specific vulnerability
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')

    param_name = parameter.split(":")[-1].strip().lower()

    return ("SQLI", "param", parsed.netloc, normalized_path, param_name)


def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
    """
    # PURE
    Fallback deduplication using fingerprints if LLM fails.

    Args:
        wet_findings: List of WET finding dicts

    Returns:
        Deduplicated list (DRY list)
    """
    seen_fingerprints = set()
    dry_list = []

    for finding in wet_findings:
        fingerprint = generate_sqli_fingerprint(
            finding.get("parameter", ""),
            finding.get("url", "")
        )

        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            dry_list.append(finding)

    logger.info(f"Fallback fingerprint dedup: {len(wet_findings)} -> {len(dry_list)}")
    return dry_list


__all__ = [
    "generate_sqli_fingerprint",
    "fallback_fingerprint_dedup",
]
