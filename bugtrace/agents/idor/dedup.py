"""
IDOR Dedup - Pure Functions

Pure functions for IDOR finding fingerprint-based deduplication.

All functions are PURE: no side effects, no self, data as parameters.
"""

from typing import Dict, List, Tuple
from urllib.parse import urlparse


def generate_idor_fingerprint(url: str, resource_type: str) -> Tuple:
    """Generate IDOR finding fingerprint for expert deduplication.

    IDOR signature: Endpoint + resource type (parameter).

    Args:
        url: Target URL
        resource_type: Resource type / parameter name

    Returns:
        Tuple fingerprint for deduplication
    """  # PURE
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip('/')

    fingerprint = ("IDOR", parsed.netloc, normalized_path, resource_type)
    return fingerprint


def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
    """Fallback fingerprint-based deduplication (no LLM).

    Args:
        wet_findings: List of WET finding dicts

    Returns:
        Deduplicated list of findings
    """  # PURE
    seen_fingerprints = set()
    dry_list = []

    for finding_data in wet_findings:
        url = finding_data.get("url", "")
        parameter = finding_data.get("parameter", "")

        if not url or not parameter:
            continue

        fingerprint = generate_idor_fingerprint(url, parameter)

        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            dry_list.append(finding_data)

    return dry_list


__all__ = [
    "generate_idor_fingerprint",
    "fallback_fingerprint_dedup",
]
