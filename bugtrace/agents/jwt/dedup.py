"""
JWT Dedup - Pure Functions

Pure functions for JWT finding fingerprint-based deduplication.

All functions are PURE: no side effects, no self, data as parameters.
"""

import hashlib
from typing import Dict, List, Tuple
from urllib.parse import urlparse


def generate_jwt_fingerprint(url: str, vuln_type: str, token: str = None) -> Tuple:
    """Generate JWT finding fingerprint for expert deduplication.

    JWT vulnerabilities are token-specific, not URL-specific.
    Different tokens on same domain can have different vulnerabilities.

    Args:
        url: Target URL
        vuln_type: Vulnerability type (e.g., "none algorithm", "weak secret")
        token: JWT token string (optional, recommended for accurate dedup)

    Returns:
        Tuple fingerprint for deduplication
    """  # PURE
    parsed = urlparse(url)

    if token:
        token_hash = hashlib.sha256(token.encode()).hexdigest()[:8]
        fingerprint = ("JWT", parsed.netloc, vuln_type, token_hash)
    else:
        fingerprint = ("JWT", parsed.netloc, vuln_type)

    return fingerprint


def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:
    """Fallback fingerprint-based deduplication if LLM fails.

    Uses generate_jwt_fingerprint for expert dedup.

    Args:
        wet_findings: List of WET finding dicts

    Returns:
        Deduplicated list of findings
    """  # PURE
    seen = set()
    dry_list = []

    for finding in wet_findings:
        url = finding.get("url", "")
        token = finding.get("token", "")
        vuln_type = finding.get("vuln_type", finding.get("type", "JWT"))

        fingerprint = generate_jwt_fingerprint(url, vuln_type, token)

        if fingerprint not in seen:
            seen.add(fingerprint)
            dry_list.append(finding)

    return dry_list


__all__ = [
    "generate_jwt_fingerprint",
    "fallback_fingerprint_dedup",
]
