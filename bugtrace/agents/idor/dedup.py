"""
IDOR Dedup - Pure Functions

Pure functions for IDOR finding fingerprint-based deduplication.

All functions are PURE: no side effects, no self, data as parameters.
"""

from typing import Dict, List, Tuple
from urllib.parse import parse_qsl, urlparse

from bugtrace.agents.idor.payloads import inject_id


def generate_idor_fingerprint(
    url: str,
    resource_type: str,
    original_value: str = "",
) -> Tuple:
    """Generate IDOR finding fingerprint for expert deduplication.

    IDOR signature: endpoint route + effective mutation.

    Args:
        url: Target URL
        resource_type: Resource type / parameter name

    Returns:
        Tuple fingerprint for deduplication
    """  # PURE
    mutated_url = inject_id(url, "__BUGTRACE_ID__", resource_type, original_value)
    parsed = urlparse(mutated_url)
    normalized_path = parsed.path.rstrip('/') or "/"
    normalized_query = tuple(sorted(parse_qsl(parsed.query, keep_blank_values=True)))

    return ("IDOR", parsed.netloc.lower(), normalized_path, normalized_query)


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

        fingerprint = generate_idor_fingerprint(
            url,
            parameter,
            str(finding_data.get("original_value", "")),
        )

        if fingerprint not in seen_fingerprints:
            seen_fingerprints.add(fingerprint)
            dry_list.append(finding_data)

    return dry_list


__all__ = [
    "generate_idor_fingerprint",
    "fallback_fingerprint_dedup",
]
