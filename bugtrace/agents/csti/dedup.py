"""
CSTI Deduplication

PURE functions for CSTI finding fingerprinting and deduplication.
"""

from typing import Dict, List, Tuple
from urllib.parse import urlparse

from bugtrace.agents.csti.engines import CLIENT_SIDE_ENGINES


def generate_csti_fingerprint(
    url: str, parameter: str, template_engine: str
) -> Tuple:  # PURE
    """
    Generate CSTI finding fingerprint for expert deduplication.

    Client-side engines (Angular, Vue) share a page-level scope,
    so multiple params on the same page = one vulnerability.
    Server-side engines are param-specific.

    Args:
        url: The finding URL
        parameter: The vulnerable parameter
        template_engine: Detected template engine name

    Returns:
        Tuple fingerprint for deduplication
    """
    parsed = urlparse(url)
    normalized_path = parsed.path.rstrip("/")

    is_client_side = template_engine.lower() in CLIENT_SIDE_ENGINES

    if is_client_side:
        # Same page + same engine = same Angular/Vue scope = one finding
        return ("CSTI", parsed.netloc, normalized_path, template_engine)
    else:
        # Server-side: each parameter is a separate injection point
        return ("CSTI", parsed.netloc, normalized_path, parameter.lower(), template_engine)


def fallback_fingerprint_dedup(wet_findings: List[Dict]) -> List[Dict]:  # PURE
    """
    Fallback fingerprint-based deduplication if LLM fails.

    Args:
        wet_findings: List of WET finding dicts

    Returns:
        Deduplicated list of findings
    """
    seen = set()
    dry_list = []

    for finding in wet_findings:
        url = finding.get("url", "")
        parameter = finding.get("parameter", "")
        template_engine = finding.get("template_engine", "unknown")

        fingerprint = generate_csti_fingerprint(url, parameter, template_engine)

        if fingerprint not in seen:
            seen.add(fingerprint)
            dry_list.append(finding)

    return dry_list


def normalize_csti_finding_params(findings: List[Dict]) -> List[Dict]:  # PURE
    """
    Normalize synthetic param names from ThinkingConsolidation.

    Some findings have synthetic params like 'URL Path/Fragment', 'None (POST Body)',
    '_auto_discover', 'username password' etc. These are labels, not real query params.
    When the URL already has query params, expand the finding into one per real param.
    This ensures _inject() creates valid URLs for testing.

    Args:
        findings: List of finding dicts

    Returns:
        Normalized list with synthetic params replaced by real URL query params
    """
    from urllib.parse import urlparse, parse_qs

    normalized = []
    seen_url_param = set()  # Dedup: (url_path, param) pairs

    for finding in findings:
        param = finding.get("parameter", "")
        url = finding.get("url", "")

        is_synthetic = (
            " " in param
            or "/" in param
            or param.startswith("_auto")
            or param.startswith("None")
            or param.startswith("URL ")
            or param.startswith("POST ")
        )

        if is_synthetic:
            parsed = urlparse(url)
            url_params = parse_qs(parsed.query)

            if url_params:
                for real_param in url_params:
                    key = (parsed.path, real_param)
                    if key not in seen_url_param:
                        seen_url_param.add(key)
                        new_finding = dict(finding)
                        new_finding["parameter"] = real_param
                        new_finding["_original_parameter"] = param
                        normalized.append(new_finding)
            else:
                # No URL params -- keep original (auto-discover will handle)
                key = (parsed.path, param)
                if key not in seen_url_param:
                    seen_url_param.add(key)
                    normalized.append(finding)
        else:
            parsed = urlparse(url)
            key = (parsed.path, param)
            if key not in seen_url_param:
                seen_url_param.add(key)
                normalized.append(finding)

    return normalized
