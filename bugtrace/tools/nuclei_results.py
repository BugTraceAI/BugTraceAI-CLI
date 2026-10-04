"""Helpers for consuming the structured result returned by ``run_nuclei``."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any, Collection, Dict, List


_INFRASTRUCTURE_TEMPLATE_IDS = frozenset({"tech-detect", "waf-detect"})
_INFRASTRUCTURE_TAGS = frozenset({"tech", "waf", "discovery"})
_WAF_BLOCK_MARKERS = (
    "errors.edgesuite.net",
    "request has been blocked",
    "the requested url was rejected",
    "cf-mitigated",
    "attention required",
)
_GENERIC_BLOCK_MARKERS = (
    "access denied",
    "you don't have permission to access",
)
_WAF_SERVER_MARKERS = (
    "akamai",
    "cloudflare",
    "imperva",
    "incapsula",
    "sucuri",
    "modsecurity",
    "fortinet",
)


def _nuclei_template_id(finding: Mapping[str, Any]) -> str:
    return str(finding.get("template-id") or finding.get("template_id") or "").lower()


def is_nuclei_infrastructure_finding(finding: Mapping[str, Any]) -> bool:
    """Return whether a Nuclei result is technology/WAF context, not a vulnerability."""
    template_id = _nuclei_template_id(finding)
    info = finding.get("info", {})
    tags = info.get("tags", []) if isinstance(info, Mapping) else []
    normalized_tags = {str(tag).lower() for tag in tags}
    return template_id in _INFRASTRUCTURE_TEMPLATE_IDS or bool(
        normalized_tags & _INFRASTRUCTURE_TAGS
    )


def is_nuclei_waf_block_response(finding: Mapping[str, Any]) -> bool:
    """Return whether a Nuclei HTTP sample is a WAF denial page, not app evidence."""
    response = str(finding.get("response") or "")
    if not response:
        return False

    text = response.casefold()
    if any(marker in text for marker in _WAF_BLOCK_MARKERS):
        return True

    status_match = re.search(r"HTTP/\\d(?:\\.\\d)?\\s+(\\d{3})", response)
    status = int(status_match.group(1)) if status_match else 0
    has_generic_block = any(marker in text for marker in _GENERIC_BLOCK_MARKERS)
    has_waf_server = any(marker in text for marker in _WAF_SERVER_MARKERS)
    return status in {403, 406, 429, 503} and has_generic_block and has_waf_server


def is_reportable_nuclei_finding(
    finding: Mapping[str, Any],
    *,
    classified_template_ids: Collection[str] = (),
) -> bool:
    """Keep report candidates separate from tech context and blocked responses."""
    template_id = _nuclei_template_id(finding)
    classified = {str(item).lower() for item in classified_template_ids}
    return (
        template_id not in classified
        and not is_nuclei_infrastructure_finding(finding)
        and not is_nuclei_waf_block_response(finding)
    )


def flatten_nuclei_results(results: Any) -> List[Dict[str, Any]]:
    """Return valid findings from current and legacy Nuclei result formats.

    ``ExternalToolManager.run_nuclei`` returns separate technology and
    vulnerability batches. Older callers expected a flat list, so this adapter
    provides one canonical view while ignoring malformed entries.
    """
    if isinstance(results, Mapping):
        batches = (results.get("tech_findings", []), results.get("vuln_findings", []))
    elif isinstance(results, list):
        batches = (results,)
    else:
        return []

    findings: List[Dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for batch in batches:
        if not isinstance(batch, list):
            continue
        for finding in batch:
            if not isinstance(finding, Mapping):
                continue
            item = dict(finding)
            key = (
                str(item.get("template-id") or item.get("template_id") or ""),
                str(item.get("matched-at") or item.get("matched_at") or item.get("host") or ""),
            )
            if key != ("", "") and key in seen:
                continue
            seen.add(key)
            findings.append(item)

    return findings


def nuclei_candidate_records(
    results: Any,
    default_url: str,
) -> List[tuple[str, Dict[str, Any]]]:
    """Build memory-safe candidate records from structured Nuclei results."""
    candidates: List[tuple[str, Dict[str, Any]]] = []
    for finding in flatten_nuclei_results(results):
        info = finding.get("info", {})
        if not isinstance(info, Mapping):
            info = {}
        template_id = str(finding.get("template-id") or "unknown")
        matched_url = str(finding.get("matched-at") or default_url)
        candidates.append(
            (
                f"nuclei:{template_id}:{matched_url}",
                {
                    "url": matched_url,
                    "type": info.get("name", "Nuclei Finding"),
                    "severity": info.get("severity", "info"),
                    "template_id": template_id,
                    "details": info.get("description", ""),
                    "source": "nuclei",
                },
            )
        )
    return candidates
