"""Pure report inclusion / format policy (Phase 5).

No DB, FS, HTML generators, or ReportService side effects.
ReportService adapters call these for status gating and JSON shape extraction.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Sequence

REPORTABLE_STATUSES: frozenset[str] = frozenset(
    {
        "VALIDATED_CONFIRMED",
        "MANUAL_REVIEW_RECOMMENDED",
        "PENDING_VALIDATION",
        "PENDING_CDP_VALIDATION",
        "PENDING",
    }
)

VALID_REPORT_FORMATS: frozenset[str] = frozenset({"html", "markdown", "json"})


def enum_value(value: Any) -> str:
    """Normalize enum or plain status to string."""
    return value.value if hasattr(value, "value") else str(value)


def is_reportable_status(status: Any) -> bool:
    return enum_value(status) in REPORTABLE_STATUSES


def is_reportable_finding_dict(finding: Mapping[str, Any]) -> bool:
    """Empty/missing status is reportable (legacy parity); else status gate."""
    status = finding.get("status")
    if status in (None, ""):
        return True
    return is_reportable_status(status)


def normalize_report_format(fmt: str) -> str:
    """Lowercase format; raise ValueError if not in allowlist."""
    text = (fmt or "").strip().lower()
    if text not in VALID_REPORT_FORMATS:
        raise ValueError(
            f"Invalid report format: {fmt}. Must be html, markdown, or json"
        )
    return text


def extract_rich_findings(data: Any) -> List[Dict[str, Any]]:
    """Extract findings from common report JSON shapes (list or nested dict)."""
    if isinstance(data, list):
        return [f for f in data if isinstance(f, dict)]
    if not isinstance(data, dict):
        return []

    findings = data.get("validated_findings")
    if findings is None:
        findings = data.get("findings", [])
    manual_review = data.get("manual_review", [])
    # PENDING/POTENTIAL findings are reportable and appear in MD/engagement.
    pending = data.get("pending", [])

    rich: List[Dict[str, Any]] = []
    if isinstance(findings, list):
        rich.extend(f for f in findings if isinstance(f, dict))
    if isinstance(manual_review, list):
        rich.extend(f for f in manual_review if isinstance(f, dict))
    if isinstance(pending, list):
        rich.extend(f for f in pending if isinstance(f, dict))
    return rich


def filter_reportable_findings(
    findings: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    return [dict(f) for f in findings if is_reportable_finding_dict(f)]


__all__ = [
    "REPORTABLE_STATUSES",
    "VALID_REPORT_FORMATS",
    "enum_value",
    "is_reportable_status",
    "is_reportable_finding_dict",
    "normalize_report_format",
    "extract_rich_findings",
    "filter_reportable_findings",
]
