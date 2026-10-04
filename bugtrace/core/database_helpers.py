"""Pure DB finding description/status helpers."""

from __future__ import annotations

from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime

from bugtrace.schemas.db_models import FindingStatus, ScanStatus


@dataclass
class ScanInfo:
    """Metadata about a scan."""
    scan_id: int
    target_url: str
    timestamp: datetime
    status: ScanStatus
    progress_percent: int


def _build_csti_description(evidence: Dict, param: str, payload: str) -> List[str]:
    """Build CSTI-specific description parts."""
    engine = evidence.get("engine", "unknown")
    method = evidence.get("method", "injection")
    parts = [
        f"Client-Side Template Injection (CSTI) detected via {method}.",
        f"Parameter: {param}",
        f"Template Engine: {engine}"
    ]
    if payload:
        parts.append(f"Payload: {payload}")
    if "proof" in evidence:
        parts.append(f"Evidence: {evidence['proof']}")
    return parts


def _build_sqli_description(evidence: Dict, param: str) -> List[str]:
    """Build SQLi-specific description parts."""
    parts = [
        f"SQL Injection vulnerability confirmed.",
        f"Parameter: {param}"
    ]
    if evidence.get("db_type"):
        parts.append(f"Database: {evidence['db_type']}")
    if evidence.get("injection_type"):
        parts.append(f"Type: {evidence['injection_type']}")
    return parts


def _build_xss_description(evidence: Dict, param: str, payload: str) -> List[str]:
    """Build XSS-specific description parts."""
    parts = [
        f"Cross-Site Scripting (XSS) vulnerability detected.",
        f"Parameter: {param}"
    ]
    if payload:
        parts.append(f"Payload: {payload}")
    if evidence.get("context"):
        parts.append(f"Context: {evidence['context']}")
    return parts


def _convert_evidence_to_description(evidence: Dict, finding_data: Dict) -> str:
    """Convert evidence dict to readable description."""
    if isinstance(evidence, str):
        return evidence

    if not isinstance(evidence, dict):
        return "Vulnerability detected."

    vuln_type = (finding_data.get("type") or "").upper()
    param = finding_data.get("parameter", "unknown")
    payload = finding_data.get("payload", "")

    if vuln_type in ["CSTI", "SSTI"]:
        parts = _build_csti_description(evidence, param, payload)
    elif vuln_type in ["SQLI", "SQL"]:
        parts = _build_sqli_description(evidence, param)
    elif vuln_type == "XSS":
        parts = _build_xss_description(evidence, param, payload)
    else:
        # Generic fallback
        parts = [f"{k}: {v}" for k, v in evidence.items() if isinstance(v, str) and v]

    return "\n".join(parts) if parts else "Vulnerability detected."


# -- Finding field resolution: pure policy in finding_policy; thin enum adapters --

from bugtrace.core import finding_policy as _finding_policy

SEVERITY_RANK = _finding_policy.SEVERITY_RANK
DEFAULT_CONFIDENCE = _finding_policy.DEFAULT_CONFIDENCE
CONFIDENCE_FLOOR = {
    FindingStatus.VALIDATED_CONFIRMED: _finding_policy.CONFIDENCE_FLOOR[
        _finding_policy.VALIDATED_CONFIRMED
    ],
    FindingStatus.PENDING_VALIDATION: _finding_policy.CONFIDENCE_FLOOR[
        _finding_policy.PENDING_VALIDATION
    ],
}
_TERMINAL_VERDICTS = frozenset(
    {
        FindingStatus.VALIDATED_CONFIRMED,
        FindingStatus.VALIDATED_FALSE_POSITIVE,
        FindingStatus.MANUAL_REVIEW_RECOMMENDED,
    }
)


def _rank_severity(severity: str) -> int:
    """# PURE — Map severity string to numeric rank for comparison."""
    return _finding_policy.rank_severity(severity)


def _higher_severity(current: str, candidate: str) -> str:
    """# PURE — Return the higher of two severity values."""
    return _finding_policy.higher_severity(current, candidate)


def _resolve_confidence(explicit: float | None, status: FindingStatus) -> float:
    """# PURE — Derive confidence from explicit value + status floor."""
    return _finding_policy.resolve_confidence(
        explicit, status.value if isinstance(status, FindingStatus) else status
    )


def _resolve_status(current: FindingStatus, incoming, validated: bool) -> FindingStatus:
    """# PURE — Resolve a finding's status when updating an existing row.

    Delegates transition rules to finding_policy; returns FindingStatus enums
    for the SQLite adapter layer.
    """
    resolved = _finding_policy.resolve_status_update(
        current, incoming, validated=validated
    )
    try:
        return FindingStatus(resolved)
    except ValueError:
        return current


def _evidence_to_description(finding_data: Dict) -> str:
    """Convert finding data to a human-readable description."""
    # Priority: description > note > evidence (converted) > fallback
    desc = finding_data.get("description")
    if desc and isinstance(desc, str) and len(desc) > 10:
        return desc

    note = finding_data.get("note")
    if note and isinstance(note, str) and len(note) > 10:
        return note

    evidence = finding_data.get("evidence")
    if evidence:
        return _convert_evidence_to_description(evidence, finding_data)

    # Fallback
    vuln_type = finding_data.get("type", "Unknown")
    param = finding_data.get("parameter", "")
    return f"{vuln_type} vulnerability detected on parameter: {param}" if param else f"{vuln_type} vulnerability detected."


