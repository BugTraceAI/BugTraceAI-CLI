"""Pure scan status / list / report-count projection (Phase 5).

No DB, FS, asyncio, or ScanService. Shells load data and call these.
"""

from __future__ import annotations

from typing import Any, Dict, Mapping, Optional, Sequence


def normalize_progress(progress: object) -> int:
    """Return a user-facing progress percentage in the inclusive 0..100 range."""
    try:
        pct = int(progress)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        pct = 0
    return max(0, min(100, pct))


def exposed_progress(status: object, progress: object) -> int:
    """Normalize progress and repair legacy COMPLETED rows stuck at 0%."""
    status_text = (
        status.value if hasattr(status, "value") else str(status or "")
    ).upper()
    pct = normalize_progress(progress)
    if status_text == "COMPLETED" and pct == 0:
        return 100
    return pct


def normalize_pagination(page: object = 1, per_page: object = 20) -> tuple[int, int, int]:
    """Return (page, per_page, offset) with 1-indexed page and per_page >= 1."""
    try:
        p = int(page)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"page must be int, got {page!r}") from exc
    try:
        pp = int(per_page)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"per_page must be int, got {per_page!r}") from exc
    if p < 1:
        raise ValueError(f"page must be >= 1, got {p}")
    if pp < 1:
        raise ValueError(f"per_page must be >= 1, got {pp}")
    return p, pp, (p - 1) * pp


def project_db_scan_status(
    *,
    scan_id: int,
    target_url: str,
    status: object,
    progress: object,
    origin: object = None,
    enrichment_status: object = None,
    scan_type: object = None,
    max_depth: object = None,
    max_urls: object = None,
    provider: object = None,
    detections_count: int = 0,
    uptime_seconds: object = None,
    active_agent: object = None,
    phase: object = None,
) -> Dict[str, Any]:
    """Build ScanStatusResponse-shaped dict for completed/DB-backed scans."""
    status_text = (
        status.value if hasattr(status, "value") else str(status or "")
    )
    return {
        "scan_id": scan_id,
        "target": target_url or "unknown",
        "status": status_text,
        "progress": exposed_progress(status, progress),
        "uptime_seconds": uptime_seconds,
        "findings_count": int(detections_count),
        "active_agent": active_agent,
        "phase": phase,
        "origin": origin or "unknown",
        "enrichment_status": enrichment_status,
        "scan_type": scan_type,
        "max_depth": max_depth,
        "max_urls": max_urls,
        "provider": provider,
    }


def project_list_response(
    scans: Sequence[Mapping[str, Any]],
    *,
    total: int,
    page: int,
    per_page: int,
) -> Dict[str, Any]:
    return {
        "scans": list(scans),
        "total": int(total),
        "page": int(page),
        "per_page": int(per_page),
    }


def list_len(value: object) -> int:
    return len(value) if isinstance(value, list) else 0


def report_counts_from_artifacts(
    raw_document: object | None,
    validated_document: object | None,
) -> Dict[str, int]:
    """Compute distinct user-facing counters from report JSON documents.

    Does not collapse findings_count/detections/confirmed into one number.
    """
    counts: Dict[str, int] = {}

    if raw_document is not None:
        if isinstance(raw_document, dict):
            raw_findings = raw_document.get("findings", [])
        else:
            raw_findings = raw_document
        counts["detections_count"] = list_len(raw_findings)

    if isinstance(validated_document, dict):
        confirmed = validated_document.get("findings", [])
        manual = validated_document.get("manual_review", [])
        counts["confirmed_count"] = list_len(confirmed)
        counts["manual_review_count"] = list_len(manual)
        counts["reportable_count"] = (
            counts["confirmed_count"] + counts["manual_review_count"]
        )
    elif validated_document is not None and isinstance(validated_document, list):
        counts["confirmed_count"] = list_len(validated_document)
        counts["manual_review_count"] = 0
        counts["reportable_count"] = counts["confirmed_count"]

    return counts


def findings_count_for_status(
    report_counts: Mapping[str, int],
    *,
    db_findings_fallback: int = 0,
) -> int:
    """Prefer artifact detections_count; else DB finding row count."""
    if "detections_count" in report_counts:
        return int(report_counts["detections_count"])
    return int(db_findings_fallback)


def project_active_scan_status(
    *,
    scan_id: int,
    target_url: str,
    status: object,
    progress: object,
    uptime_seconds: object,
    findings_count: object,
    active_agent: object = None,
    phase: object = None,
    scan_type: object = None,
    max_depth: object = None,
    max_urls: object = None,
    provider: object = None,
    origin: object = None,
    enrichment_status: object = None,
) -> Dict[str, Any]:
    """Status dict for in-memory ScanContext (active scans)."""
    status_text = str(status or "").upper()
    pct = normalize_progress(progress)
    out: Dict[str, Any] = {
        "scan_id": scan_id,
        "target": target_url,
        "status": status_text,
        "progress": pct,
        "uptime_seconds": uptime_seconds,
        "findings_count": int(findings_count or 0),
        "active_agent": active_agent,
        "phase": phase,
        "scan_type": scan_type,
        "max_depth": max_depth,
        "max_urls": max_urls,
        "provider": provider,
    }
    if origin is not None:
        out["origin"] = origin
    if enrichment_status is not None:
        out["enrichment_status"] = enrichment_status
    return out


__all__ = [
    "normalize_progress",
    "exposed_progress",
    "normalize_pagination",
    "project_db_scan_status",
    "project_list_response",
    "list_len",
    "report_counts_from_artifacts",
    "findings_count_for_status",
    "project_active_scan_status",
]
