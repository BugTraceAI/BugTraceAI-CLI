"""Pure WebSocket scan-stream envelope policy (Phase 5 prep).

No FastAPI, asyncio, or DB. Freezes envelope shape, event_type mapping,
replay filtering, and path ownership constants for offline contracts.

Live paths (both must keep envelope parity until WEB cutover):
- Canonical: ``/api/ws/scans/{scan_id}`` (router under ``/api``)
- Compat:    ``/ws/scans/{scan_id}`` (app-level, supports ``last_seq``)
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Sequence

# Path ownership (string templates; no routing).
WS_PATH_CANONICAL = "/api/ws/scans/{scan_id}"
WS_PATH_COMPAT = "/ws/scans/{scan_id}"

# Keys the WEB client (`useScanSocket`) expects on each frame.
REQUIRED_ENVELOPE_KEYS = frozenset({"event_type", "seq", "timestamp", "data"})

# Terminal event types that end the live stream (compat path).
TERMINAL_EVENT_TYPES = frozenset({"scan_complete", "error"})

# Explicit internal event → WS event_type (ServiceEventBus map).
EVENT_TYPE_MAP: dict[str, str] = {
    "scan.created": "scan_created",
    "scan.started": "scan_started",
    "scan.completed": "scan_complete",
    "scan.stopped": "scan_complete",
    "scan.failed": "error",
    "scan.error": "error",
    "scan.paused": "scan_paused",
    "scan.resumed": "scan_resumed",
    "vulnerability_detected": "finding_discovered",
    "pipeline_started": "log",
    "pipeline_complete": "log",
    "pipeline_error": "error",
    "url_analyzed": "log",
    "pipeline_progress": "pipeline_progress",
    "agent_update": "agent_update",
    "metrics_update": "metrics_update",
    "scan_complete_summary": "scan_complete_summary",
    "scan_log": "log",
}

_VERBOSE_PREFIXES = frozenset(
    {
        "pipeline",
        "recon",
        "discovery",
        "strategy",
        "exploit",
        "auth",
        "validation",
        "reporting",
    }
)


def map_event_type(event: str) -> str:
    """Map internal bus event names to WS event_type strings."""
    if event in EVENT_TYPE_MAP:
        return EVENT_TYPE_MAP[event]

    if "." in event:
        prefix = event.split(".", 1)[0]
        if prefix in _VERBOSE_PREFIXES:
            return event

    if "agent" in event:
        return "agent_active"
    if event == "finding_discovered":
        return "finding_discovered"
    if "finding" in event:
        return "log"
    if "phase" in event:
        return "phase_complete"
    return event


def build_history_entry(
    event: str,
    data: Mapping[str, Any],
    *,
    seq: int,
    timestamp_iso: str,
    event_type: str | None = None,
) -> Dict[str, Any]:
    """Build a scan-scoped history / stream frame.

    Includes legacy ``event`` key (internal name) plus WEB-facing keys.
    ``data`` is nested under ``data`` for envelope parity with WEB.
    """
    et = event_type if event_type is not None else map_event_type(event)
    return {
        "event": event,
        "data": dict(data),
        "timestamp": timestamp_iso,
        "seq": seq,
        "event_type": et,
    }


def envelope_has_required_keys(frame: Mapping[str, Any]) -> bool:
    """True when WEB-facing required keys are present (data may be empty dict)."""
    return REQUIRED_ENVELOPE_KEYS.issubset(frame.keys()) and "data" in frame


def events_after_seq(
    history: Sequence[Mapping[str, Any]], since_seq: int
) -> List[Dict[str, Any]]:
    """Replay filter: events with seq > since_seq (since_seq=0 → all)."""
    if since_seq == 0:
        return [dict(e) for e in history]
    return [dict(e) for e in history if int(e.get("seq", 0)) > since_seq]


def should_skip_stream_event(
    event: Mapping[str, Any], highest_sent: int
) -> bool:
    """True when live stream should not forward this frame."""
    if event.get("event_type") == "heartbeat":
        return True
    return int(event.get("seq", 0)) <= highest_sent


def is_terminal_event_type(event_type: object) -> bool:
    return str(event_type) in TERMINAL_EVENT_TYPES


__all__ = [
    "WS_PATH_CANONICAL",
    "WS_PATH_COMPAT",
    "REQUIRED_ENVELOPE_KEYS",
    "TERMINAL_EVENT_TYPES",
    "EVENT_TYPE_MAP",
    "map_event_type",
    "build_history_entry",
    "envelope_has_required_keys",
    "events_after_seq",
    "should_skip_stream_event",
    "is_terminal_event_type",
]
