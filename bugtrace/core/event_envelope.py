"""Pure event envelope values for the functional core (Phase 2).

No network, filesystem, asyncio, or global bus access. Callers build an
``EventEnvelope`` and pass ``to_bus_args()`` into the existing EventBus.emit
surface so wire/payload names stay compatible.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Mapping, MutableMapping


def normalize_event_name(event: object) -> str:
    """Normalize EventType | str | other to a stable event name string."""
    if event is None:
        raise ValueError("event name is required")
    if hasattr(event, "value") and not isinstance(event, str):
        value = getattr(event, "value")
        if isinstance(value, str) and value:
            return value
    text = str(event).strip()
    if not text:
        raise ValueError("event name is empty")
    # Allow EventType.NAME style if someone passes the enum member str form poorly.
    if text.startswith("EventType."):
        text = text.split(".", 1)[1].lower()
    return text


def extract_scan_context(data: Mapping[str, Any] | None) -> str | None:
    if not data:
        return None
    raw = data.get("scan_context")
    if raw is None or raw == "":
        return None
    return str(raw)


def extract_scan_id(data: Mapping[str, Any] | None) -> int | str | None:
    if not data:
        return None
    if "scan_id" not in data:
        return None
    return data.get("scan_id")


@dataclass(frozen=True)
class EventEnvelope:
    """Immutable event value: type name + payload + optional scope metadata.

    ``data`` is the bus payload dict (same keys callers use today). Optional
    ``seq`` is for service-layer history projection only; core bus ignores it.
    """

    event: str
    data: Mapping[str, Any] = field(default_factory=dict)
    scan_context: str | None = None
    scan_id: int | str | None = None
    seq: int | None = None
    schema_version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "event", normalize_event_name(self.event))
        # Freeze payload view: store a shallow copy tuple-safe via Mapping proxy style dict
        payload = dict(self.data or {})
        object.__setattr__(self, "data", payload)
        if self.scan_context is None:
            object.__setattr__(self, "scan_context", extract_scan_context(payload))
        if self.scan_id is None and "scan_id" in payload:
            object.__setattr__(self, "scan_id", payload.get("scan_id"))

    def with_data(self, **updates: Any) -> EventEnvelope:
        merged = dict(self.data)
        merged.update(updates)
        return replace(
            self,
            data=merged,
            scan_context=extract_scan_context(merged) or self.scan_context,
            scan_id=extract_scan_id(merged) if "scan_id" in merged else self.scan_id,
        )

    def to_bus_payload(self) -> dict[str, Any]:
        """Payload dict for EventBus.emit — preserves scan_context/scan_id keys."""
        payload = dict(self.data)
        if self.scan_context is not None and "scan_context" not in payload:
            payload["scan_context"] = self.scan_context
        if self.scan_id is not None and "scan_id" not in payload:
            payload["scan_id"] = self.scan_id
        return payload

    def to_bus_args(self) -> tuple[str, dict[str, Any]]:
        """``event, data`` pair for ``await event_bus.emit(*envelope.to_bus_args())``."""
        return self.event, self.to_bus_payload()

    def to_history_entry(self, *, timestamp_iso: str, seq: int | None = None) -> dict[str, Any]:
        """Shape compatible with ServiceEventBus history entries (without event_type map)."""
        use_seq = self.seq if seq is None else seq
        return {
            "event": self.event,
            "data": self.to_bus_payload(),
            "timestamp": timestamp_iso,
            "seq": use_seq,
        }

    @classmethod
    def create(
        cls,
        event: object,
        data: Mapping[str, Any] | None = None,
        *,
        scan_context: str | None = None,
        scan_id: int | str | None = None,
        seq: int | None = None,
    ) -> EventEnvelope:
        payload: MutableMapping[str, Any] = dict(data or {})
        if scan_context is not None:
            payload.setdefault("scan_context", scan_context)
        if scan_id is not None:
            payload.setdefault("scan_id", scan_id)
        return cls(
            event=normalize_event_name(event),
            data=payload,
            scan_context=scan_context,
            scan_id=scan_id,
            seq=seq,
        )

    @classmethod
    def from_emit(cls, event: object, data: Mapping[str, Any] | None) -> EventEnvelope:
        """Reconstruct an envelope from a legacy emit(event, data) call site."""
        return cls.create(event, data)


def ensure_bus_emit_args(
    event: object | EventEnvelope,
    data: Mapping[str, Any] | None = None,
) -> tuple[str, dict[str, Any]]:
    """Accept either legacy (event, data) or an EventEnvelope; return bus args."""
    if isinstance(event, EventEnvelope):
        return event.to_bus_args()
    return EventEnvelope.from_emit(event, data).to_bus_args()
