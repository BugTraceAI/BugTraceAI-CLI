"""Pure queue item construction and specialist-queue naming policy (Phase 2).

No asyncio queues, filesystem spill, or settings. The live ``QueueItem`` and
``QueueManager`` remain the imperative shell; this module owns shape rules.
"""

from __future__ import annotations

from typing import Any, Mapping

# Canonical specialist queue names — keep aligned with queue.SPECIALIST_QUEUES.
SPECIALIST_QUEUE_NAMES: tuple[str, ...] = (
    "xss",
    "sqli",
    "csti",
    "lfi",
    "idor",
    "rce",
    "ssrf",
    "xxe",
    "jwt",
    "openredirect",
    "prototype_pollution",
    "file_upload",
    "chain_discovery",
    "api_security",
    "header_injection",
    "mass_assignment",
)

SPECIALIST_QUEUE_SET: frozenset[str] = frozenset(SPECIALIST_QUEUE_NAMES)

# Required top-level keys for a specialist work payload (WET-style candidate).
# Extra keys are allowed; missing required keys fail validation.
REQUIRED_PAYLOAD_KEYS: frozenset[str] = frozenset({"url"})


def normalize_queue_name(name: object) -> str:
    text = str(name or "").strip().lower()
    if not text:
        raise ValueError("queue name is empty")
    return text


def is_known_specialist_queue(name: object) -> bool:
    try:
        return normalize_queue_name(name) in SPECIALIST_QUEUE_SET
    except ValueError:
        return False


def validate_work_payload(payload: Mapping[str, Any] | None) -> tuple[bool, str]:
    """Return (ok, error). Does not mutate payload."""
    if not isinstance(payload, Mapping):
        return False, "payload must be a mapping"
    missing = sorted(k for k in REQUIRED_PAYLOAD_KEYS if k not in payload or payload[k] in (None, ""))
    if missing:
        return False, f"payload missing required keys: {', '.join(missing)}"
    return True, ""


def build_queue_item_fields(
    payload: Mapping[str, Any],
    scan_context: str,
    *,
    enqueued_at: float,
) -> dict[str, Any]:
    """Pure field dict matching QueueItem attributes (caller supplies clock)."""
    ok, err = validate_work_payload(payload)
    if not ok:
        raise ValueError(err)
    ctx = str(scan_context or "").strip()
    if not ctx:
        raise ValueError("scan_context is required")
    return {
        "payload": dict(payload),
        "scan_context": ctx,
        "enqueued_at": float(enqueued_at),
    }


def queue_item_from_fields(fields: Mapping[str, Any]):
    """Adapter: materialize live QueueItem from pure fields (imports queue)."""
    from bugtrace.core.queue import QueueItem

    return QueueItem(
        payload=dict(fields["payload"]),
        scan_context=fields["scan_context"],
        enqueued_at=fields["enqueued_at"],
    )


def make_queue_item(
    payload: Mapping[str, Any],
    scan_context: str,
    *,
    enqueued_at: float | None = None,
    clock=None,
):
    """Build a QueueItem; clock is ``callable() -> float`` when enqueued_at omitted."""
    if enqueued_at is None:
        if clock is None:
            import time

            clock = time.monotonic
        enqueued_at = float(clock())
    fields = build_queue_item_fields(payload, scan_context, enqueued_at=enqueued_at)
    return queue_item_from_fields(fields)
