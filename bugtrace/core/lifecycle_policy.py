"""Pure scan lifecycle decisions (Phase 3 foundation).

Commands in → next status / effect descriptors out. No asyncio, ScanService,
database, or TeamOrchestrator. Adapters execute effects later.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

# Align with ScanStatus string values in db_models.
PENDING = "PENDING"
INITIALIZING = "INITIALIZING"
RUNNING = "RUNNING"
PAUSED = "PAUSED"
COMPLETED = "COMPLETED"
STOPPED = "STOPPED"
FAILED = "FAILED"
CANCELLED = "CANCELLED"

ACTIVE = frozenset({PENDING, INITIALIZING, RUNNING, PAUSED})
TERMINAL = frozenset({COMPLETED, STOPPED, FAILED, CANCELLED})

# ScanContext / in-memory status strings → policy status names.
# "stopping" is still an active stop in flight; treat as RUNNING for can_stop.
MEMORY_STATUS_MAP: dict[str, str] = {
    "RUNNING": RUNNING,
    "PAUSED": PAUSED,
    "PENDING": PENDING,
    "INITIALIZING": INITIALIZING,
    "COMPLETED": COMPLETED,
    "STOPPED": STOPPED,
    "FAILED": FAILED,
    "CANCELLED": CANCELLED,
    "STOPPING": RUNNING,
}


@dataclass(frozen=True)
class LifecycleEffect:
    """Named effect descriptor for the imperative shell."""

    kind: str
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class LifecycleDecision:
    allowed: bool
    from_status: str
    to_status: str | None
    effects: tuple[LifecycleEffect, ...] = ()
    error: str | None = None


def normalize_status(status: object) -> str:
    if status is None:
        raise ValueError("status required")
    from enum import Enum

    if isinstance(status, Enum):
        status = status.value
    text = str(status).strip().upper()
    if not text:
        raise ValueError("status empty")
    return text


def memory_status_to_policy(status: object | None) -> str:
    """Map ScanContext / API memory status strings onto policy status names.

    Unknown non-empty values are uppercased and returned as-is so future labels
    fail closed only at can_* gates, not here.
    """
    if status is None:
        return RUNNING
    from enum import Enum

    if isinstance(status, Enum):
        status = status.value
    key = str(status).strip().upper()
    if not key:
        return RUNNING
    return MEMORY_STATUS_MAP.get(key, key)


def effect_kinds(decision: LifecycleDecision) -> tuple[str, ...]:
    """Ordered effect kind names from a decision (pure projection)."""
    return tuple(e.kind for e in decision.effects)


def can_start(current: object | None) -> bool:
    if current is None:
        return True
    s = normalize_status(current)
    return s in TERMINAL or s == PENDING


def can_stop(current: object) -> bool:
    return normalize_status(current) in ACTIVE


def can_pause(current: object) -> bool:
    return normalize_status(current) == RUNNING


def can_resume(current: object) -> bool:
    return normalize_status(current) == PAUSED


def decide_start(current: object | None, *, scan_id: int | str | None = None) -> LifecycleDecision:
    cur = normalize_status(current) if current is not None else PENDING
    if not can_start(current):
        return LifecycleDecision(
            allowed=False,
            from_status=cur,
            to_status=None,
            error=f"cannot start from status {cur}",
        )
    effects = (
        LifecycleEffect("persist_status", {"status": RUNNING, "scan_id": scan_id}),
        LifecycleEffect("spawn_orchestrator", {"scan_id": scan_id}),
        LifecycleEffect("emit_event", {"event": "pipeline_started", "scan_id": scan_id}),
    )
    return LifecycleDecision(
        allowed=True, from_status=cur, to_status=RUNNING, effects=effects
    )


def decide_stop(current: object, *, scan_id: int | str | None = None) -> LifecycleDecision:
    cur = normalize_status(current)
    if not can_stop(current):
        return LifecycleDecision(
            allowed=False,
            from_status=cur,
            to_status=None,
            error=f"cannot stop from status {cur}",
        )
    effects = (
        LifecycleEffect("signal_orchestrator_stop", {"scan_id": scan_id}),
        LifecycleEffect("persist_status", {"status": STOPPED, "scan_id": scan_id}),
        LifecycleEffect("emit_event", {"event": "pipeline_complete", "scan_id": scan_id}),
        LifecycleEffect("cleanup_resources", {"scan_id": scan_id}),
    )
    return LifecycleDecision(
        allowed=True, from_status=cur, to_status=STOPPED, effects=effects
    )


def decide_pause(current: object, *, scan_id: int | str | None = None) -> LifecycleDecision:
    cur = normalize_status(current)
    if not can_pause(current):
        return LifecycleDecision(
            allowed=False,
            from_status=cur,
            to_status=None,
            error=f"cannot pause from status {cur}",
        )
    effects = (
        LifecycleEffect("signal_orchestrator_pause", {"scan_id": scan_id}),
        LifecycleEffect("persist_status", {"status": PAUSED, "scan_id": scan_id}),
        LifecycleEffect("emit_event", {"event": "pipeline_paused", "scan_id": scan_id}),
    )
    return LifecycleDecision(
        allowed=True, from_status=cur, to_status=PAUSED, effects=effects
    )


def decide_resume(current: object, *, scan_id: int | str | None = None) -> LifecycleDecision:
    cur = normalize_status(current)
    if not can_resume(current):
        return LifecycleDecision(
            allowed=False,
            from_status=cur,
            to_status=None,
            error=f"cannot resume from status {cur}",
        )
    effects = (
        LifecycleEffect("signal_orchestrator_resume", {"scan_id": scan_id}),
        LifecycleEffect("persist_status", {"status": RUNNING, "scan_id": scan_id}),
        LifecycleEffect("emit_event", {"event": "pipeline_resumed", "scan_id": scan_id}),
    )
    return LifecycleDecision(
        allowed=True, from_status=cur, to_status=RUNNING, effects=effects
    )


# ---------------------------------------------------------------------------
# Concurrent capacity (P5-SCAN-1) — pure, no asyncio.Semaphore
# ---------------------------------------------------------------------------

DEFAULT_MAX_CONCURRENT = 1


def normalize_max_concurrent(max_concurrent: object) -> int:
    """Coerce max concurrent capacity; must be a positive int."""
    try:
        n = int(max_concurrent)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise ValueError(f"max_concurrent must be an int, got {max_concurrent!r}") from exc
    if n < 1:
        raise ValueError(f"max_concurrent must be >= 1, got {n}")
    return n


def can_accept_new_scan(active_count: object, max_concurrent: object) -> bool:
    """True when creating another in-memory active scan is allowed."""
    active = int(active_count)  # type: ignore[arg-type]
    if active < 0:
        raise ValueError(f"active_count must be >= 0, got {active}")
    return active < normalize_max_concurrent(max_concurrent)


def concurrent_limit_message(max_concurrent: object) -> str:
    """User-facing error text when at capacity (parity with ScanService)."""
    n = normalize_max_concurrent(max_concurrent)
    return (
        f"Maximum concurrent scans ({n}) already running. "
        f"Wait for a scan to complete or stop one."
    )


def decide_accept_scan(
    active_count: object,
    max_concurrent: object,
    *,
    scan_id: int | str | None = None,
) -> LifecycleDecision:
    """Gate for create_scan capacity. Effects are descriptors only (shell enforces)."""
    cap = normalize_max_concurrent(max_concurrent)
    active = int(active_count)  # type: ignore[arg-type]
    if active < 0:
        return LifecycleDecision(
            allowed=False,
            from_status=PENDING,
            to_status=None,
            error=f"active_count must be >= 0, got {active}",
        )
    if not can_accept_new_scan(active, cap):
        return LifecycleDecision(
            allowed=False,
            from_status=PENDING,
            to_status=None,
            error=concurrent_limit_message(cap),
        )
    effects = (
        LifecycleEffect(
            "reserve_active_slot",
            {"scan_id": scan_id, "active_count": active, "max_concurrent": cap},
        ),
    )
    return LifecycleDecision(
        allowed=True,
        from_status=PENDING,
        to_status=INITIALIZING,
        effects=effects,
    )
