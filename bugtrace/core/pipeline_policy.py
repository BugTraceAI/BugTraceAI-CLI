"""Pure pipeline phase transition policy (Phase 3 foundation).

No asyncio, event bus, settings, or logging. String phase names match
``PipelinePhase`` values in ``pipeline.py`` so the live state machine can
delegate validity checks without import cycles.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

# Phase name strings (mirror PipelinePhase values).
IDLE = "idle"
RECONNAISSANCE = "reconnaissance"
DISCOVERY = "discovery"
STRATEGY = "strategy"
EXPLOITATION = "exploitation"
VALIDATION = "validation"
REPORTING = "reporting"
COMPLETE = "complete"
ERROR = "error"
PAUSED = "paused"

ACTIVE_PHASES: tuple[str, ...] = (
    RECONNAISSANCE,
    DISCOVERY,
    STRATEGY,
    EXPLOITATION,
    VALIDATION,
    REPORTING,
)

ALL_PHASES: frozenset[str] = frozenset(
    {
        IDLE,
        *ACTIVE_PHASES,
        COMPLETE,
        ERROR,
        PAUSED,
    }
)

# Graph: from_phase -> allowed to_phases
VALID_TRANSITION_GRAPH: dict[str, tuple[str, ...]] = {
    IDLE: (RECONNAISSANCE,),
    RECONNAISSANCE: (DISCOVERY, PAUSED, ERROR),
    DISCOVERY: (STRATEGY, PAUSED, ERROR),
    STRATEGY: (EXPLOITATION, PAUSED, ERROR),
    EXPLOITATION: (VALIDATION, PAUSED, ERROR),
    VALIDATION: (REPORTING, PAUSED, ERROR),
    REPORTING: (COMPLETE, ERROR),
    PAUSED: ACTIVE_PHASES,
    COMPLETE: (IDLE,),
    ERROR: (IDLE,),
}


def normalize_phase(phase: object) -> str:
    if phase is None:
        raise ValueError("phase is required")
    # str Enum members are instances of str; prefer .value before str(member).
    from enum import Enum

    if isinstance(phase, Enum):
        phase = phase.value
    text = str(phase).strip().lower()
    if text not in ALL_PHASES:
        raise ValueError(f"unknown pipeline phase: {phase!r}")
    return text


def can_transition(from_phase: object, to_phase: object) -> bool:
    """True when the pure transition graph allows from → to."""
    try:
        src = normalize_phase(from_phase)
        dst = normalize_phase(to_phase)
    except ValueError:
        return False
    return dst in VALID_TRANSITION_GRAPH.get(src, ())


def allowed_targets(from_phase: object) -> tuple[str, ...]:
    src = normalize_phase(from_phase)
    return VALID_TRANSITION_GRAPH.get(src, ())


@dataclass(frozen=True)
class TransitionDecision:
    """Result of evaluating a phase transition command (pure)."""

    allowed: bool
    from_phase: str
    to_phase: str
    reason: str
    error: str | None = None

    def raise_if_denied(self) -> None:
        if not self.allowed:
            raise ValueError(self.error or "transition denied")


def decide_transition(
    from_phase: object,
    to_phase: object,
    reason: str,
) -> TransitionDecision:
    """Reducer-style decision: does not mutate any live state."""
    src = normalize_phase(from_phase)
    dst = normalize_phase(to_phase)
    if dst in VALID_TRANSITION_GRAPH.get(src, ()):
        return TransitionDecision(
            allowed=True, from_phase=src, to_phase=dst, reason=reason
        )
    targets = list(VALID_TRANSITION_GRAPH.get(src, ()))
    return TransitionDecision(
        allowed=False,
        from_phase=src,
        to_phase=dst,
        reason=reason,
        error=(
            f"Invalid transition: {src} -> {dst}. "
            f"Valid targets: {targets}"
        ),
    )


def apply_flags(
    to_phase: str,
    *,
    paused: bool,
    pause_reason: str | None,
    error: str | None,
    reason: str,
) -> dict[str, object]:
    """Pure flag updates for paused/error when entering a phase."""
    to_phase = normalize_phase(to_phase)
    new_paused = paused
    new_pause_reason = pause_reason
    new_error = error
    if to_phase == PAUSED:
        new_paused = True
        new_pause_reason = reason
    elif paused and to_phase != PAUSED:
        new_paused = False
        new_pause_reason = None
    if to_phase == ERROR:
        new_error = reason
    elif to_phase == IDLE:
        new_error = None
    return {
        "paused": new_paused,
        "pause_reason": new_pause_reason,
        "error": new_error,
    }


def graph_matches_enum_map(enum_transitions: Mapping[object, list]) -> bool:
    """Parity helper: compare live VALID_TRANSITIONS enum map to pure graph."""
    converted: dict[str, tuple[str, ...]] = {}
    for key, vals in enum_transitions.items():
        k = normalize_phase(key)
        converted[k] = tuple(normalize_phase(v) for v in vals)
    return converted == VALID_TRANSITION_GRAPH
