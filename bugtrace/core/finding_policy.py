"""Pure finding status and severity policy (Phase 2 foundation).

No I/O, database, network, or settings. Status values are plain strings that
mirror ``FindingStatus`` in ``bugtrace.schemas.db_models`` so the SQLModel
enum remains the persistence adapter while this module owns transition rules.
"""

from __future__ import annotations

from typing import Iterable

# Canonical lifecycle strings (must stay aligned with db_models.FindingStatus).
PENDING_VALIDATION = "PENDING_VALIDATION"
VALIDATED_CONFIRMED = "VALIDATED_CONFIRMED"
VALIDATED_FALSE_POSITIVE = "VALIDATED_FALSE_POSITIVE"
MANUAL_REVIEW_RECOMMENDED = "MANUAL_REVIEW_RECOMMENDED"
SKIPPED = "SKIPPED"
ERROR = "ERROR"

ALL_STATUSES: frozenset[str] = frozenset(
    {
        PENDING_VALIDATION,
        VALIDATED_CONFIRMED,
        VALIDATED_FALSE_POSITIVE,
        MANUAL_REVIEW_RECOMMENDED,
        SKIPPED,
        ERROR,
    }
)

# Definitive validator verdicts that may downgrade an existing row.
TERMINAL_VERDICTS: frozenset[str] = frozenset(
    {
        VALIDATED_CONFIRMED,
        VALIDATED_FALSE_POSITIVE,
        MANUAL_REVIEW_RECOMMENDED,
    }
)

# Statuses that are safe to surface as confirmed/reportable by default policy.
REPORTABLE_STATUSES: frozenset[str] = frozenset(
    {
        VALIDATED_CONFIRMED,
        MANUAL_REVIEW_RECOMMENDED,
    }
)

SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

CONFIDENCE_FLOOR: dict[str, float] = {
    VALIDATED_CONFIRMED: 0.95,
    PENDING_VALIDATION: 0.5,
}

DEFAULT_CONFIDENCE = 0.85


def normalize_status(value: object | None) -> str | None:
    """Parse a status-like value to a canonical string, or None if unknown."""
    if value is None:
        return None
    if hasattr(value, "value"):
        value = getattr(value, "value")
    text = str(value).strip()
    if not text:
        return None
    upper = text.upper()
    if upper in ALL_STATUSES:
        return upper
    return None


def rank_severity(severity: str | None) -> int:
    """Map severity string to numeric rank for comparison."""
    return SEVERITY_RANK.get((severity or "").upper(), -1)


def higher_severity(current: str | None, candidate: str | None) -> str:
    """Return the higher of two severity values (uppercased)."""
    cur = (current or "").upper()
    cand = (candidate or "").upper()
    return cand if rank_severity(cand) > rank_severity(cur) else cur


def resolve_confidence(explicit: float | None, status: str | None) -> float:
    """Derive confidence from an explicit value plus a status floor."""
    canon = normalize_status(status) or ""
    floor = CONFIDENCE_FLOOR.get(canon, 0.0)
    base = explicit if explicit is not None else DEFAULT_CONFIDENCE
    return max(base, floor)


def resolve_status_update(
    current: str | object | None,
    incoming: str | object | None,
    *,
    validated: bool,
) -> str:
    """Resolve a finding's status when updating an existing record.

    Rules (in order):
      1. A positive validation signal always confirms — VALIDATED_CONFIRMED wins.
      2. An explicit terminal verdict (confirmed / false-positive / manual-review)
         is honored (may downgrade).
      3. Partial/unknown signals leave the current status untouched.
    """
    current_s = normalize_status(current) or PENDING_VALIDATION
    if validated:
        return VALIDATED_CONFIRMED
    candidate = normalize_status(incoming)
    if candidate is not None and candidate in TERMINAL_VERDICTS:
        return candidate
    return current_s


def is_reportable_status(status: str | object | None) -> bool:
    canon = normalize_status(status)
    return canon in REPORTABLE_STATUSES if canon else False


def finding_identity_key(
    *,
    vuln_type: str | None,
    url: str | None,
    parameter: str | None,
    payload: str | None = None,
) -> tuple[str, str, str, str]:
    """Stable identity tuple for expand-and-reconcile / dedup (no hashing I/O).

    Payload is included so distinct proofs on the same parameter do not collapse
    incorrectly; callers that want coarser dedup may ignore the last element.
    """
    return (
        (vuln_type or "").strip().upper(),
        (url or "").strip(),
        (parameter or "").strip(),
        (payload or "").strip(),
    )


def statuses_aligned_with(enum_values: Iterable[str]) -> bool:
    """True when an external enum's values cover the canonical set (parity check)."""
    return set(enum_values) == set(ALL_STATUSES)
