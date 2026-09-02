"""XSSAgent — compatibility facade (P4-XSS-15).

Canonical implementation lives in ``bugtrace.agents.xss.agent``.

This module preserves the historical import path used by CLI, team flows,
smokes, and unit tests:

    from bugtrace.agents.xss_agent import XSSAgent

It also re-exports pure helpers that smokes/canaries still resolve on this
module namespace (position/breakouts/seed enrichment / shell constants).
"""

from __future__ import annotations

# Implementation owner.
from bugtrace.agents.xss.agent import XSSAgent, run_xss_scan

# Type owner (no dual ClassDef here — contract fixtures enforce this).
from bugtrace.agents.xss.types import (
    InjectionContext,
    ValidationMethod,
    XSSFinding,
)

# Seed enrichment aliases expected on this module by unit tests.
from bugtrace.agents.xss.finding_builder import (
    SENSITIVE_HEADERS as _SENSITIVE_HEADERS,
    mask_auth_headers as _mask_auth_headers,
    auth_meta as _auth_meta,
    excerpt_around as _excerpt_around,
    build_raw_http as _build_raw_http,
    promote_repro as _promote_repro,
)

# Context-set normaliser re-export (test identity with package owner).
from bugtrace.agents.xss.context_reflection import (
    as_context_set as _as_context_set,
    canonical_probe_context,
    CONTEXT_EXPLOITABILITY as _CONTEXT_EXPLOITABILITY,
)

# Shell constants used by smoke_xss_coverage canaries.
from bugtrace.agents.xss.shell_constants import (
    _BROWSER_ONLY_CONTEXTS,
    _CDP_PROOF_LOCK,
    _L05_CHAR_PROBE,
    _LEGACY_PROBE_MARKER,
    _PROBE_NO_REFLECTION,
    _PROBE_NO_RESPONSE,
    _PROBE_REFLECTED,
    _REDIRECT_PARAM_SET,
    _REFLECTION_SNIPPET_RADIUS,
)

# Position + breakouts: smokes monkeypatch / read constants on this module.
import bugtrace.agents.xss.position as _xss_position  # noqa: E402
import bugtrace.agents.xss.breakouts as _xss_breakouts  # noqa: E402

globals().update(
    {
        name: value
        for name, value in vars(_xss_position).items()
        if not name.startswith("__")
    }
)
globals().update(
    {
        name: value
        for name, value in vars(_xss_breakouts).items()
        if not name.startswith("__")
    }
)

__all__ = [
    "XSSAgent",
    "run_xss_scan",
    "XSSFinding",
    "InjectionContext",
    "ValidationMethod",
    "canonical_probe_context",
    "_CONTEXT_EXPLOITABILITY",
]
